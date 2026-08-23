use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::{Application, NetworksRequest};
use crate::daemon_event::emit_json_event_nonfatal;
use crate::daemon_runtime::SharedPayloads;
use crate::nm::Nm;
use crate::protocol::{Method, Stream};

pub(crate) struct SubscriptionState {
    id: String,
    owner: Option<String>,
    streams: Vec<Stream>,
    emitter: SignalEmitter<'static>,
    last_status: Option<Value>,
    last_connectivity: Option<Value>,
    last_inventory: Option<Value>,
    last_networks: Option<Value>,
}

impl SubscriptionState {
    pub(crate) fn new(
        id: String,
        owner: Option<String>,
        streams: Vec<Stream>,
        emitter: SignalEmitter<'static>,
    ) -> Self {
        Self {
            id,
            owner,
            streams,
            emitter,
            last_status: None,
            last_connectivity: None,
            last_inventory: None,
            last_networks: None,
        }
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn watches(&self, stream: Stream) -> bool {
        self.streams.contains(&stream)
    }

    pub(crate) fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    pub(crate) fn owned_by(&self, owner: &str) -> bool {
        self.owner.as_deref() == Some(owner)
    }

    pub(crate) fn emit_external(&self, stream: Stream, request_id: &str, event: &str, data: Value) {
        if self.watches(stream) {
            emit_json_event_nonfatal(&self.emitter, stream, Some(request_id), event, data);
        }
    }

    pub(crate) fn emit_changes(&mut self, payloads: &SharedPayloads) {
        emit_payload_change(
            &self.emitter,
            &self.id,
            self.watches(Stream::WifiStatus),
            Stream::WifiStatus,
            Method::WifiStatus,
            &mut self.last_status,
            payloads.status.as_ref(),
        );
        emit_payload_change(
            &self.emitter,
            &self.id,
            self.watches(Stream::NetworkConnectivity),
            Stream::NetworkConnectivity,
            Method::NetworkConnectivity,
            &mut self.last_connectivity,
            payloads.connectivity.as_ref(),
        );
        emit_payload_change(
            &self.emitter,
            &self.id,
            self.watches(Stream::NetworkInventory),
            Stream::NetworkInventory,
            Method::NetworkInventory,
            &mut self.last_inventory,
            payloads.inventory.as_ref(),
        );
        if self.watches(Stream::WifiNetworks)
            && let Some(value) = &payloads.networks
        {
            emit_network_changes(&self.emitter, &self.id, &mut self.last_networks, value);
        }
    }
}

fn emit_payload_change(
    emitter: &SignalEmitter<'static>,
    id: &str,
    watched: bool,
    stream: Stream,
    method: Method,
    previous: &mut Option<Value>,
    value: Option<&Value>,
) {
    if watched && let Some(value) = value {
        emit_on_change(emitter, stream, id, method, previous, value);
    }
}

pub(crate) fn refresh_payloads(
    nm: &Nm,
    need_status: bool,
    need_connectivity: bool,
    need_inventory: bool,
    need_networks: bool,
) -> SharedPayloads {
    let started = Instant::now();
    let application = Application::new(nm);
    let status = need_status
        .then(|| application.status())
        .and_then(log_typed_refresh_error);
    let connectivity_from_status = status
        .as_ref()
        .and_then(|status| status.connectivity.clone());
    let payloads = SharedPayloads {
        status: status.map(|status| json!(status)),
        connectivity: need_connectivity
            .then(|| match connectivity_from_status {
                Some(connectivity) => Ok(json!(connectivity)),
                None => application
                    .connectivity()
                    .map(|connectivity| json!(connectivity)),
            })
            .and_then(log_typed_refresh_error),
        inventory: need_inventory
            .then(|| {
                application
                    .network_inventory()
                    .map(|inventory| json!(inventory))
            })
            .and_then(log_typed_refresh_error),
        networks: need_networks
            .then(|| {
                application
                    .networks(NetworksRequest::new(false, false, Duration::from_secs(10)))
                    .map(|result| {
                        json!({
                            "networks": result.networks,
                            "snapshot": result.snapshot,
                            "warning": result.warning,
                        })
                    })
            })
            .and_then(log_typed_refresh_error),
    };
    tracing::debug!(
        need_status,
        need_connectivity,
        need_inventory,
        need_networks,
        status_available = payloads.status.is_some(),
        connectivity_available = payloads.connectivity.is_some(),
        inventory_available = payloads.inventory.is_some(),
        networks_available = payloads.networks.is_some(),
        connectivity_state = payloads
            .connectivity
            .as_ref()
            .and_then(|value| value.get("state"))
            .and_then(|value| value.as_str())
            .unwrap_or("unavailable"),
        elapsed_ms = started.elapsed().as_millis(),
        "refreshed shared NetworkManager subscription payloads"
    );
    payloads
}

fn log_typed_refresh_error<T>(result: anyhow::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(error = %crate::error::err_chain(&error), "shared subscription refresh failed");
            None
        }
    }
}

fn emit_network_changes(
    emitter: &SignalEmitter<'static>,
    subscription_id: &str,
    last: &mut Option<Value>,
    value: &Value,
) {
    let initial = last.is_none();
    let Some(mut payload) = network_delta(last.as_ref(), value) else {
        return;
    };
    *last = Some(value.clone());
    payload.insert("initial".to_string(), json!(initial));
    payload.insert("subscription_id".to_string(), json!(subscription_id));
    emit_json_event_nonfatal(
        emitter,
        Stream::WifiNetworks,
        Some(subscription_id),
        "changed",
        Value::Object(payload),
    );
}

fn network_delta(previous: Option<&Value>, current: &Value) -> Option<Map<String, Value>> {
    let current_networks = current.get("networks")?.as_array()?;
    let previous_networks = previous
        .and_then(|payload| payload.get("networks"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let previous_by_key = networks_by_key(previous_networks);
    let current_by_key = networks_by_key(current_networks);

    let added = current_networks
        .iter()
        .filter(|network| {
            network_key(network).is_some_and(|key| !previous_by_key.contains_key(key))
        })
        .cloned()
        .collect::<Vec<_>>();
    let changed = current_networks
        .iter()
        .filter(|network| {
            network_key(network).is_some_and(|key| {
                previous_by_key
                    .get(key)
                    .is_some_and(|previous| network_entry_changed(previous, network))
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    let removed = previous_networks
        .iter()
        .filter(|network| network_key(network).is_some_and(|key| !current_by_key.contains_key(key)))
        .cloned()
        .collect::<Vec<_>>();

    if previous.is_some() && added.is_empty() && removed.is_empty() && changed.is_empty() {
        return None;
    }

    let mut delta = Map::new();
    delta.insert("added".to_string(), json!(added));
    delta.insert("removed".to_string(), json!(removed));
    delta.insert("changed".to_string(), json!(changed));
    if let Some(snapshot) = current.get("snapshot") {
        delta.insert("snapshot".to_string(), snapshot.clone());
    }
    if let Some(warning) = current.get("warning").filter(|warning| !warning.is_null()) {
        delta.insert("warning".to_string(), warning.clone());
    }
    Some(delta)
}

fn networks_by_key(networks: &[Value]) -> HashMap<&str, &Value> {
    networks
        .iter()
        .filter_map(|network| Some((network_key(network)?, network)))
        .collect()
}

fn network_key(network: &Value) -> Option<&str> {
    network.get("key").and_then(Value::as_str)
}

fn network_entry_changed(previous: &Value, current: &Value) -> bool {
    comparable_network_entry(previous) != comparable_network_entry(current)
}

fn comparable_network_entry(network: &Value) -> Value {
    let mut network = network.clone();
    let Some(object) = network.as_object_mut() else {
        return network;
    };
    object.remove("last_seen_age_ms");
    if let Some(access_points) = object
        .get_mut("access_points")
        .and_then(Value::as_array_mut)
    {
        for access_point in access_points {
            if let Some(access_point) = access_point.as_object_mut() {
                access_point.remove("last_seen_age_ms");
            }
        }
    }
    network
}

fn emit_on_change(
    emitter: &SignalEmitter<'static>,
    stream: Stream,
    subscription_id: &str,
    method: Method,
    last: &mut Option<Value>,
    value: &Value,
) {
    if last.as_ref() == Some(value) {
        return;
    }
    if stream == Stream::NetworkConnectivity {
        tracing::info!(
            subscription_id,
            previous_state = last
                .as_ref()
                .and_then(|previous| previous.get("state"))
                .and_then(|value| value.as_str())
                .unwrap_or("unavailable"),
            connectivity_state = value
                .get("state")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown"),
            connectivity_code = value
                .get("code")
                .and_then(|value| value.as_u64())
                .unwrap_or(0),
            captive_portal = value
                .get("captive_portal")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            full = value
                .get("full")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            "emitting NetworkManager connectivity transition"
        );
    }
    *last = Some(value.clone());
    let mut payload = Map::new();
    payload.insert("subscription_id".to_string(), json!(subscription_id));
    payload.insert(method.spec().response_key.to_string(), value.clone());
    emit_json_event_nonfatal(
        emitter,
        stream,
        Some(subscription_id),
        "changed",
        Value::Object(payload),
    );
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::network_delta;

    #[test]
    fn network_delta_reports_added_removed_and_changed_entries() {
        let previous = json!({
            "networks": [
                { "key": "removed", "strength": 20 },
                { "key": "changed", "strength": 30 },
                { "key": "same", "strength": 40 }
            ],
            "snapshot": { "updated_at_ms": 1 }
        });
        let snapshot = json!({
            "source": "network-manager",
            "updated_at_ms": 2,
            "age_ms": 0,
            "stale": false,
            "scanning": false,
            "refresh_requested": false
        });
        let current = json!({
            "networks": [
                { "key": "changed", "strength": 70 },
                { "key": "same", "strength": 40 },
                { "key": "added", "strength": 50 }
            ],
            "snapshot": snapshot
        });

        let delta = network_delta(Some(&previous), &current).expect("network changes");

        assert_eq!(delta["added"], json!([{ "key": "added", "strength": 50 }]));
        assert_eq!(
            delta["removed"],
            json!([{ "key": "removed", "strength": 20 }])
        );
        assert_eq!(
            delta["changed"],
            json!([{ "key": "changed", "strength": 70 }])
        );
        assert_eq!(delta["snapshot"], snapshot);
    }

    #[test]
    fn initial_network_delta_adds_the_complete_list() {
        let current = json!({
            "networks": [{ "key": "one" }, { "key": "two" }],
            "snapshot": { "updated_at_ms": 2 }
        });

        let delta = network_delta(None, &current).expect("initial network snapshot");

        assert_eq!(delta["added"], current["networks"]);
        assert_eq!(delta["removed"], json!([]));
        assert_eq!(delta["changed"], json!([]));
    }

    #[test]
    fn network_delta_ignores_snapshot_metadata_only_changes() {
        let previous = json!({
            "networks": [{
                "key": "same",
                "strength": 40,
                "last_seen_age_ms": 1000,
                "access_points": [{ "path": "/ap/1", "last_seen_age_ms": 1000 }]
            }],
            "snapshot": { "updated_at_ms": 1 }
        });
        let current = json!({
            "networks": [{
                "key": "same",
                "strength": 40,
                "last_seen_age_ms": 2000,
                "access_points": [{ "path": "/ap/1", "last_seen_age_ms": 2000 }]
            }],
            "snapshot": { "updated_at_ms": 2 }
        });

        assert_eq!(network_delta(Some(&previous), &current), None);
    }

    #[test]
    fn network_delta_requires_a_network_array() {
        assert_eq!(network_delta(None, &Value::Null), None);
    }
}
