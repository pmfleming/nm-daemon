use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::{Application, NetworksRequest};
use crate::daemon_event::emit_json_event_nonfatal;
use crate::nm::Nm;
use crate::protocol::{Method, Stream};

#[derive(Default)]
pub(crate) struct SharedPayloads {
    pub(crate) status: Option<Value>,
    pub(crate) connectivity: Option<Value>,
    pub(crate) inventory: Option<Value>,
    pub(crate) networks: Option<Value>,
}

pub(crate) struct SubscriptionState {
    id: String,
    owner: Option<String>,
    streams: Vec<Stream>,
    emitter: SignalEmitter<'static>,
    last: SharedPayloads,
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
            last: SharedPayloads::default(),
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

    pub(crate) fn emit_external(&self, stream: Stream, request_id: &str, event: &str, data: Value) {
        emit_json_event_nonfatal(&self.emitter, stream, Some(request_id), event, data);
    }

    pub(crate) fn emit_changes(&mut self, payloads: &SharedPayloads) {
        for (stream, method, previous, value) in [
            (
                Stream::WifiStatus,
                Method::WifiStatus,
                &mut self.last.status,
                &payloads.status,
            ),
            (
                Stream::NetworkConnectivity,
                Method::NetworkConnectivity,
                &mut self.last.connectivity,
                &payloads.connectivity,
            ),
            (
                Stream::NetworkInventory,
                Method::NetworkInventory,
                &mut self.last.inventory,
                &payloads.inventory,
            ),
        ] {
            if self.streams.contains(&stream)
                && let Some(value) = value
            {
                emit_on_change(&self.emitter, stream, &self.id, method, previous, value);
            }
        }
        if self.watches(Stream::WifiNetworks)
            && let Some(value) = &payloads.networks
        {
            emit_network_changes(&self.emitter, &self.id, &mut self.last.networks, value);
        }
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
    let connectivity = need_connectivity
        .then(|| {
            match status
                .as_ref()
                .and_then(|status| status.connectivity.as_ref())
            {
                Some(connectivity) => Ok(json!(connectivity)),
                None => nm
                    .connectivity_snapshot()
                    .map(|connectivity| json!(connectivity)),
            }
        })
        .and_then(log_typed_refresh_error);
    let payloads = SharedPayloads {
        status: status.map(|status| json!(status)),
        connectivity,
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
        .collect::<Vec<_>>();
    let changed = current_networks
        .iter()
        .filter(|network| {
            network_key(network)
                .and_then(|key| previous_by_key.get(key))
                .is_some_and(|previous| network_entry_changed(previous, network))
        })
        .collect::<Vec<_>>();
    let removed = previous_networks
        .iter()
        .filter(|network| network_key(network).is_some_and(|key| !current_by_key.contains_key(key)))
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
    !equal_network_fields(previous, current, |key, previous, current| {
        match (key, previous, current) {
            ("access_points", Value::Array(previous), Value::Array(current)) => {
                previous.len() == current.len()
                    && previous.iter().zip(current).all(|(previous, current)| {
                        equal_network_fields(previous, current, |_, a, b| a == b)
                    })
            }
            _ => previous == current,
        }
    })
}

// Ignore age only at the network and AP object boundaries, not in arbitrary
// nested metadata. Compare borrowed values without copying either JSON tree.
fn equal_network_fields(
    previous: &Value,
    current: &Value,
    equal: impl Fn(&str, &Value, &Value) -> bool,
) -> bool {
    let (Value::Object(previous), Value::Object(current)) = (previous, current) else {
        return previous == current;
    };
    stable_fields(previous).count() == stable_fields(current).count()
        && stable_fields(previous).all(|(key, value)| {
            current
                .get(key)
                .is_some_and(|current| equal(key, value, current))
        })
}

fn stable_fields(object: &Map<String, Value>) -> impl Iterator<Item = (&String, &Value)> {
    object.iter().filter(|(key, _)| *key != "last_seen_age_ms")
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
    use serde_json::json;

    use super::{network_delta, network_entry_changed};

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
        // Only the two documented age fields are volatile; preserve all other
        // differences, including missing/null fields and AP order/length.
        for changed in [
            json!({"key":"same", "strength":41}),
            json!({"key":"same", "strength":40, "access_points":null}),
            json!({"key":"same", "strength":40, "access_points":[]}),
            json!({"key":"same", "strength":40, "access_points":[{"path":"/ap/2"}]}),
            json!({"key":"same", "strength":40, "access_points":[{"path":"/ap/1", "extra":null}]}),
        ] {
            assert!(network_entry_changed(&previous["networks"][0], &changed));
            assert!(network_entry_changed(&changed, &previous["networks"][0]));
        }
        assert!(!network_entry_changed(
            &json!({"key":"x"}),
            &json!({"key":"x", "last_seen_age_ms":1})
        ));
        assert!(network_entry_changed(
            &json!({"key":"x", "metadata":{"last_seen_age_ms":1}}),
            &json!({"key":"x", "metadata":{"last_seen_age_ms":2}})
        ));
    }
}
