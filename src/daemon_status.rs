use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use shelllist_daemon_tokio::EventEmitter as SignalEmitter;

use crate::application::{Application, NetworksRequest};
use crate::daemon_event::{emit_json_event_nonfatal, emit_subscription_event_nonfatal};
use crate::nm::Nm;
use crate::protocol::{Method, Stream};

pub(crate) mod network_updates;
pub(crate) mod observation;
use network_updates::NetworkUpdates;

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
    networks: NetworkUpdates,
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
            networks: NetworkUpdates::default(),
        }
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn watches(&self, stream: Stream) -> bool {
        !self.emitter.is_closed() && self.streams.contains(&stream)
    }

    pub(crate) fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    pub(crate) fn emit_external(&self, stream: Stream, request_id: &str, event: &str, data: Value) {
        emit_json_event_nonfatal(&self.emitter, stream, Some(request_id), event, data);
    }

    pub(crate) fn emit_changes(&mut self, payloads: &SharedPayloads) {
        if self.emitter.is_closed() {
            return;
        }
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
            emit_network_changes(&self.emitter, &self.id, &mut self.networks, value);
        }
    }
}

pub(crate) fn refresh_payloads(
    nm: &Nm,
    need_connectivity: bool,
    need_inventory: bool,
    need_networks: bool,
) -> SharedPayloads {
    let started = Instant::now();
    let application = Application::new(nm);
    let connectivity = need_connectivity
        .then(|| {
            nm.connectivity_snapshot()
                .map(|connectivity| json!(connectivity))
        })
        .and_then(log_typed_refresh_error);
    let payloads = SharedPayloads {
        // Only the runtime-owned status capture may populate this projection.
        status: None,
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
                            "warning": null,
                        })
                    })
            })
            .and_then(log_typed_refresh_error),
    };
    tracing::debug!(
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
    result
        .inspect_err(|error| {
            tracing::warn!(error = %crate::error::err_chain(error), "shared subscription refresh failed");
        })
        .ok()
}

fn emit_network_changes(
    emitter: &SignalEmitter<'static>,
    subscription_id: &str,
    updates: &mut NetworkUpdates,
    value: &Value,
) {
    let Some(payload) = updates.project(value) else {
        return;
    };
    emit_subscription_event_nonfatal(
        emitter,
        Stream::WifiNetworks,
        subscription_id,
        "changed",
        payload,
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
    payload.insert(method.spec().response_key.to_string(), value.clone());
    emit_subscription_event_nonfatal(
        emitter,
        stream,
        subscription_id,
        "changed",
        Value::Object(payload),
    );
}
