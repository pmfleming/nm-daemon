//! A subscriber's delta chain. Cursor and collection advance together, before
//! emission: a failed emission is detectable by the next delta's base revision.
use std::collections::HashMap;

use serde_json::{Map, Value, json};

pub(crate) const MAX_REVISION: u64 = (1_u64 << 53) - 1;

pub(crate) struct NetworkUpdates {
    epoch: String,
    revision: u64,
    last: Option<Value>,
}
impl Default for NetworkUpdates {
    fn default() -> Self {
        Self {
            epoch: uuid::Uuid::new_v4().to_string(),
            revision: 0,
            last: None,
        }
    }
}
impl NetworkUpdates {
    pub(crate) fn project(&mut self, current: &Value) -> Option<Value> {
        // Never wrap or publish an integer that QML cannot represent exactly.
        if self.revision == MAX_REVISION {
            *self = Self::default();
        }
        let mut delta = network_delta(self.last.as_ref(), current)?;
        delta.insert("initial".into(), json!(self.last.is_none()));
        delta.insert("epoch".into(), json!(self.epoch));
        delta.insert("base_revision".into(), json!(self.revision));
        self.revision += 1;
        delta.insert("revision".into(), json!(self.revision));
        self.last = Some(current.clone());
        Some(Value::Object(delta))
    }
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

    let added: Vec<Value> = current_networks
        .iter()
        .filter(|network| {
            network_key(network).is_some_and(|key| !previous_by_key.contains_key(key))
        })
        .cloned()
        .collect();
    let changed: Vec<Value> = current_networks
        .iter()
        .filter(|network| {
            network_key(network)
                .and_then(|key| previous_by_key.get(key))
                .is_some_and(|previous| network_entry_changed(previous, network))
        })
        .cloned()
        .collect();
    let removed: Vec<Value> = previous_networks
        .iter()
        .filter(|network| network_key(network).is_some_and(|key| !current_by_key.contains_key(key)))
        .cloned()
        .collect();

    if previous.is_some() && added.is_empty() && removed.is_empty() && changed.is_empty() {
        return None;
    }

    let mut delta = Map::new();
    delta.insert("added".to_string(), Value::Array(added));
    delta.insert("removed".to_string(), Value::Array(removed));
    delta.insert("changed".to_string(), Value::Array(changed));
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

#[cfg(test)]
mod tests {
    use super::{MAX_REVISION, NetworkUpdates};
    use crate::daemon_status::{SharedPayloads, SubscriptionState};
    use crate::protocol::Stream;
    use serde_json::{Value, json};
    use std::time::Duration;
    fn networks(key: &str, strength: u8) -> Value {
        json!({"networks":[{"key":key,"strength":strength,"last_seen_age_ms":1}]})
    }
    #[test]
    fn initial_and_delta_share_a_cursor_and_unchanged_reads_do_not_advance_it() {
        let mut updates = NetworkUpdates::default();
        let a = updates.project(&networks("a", 50)).unwrap();
        assert_eq!(a["initial"], true);
        assert_eq!(a["base_revision"], 0);
        assert_eq!(a["revision"], 1);
        assert_eq!(a["added"][0]["key"], "a");
        assert!(updates.project(&networks("a", 50)).is_none());
        let mut aged = networks("a", 50);
        aged["networks"][0]["last_seen_age_ms"] = json!(200);
        assert!(updates.project(&aged).is_none());
        let b = updates.project(&networks("a", 60)).unwrap();
        assert_eq!(b["epoch"], a["epoch"]);
        assert_eq!(b["initial"], false);
        assert_eq!(b["base_revision"], a["revision"]);
        assert_eq!(b["revision"], 2);
        assert_eq!(b["changed"][0]["strength"], 60);
        // Simulate loss of b. The next record cannot be applied to a's revision.
        let c = updates.project(&networks("b", 70)).unwrap();
        assert_eq!(c["base_revision"], 2);
        assert_eq!(c["revision"], 3);
        assert_eq!(c["removed"][0]["key"], "a");
        assert_eq!(c["added"][0]["key"], "b");

        let next = json!({"networks": [
            {"key":"z", "strength":10}, {"key":"b", "strength":80},
            {"key":"a", "strength":20}, {"strength":90}
        ], "snapshot":{"source":"scan"}, "warning":"partial"});
        let delta = updates.project(&next).unwrap();
        assert_eq!(
            delta["added"],
            json!([next["networks"][0], next["networks"][2]])
        );
        assert_eq!(delta["changed"], json!([next["networks"][1]]));
        assert_eq!(delta["removed"], json!([]));
        assert_eq!(delta["snapshot"], next["snapshot"]);
        assert_eq!(delta["warning"], "partial");
        assert!(updates.project(&next).is_none());
        let empty = updates.project(&json!({"networks":[]})).unwrap();
        assert_eq!(
            empty["removed"],
            json!(&next["networks"].as_array().unwrap()[..3])
        );
    }
    #[test]
    fn replacement_and_other_subscribers_have_independent_full_baselines() {
        let mut old = NetworkUpdates::default();
        let a = old.project(&networks("a", 50)).unwrap();
        old.project(&networks("b", 60));
        let mut fresh = NetworkUpdates::default();
        let b = fresh.project(&networks("b", 60)).unwrap();
        assert_ne!(a["epoch"], b["epoch"]);
        assert_eq!(b["base_revision"], 0);
        assert_eq!(b["revision"], 1);
        assert_eq!(b["initial"], true);
        assert_eq!(b["added"][0]["key"], "b");
        assert_eq!(b["removed"], json!([]));
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_dbus_emission_preserves_subscription_cursor_and_replacement_baseline() {
        use futures::StreamExt;
        use zbus::{MessageStream, connection::Builder, object_server::SignalEmitter};
        let (server, client) = tokio::net::UnixStream::pair().unwrap();
        let (server, client) = tokio::try_join!(
            Builder::unix_stream(server)
                .server(zbus::Guid::generate())
                .unwrap()
                .p2p()
                .build(),
            Builder::unix_stream(client).p2p().build(),
        )
        .unwrap();
        let mut events = MessageStream::from(&client);
        let emitter = SignalEmitter::new(&server, crate::protocol::DBUS_OBJECT_PATH)
            .unwrap()
            .into_owned();
        let mut first = SubscriptionState::new(
            "first".into(),
            Some("owner-a".into()),
            vec![Stream::WifiNetworks],
            emitter.clone().into(),
        );
        for (key, strength) in [("a", 50), ("a", 60), ("b", 70)] {
            first.emit_changes(&SharedPayloads {
                networks: Some(networks(key, strength)),
                ..Default::default()
            });
        }
        let mut replacement = SubscriptionState::new(
            "replacement".into(),
            Some("owner-b".into()),
            vec![Stream::WifiNetworks],
            emitter.into(),
        );
        replacement.emit_changes(&SharedPayloads {
            networks: Some(networks("b", 70)),
            ..Default::default()
        });
        let received = tokio::time::timeout(Duration::from_secs(3), async {
            let mut values = Vec::new();
            while values.len() < 4 {
                let message = events.next().await.unwrap().unwrap();
                if message
                    .header()
                    .member()
                    .is_some_and(|name| name.as_str() == "Event")
                {
                    let (stream, body): (String, String) = message.body().deserialize().unwrap();
                    assert_eq!(stream, "wifi.networks");
                    values.push(serde_json::from_str::<Value>(&body).unwrap());
                }
            }
            values
        })
        .await
        .unwrap();
        for (index, value) in received[..3].iter().enumerate() {
            assert_eq!(value["subscription_id"], "first");
            assert_eq!(value["data"]["base_revision"], index);
            assert_eq!(value["data"]["revision"], index + 1);
            assert_eq!(value["data"]["epoch"], received[0]["data"]["epoch"]);
        }
        assert_eq!(received[3]["subscription_id"], "replacement");
        assert_eq!(received[3]["data"]["initial"], true);
        assert_eq!(received[3]["data"]["base_revision"], 0);
        assert_eq!(received[3]["data"]["revision"], 1);
        assert_ne!(received[3]["data"]["epoch"], received[0]["data"]["epoch"]);
        assert_eq!(received[3]["data"]["added"][0]["key"], "b");
    }

    #[test]
    fn exhausted_cursor_starts_a_new_full_epoch_without_rounding_or_wrapping() {
        let mut updates = NetworkUpdates::default();
        let old = updates.project(&networks("a", 50)).unwrap();
        updates.revision = MAX_REVISION;
        let next = updates.project(&networks("a", 50)).unwrap();
        assert_ne!(old["epoch"], next["epoch"]);
        assert_eq!(next["initial"], true);
        assert_eq!(next["base_revision"], 0);
        assert_eq!(next["revision"], 1);
    }
}
