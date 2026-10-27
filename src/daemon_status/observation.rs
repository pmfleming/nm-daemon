//! One authoritative Wi-Fi status observation owner, shared by reads and watches.
//! Capture is serialized; invalidations never wait for a blocking NM read. A read
//! invalidated in flight cannot acquire a newer publication identity on completion.
use std::sync::Mutex;

use anyhow::Result;
use serde_json::{Value, json};

use crate::error::{DomainError, ErrorOperation, recover_lock};

const MAX_REVISION: u64 = (1_u64 << 53) - 1;

pub(crate) struct StatusObservations {
    capture: Mutex<()>,
    state: Mutex<State>,
}

struct State {
    generation: u64,
    epoch: String,
    previous_epoch: Option<String>,
    revision: u64,
    value: Option<Value>,
}

impl Default for StatusObservations {
    fn default() -> Self {
        Self {
            capture: Mutex::new(()),
            state: Mutex::new(State {
                generation: 0,
                epoch: uuid::Uuid::new_v4().to_string(),
                previous_epoch: None,
                revision: 0,
                value: None,
            }),
        }
    }
}

impl StatusObservations {
    pub(crate) fn invalidate(&self) {
        let mut state = recover_lock(&self.state, "status observation");
        state.generation = state
            .generation
            .checked_add(1)
            .expect("status generation exhausted");
    }

    pub(crate) fn observe(&self, read: impl FnOnce() -> Result<Value>) -> Result<Value> {
        let _capture = recover_lock(&self.capture, "status capture");
        let generation = recover_lock(&self.state, "status observation").generation;
        let mut value = match read() {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(error = %crate::error::err_chain(&error), "Wi-Fi status unavailable");
                json!({"available": false})
            }
        };
        if value.get("available").is_none() {
            value["available"] = json!(true);
        }
        let mut state = recover_lock(&self.state, "status observation");
        if generation != state.generation {
            return Err(DomainError::conflict(
                ErrorOperation::Status,
                "Wi-Fi status changed during observation; read current state again",
            )
            .into());
        }
        if state.value.as_ref() != Some(&value) {
            if state.revision == MAX_REVISION {
                state.previous_epoch = Some(std::mem::replace(
                    &mut state.epoch,
                    uuid::Uuid::new_v4().to_string(),
                ));
                state.revision = 0;
            }
            state.revision += 1;
            state.value = Some(value.clone());
        }
        value["_publication"] = json!({
            "epoch": state.epoch,
            "revision": state.revision,
        });
        if let Some(previous) = &state.previous_epoch {
            value["_publication"]["previous_epoch"] = json!(previous);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_reads_share_watch_identity_and_unavailable_is_ordered() {
        let observations = StatusObservations::default();
        let a = observations
            .observe(|| Ok(json!({"active": true})))
            .unwrap();
        assert_eq!(
            a,
            observations
                .observe(|| Ok(json!({"active": true})))
                .unwrap()
        );
        let unavailable = observations
            .observe(|| anyhow::bail!("synthetic unavailable"))
            .unwrap();
        assert_eq!(unavailable["available"], false);
        assert_eq!(unavailable["_publication"]["revision"], 2);
        let restored = observations
            .observe(|| Ok(json!({"active": true})))
            .unwrap();
        assert_eq!(restored["_publication"]["revision"], 3);
        assert_eq!(
            a["_publication"]["epoch"],
            restored["_publication"]["epoch"]
        );
    }

    #[test]
    fn invalidation_during_capture_does_not_publish_or_consume_revision() {
        let observations = StatusObservations::default();
        let a = observations
            .observe(|| Ok(json!({"active": false})))
            .unwrap();
        let stale = observations.observe(|| {
            observations.invalidate(); // signal/owner change while NM read is held
            Ok(json!({"active": true}))
        });
        assert!(stale.is_err());
        assert_eq!(
            a,
            observations
                .observe(|| Ok(json!({"active": false})))
                .unwrap()
        );
    }

    #[test]
    fn concurrent_read_invalidated_by_signal_cannot_overtake_fresh_capture() {
        use std::{
            sync::{Arc, mpsc},
            time::Duration,
        };
        let observations = Arc::new(StatusObservations::default());
        let (entered, started) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let old = Arc::clone(&observations);
        let stale = std::thread::spawn(move || {
            old.observe(|| {
                entered.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok(json!({"active": true}))
            })
        });
        started.recv_timeout(Duration::from_secs(3)).unwrap();
        observations.invalidate();
        let fresh = Arc::clone(&observations);
        let current = std::thread::spawn(move || fresh.observe(|| Ok(json!({"active": false}))));
        release.send(()).unwrap();
        assert!(stale.join().unwrap().is_err());
        let current = current.join().unwrap().unwrap();
        assert_eq!(current["active"], false);
        assert_eq!(current["_publication"]["revision"], 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_subscription_serializer_preserves_unavailable_publication() {
        use crate::{
            daemon_status::{SharedPayloads, SubscriptionState},
            protocol::Stream,
        };
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
        let mut subscription = SubscriptionState::new(
            "status-owned".into(),
            Some("owner".into()),
            vec![Stream::WifiStatus],
            emitter.into(),
        );
        let observations = StatusObservations::default();
        let available = observations
            .observe(|| Ok(json!({"active": false})))
            .unwrap();
        let unavailable = observations
            .observe(|| anyhow::bail!("synthetic unavailable"))
            .unwrap();
        for value in [&available, &unavailable] {
            subscription.emit_changes(&SharedPayloads {
                status: Some(value.clone()),
                ..Default::default()
            });
        }
        let received = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut values = Vec::new();
            while values.len() < 2 {
                let message = events.next().await.unwrap().unwrap();
                if message
                    .header()
                    .member()
                    .is_some_and(|name| name.as_str() == "Event")
                {
                    let (stream, body): (String, String) = message.body().deserialize().unwrap();
                    assert_eq!(stream, "wifi.status");
                    values.push(serde_json::from_str::<Value>(&body).unwrap());
                }
            }
            values
        })
        .await
        .unwrap();
        assert_eq!(received[0]["data"]["status"], available);
        assert_eq!(received[1]["data"]["status"], unavailable);
        assert_eq!(received[1]["subscription_id"], "status-owned");
    }

    #[test]
    fn real_nm_owner_replacement_retires_old_scope_and_orders_unavailability() -> Result<()> {
        use crate::test_support::{
            bus::TestBus,
            workflows::{FakeNm, Outcome, isolated},
        };
        isolated(
            concat!(
                module_path!(),
                "::real_nm_owner_replacement_retires_old_scope_and_orders_unavailability"
            ),
            || {
                let bus = TestBus::new()?;
                let first = FakeNm::on_bus(&bus, [])?;
                let retired_scope = first.nm.scoped()?;
                let runtime = crate::daemon_runtime::DaemonRuntime::start(
                    first.nm,
                    tokio::runtime::Handle::current(),
                )?;
                let initial = runtime.call_status()?["data"]["status"].clone();
                assert_eq!(initial["available"], true);
                first.peer.server.release_name(crate::nm::NM_DEST)?;
                runtime.network_manager_owner_changed(None);
                let unavailable = runtime.call_status()?["data"]["status"].clone();
                assert_eq!(unavailable["available"], false);
                assert_eq!(unavailable["_publication"]["revision"], 2);
                // Keep the old unique endpoint alive: availability must follow the
                // authoritative name owner, not whichever retired peer still replies.
                let replacement = FakeNm::on_bus(&bus, [])?;
                replacement.state.lock().unwrap().current = Some(Outcome::Connected);
                runtime.network_manager_owner_changed(
                    replacement
                        .peer
                        .server
                        .unique_name()
                        .map(|name| name.as_str()),
                );
                assert!(retired_scope.ensure_current_owner().is_err());
                let restored = runtime.call_status()?["data"]["status"].clone();
                assert_eq!(restored["available"], true);
                assert_eq!(restored["active"], true);
                assert_eq!(restored["_publication"]["revision"], 3);
                assert_eq!(
                    restored["_publication"]["epoch"],
                    initial["_publication"]["epoch"]
                );
                assert!(first.state.lock().unwrap().activations.is_empty());
                assert!(replacement.state.lock().unwrap().activations.is_empty());
                tokio::runtime::Handle::current().block_on(runtime.shutdown());
                Ok(())
            },
        )
    }

    #[test]
    fn rollover_lineage_survives_coalescing() {
        let observations = StatusObservations::default();
        observations
            .observe(|| Ok(json!({"active": false})))
            .unwrap();
        let old_epoch = {
            let mut state = observations.state.lock().unwrap();
            state.revision = MAX_REVISION;
            state.epoch.clone()
        };
        let rolled = observations
            .observe(|| Ok(json!({"active": true})))
            .unwrap();
        let next = observations
            .observe(|| Ok(json!({"active": false})))
            .unwrap();
        assert_eq!(rolled["_publication"]["revision"], 1);
        assert_eq!(next["_publication"]["revision"], 2);
        assert_eq!(next["_publication"]["previous_epoch"], old_epoch);
        assert_ne!(next["_publication"]["epoch"], old_epoch);
        assert_eq!(
            next["_publication"]["epoch"],
            rolled["_publication"]["epoch"]
        );
    }
}
