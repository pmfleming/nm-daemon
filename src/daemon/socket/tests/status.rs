//! Real serializers/ingress; synthetic NM facts, no host backend or effects.
use super::*;

#[test]
fn status_watch_and_reads_share_identity_and_repair_quiet_final_loss() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::status_watch_and_reads_share_identity_and_repair_quiet_final_loss"
        ),
        || {
            let rig = Rig::new([])?;
            let mut a = rig.peer()?;
            let mut peer = rig.peer()?;
            let subscription = a.subscribe("status", &["wifi.status", "wifi.secret"])?;
            peer.subscribe("peer", &["wifi.secret"])?;
            let baseline = tokio::runtime::Handle::current().block_on(a.matching(|record| {
                record["kind"] == "event"
                    && record["event"]["subscription_id"] == subscription
                    && record["event"]["event"] == "changed"
                    && record["event"]["stream"] == "wifi.status"
            }))?["event"]["data"]["status"]
                .clone();
            assert_eq!(baseline["available"], true, "{baseline}");
            assert_eq!(baseline["active"], false);
            assert_eq!(baseline["_publication"]["revision"], 1);
            assert!(baseline["_publication"]["epoch"].is_string());
            assert_eq!(
                a.call("wifi.status", json!({}))?["data"]["status"],
                baseline
            );
            let dbus: String = rig.dbus()?.call("Call", &("wifi.status", "{}"))?;
            assert_eq!(
                serde_json::from_str::<Value>(&dbus)?["data"]["status"],
                baseline
            );
            // Do not emit a property signal. No later delivery witnesses the loss;
            // only the explicitly requested authoritative read repairs current state.
            rig.fake.state.lock().unwrap().current = Some(Outcome::Connected);
            let repaired = a.call("wifi.status", json!({}))?["data"]["status"].clone();
            assert_eq!(repaired["available"], true, "{repaired}");
            assert_eq!(repaired["active"], true);
            assert_eq!(
                repaired["_publication"]["epoch"],
                baseline["_publication"]["epoch"]
            );
            assert!(
                repaired["_publication"]["revision"]
                    .as_u64()
                    .context("repaired status revision")?
                    > baseline["_publication"]["revision"]
                        .as_u64()
                        .context("baseline status revision")?
            );
            assert_eq!(
                rig.runtime
                    .subscriber_owners(crate::protocol::Stream::WifiSecret)
                    .len(),
                2
            );
            assert_eq!(peer.call("wifi.status", json!({}))?["ok"], true);
            // Lose only the scripted NM endpoint, not the admitted daemon/owner.
            // The real read serializer must publish unavailable, never inactive.
            rig.fake._peer.server.clone().close()?;
            let unavailable = a.call("wifi.status", json!({}))?["data"]["status"].clone();
            assert_eq!(unavailable["available"], false, "{unavailable}");
            assert!(unavailable.get("active").is_none());
            assert_eq!(
                unavailable["_publication"]["epoch"],
                repaired["_publication"]["epoch"]
            );
            assert!(
                unavailable["_publication"]["revision"]
                    .as_u64()
                    .context("unavailable revision")?
                    > repaired["_publication"]["revision"]
                        .as_u64()
                        .context("repaired revision")?
            );
            assert_eq!(
                a.call("wifi.status", json!({}))?["data"]["status"],
                unavailable
            );
            assert_eq!(
                peer.call("operation.status", json!({"request_id":"not-owned"}))?["data"]["result"]
                    ["status"],
                "unknown"
            );
            assert_eq!(
                rig.runtime
                    .subscriber_owners(crate::protocol::Stream::WifiSecret)
                    .len(),
                2
            );
            let state = rig.fake.state.lock().unwrap();
            assert!(state.activations.is_empty());
            assert!(state.deactivated.is_empty());
            assert_eq!(state.added, 0);
            assert_eq!(state.updates, 0);
            assert_eq!(state.deleted, 0);
            assert_eq!(state.connectivity_checks, 0);
            assert_eq!(state.secret_probes, 0);
            drop(state);
            drop(a);
            drop(peer);
            rig.finish()
        },
    )
}

#[test]
fn connectivity_rpc_is_an_active_check_and_not_a_recovery_read() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::connectivity_rpc_is_an_active_check_and_not_a_recovery_read"
        ),
        || {
            let rig = Rig::new([])?;
            let mut peer = rig.peer()?;
            assert_eq!(peer.call("wifi.status", json!({}))?["ok"], true);
            assert_eq!(rig.fake.state.lock().unwrap().connectivity_checks, 0);
            // Explicit synthetic active-check witness for the remaining API row.
            // This is not invoked by the status recovery path or a real backend.
            assert_eq!(peer.call("network.connectivity", json!({}))?["ok"], true);
            assert_eq!(rig.fake.state.lock().unwrap().connectivity_checks, 1);
            assert_eq!(peer.call("wifi.status", json!({}))?["ok"], true);
            assert_eq!(rig.fake.state.lock().unwrap().connectivity_checks, 1);
            assert!(rig.fake.state.lock().unwrap().activations.is_empty());
            drop(peer);
            rig.finish()
        },
    )
}
