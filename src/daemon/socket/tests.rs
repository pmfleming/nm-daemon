//! Real private D-Bus + Unix sockets; all NetworkManager work is scripted.
mod probe;
use super::*;
use crate::test_support::{
    bus::TestBus,
    workflows::{FakeNm, Outcome, isolated},
};
use anyhow::{Context, ensure};
use serde_json::json;
use std::{collections::VecDeque, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::oneshot,
};

struct Fixture {
    state: Arc<std::sync::Mutex<crate::test_support::workflows::State>>,
    _peer: crate::test_support::TestPeer,
}
struct Rig {
    bus: TestBus,
    fake: Fixture,
    runtime: Arc<crate::daemon_runtime::DaemonRuntime>,
    connection: zbus::blocking::Connection,
    client: zbus::blocking::Connection,
    directory: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl Rig {
    fn new(script: impl IntoIterator<Item = Outcome>) -> Result<Self> {
        let bus = TestBus::new()?;
        let FakeNm { nm, state, peer } = FakeNm::new(script, false)?;
        let fake = Fixture { state, _peer: peer };
        let handle = tokio::runtime::Handle::current();
        let runtime = crate::daemon_runtime::DaemonRuntime::start(nm, handle.clone())?;
        let connection = zbus::blocking::connection::Builder::address(bus.address())?
            .name(crate::protocol::DBUS_BUS_NAME)?
            .serve_at(
                DBUS_OBJECT_PATH,
                NmDaemonInterface::new(runtime.clone(), &handle),
            )?
            .build()?;
        let client = bus.connect()?;
        // The workflow directory includes the test name and exceeds SUN_LEN;
        // the private bus already owns a short, newly-created 0700 directory.
        let directory = bus.runtime_directory().to_owned();
        let mut rig = Self {
            bus,
            fake,
            runtime,
            connection,
            client,
            directory,
            stop: None,
            task: None,
        };
        handle.block_on(rig.start())?;
        Ok(rig)
    }
    async fn start(&mut self) -> Result<()> {
        let listener = JsonlListener::bind(&self.directory, "nm-daemon").await?;
        let service = Arc::new(Service {
            connection: self.connection.inner().clone(),
        });
        let (stop, stopped) = oneshot::channel();
        self.stop = Some(stop);
        self.task = Some(tokio::spawn(listener.serve(
            service,
            crate::client::NmCorrelation,
            JsonlSocketConfig::default(),
            async {
                let _ = stopped.await;
            },
        )));
        Ok(())
    }
    async fn stop(&mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            tokio::time::timeout(Duration::from_secs(5), task).await???;
        }
        Ok(())
    }
    fn peer(&self) -> Result<Peer> {
        tokio::runtime::Handle::current().block_on(async {
            Ok(Peer {
                io: BufReader::new(
                    UnixStream::connect(self.directory.join("nm-daemon.sock")).await?,
                ),
                pending: VecDeque::new(),
            })
        })
    }
    fn dbus(&self) -> Result<zbus::blocking::Proxy<'_>> {
        Ok(zbus::blocking::Proxy::new(
            &self.client,
            crate::protocol::DBUS_BUS_NAME,
            DBUS_OBJECT_PATH,
            crate::protocol::DBUS_INTERFACE,
        )?)
    }
    fn finish(mut self) -> Result<()> {
        tokio::runtime::Handle::current().block_on(async {
            self.stop().await?;
            self.runtime.shutdown().await;
            self.connection.inner().clone().close().await?;
            Ok(())
        })
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
struct Peer {
    io: BufReader<UnixStream>,
    pending: VecDeque<Value>,
}
impl Peer {
    async fn matching(&mut self, matches: impl Fn(&Value) -> bool) -> Result<Value> {
        if let Some(index) = self.pending.iter().position(&matches) {
            return Ok(self.pending.remove(index).unwrap());
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                ensure!(
                    self.io.read_line(&mut line).await? > 0,
                    "unexpected socket EOF"
                );
                let value = serde_json::from_str(&line)?;
                if matches(&value) {
                    return Ok(value);
                }
                ensure!(self.pending.len() < 128, "test event backlog exceeded");
                self.pending.push_back(value);
            }
        })
        .await?
    }
    fn request(&mut self, request: Value) -> Result<Value> {
        tokio::runtime::Handle::current().block_on(async {
            self.io
                .get_mut()
                .write_all(format!("{request}\n").as_bytes())
                .await?;
            self.matching(|reply| reply["kind"] == "response" && reply["id"] == request["id"])
                .await
        })
    }
    fn subscribe(&mut self, id: &str, streams: &[&str]) -> Result<String> {
        let reply = self.request(json!({"op":"subscribe", "id":id, "streams":streams,
            "route":{"consumerId":id,"localId":id,"generation":1,"kind":"subscription"}}))?;
        assert_eq!(reply["response"]["ok"], true, "{reply}");
        assert_eq!(reply["route"]["consumerId"], id);
        Ok(reply["response"]["data"]["subscription"]["id"]
            .as_str()
            .context("subscription id")?
            .into())
    }
    fn baseline(&mut self, subscription: &str) -> Result<Value> {
        tokio::runtime::Handle::current().block_on(self.matching(|event| {
            event["kind"] == "event"
                && event["event"]["subscription_id"] == subscription
                && event["event"]["data"]["initial"] == true
        }))
    }
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        Ok(self.request(json!({"op":"call","id":"call","method":method,"params":params}))?["response"].clone())
    }
}
fn until(mut predicate: impl FnMut() -> bool) -> Result<()> {
    tokio::runtime::Handle::current().block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !predicate() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("state did not converge")
    })
}

#[test]
fn socket_matches_dbus_dispatch_and_keeps_owners_separate() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::socket_matches_dbus_dispatch_and_keeps_owners_separate"
        ),
        || {
            let rig = Rig::new([])?;
            let mut a = rig.peer()?;
            let mut b = rig.peer()?;
            for (method, params) in [
                ("network.connectivity", json!({})),
                ("wifi.saved", json!({})),
                ("not.real", json!({})),
                ("wifi.connectTarget", json!({})),
                ("wifi.scan", json!({"timeout":u64::MAX})),
            ] {
                let bus: String = rig.dbus()?.call("Call", &(method, params.to_string()))?;
                assert_eq!(
                    a.call(method, params)?,
                    serde_json::from_str::<Value>(&bus)?
                );
            }
            let sub_a = a.subscribe("a", &["wifi.networks", "wifi.secret"])?;
            let baseline = a.baseline(&sub_a)?;
            assert_eq!(baseline["event"]["data"]["base_revision"], 0);
            assert_eq!(baseline["event"]["data"]["revision"], 1);
            assert_eq!(baseline["route"]["consumerId"], "a");
            let sub_b = b.subscribe("b", &["wifi.secret"])?;
            let rejected = b.request(json!({"op":"cancel","id":"foreign","request_id":sub_a}))?;
            assert_eq!(rejected["response"]["error"]["code"], "request-not-found");
            assert_eq!(
                rig.runtime
                    .subscriber_owners(crate::protocol::Stream::WifiSecret)
                    .len(),
                2
            );
            let _: String = rig.dbus()?.call("Subscribe", &(vec!["wifi.secret"],))?;
            let handle = tokio::runtime::Handle::current();
            assert_eq!(
                handle.block_on(rig.runtime.dbus_owner_names()),
                vec![rig.client.unique_name().unwrap().to_string()]
            );
            rig.client.clone().close()?;
            let monitor =
                shelllist_daemon_tokio::OwnerLossMonitor::new(rig.connection.inner().clone());
            handle.block_on(super::super::reconcile_owners(&monitor, &rig.runtime))?;
            assert_eq!(
                rig.runtime
                    .subscriber_owners(crate::protocol::Stream::WifiSecret)
                    .len(),
                2
            );
            drop(a);
            // This synchronous query is intentionally outside Tokio's worker thread.
            for _ in 0..100 {
                if rig
                    .runtime
                    .subscriber_owners(crate::protocol::Stream::WifiSecret)
                    .len()
                    == 1
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                rig.runtime
                    .subscriber_owners(crate::protocol::Stream::WifiSecret)
                    .len(),
                1
            );
            assert_eq!(b.call("network.connectivity", json!({}))?["ok"], true);
            assert_eq!(
                b.request(json!({"op":"cancel","id":"owned","request_id":sub_b}))?["response"]["ok"],
                true
            );
            assert!(rig.fake.state.lock().unwrap().activations.is_empty());
            drop(b);
            rig.finish()
        },
    )
}

#[test]
fn disconnect_cancels_owned_connect_and_reconnect_never_replays_it() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::disconnect_cancels_owned_connect_and_reconnect_never_replays_it"
        ),
        || {
            let mut rig = Rig::new([Outcome::AwaitingSecrets])?;
            let mut a = rig.peer()?;
            let sub = a.subscribe("a", &["wifi.networks", "wifi.secret"])?;
            let baseline = a.baseline(&sub)?;
            let owner = rig
                .runtime
                .subscriber_owners(crate::protocol::Stream::WifiSecret)
                .pop()
                .context("socket owner")?;
            let mut b = rig.peer()?;
            b.subscribe("b", &["wifi.secret"])?;
            let mut target = crate::model::example_connect_target(false);
            target.ap_path = Some(crate::model::NmObjectPath::parse(
                "/org/freedesktop/NetworkManager/AccessPoint/1".into(),
            )?);
            target.security = Some(crate::model::Security::Open);
            let params =
                crate::daemon_connect::DbusConnectTargetParams::for_target(target, None, None);
            let started = a.call("wifi.connectTarget", serde_json::to_value(params)?)?;
            assert_eq!(started["ok"], true, "{started}");
            let id = started["data"]["result"]["request_id"]
                .as_str()
                .context("connect operation id")?;
            until(|| rig.fake.state.lock().unwrap().activations.len() == 1).with_context(|| {
                format!(
                    "connect status: {}",
                    rig.runtime.request_status(id, Some(&owner))
                )
            })?;
            assert_eq!(
                b.call("operation.status", json!({"request_id":id}))?["data"]["result"]["status"],
                "unknown"
            );
            assert_eq!(
                b.request(json!({"op":"cancel","id":"foreign","request_id":id}))?["response"]["error"]
                    ["code"],
                "request-not-found"
            );
            assert!(rig.fake.state.lock().unwrap().deactivated.is_empty());
            drop(a);
            until(|| !rig.fake.state.lock().unwrap().deactivated.is_empty())?;
            until(|| rig.runtime.request_status(id, Some(&owner))["status"] == "finished")?;
            assert_eq!(
                rig.runtime.request_status(id, Some(&owner))["event"]["event"],
                "cancelled"
            );
            assert_eq!(b.call("network.connectivity", json!({}))?["ok"], true);
            // Recreate the listener, not the OS process. Every remaining connection
            // closes; a fresh subscription must establish a new full baseline.
            tokio::runtime::Handle::current().block_on(async {
                rig.stop().await?;
                rig.start().await
            })?;
            drop(b);
            let mut fresh = rig.peer()?;
            let replacement = fresh.subscribe("new", &["wifi.networks"])?;
            let recovered = fresh.baseline(&replacement)?;
            assert_ne!(
                recovered["event"]["data"]["epoch"],
                baseline["event"]["data"]["epoch"]
            );
            assert_eq!(recovered["event"]["data"]["revision"], 1);
            assert_eq!(
                fresh.call("operation.status", json!({"request_id":id}))?["data"]["result"]["status"],
                "unknown"
            );
            assert_eq!(rig.fake.state.lock().unwrap().activations.len(), 1);
            drop(fresh);
            rig.finish()
        },
    )
}
