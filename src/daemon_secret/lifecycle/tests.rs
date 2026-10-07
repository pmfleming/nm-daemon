use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use zbus::blocking::{Connection, Proxy};
use zvariant::OwnedObjectPath;

use super::super::{REGISTERED, SECRET_AGENT_OBJECT_PATH, with_pending_registry};
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::ErrorOperation;
use crate::nm::{ConnectionSettings, NM_DEST, Nm};
use crate::test_support::bus::TestBus;
use crate::test_support::workflows::{PROFILE, isolated};

#[derive(Default)]
struct Calls {
    capabilities: AtomicUsize,
    plain: AtomicUsize,
    mode: AtomicU8,
    deletes: AtomicUsize,
}
struct Manager(Arc<Calls>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.AgentManager")]
impl Manager {
    async fn register_with_capabilities(
        &self,
        _id: &str,
        capabilities: u32,
    ) -> zbus::fdo::Result<()> {
        assert_eq!(capabilities, 1);
        self.0.capabilities.fetch_add(1, Ordering::SeqCst);
        match self.0.mode.load(Ordering::SeqCst) {
            1 => Err(zbus::fdo::Error::UnknownMethod("old NM".into())),
            2 => Err(zbus::fdo::Error::AccessDenied("denied".into())),
            3 => std::future::pending().await,
            _ => Ok(()),
        }
    }
    fn register(&self, _id: &str) {
        self.0.plain.fetch_add(1, Ordering::SeqCst);
    }
}
struct Profile(Arc<Calls>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl Profile {
    fn delete(&self) {
        self.0.deletes.fetch_add(1, Ordering::SeqCst);
    }
}
fn serve(bus: &TestBus, calls: &Arc<Calls>) -> Result<Connection> {
    let connection = bus.connect()?;
    connection
        .object_server()
        .at(super::AGENT_MANAGER_PATH, Manager(Arc::clone(calls)))?;
    connection
        .object_server()
        .at(PROFILE, Profile(Arc::clone(calls)))?;
    connection.request_name(NM_DEST)?;
    Ok(connection)
}
fn until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "owner lifecycle did not converge"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn terminal_owner_fence_does_not_depend_on_watcher_delivery() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::terminal_owner_fence_does_not_depend_on_watcher_delivery"
        ),
        || {
            let bus = TestBus::new()?;
            let calls = Arc::new(Calls::default());
            let old = serve(&bus, &calls)?;
            let nm = Nm::with_connection_runner_destination_and_telemetry(
                bus.connect()?,
                crate::command::default_runner(),
                NM_DEST,
                Arc::new(crate::nl80211::UnavailableWirelessTelemetry),
            )?;
            let executor = tokio::runtime::Runtime::new()?;
            let runtime = DaemonRuntime::start(nm, executor.handle().clone())?;
            let (release, wait) = std::sync::mpsc::channel();
            let (started, ready) = std::sync::mpsc::channel();
            let id = runtime.start_cancellable(
                "fenced",
                TaskKind::Connect,
                None,
                None,
                move |_, _, _| {
                    started.send(()).unwrap();
                    let _ = wait.recv_timeout(Duration::from_secs(10));
                },
            )?;
            ready.recv_timeout(Duration::from_secs(5))?;
            old.release_name(NM_DEST)?;
            let _new = serve(&bus, &Arc::new(Calls::default()))?;
            assert_eq!(
                runtime.request_status(&id, None)["cancellation_requested"],
                false
            );
            let event = runtime.store_terminal_result(
                &id,
                None,
                crate::protocol::Stream::WifiConnect,
                serde_json::json!({"event":"succeeded", "result":{"portal":true}}),
            );
            assert_eq!(event["event"], "cancelled");
            assert!(event.get("result").is_none());
            release.send(())?;
            executor.block_on(runtime.shutdown());
            Ok(())
        },
    )
}

#[test]
fn restart_recovers_registration_and_fences_pending_work_and_secrets() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::restart_recovers_registration_and_fences_pending_work_and_secrets"
        ),
        || {
            let bus = TestBus::new()?;
            let connection = bus.connect()?;
            let nm = Nm::with_connection_runner_destination_and_telemetry(
                connection.clone(),
                crate::command::default_runner(),
                NM_DEST,
                Arc::new(crate::nl80211::UnavailableWirelessTelemetry),
            )?;
            let executor = tokio::runtime::Runtime::new()?;
            let runtime = DaemonRuntime::start(nm, executor.handle().clone())?;
            super::super::export_secret_agent(&connection, &runtime)?;
            let watch = executor.spawn(super::watch_network_manager(Arc::clone(&runtime)));

            // Starting without NM is supported and must not register/auto-activate it.
            assert!(runtime.call(ErrorOperation::Status, |_| Ok(())).is_err());
            assert!(!REGISTERED.load(Ordering::Acquire));
            let old_calls = Arc::new(Calls::default());
            let old = serve(&bus, &old_calls)?;
            until(|| REGISTERED.load(Ordering::Acquire));
            assert_eq!(old_calls.capabilities.load(Ordering::SeqCst), 1);

            let (release, wait) = std::sync::mpsc::channel();
            let (done, completed) = std::sync::mpsc::channel();
            let weak = Arc::downgrade(&runtime);
            let id = runtime.start_cancellable(
                "owner-test",
                TaskKind::Connect,
                Some("frontend".into()),
                None,
                move |nm, cancelled, id| {
                    wait.recv_timeout(Duration::from_secs(10)).unwrap();
                    // Deliberately attempt stale cleanup even though cancellation is set.
                    let deleted =
                        nm.delete_connection(&OwnedObjectPath::try_from(PROFILE).unwrap());
                    let event = weak.upgrade().unwrap().store_terminal_result(
                        id,
                        Some("frontend".into()),
                        crate::protocol::Stream::WifiConnect,
                        serde_json::json!({"event":"succeeded", "result":{"portal":true}}),
                    );
                    done.send((cancelled.load(Ordering::Acquire), deleted.is_err(), event))
                        .unwrap();
                },
            )?;

            // Exercise the exported interface with a genuine sender and pending reply.
            let agent_owner = connection.unique_name().unwrap().to_string();
            let caller = old.clone();
            let (secret_done, secret_result) = std::sync::mpsc::channel();
            let secret_thread = std::thread::spawn(move || {
                let proxy = Proxy::new(
                    &caller,
                    agent_owner,
                    SECRET_AGENT_OBJECT_PATH,
                    "org.freedesktop.NetworkManager.SecretAgent",
                )
                .unwrap();
                let result = proxy.call::<_, _, ConnectionSettings>(
                    "GetSecrets",
                    &(
                        ConnectionSettings::new(),
                        OwnedObjectPath::try_from(PROFILE).unwrap(),
                        "802-11-wireless-security",
                        Vec::<String>::new(),
                        3_u32,
                    ),
                );
                secret_done.send(result.is_err()).unwrap();
            });
            until(|| with_pending_registry(|registry| !registry.requests.is_empty()));
            old.release_name(NM_DEST)?;
            until(|| !REGISTERED.load(Ordering::Acquire));
            assert!(secret_result.recv_timeout(Duration::from_secs(5))?);
            secret_thread.join().unwrap();
            assert!(with_pending_registry(|registry| registry
                .requests
                .is_empty()));
            assert!(runtime.call(ErrorOperation::Status, |_| Ok(())).is_err());

            let new_calls = Arc::new(Calls::default());
            let new = serve(&bus, &new_calls)?;
            until(|| REGISTERED.load(Ordering::Acquire));
            release.send(())?;
            let (cancelled, rejected, event) = completed.recv_timeout(Duration::from_secs(5))?;
            assert!(cancelled && rejected);
            assert_eq!(event["event"], "cancelled");
            assert!(event.get("result").is_none());
            assert_eq!(
                runtime.request_status(&id, Some("frontend"))["event"]["event"],
                "cancelled"
            );
            assert_eq!(old_calls.deletes.load(Ordering::SeqCst), 0);
            assert_eq!(new_calls.deletes.load(Ordering::SeqCst), 0);
            runtime.call(ErrorOperation::ProfileOperation, |nm| {
                nm.delete_connection(&PROFILE.try_into()?)
            })?;
            assert_eq!(new_calls.deletes.load(Ordering::SeqCst), 1);
            let mut stale = super::super::PendingSecretRequest::new(
                PROFILE.try_into()?,
                "802-11-wireless-security",
                Vec::new(),
                3,
            );
            stale.nm_owner = Some(old.unique_name().unwrap().to_string());
            assert!(super::super::register_pending(&stale, vec!["frontend".into()]).is_err());
            assert!(super::super::ensure_request_owner(&stale).is_err());

            // An old owner still connected to the bus cannot cancel/save/delete secrets.
            let proxy = Proxy::new(
                &old,
                connection.unique_name().unwrap().as_str(),
                SECRET_AGENT_OBJECT_PATH,
                "org.freedesktop.NetworkManager.SecretAgent",
            )?;
            let result = proxy.call::<_, _, ()>(
                "DeleteSecrets",
                &(
                    ConnectionSettings::new(),
                    OwnedObjectPath::try_from(PROFILE)?,
                ),
            );
            assert!(
                matches!(result, Err(zbus::Error::MethodError(ref name, _, _)) if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied")
            );

            // Permission errors must not downgrade capabilities. Only UnknownMethod does.
            new.release_name(NM_DEST)?;
            until(|| !REGISTERED.load(Ordering::Acquire));
            let denied_calls = Arc::new(Calls::default());
            denied_calls.mode.store(2, Ordering::SeqCst);
            let denied = serve(&bus, &denied_calls)?;
            until(|| denied_calls.capabilities.load(Ordering::SeqCst) >= 2);
            assert_eq!(denied_calls.plain.load(Ordering::SeqCst), 0);
            assert!(!REGISTERED.load(Ordering::Acquire));
            denied.release_name(NM_DEST)?;
            let legacy_calls = Arc::new(Calls::default());
            legacy_calls.mode.store(1, Ordering::SeqCst);
            let legacy = serve(&bus, &legacy_calls)?;
            until(|| REGISTERED.load(Ordering::Acquire));
            assert_eq!(legacy_calls.plain.load(Ordering::SeqCst), 1);

            // A hung registration does not prevent noticing owner loss/replacement.
            legacy.release_name(NM_DEST)?;
            until(|| !REGISTERED.load(Ordering::Acquire));
            let hung_calls = Arc::new(Calls::default());
            hung_calls.mode.store(3, Ordering::SeqCst);
            let hung = serve(&bus, &hung_calls)?;
            until(|| hung_calls.capabilities.load(Ordering::SeqCst) == 1);
            hung.release_name(NM_DEST)?;
            let recovered_calls = Arc::new(Calls::default());
            let recovered = serve(&bus, &recovered_calls)?;
            until(|| REGISTERED.load(Ordering::Acquire));
            assert_eq!(recovered_calls.capabilities.load(Ordering::SeqCst), 1);
            recovered.release_name(NM_DEST)?;
            until(|| !REGISTERED.load(Ordering::Acquire));
            watch.abort();
            let _ = executor.block_on(watch);
            executor.block_on(runtime.shutdown());
            Ok(())
        },
    )
}
