use std::sync::Arc;

use anyhow::{Context, Result};
use futures::StreamExt;
use serde_json::json;
use zbus::message::Header;
use zbus::object_server::SignalEmitter;

use crate::daemon_dispatch::{dispatch_call, json_response, subscribe_streams};
use crate::daemon_event::emit_json_event_nonfatal;
use crate::daemon_runtime::DaemonRuntime;
use crate::error::{ErrorOperation, ensure_domain};
use crate::protocol::{DBUS_BUS_NAME, DBUS_INTERFACE, DBUS_OBJECT_PATH, Stream};

pub(crate) async fn run_daemon() -> Result<()> {
    let tokio = tokio::runtime::Handle::current();
    let runtime =
        tokio::task::spawn_blocking(move || DaemonRuntime::start(crate::nm::Nm::new()?, tokio))
            .await
            .context("join NetworkManager runtime initialization")??;
    let connection = zbus::connection::Builder::session()
        .context("connect to session D-Bus")?
        .name(DBUS_BUS_NAME)
        .with_context(|| format!("own D-Bus name {DBUS_BUS_NAME}"))?
        .serve_at(
            DBUS_OBJECT_PATH,
            NmDaemonInterface {
                runtime: Arc::clone(&runtime),
                tokio: tokio::runtime::Handle::current(),
            },
        )
        .context("export nm-daemon D-Bus object")?
        .build()
        .await
        .context("start nm-daemon D-Bus service")?;
    let owner_watch = tokio::spawn(watch_client_disconnects(
        connection.clone(),
        Arc::clone(&runtime),
    ));
    register_secret_agent(&runtime);
    log_daemon_started();
    let result = wait_for_shutdown().await;
    owner_watch.abort();
    result
}

async fn wait_for_shutdown() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("listen for SIGTERM")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("wait for Ctrl-C"),
        _ = terminate.recv() => Ok(()),
    }
}

fn register_secret_agent(runtime: &Arc<DaemonRuntime>) {
    if let Err(err) =
        crate::daemon_secret::register_secret_agent(&runtime.network_manager_connection(), runtime)
    {
        tracing::warn!(error = %crate::error::err_chain(&err), "NetworkManager SecretAgent registration failed");
    }
}

fn log_daemon_started() {
    tracing::info!(
        bus_name = DBUS_BUS_NAME,
        object_path = DBUS_OBJECT_PATH,
        interface = DBUS_INTERFACE,
        "nm-daemon D-Bus service started"
    );
}

struct NmDaemonInterface {
    runtime: Arc<DaemonRuntime>,
    tokio: tokio::runtime::Handle,
}

#[zbus::interface(name = "org.laufan.NmDaemon1")]
impl NmDaemonInterface {
    /// Dispatches an nm-api v1 method and returns its JSON envelope.
    async fn call(
        &self,
        method: &str,
        params_json: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> String {
        let method = method.to_string();
        let params_json = params_json.to_string();
        let owner = header.sender().map(ToString::to_string);
        let emitter = directed_emitter(&emitter, &header);
        let runtime = Arc::clone(&self.runtime);
        self.tokio
            .spawn_blocking(move || {
                json_response(dispatch_call(
                    &method,
                    &params_json,
                    owner,
                    emitter,
                    &runtime,
                ))
            })
            .await
            .unwrap_or_else(|error| {
                json_response(Err(crate::error::DomainError::internal(
                    ErrorOperation::Unknown,
                    format!("D-Bus call task failed: {error}"),
                )
                .into()))
            })
    }

    /// Subscribe to daemon event streams. Event signals are directed to the subscribing owner.
    async fn subscribe(
        &self,
        streams: Vec<String>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> String {
        let owner = header.sender().map(ToString::to_string);
        let emitter = directed_emitter(&emitter, &header);
        let runtime = Arc::clone(&self.runtime);
        self.tokio
            .spawn_blocking(move || {
                json_response(subscribe_streams(streams, owner, emitter, &runtime))
            })
            .await
            .unwrap_or_else(|error| {
                json_response(Err(crate::error::DomainError::internal(
                    ErrorOperation::Subscribe,
                    format!("D-Bus subscription task failed: {error}"),
                )
                .into()))
            })
    }

    /// Cancel a daemon request or subscription. In-flight NetworkManager calls may finish later.
    async fn cancel(
        &self,
        request_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) {
        let request_id = request_id.to_string();
        let owner = header.sender().map(ToString::to_string);
        let emitter = directed_emitter(&emitter, &header);
        let runtime = Arc::clone(&self.runtime);
        if let Err(error) = self
            .tokio
            .spawn_blocking(move || {
                let outcome = runtime.cancel(&request_id, owner.as_deref());
                if outcome.subscription {
                    emit_json_event_nonfatal(
                        &emitter,
                        Stream::DaemonSubscription,
                        Some(&request_id),
                        "cancelled",
                        json!({ "subscription_id": request_id, "found": true }),
                    );
                }
                if outcome.task || !outcome.found() {
                    emit_json_event_nonfatal(
                        &emitter,
                        Stream::DaemonRequest,
                        Some(&request_id),
                        "cancelled",
                        json!({ "request_id": request_id, "found": outcome.task }),
                    );
                }
            })
            .await
        {
            tracing::warn!(%error, "D-Bus cancellation task failed");
        }
    }

    #[zbus(signal)]
    async fn event(emitter: &SignalEmitter<'_>, stream: &str, event_json: &str)
    -> zbus::Result<()>;
}

/// Makes every event originating from a method call private to that caller.
///
/// This is a security boundary, not just routing: operation results may carry
/// short-lived credentials (for example a newly generated hotspot passphrase),
/// so callers must never receive a broadcast emitter when D-Bus supplied a
/// unique sender name.
fn directed_emitter(emitter: &SignalEmitter<'_>, header: &Header<'_>) -> SignalEmitter<'static> {
    match header.sender() {
        Some(sender) => emitter.to_owned().set_destination(sender.to_owned().into()),
        None => emitter.to_owned(),
    }
}

async fn watch_client_disconnects(connection: zbus::Connection, runtime: Arc<DaemonRuntime>) {
    if let Err(error) = run_owner_watch(&connection, &runtime).await {
        tracing::warn!(error = %crate::error::err_chain(&error), "D-Bus owner watcher stopped");
    }
}

async fn run_owner_watch(connection: &zbus::Connection, runtime: &DaemonRuntime) -> Result<()> {
    let proxy = zbus::Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    .context("create D-Bus owner proxy")?;
    let mut changes = proxy
        .receive_signal("NameOwnerChanged")
        .await
        .context("receive D-Bus owner changes")?;
    while let Some(message) = changes.next().await {
        let (name, _old_owner, new_owner): (String, String, String) = message
            .body()
            .deserialize()
            .context("decode D-Bus owner change")?;
        if name.starts_with(':') && new_owner.is_empty() {
            runtime.drop_owner(name);
        }
    }
    anyhow::bail!("D-Bus owner-change stream ended")
}

pub(crate) fn emit_event_signal(
    emitter: &SignalEmitter<'_>,
    stream: Stream,
    event_json: String,
) -> Result<()> {
    zbus::block_on(NmDaemonInterface::event(
        emitter,
        stream.as_str(),
        &event_json,
    ))
    .map_err(|error| ensure_domain(ErrorOperation::EmitEvent, error.into()))
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};
    use zbus::blocking::Proxy;
    use zvariant::OwnedObjectPath;

    use super::{DBUS_INTERFACE, DBUS_OBJECT_PATH, NmDaemonInterface};
    use crate::command::SystemCommandRunner;
    use crate::daemon_runtime::DaemonRuntime;
    use crate::nl80211::UnavailableWirelessTelemetry;
    use crate::nm::{NM_PATH, Nm};
    use crate::test_support::TestPeer;

    struct FakeNetworkManagerSettings;

    #[zbus::interface(name = "org.freedesktop.NetworkManager.Settings")]
    impl FakeNetworkManagerSettings {
        fn list_connections(&self) -> Vec<OwnedObjectPath> {
            Vec::new()
        }
    }

    struct FakeNetworkManager;

    #[zbus::interface(name = "org.freedesktop.NetworkManager")]
    impl FakeNetworkManager {
        fn check_connectivity(&self) -> u32 {
            4
        }
    }

    const CHILD_ENV: &str = "NM_DAEMON_DBUS_TEST_CHILD";
    const TEST_NAME: &str =
        "daemon::tests::dbus_dispatch_and_subscription_lifecycle_runs_against_fake_networkmanager";

    #[test]
    fn dbus_dispatch_and_subscription_lifecycle_runs_against_fake_networkmanager() {
        if std::env::var_os(CHILD_ENV).is_some() {
            return run_dbus_lifecycle_test();
        }
        assert!(
            (0..3).any(|_| run_bounded_dbus_child()),
            "D-Bus lifecycle test timed out after 3 attempts"
        );
    }

    fn run_bounded_dbus_child() -> bool {
        let mut child = Command::new(std::env::current_exe().expect("locate test executable"))
            .args(["--exact", TEST_NAME, "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .spawn()
            .expect("spawn bounded D-Bus lifecycle test");
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(10) {
            if let Some(status) = child.try_wait().expect("poll D-Bus lifecycle test") {
                return status.success();
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().expect("stop timed-out D-Bus lifecycle test");
        child.wait().expect("reap timed-out D-Bus lifecycle test");
        false
    }

    fn run_dbus_lifecycle_test() {
        let networkmanager = TestPeer::new(":1.0", ":1.1");
        networkmanager
            .server
            .object_server()
            .at(NM_PATH, FakeNetworkManager)
            .unwrap();
        networkmanager
            .server
            .object_server()
            .at(
                "/org/freedesktop/NetworkManager/Settings",
                FakeNetworkManagerSettings,
            )
            .unwrap();
        let nm = Nm::with_connection_runner_destination_and_telemetry(
            networkmanager.client.clone(),
            Arc::new(SystemCommandRunner),
            ":1.0",
            Arc::new(UnavailableWirelessTelemetry),
        )
        .unwrap();
        let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let runtime = DaemonRuntime::start(nm, tokio_runtime.handle().clone()).unwrap();

        let daemon = TestPeer::new(":1.2", ":1.3");
        daemon
            .server
            .object_server()
            .at(
                DBUS_OBJECT_PATH,
                NmDaemonInterface {
                    runtime: Arc::clone(&runtime),
                    tokio: tokio_runtime.handle().clone(),
                },
            )
            .unwrap();
        let proxy = Proxy::new(&daemon.client, ":1.2", DBUS_OBJECT_PATH, DBUS_INTERFACE).unwrap();

        let response_json: String = proxy.call("Call", &("network.connectivity", "{}")).unwrap();
        let response: Value = serde_json::from_str(&response_json).unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["data"]["connectivity"]["state"], "full");

        let saved_json: String = proxy.call("Call", &("wifi.saved", "{}")).unwrap();
        let saved: Value = serde_json::from_str(&saved_json).unwrap();
        assert_eq!(saved["ok"], true);
        assert_eq!(saved["data"]["profiles"], json!([]));

        let mut events = proxy.receive_signal("Event").unwrap();
        let subscription_json: String = proxy
            .call("Subscribe", &(vec!["network.connectivity"],))
            .unwrap();
        let subscription: Value = serde_json::from_str(&subscription_json).unwrap();
        let subscription_id = subscription["data"]["subscription"]["id"].as_str().unwrap();

        let (stream, subscribed) = next_event(&mut events);
        assert_eq!(stream, "network.connectivity");
        assert_eq!(subscribed["event"], "subscribed");
        assert_eq!(subscribed["subscription_id"], subscription_id);

        proxy
            .call::<_, _, ()>("Cancel", &(subscription_id,))
            .unwrap();
        loop {
            let (stream, event) = next_event(&mut events);
            if event["event"] == "cancelled" {
                assert_eq!(stream, "daemon.subscription");
                assert_eq!(event["subscription_id"], subscription_id);
                break;
            }
        }

        let unsupported_json: String = proxy.call("Call", &("not.real", "{}")).unwrap();
        let unsupported: Value = serde_json::from_str(&unsupported_json).unwrap();
        assert_eq!(unsupported["ok"], false);
        assert_eq!(unsupported["error"]["code"], "validation-error");

        let invalid_connect_json: String =
            proxy.call("Call", &("wifi.connectTarget", "{}")).unwrap();
        let invalid_connect: Value = serde_json::from_str(&invalid_connect_json).unwrap();
        assert_eq!(invalid_connect["ok"], false);
        assert_eq!(invalid_connect["error"]["code"], "validation-error");

        let excessive_scan_json: String = proxy
            .call(
                "Call",
                &("wifi.scan", r#"{"timeout":18446744073709551615}"#),
            )
            .unwrap();
        let excessive_scan: Value = serde_json::from_str(&excessive_scan_json).unwrap();
        assert_eq!(excessive_scan["ok"], false);
        assert_eq!(excessive_scan["error"]["code"], "validation-error");
    }

    fn next_event(events: &mut zbus::blocking::proxy::SignalIterator<'_>) -> (String, Value) {
        let message = events.next().expect("daemon event signal");
        let (stream, event_json): (String, String) = message.body().deserialize().unwrap();
        (stream, serde_json::from_str(&event_json).unwrap())
    }
}
