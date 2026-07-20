use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use zbus::MatchRule;
use zbus::blocking::MessageIterator;
use zbus::message::{Header, Type};
use zbus::object_server::SignalEmitter;

use crate::daemon_dispatch::{dispatch_call, json_response, subscribe_streams};
use crate::daemon_event::event_json;
use crate::daemon_runtime::DaemonRuntime;
use crate::error::{
    DomainError, ErrorCode, ErrorOperation, ErrorSource, best_effort, ensure_domain,
};
use crate::protocol::{DBUS_BUS_NAME, DBUS_INTERFACE, DBUS_OBJECT_PATH, Stream};

pub(crate) fn run_daemon() -> Result<()> {
    let connection = zbus::blocking::Connection::session().context("connect to session D-Bus")?;
    let runtime = DaemonRuntime::start(crate::nm::Nm::new()?);
    export_daemon_interface(&connection, &runtime)?;
    watch_client_disconnects(connection.clone(), Arc::clone(&runtime));
    register_secret_agent(&connection, &runtime);
    log_daemon_started();
    loop {
        std::thread::park();
    }
}

fn export_daemon_interface(
    connection: &zbus::blocking::Connection,
    runtime: &Arc<DaemonRuntime>,
) -> Result<()> {
    connection
        .object_server()
        .at(
            DBUS_OBJECT_PATH,
            NmDaemonInterface {
                runtime: Arc::clone(runtime),
            },
        )
        .context("export nm-daemon D-Bus object")?;
    connection
        .request_name(DBUS_BUS_NAME)
        .with_context(|| format!("own D-Bus name {DBUS_BUS_NAME}"))?;
    Ok(())
}

fn register_secret_agent(connection: &zbus::blocking::Connection, runtime: &DaemonRuntime) {
    if let Err(err) = crate::daemon_secret::register_secret_agent(
        connection,
        &runtime.network_manager_connection(),
    ) {
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
}

#[zbus::interface(name = "org.laufan.NmDaemon1")]
impl NmDaemonInterface {
    /// Dispatches an nm-api v1 method and returns its JSON envelope.
    fn call(
        &self,
        method: &str,
        params_json: &str,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> String {
        json_response(dispatch_call(
            method,
            params_json,
            emitter.to_owned(),
            &self.runtime,
        ))
    }

    /// Subscribe to daemon event streams. Signals are broadcast as Event(stream, event_json).
    fn subscribe(
        &self,
        streams: Vec<String>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> String {
        json_response(subscribe_streams(
            streams,
            header.sender().map(ToString::to_string),
            emitter.to_owned(),
            &self.runtime,
        ))
    }

    /// Cancel a daemon request or subscription. In-flight NetworkManager calls may finish later.
    fn cancel(&self, request_id: &str, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) {
        let outcome = self.runtime.cancel(request_id);
        if outcome.subscription {
            emit_json_event_nonfatal(
                &emitter,
                Stream::DaemonSubscription,
                Some(request_id),
                "cancelled",
                json!({ "subscription_id": request_id, "found": true }),
            );
        }
        if outcome.task || !outcome.found() {
            emit_json_event_nonfatal(
                &emitter,
                Stream::DaemonRequest,
                Some(request_id),
                "cancelled",
                json!({ "request_id": request_id, "found": outcome.task }),
            );
        }
    }

    #[zbus(signal)]
    async fn event(emitter: &SignalEmitter<'_>, stream: &str, event_json: &str)
    -> zbus::Result<()>;
}

fn watch_client_disconnects(connection: zbus::blocking::Connection, runtime: Arc<DaemonRuntime>) {
    std::thread::Builder::new()
        .name("nm-dbus-owners".to_string())
        .spawn(move || {
            log_owner_watch_result(run_owner_watch(&connection, &runtime));
        })
        .expect("spawn D-Bus owner watcher");
}

fn run_owner_watch(connection: &zbus::blocking::Connection, runtime: &DaemonRuntime) -> Result<()> {
    let rule = owner_change_rule()?;
    let mut changes = MessageIterator::for_match_rule(rule, connection, Some(64))?;
    for message in &mut changes {
        handle_owner_change(message?, runtime)?;
    }
    Ok(())
}

fn owner_change_rule() -> Result<MatchRule<'static>> {
    Ok(MatchRule::builder()
        .msg_type(Type::Signal)
        .sender("org.freedesktop.DBus")?
        .interface("org.freedesktop.DBus")?
        .member("NameOwnerChanged")?
        .build())
}

fn handle_owner_change(message: zbus::Message, runtime: &DaemonRuntime) -> Result<()> {
    let (name, _old_owner, new_owner): (String, String, String) = message.body().deserialize()?;
    if name.starts_with(':') && new_owner.is_empty() {
        runtime.drop_owner(name);
    }
    Ok(())
}

fn log_owner_watch_result(result: Result<()>) {
    if let Err(error) = result {
        tracing::warn!(error = %crate::error::err_chain(&error), "D-Bus owner watcher stopped");
    }
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

pub(crate) fn emit_json_event(
    emitter: &SignalEmitter<'_>,
    stream: Stream,
    request_id: Option<&str>,
    event: &str,
    data: Value,
) -> Result<()> {
    if !stream.spec().events.contains(&event) {
        return Err(DomainError::new(
            ErrorCode::InternalError,
            ErrorOperation::EmitEvent,
            ErrorSource::Internal,
            format!("event '{event}' is not registered for stream '{stream}'"),
        )
        .with_detail("stream", stream.as_str())
        .with_detail("event", event)
        .into());
    }
    emit_event_signal(emitter, stream, event_json(stream, request_id, event, data))
}

pub(crate) fn emit_json_event_nonfatal(
    emitter: &SignalEmitter<'_>,
    stream: Stream,
    request_id: Option<&str>,
    event: &str,
    data: Value,
) {
    best_effort(
        format!("failed to emit registered JSON event {stream}.{event}"),
        || emit_json_event(emitter, stream, request_id, event, data),
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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

    #[test]
    fn dbus_dispatch_and_subscription_lifecycle_runs_against_fake_networkmanager() {
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
        );
        let runtime = DaemonRuntime::start(nm);

        let daemon = TestPeer::new(":1.2", ":1.3");
        daemon
            .server
            .object_server()
            .at(
                DBUS_OBJECT_PATH,
                NmDaemonInterface {
                    runtime: Arc::clone(&runtime),
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
    }

    fn next_event(events: &mut zbus::blocking::proxy::SignalIterator<'_>) -> (String, Value) {
        let message = events.next().expect("daemon event signal");
        let (stream, event_json): (String, String) = message.body().deserialize().unwrap();
        (stream, serde_json::from_str(&event_json).unwrap())
    }
}
