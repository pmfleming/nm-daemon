use std::io::Write;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use zbus::MatchRule;
use zbus::blocking::MessageIterator;
use zbus::blocking::Proxy;
use zbus::message::{Header, Type};
use zbus::object_server::SignalEmitter;

use crate::cli::{Command, NetworkCommand, ProfileCommand, WifiCommand};
use crate::daemon_dispatch::{dispatch_call, json_response, subscribe_streams};
use crate::daemon_event::event_json;
use crate::daemon_runtime::DaemonRuntime;
use crate::error::{DomainError, ErrorCode, ErrorOperation, ErrorSource, ensure_domain};
use crate::protocol::{Method, Stream};

pub(crate) const DBUS_BUS_NAME: &str = "org.laufan.NmDaemon";
pub(crate) const DBUS_OBJECT_PATH: &str = "/org/laufan/NmDaemon";
pub(crate) const DBUS_INTERFACE: &str = "org.laufan.NmDaemon1";

pub(crate) enum ForwardOutcome {
    Handled,
    NotForwardable,
    Unavailable,
}

pub(crate) fn try_forward_command(command: &Command) -> Result<ForwardOutcome> {
    let Some((method, params_json)) = forward_request_for_command(command) else {
        return Ok(ForwardOutcome::NotForwardable);
    };

    let connection = match zbus::blocking::Connection::session() {
        Ok(connection) => connection,
        Err(err) => {
            tracing::debug!(error = %err, "session D-Bus unavailable; running command directly");
            return Ok(ForwardOutcome::Unavailable);
        }
    };
    let proxy = Proxy::new(&connection, DBUS_BUS_NAME, DBUS_OBJECT_PATH, DBUS_INTERFACE)
        .context("create nm-daemon D-Bus proxy")?;
    let response_json: String = match proxy.call("Call", &(method.as_str(), params_json.as_str())) {
        Ok(response_json) => response_json,
        Err(err) => {
            tracing::debug!(method = %method, error = %err, "nm-daemon D-Bus service unavailable; running command directly");
            return Ok(ForwardOutcome::Unavailable);
        }
    };

    print_forwarded_response(&response_json)?;
    Ok(ForwardOutcome::Handled)
}

pub(crate) fn run_daemon() -> Result<()> {
    let connection = zbus::blocking::Connection::session().context("connect to session D-Bus")?;
    let runtime = DaemonRuntime::start(crate::nm::Nm::new()?);
    connection
        .object_server()
        .at(
            DBUS_OBJECT_PATH,
            NmDaemonInterface {
                runtime: Arc::clone(&runtime),
            },
        )
        .context("export nm-daemon D-Bus object")?;
    connection
        .request_name(DBUS_BUS_NAME)
        .with_context(|| format!("own D-Bus name {DBUS_BUS_NAME}"))?;
    watch_client_disconnects(connection.clone(), Arc::clone(&runtime));

    if let Err(err) = crate::daemon_secret::register_secret_agent(
        &connection,
        &runtime.network_manager_connection(),
    ) {
        tracing::warn!(error = %format_args!("{err:#}"), "NetworkManager SecretAgent registration failed");
    }

    tracing::info!(
        bus_name = DBUS_BUS_NAME,
        object_path = DBUS_OBJECT_PATH,
        interface = DBUS_INTERFACE,
        "nm-daemon D-Bus service started"
    );

    loop {
        std::thread::park();
    }
}

fn forward_request_for_command(command: &Command) -> Option<(Method, String)> {
    match command {
        Command::Wifi {
            command: WifiCommand::Status,
        } => Some((Method::WifiStatus, "{}".to_string())),
        Command::Wifi {
            command: WifiCommand::Networks(options),
        } => Some((Method::WifiNetworks, networks_params_json(options))),
        Command::Network {
            command: NetworkCommand::Connectivity,
        } => Some((Method::NetworkConnectivity, "{}".to_string())),
        Command::Wifi {
            command: WifiCommand::Disconnect,
        } => Some((Method::WifiDisconnect, "{}".to_string())),
        Command::Wifi {
            command: WifiCommand::Profile { command },
        } => Some((Method::WifiProfileOperation, profile_params_json(command))),
        Command::Daemon | Command::Client | Command::Wifi { .. } | Command::Debug { .. } => None,
    }
}

fn profile_params_json(command: &ProfileCommand) -> String {
    match command {
        ProfileCommand::Delete { path } => {
            json!({ "operation": "delete", "path": path }).to_string()
        }
        ProfileCommand::Autoconnect { path, enabled } => {
            json!({ "operation": "set-autoconnect", "path": path, "enabled": enabled }).to_string()
        }
        ProfileCommand::MacRandomization { path, randomized } => {
            json!({ "operation": "set-mac-randomization", "path": path, "randomized": randomized })
                .to_string()
        }
        ProfileCommand::Share { path } => json!({ "operation": "share", "path": path }).to_string(),
        ProfileCommand::SendHostname { path, enabled } => {
            json!({ "operation": "set-send-hostname", "path": path, "enabled": enabled })
                .to_string()
        }
    }
}

fn networks_params_json(options: &crate::cli::ListOptions) -> String {
    json!({
        "cached": options.cached,
        "refresh_cache": options.refresh_cache,
        "refresh_timeout": options.refresh_timeout,
    })
    .to_string()
}

fn print_forwarded_response(response_json: &str) -> Result<()> {
    let value: Value =
        serde_json::from_str(response_json).context("parse nm-daemon response JSON")?;
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer_pretty(&mut stdout, &value)
        .context("serialize forwarded response JSON")?;
    stdout.write_all(b"\n").context("write JSON newline")?;
    stdout.flush().context("flush JSON response")?;
    if value.get("ok").and_then(Value::as_bool) == Some(false) {
        return Err(crate::output::reported_error());
    }
    Ok(())
}

struct NmDaemonInterface {
    runtime: Arc<DaemonRuntime>,
}

#[zbus::interface(name = "org.laufan.NmDaemon1")]
impl NmDaemonInterface {
    /// Dispatch a stable nm-api v1 method over D-Bus.
    ///
    /// The response is always a JSON string containing the existing nm-api v1 envelope.
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
            emit_json_event_best_effort(
                &emitter,
                Stream::DaemonSubscription,
                Some(request_id),
                "cancelled",
                json!({ "subscription_id": request_id, "found": true }),
            );
        }
        if outcome.task || !outcome.found() {
            emit_json_event_best_effort(
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
            let result = (|| -> Result<()> {
                let rule = MatchRule::builder()
                    .msg_type(Type::Signal)
                    .sender("org.freedesktop.DBus")?
                    .interface("org.freedesktop.DBus")?
                    .member("NameOwnerChanged")?
                    .build();
                let mut changes = MessageIterator::for_match_rule(rule, &connection, Some(64))?;
                for message in &mut changes {
                    let message = message?;
                    let (name, _old_owner, new_owner): (String, String, String) =
                        message.body().deserialize()?;
                    if name.starts_with(':') && new_owner.is_empty() {
                        runtime.drop_owner(name);
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                tracing::warn!(error = %format_args!("{error:#}"), "D-Bus owner watcher stopped");
            }
        })
        .expect("spawn D-Bus owner watcher");
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

pub(crate) fn emit_json_event_best_effort(
    emitter: &SignalEmitter<'_>,
    stream: Stream,
    request_id: Option<&str>,
    event: &str,
    data: Value,
) {
    if let Err(err) = emit_json_event(emitter, stream, request_id, event, data) {
        tracing::warn!(stream = %stream, event, error = %format_args!("{err:#}"), "failed to emit registered JSON event");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::Value;
    use zbus::blocking::Proxy;

    use super::*;
    use crate::command::SystemCommandRunner;
    use crate::nm::{NM_PATH, Nm};
    use crate::test_support::TestPeer;

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
        let nm = Nm::with_connection_runner_and_destination(
            networkmanager.client.clone(),
            Arc::new(SystemCommandRunner),
            ":1.0",
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
