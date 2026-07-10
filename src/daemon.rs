use std::io::Write;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use zbus::blocking::Proxy;
use zbus::object_server::SignalEmitter;

use crate::cli::{Command, NetworkCommand, WifiCommand};
use crate::daemon_dispatch::{dispatch_call, json_response, subscribe_streams};
use crate::daemon_event::event_json;

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
    let response_json: String = match proxy.call("Call", &(method, params_json.as_str())) {
        Ok(response_json) => response_json,
        Err(err) => {
            tracing::debug!(method, error = %err, "nm-daemon D-Bus service unavailable; running command directly");
            return Ok(ForwardOutcome::Unavailable);
        }
    };

    print_forwarded_response(&response_json)?;
    Ok(ForwardOutcome::Handled)
}

pub(crate) fn run_daemon() -> Result<()> {
    let connection = zbus::blocking::Connection::session().context("connect to session D-Bus")?;
    connection
        .object_server()
        .at(DBUS_OBJECT_PATH, NmDaemonInterface)
        .context("export nm-daemon D-Bus object")?;
    connection
        .request_name(DBUS_BUS_NAME)
        .with_context(|| format!("own D-Bus name {DBUS_BUS_NAME}"))?;

    let _system_connection = match crate::daemon_secret::register_secret_agent(&connection) {
        Ok(system_connection) => Some(system_connection),
        Err(err) => {
            tracing::warn!(error = %format_args!("{err:#}"), "NetworkManager SecretAgent registration failed");
            None
        }
    };

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

fn forward_request_for_command(command: &Command) -> Option<(&'static str, String)> {
    match command {
        Command::Wifi {
            command: WifiCommand::Status,
        } => Some(("wifi.status", "{}".to_string())),
        Command::Wifi {
            command: WifiCommand::Networks(options),
        } => Some(("wifi.networks", networks_params_json(options))),
        Command::Network {
            command: NetworkCommand::Connectivity,
        } => Some(("network.connectivity", "{}".to_string())),
        Command::Daemon | Command::Wifi { .. } | Command::Debug { .. } => None,
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

struct NmDaemonInterface;

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
        json_response(dispatch_call(method, params_json, emitter.to_owned()))
    }

    /// Subscribe to daemon event streams. Signals are broadcast as Event(stream, event_json).
    fn subscribe(
        &self,
        streams: Vec<String>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> String {
        json_response(subscribe_streams(streams, emitter.to_owned()))
    }

    /// Cancel a daemon request or subscription. In-flight NetworkManager calls may finish later.
    fn cancel(&self, request_id: &str, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) {
        let found = crate::daemon_state::cancel(request_id);
        emit_json_event_best_effort(
            &emitter,
            "daemon.request",
            Some(request_id),
            "cancelled",
            json!({ "request_id": request_id, "found": found }),
        );
    }

    #[zbus(signal)]
    async fn event(emitter: &SignalEmitter<'_>, stream: &str, event_json: &str)
    -> zbus::Result<()>;
}

pub(crate) fn emit_event_signal(
    emitter: &SignalEmitter<'_>,
    stream: &str,
    event_json: String,
) -> Result<()> {
    zbus::block_on(NmDaemonInterface::event(emitter, stream, &event_json))
        .context("emit nm-daemon D-Bus event")
}

pub(crate) fn emit_event_signal_best_effort(
    emitter: &SignalEmitter<'_>,
    stream: &str,
    event_json: String,
) {
    if let Err(err) = emit_event_signal(emitter, stream, event_json) {
        tracing::warn!(stream, error = %err, "failed to emit nm-daemon D-Bus event");
    }
}

pub(crate) fn emit_json_event(
    emitter: &SignalEmitter<'_>,
    stream: &str,
    request_id: Option<&str>,
    event: &str,
    data: Value,
) -> Result<()> {
    emit_event_signal(emitter, stream, event_json(stream, request_id, event, data))
}

pub(crate) fn emit_json_event_best_effort(
    emitter: &SignalEmitter<'_>,
    stream: &str,
    request_id: Option<&str>,
    event: &str,
    data: Value,
) {
    emit_event_signal_best_effort(emitter, stream, event_json(stream, request_id, event, data));
}
