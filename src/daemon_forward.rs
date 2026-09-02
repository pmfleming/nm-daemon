use std::io::Write;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use zbus::blocking::Proxy;
use zbus::blocking::proxy::SignalIterator;

use crate::application::ConnectRequest;
use crate::cli::{
    Command, HotspotCommand, HotspotStartOptions, NetworkCommand, ProfileCommand, ScanOptions,
    VpnCommand, VpnConnectOptions, WifiCommand,
};
use crate::protocol::{DBUS_BUS_NAME, DBUS_INTERFACE, DBUS_OBJECT_PATH, Method, Stream};

pub(crate) enum ForwardOutcome {
    Handled,
    DirectConnect(Box<ConnectRequest>),
    NotForwardable,
    Unavailable,
}

pub(crate) fn try_forward_command(command: &Command) -> Result<ForwardOutcome> {
    if !is_forwardable(command) {
        return Ok(ForwardOutcome::NotForwardable);
    }
    let connection = match zbus::blocking::Connection::session() {
        Ok(connection) => connection,
        Err(error) => {
            tracing::debug!(%error, "session D-Bus unavailable; running command directly");
            return Ok(ForwardOutcome::Unavailable);
        }
    };
    let proxy = Proxy::new(&connection, DBUS_BUS_NAME, DBUS_OBJECT_PATH, DBUS_INTERFACE)
        .context("create nm-daemon D-Bus proxy")?;
    dispatch_forward(&proxy, command)
}

fn dispatch_forward(proxy: &Proxy<'_>, command: &Command) -> Result<ForwardOutcome> {
    match command {
        Command::Wifi {
            command: WifiCommand::Scan(options),
        } => forward_scan(proxy, options),
        Command::Wifi {
            command: WifiCommand::Connect(options),
        } => forward_connect(
            proxy,
            crate::actions::connect_ssid_request(options.clone())?,
        ),
        Command::Wifi {
            command: WifiCommand::ConnectTarget(options),
        } => forward_connect(
            proxy,
            crate::actions::connect_target_request(options.clone())?,
        ),
        Command::Hotspot {
            command: HotspotCommand::Start(options),
        } => forward_hotspot_start(proxy, options),
        Command::Vpn {
            command: VpnCommand::Connect(options),
        } => forward_vpn_connect(proxy, options),
        _ => forward_immediate(proxy, command),
    }
}

fn is_forwardable(command: &Command) -> bool {
    matches!(
        command,
        Command::Wifi {
            command: WifiCommand::Scan(_) | WifiCommand::Connect(_) | WifiCommand::ConnectTarget(_),
        } | Command::Hotspot {
            command: HotspotCommand::Start(_),
        } | Command::Vpn {
            command: VpnCommand::Connect(_),
        }
    ) || immediate_request(command).is_some()
}

fn forward_immediate(proxy: &Proxy<'_>, command: &Command) -> Result<ForwardOutcome> {
    let Some((method, params)) = immediate_request(command) else {
        return Ok(ForwardOutcome::NotForwardable);
    };
    let response: String = match proxy.call("Call", &(method.as_str(), params.as_str())) {
        Ok(response) => response,
        Err(error) => {
            tracing::debug!(%method, %error, "daemon call unavailable; running directly");
            return Ok(ForwardOutcome::Unavailable);
        }
    };
    print_response(&response)?;
    Ok(ForwardOutcome::Handled)
}

fn forward_scan(proxy: &Proxy<'_>, options: &ScanOptions) -> Result<ForwardOutcome> {
    let params = json!({
        "timeout": options.timeout,
        "strict": options.strict,
        "cache": options.cache,
        "ifname": options.ifname,
        "ssids": options.ssids,
    })
    .to_string();
    run_operation(
        proxy,
        Method::WifiScan,
        params,
        Stream::WifiScan,
        || ForwardOutcome::Unavailable,
        |events| finish_scan(events, options.quiet),
    )
}

fn forward_connect(proxy: &Proxy<'_>, request: ConnectRequest) -> Result<ForwardOutcome> {
    let params = json!({
        "target": &request.target,
        "password": &request.password,
        "wep_key_type": request.wep_key_type,
    })
    .to_string();
    run_operation(
        proxy,
        Method::WifiConnectTarget,
        params,
        Stream::WifiConnect,
        || ForwardOutcome::DirectConnect(Box::new(request)),
        finish_connect,
    )
}

fn forward_hotspot_start(
    proxy: &Proxy<'_>,
    options: &HotspotStartOptions,
) -> Result<ForwardOutcome> {
    let params = json!({
        "ssid": options.ssid,
        "passphrase": crate::actions::resolve_password(options.passphrase_stdin)?,
        "security": options.security,
        "band": options.band,
        "channel": options.channel,
        "hidden": options.hidden,
        "device": options.device,
    })
    .to_string();
    forward_simple_operation(proxy, Method::HotspotStart, params, Stream::Hotspot)
}

fn forward_vpn_connect(proxy: &Proxy<'_>, options: &VpnConnectOptions) -> Result<ForwardOutcome> {
    let params = json!({
        "uuid": options.uuid,
        "path": options.path,
        "timeout": options.timeout,
    })
    .to_string();
    forward_simple_operation(proxy, Method::VpnConnect, params, Stream::Vpn)
}

fn forward_simple_operation(
    proxy: &Proxy<'_>,
    method: Method,
    params: String,
    stream: Stream,
) -> Result<ForwardOutcome> {
    run_operation(
        proxy,
        method,
        params,
        stream,
        || ForwardOutcome::Unavailable,
        finish_operation_result,
    )
}

/// Renders the terminal event of a simple start/succeed/fail operation as the
/// same CLI envelope the direct implementation would have printed.
fn finish_operation_result(mut events: CorrelatedEvents<'_>) -> Result<ForwardOutcome> {
    while let Some(event) = events.next()? {
        match event.get("event").and_then(Value::as_str) {
            Some("succeeded") => print_response(
                &crate::output::api_data_value(
                    "result",
                    event.get("result").unwrap_or(&Value::Null),
                    "serialize forwarded operation response JSON",
                )?
                .to_string(),
            )?,
            Some("failed" | "cancelled") => print_response(&event_error(&event).to_string())?,
            _ => continue,
        }
        return Ok(ForwardOutcome::Handled);
    }
    anyhow::bail!("nm-daemon operation event stream ended before completion")
}

fn run_operation<'a>(
    proxy: &'a Proxy<'_>,
    method: Method,
    params: String,
    stream: Stream,
    unavailable: impl FnOnce() -> ForwardOutcome,
    finish: impl FnOnce(CorrelatedEvents<'a>) -> Result<ForwardOutcome>,
) -> Result<ForwardOutcome> {
    let events = match proxy.receive_signal("Event") {
        Ok(events) => events,
        Err(error) => {
            tracing::debug!(%method, %error, "could not receive daemon events");
            return Ok(unavailable());
        }
    };
    let response_json: String = match proxy.call("Call", &(method.as_str(), params.as_str())) {
        Ok(response) => response,
        Err(error) => {
            tracing::debug!(%method, %error, "daemon operation unavailable");
            return Ok(unavailable());
        }
    };
    let response = parse_response(&response_json)?;
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        print_response(&response_json)?;
        return Ok(ForwardOutcome::Handled);
    }
    finish(CorrelatedEvents {
        events,
        stream,
        request_id: request_id(&response)?,
    })
}

struct CorrelatedEvents<'a> {
    events: SignalIterator<'a>,
    stream: Stream,
    request_id: String,
}

impl CorrelatedEvents<'_> {
    fn next(&mut self) -> Result<Option<Value>> {
        for message in &mut self.events {
            let (stream, event_json): (String, String) = message.body().deserialize()?;
            let event: Value =
                serde_json::from_str(&event_json).context("parse nm-daemon event JSON")?;
            if stream == self.stream.as_str()
                && event.get("request_id").and_then(Value::as_str) == Some(&self.request_id)
            {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }
}

fn finish_scan(mut events: CorrelatedEvents<'_>, quiet: bool) -> Result<ForwardOutcome> {
    let mut access_points = Value::Array(Vec::new());
    while let Some(event) = events.next()? {
        if handle_scan_event(event, &mut access_points, quiet)? {
            return Ok(ForwardOutcome::Handled);
        }
    }
    anyhow::bail!("nm-daemon scan event stream ended before completion")
}

fn handle_scan_event(event: Value, access_points: &mut Value, quiet: bool) -> Result<bool> {
    match event.get("event").and_then(Value::as_str) {
        Some("warning") => log_scan_warning(&event),
        Some("snapshot") => *access_points = flatten_access_points(&event),
        Some("complete") => print_scan_result(access_points, quiet)?,
        Some("failed" | "cancelled") => print_response(&event_error(&event).to_string())?,
        _ => return Ok(false),
    }
    Ok(is_terminal(&event))
}

fn log_scan_warning(event: &Value) {
    let message = event
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unknown scan error");
    eprintln!("warning: scan failed: {message}; showing cached NetworkManager results");
}

fn print_scan_result(access_points: &Value, quiet: bool) -> Result<()> {
    if quiet {
        return Ok(());
    }
    let envelope = crate::output::api_data_value(
        "access_points",
        access_points,
        "serialize forwarded scan response JSON",
    )?;
    print_response(&envelope.to_string())
}

fn finish_connect(mut events: CorrelatedEvents<'_>) -> Result<ForwardOutcome> {
    while let Some(event) = events.next()? {
        match event.get("event").and_then(Value::as_str) {
            Some("succeeded") => print_connect_result(&event)?,
            Some("failed" | "cancelled") => print_response(&event_error(&event).to_string())?,
            _ => continue,
        }
        return Ok(ForwardOutcome::Handled);
    }
    anyhow::bail!("nm-daemon connect event stream ended before completion")
}

fn print_connect_result(event: &Value) -> Result<()> {
    print_response(
        &crate::output::api_data_value(
            "result",
            event.get("result").unwrap_or(&Value::Null),
            "serialize forwarded connect response JSON",
        )?
        .to_string(),
    )
}

fn is_terminal(event: &Value) -> bool {
    matches!(
        event.get("event").and_then(Value::as_str),
        Some("complete" | "failed" | "cancelled")
    )
}

fn parse_response(response_json: &str) -> Result<Value> {
    serde_json::from_str(response_json).context("parse nm-daemon response JSON")
}

fn request_id(response: &Value) -> Result<String> {
    response
        .pointer("/data/result/request_id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .context("daemon operation response did not contain request_id")
}

fn flatten_access_points(event: &Value) -> Value {
    Value::Array(
        event["networks"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|network| network["access_points"].as_array().into_iter().flatten())
            .cloned()
            .collect(),
    )
}

fn event_error(event: &Value) -> Value {
    let cancelled = event.get("event").and_then(Value::as_str) == Some("cancelled");
    let (fallback_code, fallback_message) = if cancelled {
        ("cancelled", "operation cancelled")
    } else {
        ("internal-error", "operation failed")
    };
    let details = event.get("details").cloned().unwrap_or_else(|| json!({}));
    let data = event
        .get("result")
        .map(|result| json!({ "result": result }))
        .unwrap_or_else(|| json!({}));
    json!({
        "protocol": crate::output::API_PROTOCOL,
        "version": crate::output::API_VERSION,
        "ok": false,
        "error": {
            "code": event.get("code").and_then(Value::as_str).unwrap_or(fallback_code),
            "message": event.get("message").and_then(Value::as_str).unwrap_or(fallback_message),
            "details": details,
        },
        "data": data,
    })
}

fn immediate_request(command: &Command) -> Option<(Method, String)> {
    match command {
        Command::Wifi {
            command: WifiCommand::Status,
        } => empty(Method::WifiStatus),
        Command::Wifi {
            command: WifiCommand::Networks(options),
        } => Some((
            Method::WifiNetworks,
            json!({
                "cached": options.cached,
                "refresh_cache": options.refresh_cache,
                "refresh_timeout": options.refresh_timeout,
            })
            .to_string(),
        )),
        Command::Network { command } => network_request(command),
        Command::Hotspot { command } => hotspot_request(command),
        Command::Vpn { command } => vpn_request(command),
        Command::Wifi {
            command: WifiCommand::Disconnect,
        } => empty(Method::WifiDisconnect),
        Command::Wifi {
            command: WifiCommand::Saved,
        } => empty(Method::WifiSaved),
        Command::Wifi {
            command: WifiCommand::Profile { command },
        } => Some((Method::WifiProfileOperation, profile_params(command))),
        Command::Daemon | Command::Client | Command::Wifi { .. } | Command::Debug { .. } => None,
    }
}

fn network_request(command: &NetworkCommand) -> Option<(Method, String)> {
    match command {
        NetworkCommand::Connectivity => empty(Method::NetworkConnectivity),
        NetworkCommand::Status => empty(Method::NetworkState),
        NetworkCommand::Devices => empty(Method::NetworkDevices),
        NetworkCommand::Connections => empty(Method::NetworkConnections),
        NetworkCommand::Inventory => empty(Method::NetworkInventory),
        NetworkCommand::Activate(options) => Some((
            Method::NetworkActivateProfile,
            json!({
                "uuid": options.uuid,
                "path": options.path,
                "device": options.device,
            })
            .to_string(),
        )),
        NetworkCommand::Deactivate(options) => Some((
            Method::NetworkDeactivate,
            json!({ "path": options.path, "uuid": options.uuid }).to_string(),
        )),
    }
}

fn vpn_request(command: &VpnCommand) -> Option<(Method, String)> {
    match command {
        VpnCommand::List => empty(Method::VpnList),
        VpnCommand::Status => empty(Method::VpnStatus),
        VpnCommand::Disconnect(options) => Some((
            Method::VpnDisconnect,
            json!({ "uuid": options.uuid, "path": options.path }).to_string(),
        )),
        // Connect is an event-driven operation handled by forward_vpn_connect.
        VpnCommand::Connect(_) => None,
    }
}

fn hotspot_request(command: &HotspotCommand) -> Option<(Method, String)> {
    match command {
        HotspotCommand::Capabilities => empty(Method::HotspotCapabilities),
        HotspotCommand::Status => empty(Method::HotspotStatus),
        HotspotCommand::Stop => empty(Method::HotspotStop),
        // Start is an event-driven operation handled by forward_hotspot_start.
        HotspotCommand::Start(_) => None,
    }
}

fn empty(method: Method) -> Option<(Method, String)> {
    Some((method, "{}".to_string()))
}

fn profile_params(command: &ProfileCommand) -> String {
    match command {
        ProfileCommand::Delete { path } => json!({ "operation": "delete", "path": path }),
        ProfileCommand::Autoconnect { path, enabled } => {
            json!({ "operation": "set-autoconnect", "path": path, "enabled": enabled })
        }
        ProfileCommand::Casting { path, enabled } => {
            json!({ "operation": "set-casting", "path": path, "enabled": enabled })
        }
        ProfileCommand::MacRandomization { path, randomized } => {
            json!({ "operation": "set-mac-randomization", "path": path, "randomized": randomized })
        }
        ProfileCommand::Share { path } => json!({ "operation": "share", "path": path }),
        ProfileCommand::SendHostname { path, enabled } => {
            json!({ "operation": "set-send-hostname", "path": path, "enabled": enabled })
        }
    }
    .to_string()
}

fn print_response(response_json: &str) -> Result<()> {
    let value = parse_response(response_json)?;
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{event_error, flatten_access_points};

    #[test]
    fn forwarded_operation_events_preserve_cli_envelopes() {
        let access_points = flatten_access_points(&json!({
            "networks": [{ "access_points": [1, 2] }, { "access_points": [3] }],
        }));
        assert_eq!(access_points, json!([1, 2, 3]));

        let error = event_error(&json!({
            "event": "failed",
            "code": "wrong-password",
            "result": { "reason": "wrong-password" },
        }));
        assert_eq!(error["ok"], false);
        assert_eq!(error["error"]["code"], "wrong-password");
        assert_eq!(error["data"]["result"]["reason"], "wrong-password");

        let cancelled = event_error(&json!({ "event": "cancelled" }));
        assert_eq!(cancelled["error"]["code"], "cancelled");
    }
}
