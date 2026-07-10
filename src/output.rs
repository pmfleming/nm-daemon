use std::fmt;
use std::io::{self, Write};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::model::{
    AccessPoint, ConnectFailureReason, ConnectResult, ConnectivityStatus, DisconnectResult,
    NetworkEntry, SavedWifiConnection, WifiSharePayload, WifiStatus,
};

pub(crate) const API_PROTOCOL: &str = "nm-api";
pub(crate) const API_VERSION: u32 = 1;

#[derive(Debug)]
struct ApiErrorAlreadyReported;

impl fmt::Display for ApiErrorAlreadyReported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("API error already reported")
    }
}

impl std::error::Error for ApiErrorAlreadyReported {}

pub(crate) fn reported_error() -> anyhow::Error {
    anyhow::Error::new(ApiErrorAlreadyReported)
}

pub(crate) fn is_reported_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<ApiErrorAlreadyReported>().is_some()
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub(crate) enum StreamOutput<'a> {
    Status {
        message: String,
    },
    Warning {
        message: String,
    },
    Snapshot {
        scanning: bool,
        networks_found: usize,
        networks: &'a [NetworkEntry],
    },
    Complete {
        timed_out: bool,
        networks_found: usize,
    },
}

macro_rules! print_api_data_fns {
    ($($name:ident($arg:ident: $ty:ty) => $key:literal, $context:literal;)+) => {
        $(pub(crate) fn $name($arg: $ty) -> Result<()> {
            print_api_data($key, $arg, $context)
        })+
    };
}

print_api_data_fns! {
    print_access_points_json(aps: &[AccessPoint]) => "access_points", "serialize AP response JSON";
    print_network_entries_json(networks: &[NetworkEntry]) => "networks", "serialize network response JSON";
    print_saved_wifi_connections_json(profiles: &[SavedWifiConnection]) => "profiles", "serialize saved Wi-Fi response JSON";
}

pub(crate) fn print_connect_result(result: &ConnectResult) -> Result<()> {
    if result.status == "error" {
        let code = result
            .reason
            .as_ref()
            .map(connect_failure_code)
            .transpose()?
            .unwrap_or_else(|| "unknown".to_string());
        let error = json!({
            "code": code,
            "message": &result.message,
            "details": {
                "ssid": &result.ssid,
                "result": result,
            },
        });
        return print_api_error_with_data(
            error,
            "result",
            result,
            "serialize connect error response JSON",
        );
    }

    print_api_data("result", result, "serialize connect response JSON")
}

print_api_data_fns! {
    print_connectivity(status: &ConnectivityStatus) => "connectivity", "serialize connectivity response JSON";
    print_wifi_status(status: &WifiStatus) => "status", "serialize Wi-Fi status response JSON";
    print_wifi_share_payload(payload: &WifiSharePayload) => "payload", "serialize Wi-Fi share response JSON";
    print_disconnect_result(result: &DisconnectResult) => "result", "serialize disconnect response JSON";
}

pub(crate) fn print_api_error(code: &str, message: &str) -> Result<()> {
    print_pretty_json(
        &api_error_value(code, message),
        "serialize API error response JSON",
    )
}

pub(crate) fn api_error_value(code: &str, message: &str) -> Value {
    json!({
        "protocol": API_PROTOCOL,
        "version": API_VERSION,
        "ok": false,
        "error": {
            "code": code,
            "message": message,
            "details": {},
        },
        "data": {},
    })
}

pub(crate) fn print_api_message(message: &str) -> Result<()> {
    print_api_data(
        "result",
        &json!({ "status": "ok", "message": message }),
        "serialize API message JSON",
    )
}

pub(crate) fn print_api_data<T: Serialize + ?Sized>(
    key: &str,
    value: &T,
    context: &'static str,
) -> Result<()> {
    print_pretty_json(&api_data_value(key, value, context)?, context)
}

pub(crate) fn api_data_value<T: Serialize + ?Sized>(
    key: &str,
    value: &T,
    context: &'static str,
) -> Result<Value> {
    Ok(json!({
        "protocol": API_PROTOCOL,
        "version": API_VERSION,
        "ok": true,
        "data": api_data_map(key, value, context)?,
    }))
}

fn print_api_error_with_data<T: Serialize + ?Sized>(
    error: Value,
    key: &str,
    value: &T,
    context: &'static str,
) -> Result<()> {
    let envelope = json!({
        "protocol": API_PROTOCOL,
        "version": API_VERSION,
        "ok": false,
        "error": error,
        "data": api_data_map(key, value, context)?,
    });
    print_pretty_json(&envelope, context)
}

fn api_data_map<T: Serialize + ?Sized>(
    key: &str,
    value: &T,
    context: &'static str,
) -> Result<Map<String, Value>> {
    let mut data = Map::new();
    data.insert(
        key.to_string(),
        serde_json::to_value(value).context(context)?,
    );
    Ok(data)
}

fn connect_failure_code(reason: &ConnectFailureReason) -> Result<String> {
    let value = serde_json::to_value(reason).context("serialize connect failure reason")?;
    Ok(value.as_str().unwrap_or("unknown").to_string())
}

fn print_pretty_json<T: Serialize + ?Sized>(value: &T, context: &'static str) -> Result<()> {
    let text = serde_json::to_string_pretty(value).context(context)?;
    println!("{text}");
    Ok(())
}

pub(crate) fn emit_stream_event(event: &StreamOutput<'_>) -> Result<()> {
    let mut value = serde_json::to_value(event).context("serialize JSON stream event")?;
    if let Value::Object(object) = &mut value {
        object.insert("protocol".to_string(), json!(API_PROTOCOL));
        object.insert("version".to_string(), json!(API_VERSION));
        object.insert("stream".to_string(), json!("wifi-scan"));
    }

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, &value).context("write JSON event")?;
    stdout.write_all(b"\n").context("write JSON newline")?;
    stdout.flush().context("flush JSON event")?;
    Ok(())
}
