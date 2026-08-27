use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::fmt;

use shelllist_daemon_core::{ApiError as EnvelopeError, ApiIdentity};

use crate::error::{DomainError, ErrorCode, ErrorOperation, ErrorReport, ErrorSource};
use crate::model::{
    AccessPoint, ConnectFailureReason, ConnectResult, ConnectivityStatus, DisconnectResult,
    NetworkEntry, NetworkSnapshotMetadata, SavedWifiConnection, WifiSharePayload, WifiStatus,
};

pub(crate) const API_PROTOCOL: &str = "nm-api";
pub(crate) const API_VERSION: u32 = 1;
const API: ApiIdentity = ApiIdentity::new(API_PROTOCOL, API_VERSION);

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

macro_rules! print_api_data_fns {
    ($($name:ident($arg:ident: $ty:ty) => $key:literal, $context:literal;)+) => {
        $(pub(crate) fn $name($arg: $ty) -> Result<()> {
            print_api_data($key, $arg, $context)
        })+
    };
}

print_api_data_fns! {
    print_access_points_json(aps: &[AccessPoint]) => "access_points", "serialize AP response JSON";
    print_saved_wifi_connections_json(profiles: &[SavedWifiConnection]) => "profiles", "serialize saved Wi-Fi response JSON";
}

pub(crate) fn print_network_entries_with_snapshot(
    networks: &[NetworkEntry],
    snapshot: &NetworkSnapshotMetadata,
) -> Result<()> {
    let context = "serialize network response JSON";
    let mut envelope = api_data_value("networks", networks, context)?;
    envelope["data"]["snapshot"] = serde_json::to_value(snapshot).context(context)?;
    print_pretty_json(&envelope, context)
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

pub(crate) fn print_connect_failure(result: &ConnectResult, report: &ErrorReport) -> Result<()> {
    let mut details = report
        .api_details()
        .as_object()
        .cloned()
        .unwrap_or_default();
    details.insert("ssid".to_string(), json!(&result.ssid));
    details.insert("result".to_string(), json!(result));
    let error = json!({
        "code": report.code,
        "message": report.message,
        "details": details,
    });
    print_api_error_with_data(
        error,
        "result",
        result,
        "serialize connect error response JSON",
    )
}

print_api_data_fns! {
    print_connectivity(status: &ConnectivityStatus) => "connectivity", "serialize connectivity response JSON";
    print_wifi_status(status: &WifiStatus) => "status", "serialize Wi-Fi status response JSON";
    print_wifi_share_payload(payload: &WifiSharePayload) => "payload", "serialize Wi-Fi share response JSON";
    print_disconnect_result(result: &DisconnectResult) => "result", "serialize disconnect response JSON";
}

pub(crate) fn print_error_report(report: &ErrorReport) -> Result<()> {
    print_pretty_json(
        &api_error_value_for(report),
        "serialize typed API error response JSON",
    )
}

pub(crate) fn api_error_value_for(report: &ErrorReport) -> Value {
    let code = serde_json::to_value(report.code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "internal-error".to_string());
    let mut envelope = shelllist_daemon_core::error(
        API,
        EnvelopeError::new(code, report.message.clone()).with_details(report.api_details()),
    );
    envelope["data"] = json!({});
    envelope
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
    Ok(shelllist_daemon_core::success(
        API,
        Value::Object(api_data_map(key, value, context)?),
    ))
}

fn print_api_error_with_data<T: Serialize + ?Sized>(
    error: Value,
    key: &str,
    value: &T,
    context: &'static str,
) -> Result<()> {
    let code = error["code"].as_str().unwrap_or("internal-error");
    let message = error["message"].as_str().unwrap_or("operation failed");
    let details = error.get("details").cloned();
    let api_error = details.map_or_else(
        || EnvelopeError::new(code, message),
        |details| EnvelopeError::new(code, message).with_details(details),
    );
    let mut envelope = shelllist_daemon_core::error(API, api_error);
    envelope["data"] = Value::Object(api_data_map(key, value, context)?);
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
        serde_json::to_value(value).map_err(|error| {
            DomainError::new(
                ErrorCode::InternalError,
                ErrorOperation::SerializeResponse,
                ErrorSource::Serialization,
                format!("{context}: {error}"),
            )
            .with_cause(error.into())
        })?,
    );
    Ok(data)
}

fn connect_failure_code(reason: &ConnectFailureReason) -> Result<String> {
    let value = serde_json::to_value(reason).context("serialize connect failure reason")?;
    Ok(value.as_str().unwrap_or("unknown").to_string())
}

fn print_pretty_json<T: Serialize + ?Sized>(value: &T, context: &'static str) -> Result<()> {
    let text = serde_json::to_string_pretty(value).map_err(|error| {
        DomainError::new(
            ErrorCode::InternalError,
            ErrorOperation::SerializeResponse,
            ErrorSource::Serialization,
            format!("{context}: {error}"),
        )
        .with_cause(error.into())
    })?;
    println!("{text}");
    Ok(())
}
