use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::daemon::emit_json_event_best_effort;
use crate::daemon_connect::DbusConnectTargetParams;
use crate::daemon_event::next_request_id;
use crate::daemon_scan::DbusScanParams;
use crate::daemon_secret::{SecretCapabilitiesParams, SecretProvideParams};
use crate::list::enriched_network_list;
use crate::nm::Nm;
use crate::output::{api_data_value, api_error_value};

pub(crate) fn dispatch_call(
    method: &str,
    params_json: &str,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    match method {
        "wifi.status" => call_status(),
        "network.connectivity" => call_connectivity(),
        "wifi.networks" => call_networks(parse_params(params_json)?),
        "wifi.scan" => {
            crate::daemon_scan::start_scan(parse_params::<DbusScanParams>(params_json)?, emitter)
        }
        "wifi.connectTarget" | "wifi.connect-target" => {
            crate::daemon_connect::start_connect_target(
                parse_required_params::<DbusConnectTargetParams>(params_json)?,
                emitter,
            )
        }
        "wifi.secret.capabilities" => crate::daemon_secret::capabilities(parse_params::<
            SecretCapabilitiesParams,
        >(params_json)?),
        "wifi.secret.provide" => crate::daemon_secret::provide(parse_required_params::<
            SecretProvideParams,
        >(params_json)?),
        _ => Ok(api_error_value(
            "invalid-request",
            &format!("unsupported D-Bus method key: {method}"),
        )),
    }
}

pub(crate) fn subscribe_streams(
    streams: Vec<String>,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let subscription_id = next_request_id("sub");
    let streams = normalized_streams(streams);
    for stream in &streams {
        emit_subscription_event(&emitter, &subscription_id, stream);
    }
    crate::daemon_status::spawn_subscription_worker(&subscription_id, &streams, emitter);
    api_data_value(
        "subscription",
        &json!({ "id": subscription_id, "streams": streams }),
        "serialize subscription response JSON",
    )
}

pub(crate) fn json_response(result: Result<Value>) -> String {
    let value = result.unwrap_or_else(|err| {
        let message = format!("{err:#}");
        api_error_value(crate::error::classify_error(&message), &message)
    });
    serde_json::to_string(&value).unwrap_or_else(|err| {
        format!(
            r#"{{"protocol":"nm-api","version":1,"ok":false,"error":{{"code":"internal-error","message":"serialize D-Bus response JSON: {err}","details":{{}}}},"data":{{}}}}"#
        )
    })
}

fn call_status() -> Result<Value> {
    let nm = Nm::new()?;
    let status = nm.wifi_status()?;
    if let Err(err) = crate::cache::cache_connected_network_status(&status) {
        tracing::warn!(error = %format_args!("{err:#}"), "failed to cache active Wi-Fi status");
    }
    api_data_value("status", &status, "serialize Wi-Fi status response JSON")
}

fn call_connectivity() -> Result<Value> {
    let nm = Nm::new()?;
    api_data_value(
        "connectivity",
        &nm.connectivity_check()?,
        "serialize connectivity response JSON",
    )
}

fn call_networks(params: NetworksParams) -> Result<Value> {
    let nm = Nm::new()?;
    let networks = enriched_network_list(
        &nm,
        params.cached,
        params.refresh_cache,
        params.refresh_timeout.unwrap_or(10),
        0,
        &None,
    )?;
    api_data_value("networks", &networks, "serialize network response JSON")
}

fn normalized_streams(streams: Vec<String>) -> Vec<String> {
    if streams.is_empty() {
        ["wifi.status", "network.connectivity", "wifi.scan"]
            .into_iter()
            .map(str::to_string)
            .collect()
    } else {
        streams
    }
}

fn emit_subscription_event(emitter: &SignalEmitter<'_>, subscription_id: &str, stream: &str) {
    emit_json_event_best_effort(
        emitter,
        stream,
        Some(subscription_id),
        "subscribed",
        json!({ "subscription_id": subscription_id, "stream": stream }),
    );
}

fn parse_params<T>(params_json: &str) -> Result<T>
where
    T: DeserializeOwned + Default,
{
    let params_json = params_json.trim();
    if params_json.is_empty() {
        return Ok(T::default());
    }
    parse_required_params(params_json)
}

fn parse_required_params<T>(params_json: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    serde_json::from_str(params_json.trim()).context("parse D-Bus params_json")
}

#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NetworksParams {
    cached: bool,
    refresh_cache: bool,
    refresh_timeout: Option<u64>,
}
