use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::daemon_connect::DbusConnectTargetParams;
use crate::daemon_event::{emit_json_event_nonfatal, next_request_id};
use crate::daemon_runtime::DaemonRuntime;
use crate::daemon_scan::DbusScanParams;
use crate::error::{DomainError, ErrorOperation, ErrorReport, operation_result};
use crate::output::{api_data_value, api_error_value_for};
use crate::protocol::{Method, Stream};

mod immediate;

pub(crate) fn dispatch_call(
    method: &str,
    params_json: &str,
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
    runtime: &Arc<DaemonRuntime>,
) -> Result<Value> {
    let Some(method) = Method::parse(method) else {
        return Ok(unsupported_method_value(method));
    };
    let result = dispatch_method(method, params_json, owner, emitter, runtime);
    operation_result(method.spec().operation, result)
}

fn unsupported_method_value(method: &str) -> Value {
    let error: anyhow::Error = DomainError::validation(
        ErrorOperation::ParseRequest,
        format!("unsupported D-Bus method key: {method}"),
    )
    .with_detail("method", method)
    .into();
    api_error_value_for(&ErrorReport::from_error(
        &error,
        ErrorOperation::ParseRequest,
    ))
}

pub(super) fn wrong_dispatch_group(method: Method) -> anyhow::Error {
    DomainError::internal(
        method.spec().operation,
        format!("method {method} entered the wrong immediate dispatch group"),
    )
    .into()
}

fn dispatch_method(
    method: Method,
    params_json: &str,
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
    runtime: &Arc<DaemonRuntime>,
) -> Result<Value> {
    match method {
        Method::WifiScan => crate::daemon_scan::start_scan(
            runtime,
            parse_params::<DbusScanParams>(params_json)?,
            owner,
            emitter,
        ),
        Method::WifiConnectTarget => crate::daemon_connect::start_connect_target(
            runtime,
            parse_required_params::<DbusConnectTargetParams>(params_json)?,
            owner,
            emitter,
        ),
        Method::NetworkStatisticsWatch => crate::daemon_statistics::start_watch(
            runtime,
            parse_params::<crate::daemon_statistics::StatisticsWatchParams>(params_json)?,
            owner,
            emitter,
        ),
        Method::HotspotStart => crate::daemon_hotspot::start(
            runtime,
            parse_params::<crate::daemon_hotspot::HotspotStartParams>(params_json)?,
            owner,
            emitter,
        ),
        Method::VpnConnect => crate::daemon_vpn::start_connect(
            runtime,
            parse_required_params::<crate::daemon_vpn::VpnConnectParams>(params_json)?,
            owner,
            emitter,
        ),
        Method::WifiBandSet => crate::daemon_band::start_set(
            runtime,
            parse_required_params::<crate::daemon_band::BandSetParams>(params_json)?,
            owner,
            emitter,
        ),
        _ => immediate::dispatch(method, params_json, owner.as_deref(), runtime),
    }
}

pub(crate) fn subscribe_streams(
    streams: Vec<String>,
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
    runtime: &Arc<DaemonRuntime>,
) -> Result<Value> {
    let streams = normalized_streams(streams)?;
    let subscription_id = next_request_id("sub");
    let response = api_data_value(
        "subscription",
        &json!({ "id": subscription_id, "streams": streams }),
        "serialize subscription response JSON",
    )?;
    runtime.subscribe(
        subscription_id.clone(),
        owner,
        streams.clone(),
        emitter.clone(),
    )?;
    for stream in &streams {
        emit_json_event_nonfatal(
            &emitter,
            *stream,
            Some(&subscription_id),
            "subscribed",
            json!({ "subscription_id": subscription_id, "stream": stream }),
        );
    }
    Ok(response)
}

pub(crate) fn json_response(result: Result<Value>) -> String {
    let value = result.unwrap_or_else(|err| {
        api_error_value_for(&ErrorReport::from_error(&err, ErrorOperation::Unknown))
    });
    serde_json::to_string(&value).unwrap_or_else(|err| {
        format!(
            r#"{{"protocol":"nm-api","version":1,"ok":false,"error":{{"code":"internal-error","message":"serialize D-Bus response JSON: {err}","details":{{}}}},"data":{{}}}}"#
        )
    })
}

fn normalized_streams(streams: Vec<String>) -> Result<Vec<Stream>> {
    if streams.is_empty() {
        return Ok(Stream::defaults());
    }
    let mut normalized = Vec::new();
    let mut unsupported = Vec::new();
    for name in streams {
        collect_stream(name, &mut normalized, &mut unsupported);
    }
    if unsupported.is_empty() {
        Ok(normalized)
    } else {
        Err(unsupported_streams_error(unsupported))
    }
}

fn collect_stream(name: String, normalized: &mut Vec<Stream>, unsupported: &mut Vec<String>) {
    match Stream::parse_subscription(&name) {
        Some(stream) if !normalized.contains(&stream) => normalized.push(stream),
        Some(_) => {}
        None => unsupported.push(name),
    }
}

fn unsupported_streams_error(unsupported: Vec<String>) -> anyhow::Error {
    DomainError::validation(
        ErrorOperation::Subscribe,
        "subscription contains unsupported event streams",
    )
    .with_detail("unsupported_streams", json!(unsupported))
    .with_detail("supported_streams", json!(supported_stream_names()))
    .into()
}

fn supported_stream_names() -> Vec<&'static str> {
    crate::protocol::STREAM_REGISTRY
        .iter()
        .filter(|spec| spec.subscribable)
        .map(|spec| spec.name)
        .collect()
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EmptyParams {}

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
    serde_json::from_str(params_json.trim()).map_err(|error| {
        DomainError::validation(ErrorOperation::ParseRequest, &error)
            .with_detail("transport", "dbus")
            .with_cause(error.into())
            .into()
    })
}

#[cfg(test)]
mod tests {
    use super::normalized_streams;
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
    use crate::protocol::Stream;

    #[test]
    fn empty_subscription_uses_registry_defaults() {
        assert_eq!(normalized_streams(Vec::new()).unwrap(), Stream::defaults());
    }

    #[test]
    fn subscriptions_are_typed_deduplicated_and_reject_unknown_names() {
        assert_eq!(
            normalized_streams(vec![
                "wifi.scan".to_string(),
                "wifi.scan".to_string(),
                "wifi.connect".to_string(),
            ])
            .unwrap(),
            vec![Stream::WifiScan, Stream::WifiConnect]
        );

        let error =
            normalized_streams(vec!["wifi.scan".to_string(), "not.real".to_string()]).unwrap_err();
        let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::ValidationError);
        assert_eq!(report.operation, ErrorOperation::Subscribe);
        assert_eq!(report.details["unsupported_streams"][0], "not.real");
    }
}
