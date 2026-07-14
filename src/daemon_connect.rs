use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::{Application, ConnectEvent, ConnectOutcome, ConnectRequest};
use crate::daemon::{emit_json_event, emit_json_event_nonfatal};
use crate::daemon_event::next_request_id;
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::{ErrorOperation, ErrorReport};
use crate::model::{WepKeyType, WifiConnectTarget};
use crate::nm::Nm;
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};

const STREAM: Stream = Stream::WifiConnect;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DbusConnectTargetParams {
    target: WifiConnectTarget,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    wep_key_type: Option<WepKeyType>,
}

pub(crate) fn start_connect_target(
    runtime: &Arc<DaemonRuntime>,
    params: DbusConnectTargetParams,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let request = ConnectRequest::from(params);
    request.validate()?;
    let request_id = next_request_id("connect");
    tracing::info!(
        request_id = %request_id,
        ssid = %request.target.ssid,
        ap_path = ?request.target.ap_path,
        bssid = ?request.target.bssid,
        ifname = ?request.target.ifname,
        "accepted correlated Wi-Fi connection request"
    );
    let worker_request_id = request_id.clone();
    let target_ssid = request.target.ssid_bytes().to_vec();
    runtime.start_cancellable(
        request_id.clone(),
        TaskKind::Connect,
        Some(target_ssid),
        move |nm, cancel_flag| {
            if let Err(err) =
                run_connect_worker(nm, &worker_request_id, request, cancel_flag, &emitter)
            {
                let report = ErrorReport::from_error(&err, ErrorOperation::Connect);
                emit_connect_failure(&emitter, &worker_request_id, &report);
            }
        },
    )?;
    api_data_value(
        Method::WifiConnectTarget.spec().response_key,
        &json!({
            "status": "started",
            "request_id": request_id,
            "stream": STREAM,
            "message": "Wi-Fi connection started; listen for Event('wifi.connect', event_json) signals",
        }),
        "serialize connect start response JSON",
    )
}

impl From<DbusConnectTargetParams> for ConnectRequest {
    fn from(params: DbusConnectTargetParams) -> Self {
        Self {
            target: params.target,
            password: params.password,
            wep_key_type: params.wep_key_type,
        }
    }
}

fn run_connect_worker(
    nm: &Nm,
    request_id: &str,
    request: ConnectRequest,
    cancel_flag: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) -> Result<()> {
    Application::new(nm)
        .connect(&request, Some(cancel_flag), |event| {
            emit_connect_event(emitter, request_id, event)
        })
        .map(|_| ())
}

fn emit_connect_event(
    emitter: &SignalEmitter<'static>,
    request_id: &str,
    event: &ConnectEvent,
) -> Result<()> {
    let (name, data) = match event {
        ConnectEvent::Started { message } => (
            "started",
            json!({ "request_id": request_id, "message": message }),
        ),
        ConnectEvent::Progress { message } => (
            "progress",
            json!({ "request_id": request_id, "message": message }),
        ),
        ConnectEvent::Finished(ConnectOutcome::Succeeded(result)) => {
            let connectivity_state = result
                .connectivity
                .as_ref()
                .map(|status| status.state)
                .unwrap_or("unavailable");
            let connectivity_code = result.connectivity.as_ref().map(|status| status.code);
            tracing::info!(
                %request_id,
                ssid = %result.ssid,
                connectivity_state,
                ?connectivity_code,
                suggest_open_portal = result.suggest_open_portal,
                "emitting correlated Wi-Fi connection success"
            );
            (
                "succeeded",
                json!({ "request_id": request_id, "result": result }),
            )
        }
        ConnectEvent::Finished(ConnectOutcome::Failed { result, error }) => {
            tracing::warn!(
                %request_id,
                ssid = %result.ssid,
                reason = ?result.reason,
                code = ?error.code,
                "emitting correlated Wi-Fi connection failure"
            );
            (
                "failed",
                json!({
                    "request_id": request_id,
                    "reason": result.reason,
                    "message": result.message,
                    "code": error.code,
                    "details": error.api_details(),
                }),
            )
        }
        ConnectEvent::Cancelled { message }
        | ConnectEvent::Finished(ConnectOutcome::Cancelled { message }) => {
            tracing::info!(%request_id, "emitting correlated Wi-Fi connection cancellation");
            (
                "cancelled",
                json!({ "request_id": request_id, "message": message }),
            )
        }
    };
    emit_json_event(emitter, STREAM, Some(request_id), name, data)
}

fn emit_connect_failure(emitter: &SignalEmitter<'static>, request_id: &str, report: &ErrorReport) {
    emit_json_event_nonfatal(
        emitter,
        STREAM,
        Some(request_id),
        "failed",
        json!({
            "request_id": request_id,
            "reason": report.code.connect_reason(),
            "code": report.code,
            "message": report.message,
            "details": report.api_details(),
        }),
    );
}
