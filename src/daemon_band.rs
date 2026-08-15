use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::Application;
use crate::daemon_event::{emit_json_event, emit_json_event_nonfatal, next_request_id};
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::{ErrorOperation, ErrorReport};
use crate::model::{NmObjectPath, WifiBand};
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};

const STREAM: Stream = Stream::WifiBand;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BandStatusParams {
    path: NmObjectPath,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BandSetParams {
    path: NmObjectPath,
    band: WifiBand,
}

pub(crate) fn status(runtime: &Arc<DaemonRuntime>, params: BandStatusParams) -> Result<Value> {
    runtime.call(ErrorOperation::BandOperation, move |nm| {
        api_data_value(
            Method::WifiBandStatus.spec().response_key,
            &Application::new(nm).band_status(params.path.as_str())?,
            "serialize Wi-Fi band status response JSON",
        )
    })
}

pub(crate) fn start_set(
    runtime: &Arc<DaemonRuntime>,
    params: BandSetParams,
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let request_id = next_request_id("band");
    let worker_request_id = request_id.clone();
    runtime.start_cancellable(
        request_id.clone(),
        TaskKind::Band,
        owner,
        None,
        move |nm, cancellation| {
            run_band_worker(nm, &worker_request_id, params, cancellation, &emitter);
        },
    )?;
    api_data_value(
        Method::WifiBandSet.spec().response_key,
        &json!({
            "status": "started",
            "request_id": request_id,
            "stream": STREAM,
            "message": "Wi-Fi band selection started; listen for Event('wifi.band', event_json) signals",
        }),
        "serialize Wi-Fi band start response JSON",
    )
}

fn run_band_worker(
    nm: &crate::nm::Nm,
    request_id: &str,
    params: BandSetParams,
    cancellation: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) {
    emit_json_event_nonfatal(
        emitter,
        STREAM,
        Some(request_id),
        "started",
        json!({
            "request_id": request_id,
            "phase": "preparing",
            "path": params.path.as_str(),
            "requested_band": params.band,
        }),
    );
    emit_json_event_nonfatal(
        emitter,
        STREAM,
        Some(request_id),
        "progress",
        json!({
            "request_id": request_id,
            "phase": "applying",
            "path": params.path.as_str(),
            "requested_band": params.band,
        }),
    );

    match Application::new(nm).select_band(params.path.as_str(), params.band, Some(cancellation)) {
        Ok(result) => {
            let event = if cancellation.load(Ordering::Relaxed) {
                "cancelled"
            } else {
                "succeeded"
            };
            let data = if event == "cancelled" {
                json!({
                    "request_id": request_id,
                    "phase": "cancelled",
                    "path": params.path.as_str(),
                    "requested_band": params.band,
                    "message": "Wi-Fi band selection was cancelled",
                })
            } else {
                json!({
                    "request_id": request_id,
                    "phase": "complete",
                    "path": params.path.as_str(),
                    "requested_band": params.band,
                    "result": result,
                })
            };
            emit_json_event_nonfatal(emitter, STREAM, Some(request_id), event, data);
        }
        Err(error) => {
            let report = ErrorReport::from_error(&error, ErrorOperation::BandOperation);
            let cancelled = report.code == crate::error::ErrorCode::Cancelled;
            let event = if cancelled { "cancelled" } else { "failed" };
            let data = json!({
                "request_id": request_id,
                "phase": if cancelled { "cancelled" } else { "failed" },
                "path": params.path.as_str(),
                "requested_band": params.band,
                "code": report.code,
                "message": report.message,
                "details": report.api_details(),
            });
            if let Err(emit_error) = emit_json_event(emitter, STREAM, Some(request_id), event, data)
            {
                tracing::warn!(error = %crate::error::err_chain(&emit_error), "failed to emit Wi-Fi band operation result");
            }
        }
    }
}
