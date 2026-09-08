use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::Application;
use crate::daemon_event::{OperationEvents, started_response};
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::{ErrorOperation, ErrorReport};
use crate::model::{NmObjectPath, WifiBand, WifiBandSelectionResult};
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
    runtime.call_application(Method::WifiBandStatus, move |application| {
        application.band_status(params.path.as_str())
    })
}

pub(crate) fn start_set(
    runtime: &Arc<DaemonRuntime>,
    params: BandSetParams,
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let request_id = runtime.start_cancellable(
        "band",
        TaskKind::Band,
        owner,
        None,
        move |nm, cancellation, request_id| {
            run_band_worker(nm, request_id, params, cancellation, &emitter);
        },
    )?;
    started_response(
        Method::WifiBandSet,
        STREAM,
        &request_id,
        "Wi-Fi band selection started; listen for Event('wifi.band', event_json) signals",
        json!({}),
    )
}

fn run_band_worker(
    nm: &crate::nm::Nm,
    request_id: &str,
    params: BandSetParams,
    cancellation: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) {
    let events = OperationEvents::new(emitter, STREAM, request_id);
    for (event, phase) in [("started", "preparing"), ("progress", "applying")] {
        events.event(
            event,
            json!({
                "phase": phase,
                "path": params.path.as_str(),
                "requested_band": params.band,
            }),
        );
    }
    match Application::new(nm).select_band(params.path.as_str(), params.band, Some(cancellation)) {
        Ok(result) => emit_band_success(&events, &params, cancellation, result),
        Err(error) => emit_band_error(&events, &params, &error),
    }
}

fn emit_band_success(
    events: &OperationEvents<'_, '_>,
    params: &BandSetParams,
    cancellation: &AtomicBool,
    result: WifiBandSelectionResult,
) {
    let cancelled = cancellation.load(Ordering::Relaxed);
    let (event, data) = if cancelled {
        (
            "cancelled",
            json!({
                "phase": "cancelled",
                "path": params.path.as_str(),
                "requested_band": params.band,
                "message": "Wi-Fi band selection was cancelled",
            }),
        )
    } else {
        (
            "succeeded",
            json!({
                "phase": "complete",
                "path": params.path.as_str(),
                "requested_band": params.band,
                "result": result,
            }),
        )
    };
    events.event(event, data);
}

fn emit_band_error(
    events: &OperationEvents<'_, '_>,
    params: &BandSetParams,
    error: &anyhow::Error,
) {
    let report = ErrorReport::from_error(error, ErrorOperation::BandOperation);
    let cancelled = report.code == crate::error::ErrorCode::Cancelled;
    events.event(
        if cancelled { "cancelled" } else { "failed" },
        json!({
            "phase": if cancelled { "cancelled" } else { "failed" },
            "path": params.path.as_str(),
            "requested_band": params.band,
            "code": report.code,
            "message": report.message,
            "details": report.api_details(),
        }),
    );
}
