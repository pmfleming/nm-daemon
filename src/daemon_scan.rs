use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::{Application, PreparedScanRequest, ScanEvent, ScanRequest};
use crate::daemon::{emit_json_event, emit_json_event_nonfatal};
use crate::daemon_event::next_request_id;
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::{ErrorOperation, ErrorReport};
use crate::nm::Nm;
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};

const STREAM: Stream = Stream::WifiScan;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct DbusScanParams {
    timeout: Option<u64>,
    strict: bool,
    cache: bool,
    ifname: Option<crate::model::InterfaceName>,
    #[serde(alias = "ssid")]
    ssids: Vec<String>,
}

impl From<DbusScanParams> for ScanRequest {
    fn from(params: DbusScanParams) -> Self {
        Self {
            timeout: Duration::from_secs(params.timeout.unwrap_or(12)),
            strict: params.strict,
            cache: params.cache,
            ifname: params.ifname,
            ssids: params.ssids,
        }
    }
}

pub(crate) fn start_scan(
    runtime: &Arc<DaemonRuntime>,
    params: DbusScanParams,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let request = ScanRequest::from(params).prepare()?;
    let request_id = next_request_id("scan");
    let worker_request_id = request_id.clone();
    runtime.start_cancellable(
        request_id.clone(),
        TaskKind::Scan,
        None,
        move |nm, cancellation| {
            if let Err(err) =
                run_scan_events(nm, &worker_request_id, request, cancellation, &emitter)
            {
                let report = ErrorReport::from_error(&err, ErrorOperation::Scan);
                emit_json_event_nonfatal(
                    &emitter,
                    STREAM,
                    Some(&worker_request_id),
                    if report.code == crate::error::ErrorCode::Cancelled {
                        "cancelled"
                    } else {
                        "failed"
                    },
                    json!({
                        "request_id": worker_request_id,
                        "code": report.code,
                        "message": report.message,
                        "details": report.api_details(),
                    }),
                );
            }
        },
    )?;
    api_data_value(
        Method::WifiScan.spec().response_key,
        &json!({
            "status": "started",
            "request_id": request_id,
            "stream": STREAM,
            "message": "Wi-Fi scan started; listen for Event('wifi.scan', event_json) signals",
        }),
        "serialize scan start response JSON",
    )
}

fn run_scan_events(
    nm: &Nm,
    request_id: &str,
    request: PreparedScanRequest,
    cancellation: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) -> Result<()> {
    let application = Application::new(nm);
    application
        .scan_prepared(request, Some(cancellation), |event| {
            emit_scan_event(&application, emitter, request_id, event)
        })
        .map(|_| ())
}

fn emit_scan_event(
    application: &Application<'_>,
    emitter: &SignalEmitter<'static>,
    request_id: &str,
    event: &ScanEvent,
) -> Result<()> {
    let (name, data) = match event {
        ScanEvent::Status { message } => (
            "status",
            json!({ "request_id": request_id, "message": message }),
        ),
        ScanEvent::Warning { error } => (
            "warning",
            json!({
                "request_id": request_id,
                "code": error.code,
                "message": error.message,
                "details": error.api_details(),
            }),
        ),
        ScanEvent::Snapshot {
            networks_found,
            access_points,
        } => {
            let snapshot = application.network_snapshot(access_points.clone())?;
            (
                "snapshot",
                json!({
                    "request_id": request_id,
                    "scanning": false,
                    "networks_found": networks_found,
                    "networks": snapshot.networks,
                }),
            )
        }
        ScanEvent::Complete {
            timed_out,
            networks_found,
        } => (
            "complete",
            json!({
                "request_id": request_id,
                "timed_out": timed_out,
                "networks_found": networks_found,
            }),
        ),
    };
    emit_json_event(emitter, STREAM, Some(request_id), name, data)
}
