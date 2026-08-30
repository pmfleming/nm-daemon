use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::{Application, PreparedScanRequest, ScanEvent, ScanRequest};
use crate::daemon_event::{OperationEvents, emit_json_event, started_response};
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::ErrorOperation;
use crate::nm::Nm;
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
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let request = ScanRequest::from(params).prepare()?;
    let request_id = runtime.start_cancellable(
        "scan",
        TaskKind::Scan,
        owner,
        None,
        move |nm, cancellation, request_id| {
            if let Err(error) = run_scan_events(nm, request_id, request, cancellation, &emitter) {
                OperationEvents::new(&emitter, STREAM, request_id).error(
                    &error,
                    ErrorOperation::Scan,
                    "Wi-Fi scan was cancelled",
                );
            }
        },
    )?;
    started_response(
        Method::WifiScan,
        STREAM,
        &request_id,
        "Wi-Fi scan started; listen for Event('wifi.scan', event_json) signals",
        json!({}),
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
                    "snapshot": snapshot.snapshot,
                }),
            )
        }
        ScanEvent::Complete { networks_found } => (
            "complete",
            json!({
                "request_id": request_id,
                "timed_out": false,
                "networks_found": networks_found,
            }),
        ),
    };
    emit_json_event(emitter, STREAM, Some(request_id), name, data)
}
