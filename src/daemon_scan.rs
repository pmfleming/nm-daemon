use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::daemon::{emit_json_event, emit_json_event_best_effort};
use crate::daemon_event::next_request_id;
use crate::model::{ScanRequestOptions, validate_ssid_bytes};
use crate::nm::Nm;
use crate::output::api_data_value;

const STREAM: &str = "wifi.scan";

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct DbusScanParams {
    timeout: Option<u64>,
    strict: bool,
    cache: bool,
    ifname: Option<String>,
    #[serde(alias = "ssid")]
    ssids: Vec<String>,
}

impl DbusScanParams {
    fn into_work(self) -> Result<ScanWork> {
        Ok(ScanWork {
            timeout: Duration::from_secs(self.timeout.unwrap_or(12)),
            strict: self.strict,
            cache: self.cache,
            ifname: self.ifname,
            ssid_bytes: scan_ssid_bytes(self.ssids)?,
        })
    }
}

pub(crate) fn start_scan(params: DbusScanParams, emitter: SignalEmitter<'static>) -> Result<Value> {
    let request_id = next_request_id("scan");
    spawn_scan_events(request_id.clone(), params.into_work()?, emitter);
    api_data_value(
        "result",
        &json!({
            "status": "started",
            "request_id": request_id,
            "stream": STREAM,
            "message": "Wi-Fi scan started; listen for Event('wifi.scan', event_json) signals",
        }),
        "serialize scan start response JSON",
    )
}

fn spawn_scan_events(request_id: String, work: ScanWork, emitter: SignalEmitter<'static>) {
    std::thread::spawn(move || {
        if let Err(err) = run_scan_events(&request_id, work, &emitter) {
            let message = format!("{err:#}");
            emit_json_event_best_effort(
                &emitter,
                STREAM,
                Some(&request_id),
                "failed",
                json!({
                    "request_id": request_id,
                    "code": crate::error::classify_error(&message),
                    "message": message,
                }),
            );
        }
    });
}

fn run_scan_events(
    request_id: &str,
    work: ScanWork,
    emitter: &SignalEmitter<'static>,
) -> Result<()> {
    emit_message(emitter, request_id, "status", "starting Wi-Fi scan")?;
    let ScanWork {
        timeout,
        strict,
        cache,
        ifname,
        ssid_bytes,
    } = work;
    let nm = Nm::new()?;
    if let Err(err) = nm.scan_with_options(ScanRequestOptions {
        timeout,
        ifname,
        ssid_bytes,
    }) {
        emit_message(emitter, request_id, "warning", &format!("{err:#}"))?;
        if strict {
            return Err(err);
        }
    }
    emit_snapshot_and_complete(emitter, request_id, &nm, cache)
}

fn emit_snapshot_and_complete(
    emitter: &SignalEmitter<'static>,
    request_id: &str,
    nm: &Nm,
    cache: bool,
) -> Result<()> {
    let access_points = nm.list_all_access_points()?;
    let networks_found = access_points.len();
    if cache {
        crate::cache::write_live_scan_snapshot(false, &access_points)?;
    }
    let mut networks = nm.network_entries_for_access_points(access_points)?;
    crate::cache::attach_connection_details(&mut networks);
    emit_json_event(
        emitter,
        STREAM,
        Some(request_id),
        "snapshot",
        json!({
            "request_id": request_id,
            "scanning": false,
            "networks_found": networks_found,
            "networks": networks,
        }),
    )?;
    if cache {
        crate::cache::write_complete(false, networks_found)?;
    }
    emit_json_event(
        emitter,
        STREAM,
        Some(request_id),
        "complete",
        json!({
            "request_id": request_id,
            "timed_out": false,
            "networks_found": networks_found,
        }),
    )
}

fn emit_message(
    emitter: &SignalEmitter<'static>,
    request_id: &str,
    event: &str,
    message: &str,
) -> Result<()> {
    emit_json_event(
        emitter,
        STREAM,
        Some(request_id),
        event,
        json!({ "request_id": request_id, "message": message }),
    )
}

fn scan_ssid_bytes(ssids: Vec<String>) -> Result<Vec<Vec<u8>>> {
    ssids
        .into_iter()
        .map(|ssid| {
            let bytes = ssid.into_bytes();
            validate_ssid_bytes(&bytes)?;
            Ok(bytes)
        })
        .collect()
}

struct ScanWork {
    timeout: Duration,
    strict: bool,
    cache: bool,
    ifname: Option<String>,
    ssid_bytes: Vec<Vec<u8>>,
}
