use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::connect;
use crate::daemon::{emit_json_event, emit_json_event_best_effort};
use crate::daemon_event::next_request_id;
use crate::daemon_state;
use crate::model::{ConnectResult, WepKeyType, WifiConnectTarget};
use crate::nm::Nm;
use crate::output::api_data_value;

const STREAM: &str = "wifi.connect";

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
    params: DbusConnectTargetParams,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    params.target.validate()?;
    let request_id = next_request_id("connect");
    let cancel_flag = daemon_state::register(&request_id);
    spawn_connect_worker(request_id.clone(), params, cancel_flag, emitter);
    api_data_value(
        "result",
        &json!({
            "status": "started",
            "request_id": request_id,
            "stream": STREAM,
            "message": "Wi-Fi connection started; listen for Event('wifi.connect', event_json) signals",
        }),
        "serialize connect start response JSON",
    )
}

fn spawn_connect_worker(
    request_id: String,
    params: DbusConnectTargetParams,
    cancel_flag: Arc<AtomicBool>,
    emitter: SignalEmitter<'static>,
) {
    let done = Arc::new(AtomicBool::new(false));
    spawn_networkmanager_cancel_watcher(&request_id, Arc::clone(&cancel_flag), Arc::clone(&done));
    std::thread::spawn(move || {
        if let Err(err) = run_connect_worker(&request_id, params, &cancel_flag, &emitter) {
            emit_connect_failure(&emitter, &request_id, &format!("{err:#}"), None);
        }
        done.store(true, Ordering::Relaxed);
        daemon_state::remove(&request_id);
    });
}

fn spawn_networkmanager_cancel_watcher(
    request_id: &str,
    cancel_flag: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
) {
    let request_id = request_id.to_string();
    std::thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            if daemon_state::is_cancelled(&cancel_flag) {
                abort_networkmanager_activation(&request_id);
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
}

fn abort_networkmanager_activation(request_id: &str) {
    match Nm::new().and_then(|nm| nm.disconnect_wifi()) {
        Ok(result) => {
            tracing::info!(request_id, message = %result.message, "aborted NetworkManager Wi-Fi activation after cancellation")
        }
        Err(err) => {
            tracing::warn!(request_id, error = %format_args!("{err:#}"), "failed to abort NetworkManager Wi-Fi activation after cancellation")
        }
    }
}

fn run_connect_worker(
    request_id: &str,
    params: DbusConnectTargetParams,
    cancel_flag: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) -> Result<()> {
    emit_progress(emitter, request_id, "started", "starting Wi-Fi connection")?;
    if daemon_state::is_cancelled(cancel_flag) {
        return emit_cancelled(
            emitter,
            request_id,
            "cancelled before connection attempt started",
        );
    }

    let nm = Nm::new()?;
    emit_progress(
        emitter,
        request_id,
        "progress",
        "activating NetworkManager connection",
    )?;
    let result = connect::connect_target_with_password_cancellable(
        &nm,
        &params.target,
        params.password.as_deref(),
        params.wep_key_type,
        cancel_flag,
    );

    if daemon_state::is_cancelled(cancel_flag) {
        return emit_cancelled(emitter, request_id, "connection attempt was cancelled");
    }

    match result {
        Ok(result) => emit_connect_success(emitter, request_id, &result),
        Err(err) => {
            let reason = connect::connect_failure_reason(&err);
            emit_connect_failure(
                emitter,
                request_id,
                &format!("{err:#}"),
                Some(serde_json::to_value(reason)?),
            );
            Ok(())
        }
    }
}

fn emit_progress(
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

fn emit_connect_success(
    emitter: &SignalEmitter<'static>,
    request_id: &str,
    result: &ConnectResult,
) -> Result<()> {
    emit_json_event(
        emitter,
        STREAM,
        Some(request_id),
        "succeeded",
        json!({ "request_id": request_id, "result": result }),
    )
}

fn emit_cancelled(emitter: &SignalEmitter<'static>, request_id: &str, message: &str) -> Result<()> {
    emit_json_event(
        emitter,
        STREAM,
        Some(request_id),
        "cancelled",
        json!({ "request_id": request_id, "message": message }),
    )
}

fn emit_connect_failure(
    emitter: &SignalEmitter<'static>,
    request_id: &str,
    message: &str,
    reason: Option<Value>,
) {
    emit_json_event_best_effort(
        emitter,
        STREAM,
        Some(request_id),
        "failed",
        json!({
            "request_id": request_id,
            "reason": reason,
            "message": message,
        }),
    );
}
