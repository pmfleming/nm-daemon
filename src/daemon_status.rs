use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::daemon::emit_json_event_best_effort;
use crate::daemon_state;
use crate::nm::Nm;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

pub(crate) fn spawn_subscription_worker(
    subscription_id: &str,
    streams: &[String],
    emitter: SignalEmitter<'static>,
) {
    let watched_streams = watched_streams(streams);
    if watched_streams.is_empty() {
        return;
    }
    let subscription_id = subscription_id.to_string();
    let cancel_flag = daemon_state::register(&subscription_id);
    std::thread::spawn(move || {
        run_subscription_worker(&subscription_id, watched_streams, cancel_flag, emitter);
        daemon_state::remove(&subscription_id);
    });
}

fn run_subscription_worker(
    subscription_id: &str,
    streams: Vec<WatchedStream>,
    cancel_flag: Arc<AtomicBool>,
    emitter: SignalEmitter<'static>,
) {
    let mut last_status = None;
    let mut last_connectivity = None;
    while !daemon_state::is_cancelled(&cancel_flag) {
        if let Ok(nm) = Nm::new() {
            for stream in &streams {
                stream.poll_and_emit(
                    &nm,
                    subscription_id,
                    &emitter,
                    &mut last_status,
                    &mut last_connectivity,
                );
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    emit_json_event_best_effort(
        &emitter,
        "daemon.subscription",
        Some(subscription_id),
        "cancelled",
        json!({ "subscription_id": subscription_id }),
    );
}

fn watched_streams(streams: &[String]) -> Vec<WatchedStream> {
    streams
        .iter()
        .filter_map(|stream| match stream.as_str() {
            "wifi.status" => Some(WatchedStream::WifiStatus),
            "network.connectivity" => Some(WatchedStream::NetworkConnectivity),
            _ => None,
        })
        .collect()
}

#[derive(Clone, Copy)]
enum WatchedStream {
    WifiStatus,
    NetworkConnectivity,
}

impl WatchedStream {
    fn poll_and_emit(
        self,
        nm: &Nm,
        subscription_id: &str,
        emitter: &SignalEmitter<'static>,
        last_status: &mut Option<Value>,
        last_connectivity: &mut Option<Value>,
    ) {
        match self {
            WatchedStream::WifiStatus => emit_on_change(
                emitter,
                "wifi.status",
                subscription_id,
                "changed",
                last_status,
                || status_payload(nm, subscription_id),
            ),
            WatchedStream::NetworkConnectivity => emit_on_change(
                emitter,
                "network.connectivity",
                subscription_id,
                "changed",
                last_connectivity,
                || connectivity_payload(nm, subscription_id),
            ),
        }
    }
}

fn emit_on_change(
    emitter: &SignalEmitter<'static>,
    stream: &str,
    subscription_id: &str,
    event: &str,
    last: &mut Option<Value>,
    payload: impl FnOnce() -> Result<Value>,
) {
    let Ok(value) = payload() else {
        return;
    };
    if last.as_ref() == Some(&value) {
        return;
    }
    *last = Some(value.clone());
    emit_json_event_best_effort(emitter, stream, Some(subscription_id), event, value);
}

fn status_payload(nm: &Nm, subscription_id: &str) -> Result<Value> {
    let status = nm.wifi_status()?;
    if let Err(err) = crate::cache::cache_connected_network_status(&status) {
        tracing::warn!(error = %format_args!("{err:#}"), "failed to cache active Wi-Fi status");
    }
    Ok(json!({ "subscription_id": subscription_id, "status": status }))
}

fn connectivity_payload(nm: &Nm, subscription_id: &str) -> Result<Value> {
    Ok(json!({
        "subscription_id": subscription_id,
        "connectivity": nm.connectivity_check()?,
    }))
}
