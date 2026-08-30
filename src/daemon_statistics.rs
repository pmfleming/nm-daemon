use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::daemon_event::{emit_json_event, emit_json_event_nonfatal, started_response};
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::{DomainError, ErrorOperation, ErrorReport};
use crate::model::DeviceStatisticsSample;
use crate::nm::{Nm, StatisticsDevice, statistics_rates};
use crate::protocol::{Method, Stream};

const STREAM: Stream = Stream::NetworkStatistics;
const MIN_INTERVAL_MS: u32 = 200;
const MAX_INTERVAL_MS: u32 = 60_000;
const DEFAULT_INTERVAL_MS: u32 = 1_000;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct StatisticsWatchParams {
    /// Device object path or interface name; defaults to the first device.
    device: Option<String>,
    interval_ms: Option<u32>,
}

impl StatisticsWatchParams {
    fn interval_ms(&self) -> Result<u32> {
        let interval_ms = self.interval_ms.unwrap_or(DEFAULT_INTERVAL_MS);
        if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&interval_ms) {
            return Err(DomainError::validation(
                ErrorOperation::Statistics,
                format!(
                    "interval_ms must be between {MIN_INTERVAL_MS} and {MAX_INTERVAL_MS} milliseconds"
                ),
            )
            .with_detail("interval_ms", interval_ms)
            .into());
        }
        Ok(interval_ms)
    }
}

pub(crate) fn start_watch(
    runtime: &Arc<DaemonRuntime>,
    params: StatisticsWatchParams,
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let interval_ms = params.interval_ms()?;
    let requested = params.device.clone();
    let device = runtime.call(ErrorOperation::Statistics, move |nm| {
        nm.statistics_device(requested.as_deref())
    })?;
    let worker_device = device.clone();
    let request_id = runtime.start_cancellable(
        "stats",
        TaskKind::Statistics,
        owner,
        None,
        move |nm, cancellation, request_id| {
            run_statistics_worker(
                nm,
                request_id,
                &worker_device,
                interval_ms,
                cancellation,
                &emitter,
            );
        },
    )?;
    started_response(
        Method::NetworkStatisticsWatch,
        STREAM,
        &request_id,
        "Device statistics watch started; listen for Event('network.statistics', event_json) signals",
        json!({
            "device_path": device.path,
            "device_iface": device.interface,
            "interval_ms": interval_ms,
        }),
    )
}

fn run_statistics_worker(
    nm: &Nm,
    request_id: &str,
    device: &StatisticsDevice,
    interval_ms: u32,
    cancellation: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) {
    if let Err(error) = nm.acquire_statistics_refresh(&device.path, interval_ms) {
        emit_failure(emitter, request_id, device, &error);
        return;
    }
    emit_json_event_nonfatal(
        emitter,
        STREAM,
        Some(request_id),
        "started",
        json!({
            "request_id": request_id,
            "device_path": device.path,
            "device_iface": device.interface,
            "interval_ms": interval_ms,
        }),
    );

    let result = watch_statistics(
        nm,
        request_id,
        device,
        Duration::from_millis(u64::from(interval_ms)),
        cancellation,
        emitter,
    );
    nm.release_statistics_refresh(&device.path);
    if let Err(error) = result {
        emit_failure(emitter, request_id, device, &error);
    } else {
        emit_json_event_nonfatal(
            emitter,
            STREAM,
            Some(request_id),
            "cancelled",
            json!({
                "request_id": request_id,
                "device_path": device.path,
                "device_iface": device.interface,
                "message": "Device statistics watch stopped",
            }),
        );
    }
}

fn watch_statistics(
    nm: &Nm,
    request_id: &str,
    device: &StatisticsDevice,
    interval: Duration,
    cancellation: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) -> Result<()> {
    let mut previous: Option<DeviceStatisticsSample> = None;
    while !cancellation.load(Ordering::Relaxed) {
        let mut sample = nm.device_statistics(&device.path)?;
        if let Some(previous) = &previous {
            statistics_rates(previous, &mut sample);
        }
        emit_json_event_nonfatal(
            emitter,
            STREAM,
            Some(request_id),
            "sample",
            json!({
                "request_id": request_id,
                "device_path": device.path,
                "device_iface": device.interface,
                "statistics": &sample,
            }),
        );
        previous = Some(sample);
        if !sleep_until_cancelled(interval, cancellation) {
            break;
        }
    }
    Ok(())
}

/// Sleeps in short slices so cancellation is observed well before the next
/// sample would be due. Returns false when the watch was cancelled.
fn sleep_until_cancelled(interval: Duration, cancellation: &AtomicBool) -> bool {
    const SLICE: Duration = Duration::from_millis(100);
    let deadline = Instant::now() + interval;
    while Instant::now() < deadline {
        if cancellation.load(Ordering::Relaxed) {
            return false;
        }
        std::thread::sleep(SLICE.min(deadline.saturating_duration_since(Instant::now())));
    }
    !cancellation.load(Ordering::Relaxed)
}

fn emit_failure(
    emitter: &SignalEmitter<'static>,
    request_id: &str,
    device: &StatisticsDevice,
    error: &anyhow::Error,
) {
    let report = ErrorReport::from_error(error, ErrorOperation::Statistics);
    let data = json!({
        "request_id": request_id,
        "device_path": device.path,
        "device_iface": device.interface,
        "code": report.code,
        "message": report.message,
        "details": report.api_details(),
    });
    if let Err(emit_error) = emit_json_event(emitter, STREAM, Some(request_id), "failed", data) {
        tracing::warn!(error = %crate::error::err_chain(&emit_error), "failed to emit statistics watch failure");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::{DEFAULT_INTERVAL_MS, StatisticsWatchParams, sleep_until_cancelled};
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};

    fn params(interval_ms: Option<u32>) -> StatisticsWatchParams {
        StatisticsWatchParams {
            device: None,
            interval_ms,
        }
    }

    #[test]
    fn interval_defaults_and_bounds_are_enforced() {
        assert_eq!(params(None).interval_ms().unwrap(), DEFAULT_INTERVAL_MS);
        assert_eq!(params(Some(500)).interval_ms().unwrap(), 500);
        for rejected in [0, 199, 60_001] {
            let error = params(Some(rejected)).interval_ms().unwrap_err();
            let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
            assert_eq!(report.code, ErrorCode::ValidationError);
            assert_eq!(report.operation, ErrorOperation::Statistics);
        }
    }

    #[test]
    fn an_already_cancelled_watch_does_not_wait_for_the_interval() {
        let cancellation = AtomicBool::new(true);
        let started = std::time::Instant::now();
        assert!(!sleep_until_cancelled(
            Duration::from_secs(30),
            &cancellation
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        cancellation.store(false, Ordering::Relaxed);
    }
}
