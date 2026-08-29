//! Per-device scan scheduling.
//!
//! NetworkManager rate-limits `RequestScan`, so several callers each asking for
//! their own scan produces rejections rather than fresher results. This module
//! coalesces explicit and background demand onto one in-flight scan per device,
//! waits until NetworkManager's request interval permits scanning, and retries
//! transient rate-limit rejections inside the caller's deadline.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::deadline::Deadline;
use crate::error::{DomainError, ErrorOperation, ErrorReport};
use crate::generated::{SCAN_REQUEST_INTERVAL, SCAN_SCHEDULE_POLL_INTERVAL};

/// What a caller must do after joining the scheduler for a device.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ScanTurn {
    /// This caller owns the scan and must issue `RequestScan`.
    Request { generation: u64 },
    /// Another caller's scan covers the same SSIDs; wait for its result.
    Join { generation: u64 },
    /// Another caller is scanning a different scope; wait, then claim again.
    Wait { generation: u64 },
}

#[derive(Debug, Clone)]
pub(super) enum SharedScanOutcome {
    Succeeded,
    Failed(ErrorReport),
}

#[derive(Debug, Default)]
pub(super) struct ScanScheduler {
    devices: Mutex<HashMap<String, DeviceScanState>>,
    finished: Condvar,
}

#[derive(Debug, Default)]
struct DeviceScanState {
    in_flight: bool,
    in_flight_ssids: Vec<Vec<u8>>,
    generation: u64,
    waiters: HashMap<u64, usize>,
    completions: HashMap<u64, SharedScanOutcome>,
    last_request: Option<Instant>,
    previous_request: Option<Instant>,
}

impl ScanScheduler {
    /// Claims the scan for `device_path`, joins a compatible request, or waits
    /// behind an incompatible targeted request.
    pub(super) fn claim(&self, device_path: &str, ssids: &[Vec<u8>]) -> ScanTurn {
        let mut devices = self.lock();
        let state = devices.entry(device_path.to_string()).or_default();
        let requested = normalized_ssids(ssids);
        if state.in_flight {
            *state.waiters.entry(state.generation).or_default() += 1;
            return if scan_scope_covers(&state.in_flight_ssids, &requested) {
                ScanTurn::Join {
                    generation: state.generation,
                }
            } else {
                ScanTurn::Wait {
                    generation: state.generation,
                }
            };
        }
        state.in_flight = true;
        state.in_flight_ssids = requested;
        state.generation = state.generation.wrapping_add(1);
        state.previous_request = state.last_request;
        state.last_request = Some(Instant::now());
        ScanTurn::Request {
            generation: state.generation,
        }
    }

    /// Completes one owned scan and wakes callers waiting for its exact result.
    pub(super) fn complete(&self, device_path: &str, generation: u64, outcome: SharedScanOutcome) {
        if let Some(state) = self.lock().get_mut(device_path)
            && state.in_flight
            && state.generation == generation
        {
            state.in_flight = false;
            state.in_flight_ssids.clear();
            if state.waiters.contains_key(&generation) {
                state.completions.insert(generation, outcome);
            }
        }
        self.finished.notify_all();
    }

    /// Waits for one specific in-flight scan to finish, or the deadline.
    pub(super) fn wait_for_completion(
        &self,
        device_path: &str,
        generation: u64,
        deadline: Deadline,
    ) -> Option<SharedScanOutcome> {
        let mut devices = self.lock();
        loop {
            if let Some(outcome) = devices
                .get(device_path)
                .and_then(|state| state.completions.get(&generation))
                .cloned()
            {
                consume_waiter(&mut devices, device_path, generation);
                return Some(outcome);
            }
            let wait = deadline.wait(SCAN_SCHEDULE_POLL_INTERVAL);
            if wait.is_zero() {
                consume_waiter(&mut devices, device_path, generation);
                return None;
            }
            devices = self
                .finished
                .wait_timeout(devices, wait)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
    }

    /// Records that a caller issued `RequestScan`, which restarts the interval.
    pub(super) fn note_request(&self, device_path: &str) {
        self.lock()
            .entry(device_path.to_string())
            .or_default()
            .last_request = Some(Instant::now());
    }

    /// The claim itself stamps `last_request`, so the owner needs the value
    /// recorded by the *previous* scan to compute its wait.
    pub(super) fn last_request_before_claim(&self, device_path: &str) -> Option<Instant> {
        self.lock()
            .get(device_path)
            .and_then(|state| state.previous_request)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, DeviceScanState>> {
        self.devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn consume_waiter(
    devices: &mut HashMap<String, DeviceScanState>,
    device_path: &str,
    generation: u64,
) {
    let Some(state) = devices.get_mut(device_path) else {
        return;
    };
    let Some(waiters) = state.waiters.get_mut(&generation) else {
        return;
    };
    *waiters = waiters.saturating_sub(1);
    if *waiters == 0 {
        state.waiters.remove(&generation);
        state.completions.remove(&generation);
    }
}

fn normalized_ssids(ssids: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut ssids = ssids.to_vec();
    ssids.sort();
    ssids.dedup();
    ssids
}

fn scan_scope_covers(in_flight: &[Vec<u8>], requested: &[Vec<u8>]) -> bool {
    if in_flight.is_empty() || requested.is_empty() {
        return in_flight.is_empty() && requested.is_empty();
    }
    requested
        .iter()
        .all(|ssid| in_flight.binary_search(ssid).is_ok())
}

/// How long to wait before NetworkManager will accept another `RequestScan`.
///
/// `last_scan_ms` is NetworkManager's `LastScan` in CLOCK_BOOTTIME
/// milliseconds, or a negative value when the device has never scanned.
pub(super) fn rate_limit_wait(
    last_scan_ms: i64,
    boottime_ms: i64,
    last_request: Option<Instant>,
    now: Instant,
) -> Duration {
    let since_scan = (last_scan_ms >= 0)
        .then(|| boottime_ms.saturating_sub(last_scan_ms))
        .filter(|elapsed| *elapsed >= 0)
        .map(|elapsed| Duration::from_millis(elapsed as u64));
    let since_request = last_request.map(|at| now.saturating_duration_since(at));
    [since_scan, since_request]
        .into_iter()
        .flatten()
        .map(|elapsed| SCAN_REQUEST_INTERVAL.saturating_sub(elapsed))
        .max()
        .unwrap_or_default()
}

/// True for NetworkManager rejections that succeed if simply retried later.
pub(super) fn is_transient_scan_rejection(error: &anyhow::Error) -> bool {
    let rendered = format!("{error:#}").to_ascii_lowercase();
    rendered.contains("scanning not allowed")
        || rendered.contains("device.notallowed")
        || rendered.contains("not allowed while unavailable")
        || rendered.contains("too soon")
}

/// Reads CLOCK_BOOTTIME milliseconds the way NetworkManager stamps `LastScan`.
pub(super) fn boottime_ms() -> Option<i64> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let seconds: f64 = uptime.split_whitespace().next()?.parse().ok()?;
    Some((seconds * 1000.0) as i64)
}

pub(super) fn scan_deadline_expired(message: &str) -> anyhow::Error {
    DomainError::timeout(ErrorOperation::Scan, message).into()
}

/// Sleeps in short slices so cancellation is noticed promptly. Returns false
/// when the deadline passed before the requested wait elapsed.
pub(super) fn sleep_within_deadline(
    wait: Duration,
    deadline: Deadline,
    cancellation: Option<&AtomicBool>,
    check: impl Fn(Option<&AtomicBool>) -> Result<()>,
) -> Result<bool> {
    let until = Instant::now() + wait;
    while Instant::now() < until {
        check(cancellation)?;
        if deadline.expired() {
            return Ok(false);
        }
        let slice = SCAN_SCHEDULE_POLL_INTERVAL
            .min(until.saturating_duration_since(Instant::now()))
            .min(deadline.wait(SCAN_SCHEDULE_POLL_INTERVAL));
        if slice.is_zero() {
            return Ok(!deadline.expired());
        }
        std::thread::sleep(slice);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        ScanScheduler, ScanTurn, SharedScanOutcome, boottime_ms, is_transient_scan_rejection,
        rate_limit_wait,
    };
    use crate::deadline::Deadline;
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport, ErrorSource};
    use crate::generated::SCAN_REQUEST_INTERVAL;

    #[test]
    fn one_caller_owns_the_scan_and_the_rest_join_it() {
        let scheduler = ScanScheduler::default();
        assert_eq!(
            scheduler.claim("/devices/1", &[]),
            ScanTurn::Request { generation: 1 }
        );
        assert_eq!(
            scheduler.claim("/devices/1", &[]),
            ScanTurn::Join { generation: 1 }
        );
        // A different device is scheduled independently.
        assert_eq!(
            scheduler.claim("/devices/2", &[]),
            ScanTurn::Request { generation: 1 }
        );

        scheduler.complete("/devices/1", 1, SharedScanOutcome::Succeeded);
        assert_eq!(
            scheduler.claim("/devices/1", &[]),
            ScanTurn::Request { generation: 2 }
        );
    }

    #[test]
    fn targeted_scans_only_join_a_scope_that_covers_their_ssids() {
        let scheduler = ScanScheduler::default();
        let cafe = vec![b"Cafe".to_vec()];
        let cafe_and_office = vec![b"Office".to_vec(), b"Cafe".to_vec()];
        assert_eq!(
            scheduler.claim("/devices/1", &cafe_and_office),
            ScanTurn::Request { generation: 1 }
        );
        assert_eq!(
            scheduler.claim("/devices/1", &cafe),
            ScanTurn::Join { generation: 1 }
        );
        assert_eq!(
            scheduler.claim("/devices/1", &[b"Other".to_vec()]),
            ScanTurn::Wait { generation: 1 }
        );
        assert_eq!(
            scheduler.claim("/devices/1", &[]),
            ScanTurn::Wait { generation: 1 }
        );

        scheduler.complete("/devices/1", 1, SharedScanOutcome::Succeeded);
        assert_eq!(
            scheduler.claim("/devices/1", &[]),
            ScanTurn::Request { generation: 2 }
        );
        assert_eq!(
            scheduler.claim("/devices/1", &cafe),
            ScanTurn::Wait { generation: 2 }
        );
    }

    #[test]
    fn waiting_returns_immediately_once_the_in_flight_scan_is_released() {
        let scheduler = ScanScheduler::default();
        let deadline = Deadline::from_now(Duration::from_secs(5)).unwrap();
        assert_eq!(
            scheduler.claim("/devices/1", &[]),
            ScanTurn::Request { generation: 1 }
        );
        assert_eq!(
            scheduler.claim("/devices/1", &[]),
            ScanTurn::Join { generation: 1 }
        );
        let expired = Deadline::from_now(Duration::from_millis(1)).unwrap();
        assert!(
            scheduler
                .wait_for_completion("/devices/1", 1, expired)
                .is_none()
        );

        assert_eq!(
            scheduler.claim("/devices/1", &[]),
            ScanTurn::Join { generation: 1 }
        );
        scheduler.complete("/devices/1", 1, SharedScanOutcome::Succeeded);
        assert!(matches!(
            scheduler.wait_for_completion("/devices/1", 1, deadline),
            Some(SharedScanOutcome::Succeeded)
        ));
    }

    #[test]
    fn joining_caller_receives_the_owned_scan_failure() {
        let scheduler = ScanScheduler::default();
        assert_eq!(
            scheduler.claim("/devices/1", &[]),
            ScanTurn::Request { generation: 1 }
        );
        assert_eq!(
            scheduler.claim("/devices/1", &[]),
            ScanTurn::Join { generation: 1 }
        );
        scheduler.complete(
            "/devices/1",
            1,
            SharedScanOutcome::Failed(ErrorReport {
                code: ErrorCode::AuthorizationRequired,
                operation: ErrorOperation::Scan,
                source: ErrorSource::NetworkManager,
                message: "scan permission denied".to_string(),
                details: Default::default(),
            }),
        );

        let outcome = scheduler
            .wait_for_completion(
                "/devices/1",
                1,
                Deadline::from_now(Duration::from_secs(1)).unwrap(),
            )
            .expect("owned scan outcome");
        let SharedScanOutcome::Failed(report) = outcome else {
            panic!("joined scan unexpectedly succeeded");
        };
        assert_eq!(report.code, ErrorCode::AuthorizationRequired);
        assert_eq!(report.message, "scan permission denied");
    }

    #[test]
    fn rate_limit_waits_for_whichever_of_scan_or_request_was_more_recent() {
        let now = Instant::now();
        let interval_ms = SCAN_REQUEST_INTERVAL.as_millis() as i64;

        // Never scanned and never requested: scanning is allowed immediately.
        assert!(rate_limit_wait(-1, 50_000, None, now).is_zero());
        // Scanned long ago: allowed immediately.
        assert!(rate_limit_wait(1_000, 1_000 + interval_ms * 2, None, now).is_zero());
        // Scanned just now: wait out the remaining interval.
        let wait = rate_limit_wait(50_000, 50_000, None, now);
        assert_eq!(wait, SCAN_REQUEST_INTERVAL);
        // A recent request counts even when LastScan is stale.
        let wait = rate_limit_wait(
            1_000,
            1_000 + interval_ms * 2,
            Some(now - Duration::from_millis(1)),
            now,
        );
        assert!(wait > Duration::ZERO && wait <= SCAN_REQUEST_INTERVAL);
    }

    #[test]
    fn a_boottime_clock_that_ran_backwards_does_not_produce_a_negative_wait() {
        let now = Instant::now();
        assert!(rate_limit_wait(90_000, 10_000, None, now).is_zero());
    }

    #[test]
    fn networkmanager_rate_limit_rejections_are_recognized_as_transient() {
        assert!(is_transient_scan_rejection(&anyhow::anyhow!(
            "RequestScan: Scanning not allowed immediately following previous scan"
        )));
        assert!(is_transient_scan_rejection(&anyhow::anyhow!(
            "org.freedesktop.NetworkManager.Device.NotAllowed"
        )));
        assert!(!is_transient_scan_rejection(&anyhow::anyhow!(
            "org.freedesktop.NetworkManager.PermissionDenied"
        )));
    }

    #[test]
    fn boottime_is_readable_and_monotonic_on_this_platform() {
        let first = boottime_ms().expect("boottime");
        assert!(first > 0);
        assert!(boottime_ms().expect("boottime") >= first);
    }
}
