use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::{Context, Result};
use zvariant::Value;

use super::scan_schedule::{
    ScanTurn, ScanWait, SharedScanOutcome, boottime_ms, is_transient_scan_rejection,
    rate_limit_wait, scan_deadline_expired, sleep_within_deadline,
};
use super::{Nm, WIFI_IFACE};
use crate::deadline::Deadline;
use crate::error::{DomainError, ErrorCode, ErrorOperation, ErrorReport, check_cancellation};
use crate::generated::SCAN_RETRY_DELAY;
use crate::model::{InterfaceName, ScanRequestOptions, WifiDevice};

impl Nm {
    pub(crate) fn scan_with_options(
        &self,
        options: ScanRequestOptions,
        cancellation: Option<&AtomicBool>,
    ) -> Result<()> {
        tracing::info!(
            timeout_secs = options.timeout.as_secs(),
            ssid_count = options.ssid_bytes.len(),
            ifname = ?options.ifname,
            "starting blocking Wi-Fi scan"
        );
        let deadline = Deadline::from_now(options.timeout)?;
        let devices = self.wait_for_scan_devices(
            options.ifname.as_ref().map(InterfaceName::as_str),
            deadline,
            cancellation,
        )?;
        tracing::info!(
            device_count = devices.len(),
            "discovered matching Wi-Fi scan devices"
        );
        for device in devices {
            self.scan_device(&device, deadline, &options.ssid_bytes, cancellation)
                .with_context(|| format!("scan {}", device.iface))?;
        }
        tracing::info!("blocking Wi-Fi scan completed");
        Ok(())
    }

    fn wait_for_scan_devices(
        &self,
        ifname: Option<&str>,
        deadline: Deadline,
        cancellation: Option<&AtomicBool>,
    ) -> Result<Vec<WifiDevice>> {
        let mut event_generation = self.event_generation();
        loop {
            check_scan_cancelled(cancellation)?;
            let devices = self.scan_devices(ifname)?;
            if !devices.is_empty() {
                return Ok(devices);
            }
            ensure_scan_deadline(deadline, "timed out waiting for a matching Wi-Fi device")?;
            tracing::debug!(ifname, "waiting for NetworkManager Wi-Fi device");
            event_generation = self.wait_for_event(event_generation, deadline.wait(Duration::MAX));
        }
    }

    fn scan_devices(&self, ifname: Option<&str>) -> Result<Vec<WifiDevice>> {
        Ok(self
            .wifi_devices()?
            .into_iter()
            .filter(|device| ifname.is_none_or(|ifname| device.iface == ifname))
            .collect())
    }

    fn scan_device(
        &self,
        device: &WifiDevice,
        deadline: Deadline,
        ssids: &[Vec<u8>],
        cancellation: Option<&AtomicBool>,
    ) -> Result<()> {
        check_scan_cancelled(cancellation)?;
        ensure_scan_deadline(deadline, "timed out waiting for LastScan to change")?;
        let device_path = device.path.to_string();
        let generation = loop {
            match self.scan_schedule.claim(&device_path, ssids) {
                ScanTurn::Request { generation } => break generation,
                ScanTurn::Join { generation } => {
                    // The owner requested every SSID this caller needs.
                    tracing::debug!(iface = %device.iface, "joining a compatible in-flight scan");
                    match self.scan_schedule.wait_for_completion(
                        &device_path,
                        generation,
                        deadline,
                        cancellation,
                    ) {
                        ScanWait::Completed(SharedScanOutcome::Failed(report))
                            if shared_owner_failure_is_retryable(&report)
                                && !deadline.expired() =>
                        {
                            // Cancellation and timeout belong to the owner. This
                            // caller still has its own cancellation flag/deadline.
                            continue;
                        }
                        ScanWait::Completed(outcome) => return joined_scan_result(outcome),
                        ScanWait::Cancelled => return Err(scan_cancelled_error()),
                        ScanWait::DeadlineExpired => {
                            return Err(scan_deadline_expired(
                                "timed out waiting for an in-flight scan on this device",
                            ));
                        }
                    }
                }
                ScanTurn::Wait { generation } => {
                    // A wildcard scan cannot stand in for a hidden-SSID probe,
                    // and a probe for another SSID cannot satisfy this caller.
                    tracing::debug!(iface = %device.iface, "waiting behind an incompatible in-flight scan");
                    match self.scan_schedule.wait_for_completion(
                        &device_path,
                        generation,
                        deadline,
                        cancellation,
                    ) {
                        ScanWait::Completed(_) => {}
                        ScanWait::Cancelled => return Err(scan_cancelled_error()),
                        ScanWait::DeadlineExpired => {
                            return Err(scan_deadline_expired(
                                "timed out waiting to schedule a targeted scan",
                            ));
                        }
                    }
                }
            }
        };
        let lease = ScanLease::new(self, device_path, generation);
        let result = self.run_owned_scan(device, deadline, ssids, cancellation);
        lease.complete(shared_scan_outcome(&result));
        result
    }

    fn run_owned_scan(
        &self,
        device: &WifiDevice,
        deadline: Deadline,
        ssids: &[Vec<u8>],
        cancellation: Option<&AtomicBool>,
    ) -> Result<()> {
        let last_scan = self.last_scan(device);
        tracing::debug!(iface = %device.iface, last_scan, ssid_count = ssids.len(), "requesting blocking scan for device");
        let token =
            self.request_scan_within_deadline(device, ssids, last_scan, deadline, cancellation)?;
        self.wait_for_scan_completion(device, token, deadline, cancellation)
    }

    /// Waits out NetworkManager's request interval, then issues `RequestScan`,
    /// retrying transient rate-limit rejections until the deadline.
    fn request_scan_within_deadline(
        &self,
        device: &WifiDevice,
        ssids: &[Vec<u8>],
        last_scan: i64,
        deadline: Deadline,
        cancellation: Option<&AtomicBool>,
    ) -> Result<ScanCompletionToken> {
        let device_path = device.path.to_string();
        let mut wait = self.rate_limit_wait_for(device, last_scan);
        loop {
            check_scan_cancelled(cancellation)?;
            if !wait.is_zero() {
                tracing::debug!(
                    iface = %device.iface,
                    wait_ms = wait.as_millis(),
                    "delaying scan until NetworkManager's request interval allows it"
                );
                if !sleep_within_deadline(wait, deadline, cancellation, check_scan_cancelled)? {
                    return Err(scan_deadline_expired(
                        "timed out waiting for NetworkManager's scan request interval",
                    ));
                }
            }
            check_scan_cancelled(cancellation)?;
            if let Some(token) = self.try_scan_request(device, ssids, &device_path, deadline)? {
                return Ok(token);
            }
            wait = SCAN_RETRY_DELAY;
        }
    }

    fn try_scan_request(
        &self,
        device: &WifiDevice,
        ssids: &[Vec<u8>],
        device_path: &str,
        deadline: Deadline,
    ) -> Result<Option<ScanCompletionToken>> {
        let last_scan_before_request = self.last_scan(device);
        let requested_at_boottime_ms = boottime_ms();
        match self.request_scan_for_ssids(device, ssids) {
            Ok(()) => {
                self.scan_schedule.note_request(device_path);
                tracing::debug!(
                    iface = %device.iface,
                    last_scan_before_request,
                    ?requested_at_boottime_ms,
                    "NetworkManager accepted scan request"
                );
                Ok(Some(ScanCompletionToken {
                    last_scan_before_request,
                    requested_at_boottime_ms,
                }))
            }
            Err(error) if is_transient_scan_rejection(&error) && !deadline.expired() => {
                tracing::debug!(
                    iface = %device.iface,
                    error = %crate::error::err_chain(&error),
                    "NetworkManager rejected the scan request; retrying within the deadline"
                );
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn rate_limit_wait_for(&self, device: &WifiDevice, last_scan: i64) -> Duration {
        let Some(boottime) = boottime_ms() else {
            return Duration::ZERO;
        };
        rate_limit_wait(
            last_scan,
            boottime,
            self.scan_schedule
                .last_request_before_claim(device.path.as_str()),
            std::time::Instant::now(),
        )
    }

    fn wait_for_scan_completion(
        &self,
        device: &WifiDevice,
        token: ScanCompletionToken,
        deadline: Deadline,
        cancellation: Option<&AtomicBool>,
    ) -> Result<()> {
        let mut event_generation = self.event_generation();
        while !deadline.expired() {
            check_scan_cancelled(cancellation)?;
            let after = self.last_scan(device);
            if scan_completed(after, token) {
                tracing::debug!(
                    iface = %device.iface,
                    after,
                    before = token.last_scan_before_request,
                    requested_at_boottime_ms = ?token.requested_at_boottime_ms,
                    "device scan completed"
                );
                return Ok(());
            }
            event_generation = self.wait_for_event(event_generation, deadline.wait(Duration::MAX));
        }
        Err(DomainError::timeout(
            ErrorOperation::Scan,
            "timed out waiting for LastScan to change",
        )
        .into())
    }

    pub(super) fn request_hidden_scan(&self, device: &WifiDevice, ssid_bytes: &[u8]) -> Result<()> {
        self.request_scan_for_ssids(device, &[ssid_bytes.to_vec()])
            .with_context(|| format!("RequestScan hidden SSID on {}", device.iface))
    }

    pub(crate) fn request_scan_for_ssids(
        &self,
        device: &WifiDevice,
        ssids: &[Vec<u8>],
    ) -> Result<()> {
        tracing::info!(iface = %device.iface, path = %device.path, ssid_count = ssids.len(), "requesting NetworkManager scan");
        let wifi = self.proxy_path(&device.path, WIFI_IFACE)?;
        let options = if ssids.is_empty() {
            HashMap::<&str, Value<'_>>::new()
        } else {
            HashMap::from([("ssids", Value::new(ssids.to_vec()))])
        };
        wifi.call::<_, _, ()>("RequestScan", &(options,))
            .context("RequestScan")
    }

    pub(crate) fn last_scan(&self, device: &WifiDevice) -> i64 {
        self.proxy_path(&device.path, WIFI_IFACE)
            .and_then(|wifi| wifi.get_property("LastScan").context("read LastScan"))
            .unwrap_or(-1)
    }
}

#[derive(Debug, Clone, Copy)]
struct ScanCompletionToken {
    last_scan_before_request: i64,
    requested_at_boottime_ms: Option<i64>,
}

fn scan_completed(after: i64, token: ScanCompletionToken) -> bool {
    after >= 0
        && after != token.last_scan_before_request
        && token
            .requested_at_boottime_ms
            .is_none_or(|requested_at| after >= requested_at)
}

/// Publishes the device scan's outcome even when the owner unwinds.
struct ScanLease<'a> {
    nm: &'a Nm,
    device_path: String,
    generation: u64,
    outcome: Option<SharedScanOutcome>,
}

impl<'a> ScanLease<'a> {
    fn new(nm: &'a Nm, device_path: String, generation: u64) -> Self {
        Self {
            nm,
            device_path,
            generation,
            outcome: None,
        }
    }

    fn complete(mut self, outcome: SharedScanOutcome) {
        self.outcome = Some(outcome);
    }
}

impl Drop for ScanLease<'_> {
    fn drop(&mut self) {
        let outcome = self.outcome.take().unwrap_or_else(|| {
            SharedScanOutcome::Failed(ErrorReport::from_error(
                &anyhow::anyhow!("owned Wi-Fi scan stopped before publishing an outcome"),
                ErrorOperation::Scan,
            ))
        });
        self.nm
            .scan_schedule
            .complete(&self.device_path, self.generation, outcome);
    }
}

fn shared_scan_outcome(result: &Result<()>) -> SharedScanOutcome {
    match result {
        Ok(()) => SharedScanOutcome::Succeeded,
        Err(error) => {
            SharedScanOutcome::Failed(ErrorReport::from_error(error, ErrorOperation::Scan))
        }
    }
}

fn shared_owner_failure_is_retryable(report: &ErrorReport) -> bool {
    matches!(report.code, ErrorCode::Cancelled | ErrorCode::Timeout)
}

fn joined_scan_result(outcome: SharedScanOutcome) -> Result<()> {
    match outcome {
        SharedScanOutcome::Succeeded => Ok(()),
        SharedScanOutcome::Failed(report) => {
            let mut error =
                DomainError::new(report.code, report.operation, report.source, report.message);
            for (key, value) in report.details {
                error = error.with_detail(key, value);
            }
            Err(error.into())
        }
    }
}

fn ensure_scan_deadline(deadline: Deadline, message: &str) -> Result<()> {
    if deadline.expired() {
        return Err(DomainError::timeout(ErrorOperation::Scan, message).into());
    }
    Ok(())
}

fn check_scan_cancelled(cancellation: Option<&AtomicBool>) -> Result<()> {
    check_cancellation(cancellation, ErrorOperation::Scan, "Wi-Fi scan cancelled")
}

fn scan_cancelled_error() -> anyhow::Error {
    DomainError::cancelled_operation(ErrorOperation::Scan, "Wi-Fi scan cancelled").into()
}

#[cfg(test)]
mod tests {
    use super::{ScanCompletionToken, scan_completed, shared_owner_failure_is_retryable};
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport, ErrorSource};

    #[test]
    fn scan_completion_must_be_newer_than_the_request_watermark() {
        let token = ScanCompletionToken {
            last_scan_before_request: 100,
            requested_at_boottime_ms: Some(200),
        };
        assert!(!scan_completed(150, token));
        assert!(scan_completed(200, token));
        assert!(scan_completed(201, token));
    }

    #[test]
    fn scan_completion_falls_back_to_an_immediate_baseline_without_boottime() {
        let token = ScanCompletionToken {
            last_scan_before_request: 100,
            requested_at_boottime_ms: None,
        };
        assert!(!scan_completed(100, token));
        assert!(scan_completed(101, token));
    }

    #[test]
    fn a_joiner_retries_only_owner_scoped_failures() {
        let report = |code| ErrorReport {
            code,
            operation: ErrorOperation::Scan,
            source: ErrorSource::NetworkManager,
            message: "scan outcome".to_string(),
            details: Default::default(),
        };
        assert!(shared_owner_failure_is_retryable(&report(
            ErrorCode::Cancelled
        )));
        assert!(shared_owner_failure_is_retryable(&report(
            ErrorCode::Timeout
        )));
        assert!(!shared_owner_failure_is_retryable(&report(
            ErrorCode::AuthorizationRequired
        )));
    }
}
