use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use zvariant::Value;

use super::scan_schedule::{
    ScanTurn, boottime_ms, is_transient_scan_rejection, rate_limit_wait, scan_deadline_expired,
    sleep_within_deadline,
};
use super::{Nm, WIFI_IFACE};
use crate::deadline::Deadline;
use crate::error::{DomainError, ErrorOperation};
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
        if self.scan_schedule.claim(&device_path) == ScanTurn::Join {
            // Another caller's scan for this device is already running; its
            // results are the ones this caller wants, so wait rather than
            // spending the shared rate-limit budget on a duplicate request.
            tracing::debug!(iface = %device.iface, "joining an in-flight scan for this device");
            if self
                .scan_schedule
                .wait_for_in_flight(&device_path, deadline)
            {
                return Ok(());
            }
            return Err(scan_deadline_expired(
                "timed out waiting for an in-flight scan on this device",
            ));
        }
        let lease = ScanLease {
            nm: self,
            device_path,
        };
        let result = self.run_owned_scan(device, deadline, ssids, cancellation);
        drop(lease);
        result
    }

    fn run_owned_scan(
        &self,
        device: &WifiDevice,
        deadline: Deadline,
        ssids: &[Vec<u8>],
        cancellation: Option<&AtomicBool>,
    ) -> Result<()> {
        let before = self.last_scan(device);
        tracing::debug!(iface = %device.iface, before, ssid_count = ssids.len(), "requesting blocking scan for device");
        self.request_scan_within_deadline(device, ssids, before, deadline, cancellation)?;
        self.wait_for_scan_completion(device, before, deadline, cancellation)
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
    ) -> Result<()> {
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
            match self.request_scan_for_ssids(device, ssids) {
                Ok(()) => {
                    self.scan_schedule.note_request(&device_path);
                    return Ok(());
                }
                Err(error) if !is_transient_scan_rejection(&error) => return Err(error),
                Err(error) if deadline.expired() => return Err(error),
                Err(error) => {
                    tracing::debug!(
                        iface = %device.iface,
                        error = %crate::error::err_chain(&error),
                        "NetworkManager rejected the scan request; retrying within the deadline"
                    );
                    wait = SCAN_RETRY_DELAY;
                }
            }
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
        before: i64,
        deadline: Deadline,
        cancellation: Option<&AtomicBool>,
    ) -> Result<()> {
        let mut event_generation = self.event_generation();
        while !deadline.expired() {
            check_scan_cancelled(cancellation)?;
            if self.last_scan_completed(device, before) {
                tracing::debug!(iface = %device.iface, after = self.last_scan(device), "device scan completed");
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

    fn last_scan_completed(&self, device: &WifiDevice, before: i64) -> bool {
        let after = self.last_scan(device);
        after != before && after >= 0
    }
}

/// Releases the device's scan claim even when the scan fails or unwinds.
struct ScanLease<'a> {
    nm: &'a Nm,
    device_path: String,
}

impl Drop for ScanLease<'_> {
    fn drop(&mut self) {
        self.nm.scan_schedule.release(&self.device_path);
    }
}

fn ensure_scan_deadline(deadline: Deadline, message: &str) -> Result<()> {
    if deadline.expired() {
        return Err(DomainError::timeout(ErrorOperation::Scan, message).into());
    }
    Ok(())
}

fn check_scan_cancelled(cancellation: Option<&AtomicBool>) -> Result<()> {
    if cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return Err(
            DomainError::cancelled_operation(ErrorOperation::Scan, "Wi-Fi scan cancelled").into(),
        );
    }
    Ok(())
}
