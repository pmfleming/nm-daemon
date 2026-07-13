use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use zvariant::Value;

use super::{Nm, WIFI_IFACE};
use crate::deadline::Deadline;
use crate::error::{DomainError, ErrorOperation};
use crate::model::{ScanRequestOptions, WifiDevice};

impl Nm {
    pub(crate) fn scan(&self, timeout: Duration) -> Result<()> {
        self.scan_with_options(ScanRequestOptions {
            timeout,
            ifname: None,
            ssid_bytes: Vec::new(),
        })
    }

    pub(crate) fn scan_with_options(&self, options: ScanRequestOptions) -> Result<()> {
        self.scan_with_options_cancellable(options, None)
    }

    pub(crate) fn scan_with_options_cancellable(
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
        let deadline = Deadline::from_now(options.timeout);
        let devices =
            self.wait_for_scan_devices(options.ifname.as_deref(), deadline, cancellation)?;
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
            if deadline.expired() {
                return Err(DomainError::timeout(
                    ErrorOperation::Scan,
                    "timed out waiting for a matching Wi-Fi device",
                )
                .into());
            }
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
        if deadline.expired() {
            return Err(DomainError::timeout(
                ErrorOperation::Scan,
                "timed out waiting for LastScan to change",
            )
            .into());
        }
        let before = self.last_scan(device);
        let mut event_generation = self.event_generation();
        tracing::debug!(iface = %device.iface, before, ssid_count = ssids.len(), "requesting blocking scan for device");
        self.request_scan_for_ssids(device, ssids)?;
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

fn check_scan_cancelled(cancellation: Option<&AtomicBool>) -> Result<()> {
    if cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return Err(DomainError::new(
            crate::error::ErrorCode::Cancelled,
            ErrorOperation::Scan,
            crate::error::ErrorSource::Cancellation,
            "Wi-Fi scan cancelled",
        )
        .into());
    }
    Ok(())
}
