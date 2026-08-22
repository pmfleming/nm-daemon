use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use super::{DEVICE_IFACE, Nm, recover_lock};
use crate::error::{DomainError, ErrorOperation};
use crate::model::DeviceStatisticsSample;

pub(super) const STATISTICS_IFACE: &str = "org.freedesktop.NetworkManager.Device.Statistics";

/// One resolved device that statistics can be read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatisticsDevice {
    pub(crate) path: String,
    pub(crate) interface: String,
}

/// Reference-counted `RefreshRateMs` ownership, so several watchers can share
/// one device without one leaving turning refresh off for the others.
#[derive(Debug, Default)]
pub(super) struct StatisticsRefresh {
    devices: Mutex<HashMap<String, DeviceRefresh>>,
}

#[derive(Debug)]
struct DeviceRefresh {
    watchers: usize,
    rate_ms: u32,
}

impl Nm {
    pub(crate) fn statistics_device(&self, requested: Option<&str>) -> Result<StatisticsDevice> {
        let devices = self.statistics_devices()?;
        let Some(requested) = requested else {
            return devices
                .into_iter()
                .next()
                .ok_or_else(|| no_statistics_device(None));
        };
        devices
            .into_iter()
            .find(|device| device.path == requested || device.interface == requested)
            .ok_or_else(|| no_statistics_device(Some(requested)))
    }

    fn statistics_devices(&self) -> Result<Vec<StatisticsDevice>> {
        let paths: Vec<OwnedObjectPath> = self
            .root_proxy()
            .call("GetDevices", &())
            .context("GetDevices for statistics watch")?;
        Ok(paths
            .iter()
            .filter_map(|path| {
                let device = self.proxy_path(path, DEVICE_IFACE).ok()?;
                Some(StatisticsDevice {
                    path: path.to_string(),
                    interface: device.get_property("Interface").ok()?,
                })
            })
            .collect())
    }

    /// Turns NetworkManager's statistics refresh on for this watcher, raising
    /// the shared rate when this watcher wants faster samples than the others.
    pub(crate) fn acquire_statistics_refresh(&self, device_path: &str, rate_ms: u32) -> Result<()> {
        let mut devices = recover_lock(&self.statistics.devices);
        let effective = devices
            .get(device_path)
            .map(|refresh| refresh.rate_ms.min(rate_ms))
            .unwrap_or(rate_ms);
        self.set_refresh_rate(device_path, effective)?;
        let entry = devices
            .entry(device_path.to_string())
            .or_insert(DeviceRefresh {
                watchers: 0,
                rate_ms: effective,
            });
        entry.watchers += 1;
        entry.rate_ms = effective;
        Ok(())
    }

    /// Disables statistics refresh once the last watcher for a device leaves.
    pub(crate) fn release_statistics_refresh(&self, device_path: &str) {
        let mut devices = recover_lock(&self.statistics.devices);
        let Some(entry) = devices.get_mut(device_path) else {
            return;
        };
        entry.watchers = entry.watchers.saturating_sub(1);
        if entry.watchers > 0 {
            return;
        }
        devices.remove(device_path);
        drop(devices);
        if let Err(error) = self.set_refresh_rate(device_path, 0) {
            tracing::warn!(
                device = device_path,
                error = %crate::error::err_chain(&error),
                "could not disable NetworkManager statistics refresh after the last watcher left"
            );
        }
    }

    pub(crate) fn device_statistics(&self, device_path: &str) -> Result<DeviceStatisticsSample> {
        let statistics = self.proxy(device_path, STATISTICS_IFACE)?;
        Ok(DeviceStatisticsSample {
            rx_bytes: statistics.get_property("RxBytes").unwrap_or(0),
            tx_bytes: statistics.get_property("TxBytes").unwrap_or(0),
            rx_bytes_per_second: None,
            tx_bytes_per_second: None,
            interval_ms: 0,
            sampled_at_ms: crate::cache::now_ms(),
        })
    }

    fn set_refresh_rate(&self, device_path: &str, rate_ms: u32) -> Result<()> {
        self.proxy(device_path, STATISTICS_IFACE)?
            .set_property("RefreshRateMs", rate_ms)
            .with_context(|| format!("set RefreshRateMs for {device_path}"))
    }
}

/// Derives per-second rates from two samples, tolerating counter resets.
pub(crate) fn statistics_rates(
    previous: &DeviceStatisticsSample,
    current: &mut DeviceStatisticsSample,
) {
    let elapsed_ms = current.sampled_at_ms.saturating_sub(previous.sampled_at_ms);
    current.interval_ms = elapsed_ms;
    if elapsed_ms == 0 {
        return;
    }
    let per_second = |current: u64, previous: u64| {
        let delta = current.checked_sub(previous)?;
        Some((delta as f64) * 1000.0 / (elapsed_ms as f64))
    };
    current.rx_bytes_per_second = per_second(current.rx_bytes, previous.rx_bytes);
    current.tx_bytes_per_second = per_second(current.tx_bytes, previous.tx_bytes);
}

fn no_statistics_device(requested: Option<&str>) -> anyhow::Error {
    let mut error = DomainError::not_found(
        ErrorOperation::Statistics,
        match requested {
            Some(_) => "no NetworkManager device matched the requested statistics device",
            None => "NetworkManager reported no devices to watch",
        },
    );
    if let Some(requested) = requested {
        error = error.with_detail("device", requested);
    }
    error.into()
}

#[cfg(test)]
mod tests {
    use super::statistics_rates;
    use crate::model::DeviceStatisticsSample;

    fn sample(rx: u64, tx: u64, at_ms: u128) -> DeviceStatisticsSample {
        DeviceStatisticsSample {
            rx_bytes: rx,
            tx_bytes: tx,
            rx_bytes_per_second: None,
            tx_bytes_per_second: None,
            interval_ms: 0,
            sampled_at_ms: at_ms,
        }
    }

    #[test]
    fn rates_are_derived_from_the_byte_delta_over_elapsed_time() {
        let previous = sample(1_000, 500, 1_000);
        let mut current = sample(3_000, 1_500, 3_000);
        statistics_rates(&previous, &mut current);
        assert_eq!(current.interval_ms, 2_000);
        assert_eq!(current.rx_bytes_per_second, Some(1_000.0));
        assert_eq!(current.tx_bytes_per_second, Some(500.0));
    }

    #[test]
    fn counter_resets_report_no_rate_instead_of_a_negative_one() {
        let previous = sample(9_000, 9_000, 1_000);
        let mut current = sample(10, 20, 2_000);
        statistics_rates(&previous, &mut current);
        assert_eq!(current.rx_bytes_per_second, None);
        assert_eq!(current.tx_bytes_per_second, None);
    }

    #[test]
    fn identical_timestamps_do_not_divide_by_zero() {
        let previous = sample(0, 0, 5_000);
        let mut current = sample(100, 100, 5_000);
        statistics_rates(&previous, &mut current);
        assert_eq!(current.interval_ms, 0);
        assert_eq!(current.rx_bytes_per_second, None);
    }
}
