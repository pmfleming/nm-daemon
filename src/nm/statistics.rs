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
        // Acquisition writes RefreshRateMs under this same lock. Keep the
        // final disable ordered before a new watcher's nonzero refresh rate.
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
    use super::Nm;
    use crate::command::SystemCommandRunner;
    use crate::nl80211::UnavailableWirelessTelemetry;
    use crate::test_support::TestPeer;
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;

    struct Statistics {
        rates: Arc<Mutex<Vec<u32>>>,
        stop: Mutex<Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>>,
    }

    #[zbus::interface(name = "org.freedesktop.NetworkManager.Device.Statistics")]
    impl Statistics {
        #[zbus(property)]
        fn refresh_rate_ms(&self) -> u32 {
            0
        }
        #[zbus(property)]
        fn set_refresh_rate_ms(&self, rate: u32) {
            if rate == 0
                && let Some((stopped, resume)) = self.stop.lock().unwrap().take()
            {
                stopped.send(()).unwrap();
                resume.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            self.rates.lock().unwrap().push(rate);
        }
    }

    #[test]
    fn last_watcher_disable_is_serialized_with_new_acquisition() -> anyhow::Result<()> {
        let peer = TestPeer::new(":1.0", ":1.1");
        let rates = Arc::new(Mutex::new(Vec::new()));
        let (stopped, stopping) = mpsc::sync_channel(1);
        let (resume, resumed) = mpsc::sync_channel(1);
        peer.server.object_server().at(
            "/device",
            Statistics {
                rates: Arc::clone(&rates),
                stop: Mutex::new(Some((stopped, resumed))),
            },
        )?;
        let nm = Arc::new(Nm::with_connection_runner_destination_and_telemetry(
            peer.client.clone(),
            Arc::new(SystemCommandRunner),
            ":1.0",
            Arc::new(UnavailableWirelessTelemetry),
        )?);
        nm.acquire_statistics_refresh("/device", 1_000)?;
        nm.acquire_statistics_refresh("/device", 500)?;
        nm.release_statistics_refresh("/device");
        assert_eq!(*rates.lock().unwrap(), [1_000, 500]);
        let leaving = Arc::clone(&nm);
        let leaving = std::thread::spawn(move || leaving.release_statistics_refresh("/device"));
        stopping.recv_timeout(Duration::from_secs(5))?;
        // Deterministic race fence: the setter is blocked, so acquisition must
        // still be excluded. The former early unlock fails this assertion.
        let locked = nm.statistics.devices.try_lock().is_err();
        let joining = Arc::clone(&nm);
        let joining =
            std::thread::spawn(move || joining.acquire_statistics_refresh("/device", 200));
        resume.send(())?;
        leaving.join().unwrap();
        joining.join().unwrap()?;
        assert!(
            locked,
            "last-watcher disable must retain the ownership lock"
        );
        assert_eq!(*rates.lock().unwrap(), [1_000, 500, 0, 200]);
        assert_eq!(nm.statistics.devices.lock().unwrap()["/device"].watchers, 1);
        nm.release_statistics_refresh("/device");
        assert_eq!(*rates.lock().unwrap(), [1_000, 500, 0, 200, 0]);
        Ok(())
    }
}
