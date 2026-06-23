use std::collections::HashMap;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use zvariant::Value;

use super::{Nm, POLL_INTERVAL, WIFI_IFACE};
use crate::model::WifiDevice;

impl Nm {
    pub(crate) fn scan(&self, timeout: Duration) -> Result<()> {
        let devices = self.wifi_devices()?;
        if devices.is_empty() {
            bail!("no Wi-Fi devices found");
        }
        for device in devices {
            self.scan_device(&device, timeout)
                .with_context(|| format!("scan {}", device.iface))?;
        }
        Ok(())
    }

    fn scan_device(&self, device: &WifiDevice, timeout: Duration) -> Result<()> {
        let before = self.last_scan(device);
        self.request_scan(device)?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.last_scan_completed(device, before) {
                return Ok(());
            }
            sleep(POLL_INTERVAL);
        }
        bail!("timed out waiting for LastScan to change")
    }

    pub(crate) fn request_scan(&self, device: &WifiDevice) -> Result<()> {
        let wifi = self.proxy_path(&device.path, WIFI_IFACE)?;
        let options = HashMap::<&str, Value<'_>>::new();
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
