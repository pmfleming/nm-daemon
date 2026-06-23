use std::collections::BTreeMap;

use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use super::{AP_IFACE, DEVICE_IFACE, NM_DEVICE_TYPE_WIFI, NM_IFACE, NM_PATH, Nm, WIFI_IFACE};
use crate::model::{AccessPoint, WifiDevice, security_label};

impl Nm {
    pub(crate) fn wifi_devices(&self) -> Result<Vec<WifiDevice>> {
        let nm = self.proxy(NM_PATH, NM_IFACE)?;
        let devices: Vec<OwnedObjectPath> = nm.call("GetDevices", &()).context("GetDevices")?;
        devices
            .into_iter()
            .filter_map(|path| self.wifi_device(path).transpose())
            .collect()
    }

    fn wifi_device(&self, path: OwnedObjectPath) -> Result<Option<WifiDevice>> {
        let device = self.proxy_path(&path, DEVICE_IFACE)?;
        let device_type: u32 = device
            .get_property("DeviceType")
            .with_context(|| format!("read DeviceType for {path}"))?;
        if device_type != NM_DEVICE_TYPE_WIFI {
            return Ok(None);
        }
        let iface = device
            .get_property("Interface")
            .unwrap_or_else(|_| path.to_string());
        drop(device);
        Ok(Some(WifiDevice { path, iface }))
    }

    pub(crate) fn active_ssid(&self) -> Result<Option<String>> {
        for device in self.wifi_devices()? {
            let Some(active_path) = self.active_access_point(&device)? else {
                continue;
            };
            return self
                .access_point(&active_path, true)
                .map(|ap| Some(ap.ssid));
        }
        Ok(None)
    }

    pub(super) fn visible_access_point(
        &self,
        ssid: &str,
    ) -> Result<Option<(WifiDevice, OwnedObjectPath, AccessPoint)>> {
        for device in self.wifi_devices()? {
            for path in self.device_access_points(&device)? {
                let Ok(ap) = self.access_point(&path, false) else {
                    continue;
                };
                if ap.ssid == ssid {
                    return Ok(Some((device, path, ap)));
                }
            }
        }
        Ok(None)
    }

    pub(crate) fn list_access_points(&self) -> Result<Vec<AccessPoint>> {
        let mut by_ssid = BTreeMap::new();
        for device in self.wifi_devices()? {
            self.add_device_access_points(&device, &mut by_ssid)?;
        }
        Ok(sorted_access_points(by_ssid))
    }

    fn add_device_access_points(
        &self,
        device: &WifiDevice,
        by_ssid: &mut BTreeMap<String, AccessPoint>,
    ) -> Result<()> {
        let active_path = self.active_access_point(device)?;
        for path in self.device_access_points(device)? {
            let active = active_path.as_ref().is_some_and(|active| *active == path);
            if let Some(ap) = self.read_visible_access_point(&path, active) {
                merge_access_point(by_ssid, ap);
            }
        }
        Ok(())
    }

    fn active_access_point(&self, device: &WifiDevice) -> Result<Option<OwnedObjectPath>> {
        let wifi = self.proxy_path(&device.path, WIFI_IFACE)?;
        let active_path: OwnedObjectPath = wifi
            .get_property("ActiveAccessPoint")
            .with_context(|| format!("read ActiveAccessPoint for {}", device.iface))?;
        Ok((active_path.as_str() != "/").then_some(active_path))
    }

    pub(super) fn device_access_points(&self, device: &WifiDevice) -> Result<Vec<OwnedObjectPath>> {
        let wifi = self.proxy_path(&device.path, WIFI_IFACE)?;
        wifi.call("GetAccessPoints", &())
            .with_context(|| format!("GetAccessPoints for {}", device.iface))
    }

    fn read_visible_access_point(
        &self,
        path: &OwnedObjectPath,
        active: bool,
    ) -> Option<AccessPoint> {
        match self.access_point(path, active) {
            Ok(ap) if !ap.ssid.is_empty() => Some(ap),
            Ok(_) => None,
            Err(err) => {
                eprintln!("warning: skipping access point {path}: {err:#}");
                None
            }
        }
    }

    fn access_point(&self, path: &OwnedObjectPath, active: bool) -> Result<AccessPoint> {
        let ap = self.proxy_path(path, AP_IFACE)?;
        let ssid_bytes: Vec<u8> = ap
            .get_property("Ssid")
            .with_context(|| format!("read Ssid for {path}"))?;
        let flags = ap.get_property("Flags").unwrap_or(0);
        let wpa_flags = ap.get_property("WpaFlags").unwrap_or(0);
        let rsn_flags = ap.get_property("RsnFlags").unwrap_or(0);

        Ok(AccessPoint {
            ssid: String::from_utf8_lossy(&ssid_bytes).into_owned(),
            active,
            security: security_label(flags, wpa_flags, rsn_flags),
            strength: ap.get_property("Strength").unwrap_or(0),
            frequency: ap.get_property("Frequency").unwrap_or(0),
            bssid: ap.get_property("HwAddress").unwrap_or_default(),
            last_seen: ap.get_property("LastSeen").unwrap_or(-1),
            flags,
            wpa_flags,
            rsn_flags,
        })
    }
}

fn merge_access_point(by_ssid: &mut BTreeMap<String, AccessPoint>, ap: AccessPoint) {
    by_ssid
        .entry(ap.ssid.clone())
        .and_modify(|existing| {
            if ap.active || (!existing.active && ap.strength > existing.strength) {
                *existing = ap.clone();
            }
        })
        .or_insert(ap);
}

fn sorted_access_points(by_ssid: BTreeMap<String, AccessPoint>) -> Vec<AccessPoint> {
    let mut aps: Vec<_> = by_ssid.into_values().collect();
    aps.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then_with(|| b.strength.cmp(&a.strength))
            .then_with(|| a.ssid.to_lowercase().cmp(&b.ssid.to_lowercase()))
    });
    aps
}
