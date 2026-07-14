use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use super::{AP_IFACE, DEVICE_IFACE, NM_DEVICE_TYPE_WIFI, NM_IFACE, NM_PATH, Nm, WIFI_IFACE};
use crate::model::{
    AccessPoint, WifiConnectTarget, WifiDevice, display_ssid, frequency_band, frequency_channel,
    security_flags_label, security_label, ssid_hex, wifi_mode_label,
};

impl Nm {
    pub(crate) fn wifi_devices(&self) -> Result<Vec<WifiDevice>> {
        let nm = self.proxy(NM_PATH, NM_IFACE)?;
        let devices: Vec<OwnedObjectPath> = nm.call("GetDevices", &()).context("GetDevices")?;
        let wifi_devices: Vec<_> = devices
            .into_iter()
            .filter_map(|path| self.wifi_device(path).transpose())
            .collect::<Result<_>>()?;
        tracing::debug!(count = wifi_devices.len(), "discovered Wi-Fi devices");
        Ok(wifi_devices)
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
        tracing::debug!(path = %path, iface = %iface, "found Wi-Fi device");
        Ok(Some(WifiDevice { path, iface }))
    }

    pub(crate) fn active_target_matches(&self, target: &WifiConnectTarget) -> Result<bool> {
        for device in self.wifi_devices_for_target(target)? {
            if self.active_target_matches_on_device(&device, target)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn active_target_matches_on_device(
        &self,
        device: &WifiDevice,
        target: &WifiConnectTarget,
    ) -> Result<bool> {
        let Some(active_path) = self.active_access_point(device)? else {
            return Ok(false);
        };
        let ap = self.access_point(device, &active_path, true)?;
        Ok(access_point_matches(
            &ap,
            target.ssid_bytes(),
            target.ap_path.as_deref(),
            target.bssid.as_deref(),
        ))
    }

    pub(crate) fn active_ssid_matches(&self, target: &WifiConnectTarget) -> Result<bool> {
        for device in self.wifi_devices_for_target(target)? {
            if self.active_ssid_matches_on_device(&device, target)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn active_ssid_matches_on_device(
        &self,
        device: &WifiDevice,
        target: &WifiConnectTarget,
    ) -> Result<bool> {
        let Some(active_path) = self.active_access_point(device)? else {
            return Ok(false);
        };
        let ap = self.access_point(device, &active_path, true)?;
        let matches = ap.ssid_bytes == target.ssid_bytes();
        if matches {
            tracing::debug!(
                ssid = %target.ssid,
                iface = %device.iface,
                active_bssid = %ap.bssid,
                requested_bssid = ?target.bssid,
                active_ap_path = %ap.path,
                requested_ap_path = ?target.ap_path,
                "target SSID is active; BSSID and AP path were activation hints"
            );
        }
        Ok(matches)
    }

    pub(crate) fn target_access_point_visible(&self, target: &WifiConnectTarget) -> Result<bool> {
        Ok(self.visible_access_point_for(target)?.is_some())
    }

    pub(super) fn visible_access_point_for(
        &self,
        target: &WifiConnectTarget,
    ) -> Result<Option<(WifiDevice, OwnedObjectPath, AccessPoint)>> {
        let target_ssid = target.ssid_bytes();
        let devices = self.wifi_devices_for_target(target)?;
        if let Some(match_) =
            self.visible_access_point_matching(&devices, target, target_ssid.as_ref(), false)?
        {
            return Ok(Some(match_));
        }
        if target
            .ap_path
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            && let Some(match_) =
                self.visible_access_point_matching(&devices, target, target_ssid.as_ref(), true)?
        {
            tracing::info!(
                ssid = %target.ssid,
                requested_ap_path = ?target.ap_path,
                bssid = ?target.bssid,
                "matched visible access point after ignoring stale AP object path"
            );
            return Ok(Some(match_));
        }
        tracing::debug!(ssid = %target.ssid, "no matching visible access point found");
        Ok(None)
    }

    fn visible_access_point_matching(
        &self,
        devices: &[WifiDevice],
        target: &WifiConnectTarget,
        target_ssid: &[u8],
        ignore_ap_path: bool,
    ) -> Result<Option<(WifiDevice, OwnedObjectPath, AccessPoint)>> {
        for device in devices {
            for path in self.device_access_points(device)? {
                let Ok(ap) = self.access_point(device, &path, false) else {
                    continue;
                };
                if access_point_matches(
                    &ap,
                    target_ssid,
                    (!ignore_ap_path)
                        .then_some(target.ap_path.as_deref())
                        .flatten(),
                    target.bssid.as_deref(),
                ) {
                    tracing::debug!(
                        ssid = %target.ssid,
                        iface = %device.iface,
                        ap_path = %path,
                        bssid = %ap.bssid,
                        ignore_ap_path,
                        "matched visible access point"
                    );
                    return Ok(Some((device.clone(), path, ap)));
                }
            }
        }
        Ok(None)
    }

    pub(super) fn wifi_devices_for_target(
        &self,
        target: &WifiConnectTarget,
    ) -> Result<Vec<WifiDevice>> {
        Ok(self
            .wifi_devices()?
            .into_iter()
            .filter(|device| target_matches_device(target, device))
            .collect())
    }

    pub(crate) fn list_access_points(&self) -> Result<Vec<AccessPoint>> {
        let mut by_ssid = BTreeMap::new();
        for device in self.wifi_devices()? {
            self.add_device_access_points(&device, &mut by_ssid)?;
        }
        let aps = sorted_access_points(by_ssid);
        tracing::debug!(
            count = aps.len(),
            "listed visible Wi-Fi networks after SSID deduplication"
        );
        Ok(aps)
    }

    pub(crate) fn list_all_access_points(&self) -> Result<Vec<AccessPoint>> {
        let mut aps = Vec::new();
        for device in self.wifi_devices()? {
            let active_path = self.active_access_point(&device)?;
            for path in self.device_access_points(&device)? {
                let active = active_path.as_ref().is_some_and(|active| *active == path);
                if let Some(ap) = self.read_visible_access_point(&device, &path, active) {
                    aps.push(ap);
                }
            }
        }
        sort_access_points_nmcli_like(&mut aps);
        tracing::debug!(
            count = aps.len(),
            "listed exact visible Wi-Fi access points"
        );
        Ok(aps)
    }

    fn add_device_access_points(
        &self,
        device: &WifiDevice,
        by_ssid: &mut BTreeMap<Vec<u8>, AccessPoint>,
    ) -> Result<()> {
        let active_path = self.active_access_point(device)?;
        for path in self.device_access_points(device)? {
            let active = active_path.as_ref().is_some_and(|active| *active == path);
            if let Some(ap) = self.read_visible_access_point(device, &path, active) {
                merge_access_point(by_ssid, ap);
            }
        }
        Ok(())
    }

    pub(super) fn active_access_point(
        &self,
        device: &WifiDevice,
    ) -> Result<Option<OwnedObjectPath>> {
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
        device: &WifiDevice,
        path: &OwnedObjectPath,
        active: bool,
    ) -> Option<AccessPoint> {
        match self.access_point(device, path, active) {
            Ok(ap) if !ap.ssid.is_empty() => Some(ap),
            Ok(_) => None,
            Err(err) => {
                eprintln!("warning: skipping access point {path}: {err:#}");
                None
            }
        }
    }

    pub(super) fn access_point(
        &self,
        device: &WifiDevice,
        path: &OwnedObjectPath,
        active: bool,
    ) -> Result<AccessPoint> {
        let ap = self.proxy_path(path, AP_IFACE)?;
        let ssid_bytes: Vec<u8> = ap
            .get_property("Ssid")
            .with_context(|| format!("read Ssid for {path}"))?;
        let flags = ap.get_property("Flags").unwrap_or(0);
        let wpa_flags = ap.get_property("WpaFlags").unwrap_or(0);
        let rsn_flags = ap.get_property("RsnFlags").unwrap_or(0);

        let frequency = ap.get_property("Frequency").unwrap_or(0);
        let mode = ap.get_property("Mode").unwrap_or(0);
        let last_seen = ap.get_property("LastSeen").unwrap_or(-1);
        Ok(AccessPoint {
            ssid: display_ssid(&ssid_bytes),
            ssid_hex: ssid_hex(&ssid_bytes),
            ssid_bytes,
            active,
            security: security_label(flags, wpa_flags, rsn_flags),
            strength: ap.get_property("Strength").unwrap_or(0),
            frequency,
            channel: frequency_channel(frequency),
            band: frequency_band(frequency).to_string(),
            mode: wifi_mode_label(mode).to_string(),
            max_bitrate_mbps: ap.get_property::<u32>("MaxBitrate").unwrap_or(0) / 1000,
            bandwidth_mhz: ap.get_property("Bandwidth").unwrap_or(0),
            wpa_flags_label: security_flags_label(wpa_flags),
            rsn_flags_label: security_flags_label(rsn_flags),
            bssid: ap.get_property("HwAddress").unwrap_or_default(),
            last_seen,
            last_seen_age_ms: access_point_last_seen_age_ms(last_seen),
            path: path.to_string(),
            device_path: device.path.to_string(),
            device_iface: device.iface.clone(),
            flags,
            wpa_flags,
            rsn_flags,
        })
    }
}

fn target_matches_device(target: &WifiConnectTarget, device: &WifiDevice) -> bool {
    target
        .device_path
        .as_deref()
        .filter(|value| !value.is_empty())
        .is_none_or(|path| device.path.as_str() == path)
        && target
            .ifname
            .as_deref()
            .filter(|value| !value.is_empty())
            .is_none_or(|ifname| device.iface == ifname)
}

fn access_point_matches(
    ap: &AccessPoint,
    ssid_bytes: &[u8],
    ap_path: Option<&str>,
    bssid: Option<&str>,
) -> bool {
    if ap.ssid_bytes().as_ref() != ssid_bytes {
        return false;
    }
    let ap_path = ap_path.filter(|value| !value.is_empty());
    let bssid = bssid.filter(|value| !value.is_empty());
    match (ap_path, bssid) {
        (Some(ap_path), Some(bssid)) => ap.path == ap_path && ap.bssid.eq_ignore_ascii_case(bssid),
        (Some(ap_path), None) => ap.path == ap_path,
        (None, Some(bssid)) => ap.bssid.eq_ignore_ascii_case(bssid),
        (None, None) => true,
    }
}

fn merge_access_point(by_ssid: &mut BTreeMap<Vec<u8>, AccessPoint>, ap: AccessPoint) {
    by_ssid
        .entry(ap.ssid_bytes().into_owned())
        .and_modify(|existing| {
            if ap.active || (!existing.active && ap.strength > existing.strength) {
                *existing = ap.clone();
            }
        })
        .or_insert(ap);
}

fn sorted_access_points(by_ssid: BTreeMap<Vec<u8>, AccessPoint>) -> Vec<AccessPoint> {
    let mut aps: Vec<_> = by_ssid.into_values().collect();
    aps.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then_with(|| b.strength.cmp(&a.strength))
            .then_with(|| a.ssid.to_lowercase().cmp(&b.ssid.to_lowercase()))
    });
    aps
}

fn sort_access_points_nmcli_like(aps: &mut [AccessPoint]) {
    aps.sort_by(|a, b| {
        crate::model::ap_uses_wep(a.flags, a.wpa_flags, a.rsn_flags)
            .cmp(&crate::model::ap_uses_wep(
                b.flags,
                b.wpa_flags,
                b.rsn_flags,
            ))
            .then_with(|| b.strength.cmp(&a.strength))
            .then_with(|| a.frequency.cmp(&b.frequency))
            .then_with(|| b.max_bitrate_mbps.cmp(&a.max_bitrate_mbps))
            .then_with(|| a.path.cmp(&b.path))
    });
}

fn access_point_last_seen_age_ms(last_seen_seconds: i32) -> Option<u64> {
    if last_seen_seconds < 0 {
        return None;
    }
    let uptime_seconds = system_uptime_seconds()?;
    let age_seconds = (uptime_seconds - f64::from(last_seen_seconds)).max(0.0);
    Some((age_seconds * 1000.0).round() as u64)
}

fn system_uptime_seconds() -> Option<f64> {
    let uptime = fs::read_to_string("/proc/uptime").ok()?;
    uptime.split_whitespace().next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::access_point_matches;
    use crate::model::AccessPoint;

    #[test]
    fn access_point_match_requires_path_and_bssid_when_both_are_supplied() {
        let ap = test_ap();

        assert!(access_point_matches(
            &ap,
            b"Example",
            Some("/ap/1"),
            Some("00:11:22:33:44:55")
        ));
        assert!(!access_point_matches(
            &ap,
            b"Example",
            Some("/ap/other"),
            Some("00:11:22:33:44:55")
        ));
        assert!(!access_point_matches(
            &ap,
            b"Example",
            Some("/ap/1"),
            Some("00:11:22:33:44:66")
        ));
    }

    fn test_ap() -> AccessPoint {
        AccessPoint {
            ssid: "Example".to_string(),
            ssid_bytes: b"Example".to_vec(),
            active: false,
            security: crate::model::Security::Wpa2Or3,
            strength: 80,
            frequency: 2412,
            channel: 1,
            band: "2.4 GHz".to_string(),
            mode: "Infra".to_string(),
            max_bitrate_mbps: 0,
            bandwidth_mhz: 0,
            ssid_hex: "4578616d706c65".to_string(),
            wpa_flags_label: "(none)".to_string(),
            rsn_flags_label: "(none)".to_string(),
            bssid: "00:11:22:33:44:55".to_string(),
            last_seen: 0,
            last_seen_age_ms: None,
            path: "/ap/1".to_string(),
            device_path: "/device/1".to_string(),
            device_iface: "wlan0".to_string(),
            flags: 0,
            wpa_flags: 0,
            rsn_flags: 0,
        }
    }
}
