use std::collections::{BTreeMap, HashMap};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use zbus::blocking::{Connection, Proxy};
use zvariant::{DynamicType, OwnedObjectPath, OwnedValue, Value};

use crate::model::{
    AccessPoint, NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE, WifiDevice, ap_is_passwordless,
    ap_supports_psk, security_label,
};

pub(crate) const NM_DEST: &str = "org.freedesktop.NetworkManager";
pub(crate) const WIFI_IFACE: &str = "org.freedesktop.NetworkManager.Device.Wireless";
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(250);

const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_IFACE: &str = "org.freedesktop.NetworkManager";
const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const SETTINGS_IFACE: &str = "org.freedesktop.NetworkManager.Settings";
const SETTINGS_CONNECTION_IFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const DEVICE_IFACE: &str = "org.freedesktop.NetworkManager.Device";
const ACTIVE_CONNECTION_IFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const AP_IFACE: &str = "org.freedesktop.NetworkManager.AccessPoint";
const NM_DEVICE_TYPE_WIFI: u32 = 2;
const NM_DEVICE_STATE_DISCONNECTED: u32 = 30;
const NM_DEVICE_STATE_ACTIVATED: u32 = 100;
const NM_DEVICE_STATE_DEACTIVATING: u32 = 110;
const NM_ACTIVE_CONNECTION_STATE_ACTIVATED: u32 = 2;

type ConnectionSettings = HashMap<String, HashMap<String, OwnedValue>>;

#[derive(Debug, Clone)]
pub(crate) struct WifiActivationStatus {
    pub(crate) iface: String,
    pub(crate) device_state: u32,
    pub(crate) device_state_reason: (u32, u32),
    pub(crate) active_connection_state: Option<u32>,
}

impl WifiActivationStatus {
    pub(crate) fn activated(&self) -> bool {
        self.device_state == NM_DEVICE_STATE_ACTIVATED
            && self.active_connection_state == Some(NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
    }

    pub(crate) fn terminal_failure_after_progress(&self) -> bool {
        self.device_state <= NM_DEVICE_STATE_DISCONNECTED
            || self.device_state >= NM_DEVICE_STATE_DEACTIVATING
    }
}

pub(crate) struct Nm {
    conn: Connection,
}

impl Nm {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            conn: Connection::system().context("connect to system D-Bus")?,
        })
    }

    pub(crate) fn connection(&self) -> Connection {
        self.conn.clone()
    }

    fn proxy<'a>(&'a self, path: &'a str, iface: &'a str) -> Result<Proxy<'a>> {
        Proxy::new(&self.conn, NM_DEST, path, iface).context("create D-Bus proxy")
    }

    fn proxy_path<'a>(&'a self, path: &'a OwnedObjectPath, iface: &'a str) -> Result<Proxy<'a>> {
        self.proxy(path.as_str(), iface)
    }

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

    pub(crate) fn activate_saved_wifi_connection(&self, ssid: &str) -> Result<bool> {
        let Some((connection_path, device_path, specific_object)) =
            self.saved_wifi_activation_target(ssid)?
        else {
            return Ok(false);
        };
        let nm = self.proxy(NM_PATH, NM_IFACE)?;
        let _active_connection: OwnedObjectPath = nm
            .call(
                "ActivateConnection",
                &(connection_path, device_path, specific_object),
            )
            .with_context(|| format!("ActivateConnection for saved Wi-Fi profile {ssid}"))?;
        Ok(true)
    }

    pub(crate) fn add_and_activate_wifi_connection(
        &self,
        ssid: &str,
        password: Option<&str>,
    ) -> Result<bool> {
        let Some((device, ap_path, ap)) = self.visible_access_point(ssid)? else {
            return Ok(false);
        };
        let settings = if ap_is_passwordless(ap.flags, ap.wpa_flags, ap.rsn_flags) {
            ConnectionSettings::new()
        } else if ap_supports_psk(ap.wpa_flags, ap.rsn_flags) {
            let Some(password) = password else {
                return Ok(false);
            };
            psk_wifi_connection_settings(&ap, password)?
        } else {
            return Ok(false);
        };

        let nm = self.proxy(NM_PATH, NM_IFACE)?;
        let _paths: (OwnedObjectPath, OwnedObjectPath) = nm
            .call(
                "AddAndActivateConnection",
                &(settings, device.path, ap_path),
            )
            .with_context(|| format!("AddAndActivateConnection for Wi-Fi network {ssid}"))?;
        Ok(true)
    }

    pub(crate) fn needs_wifi_password(&self, ssid: &str) -> Result<bool> {
        if self.saved_wifi_activation_target(ssid)?.is_some() {
            return Ok(false);
        }
        let Some((_device, _ap_path, ap)) = self.visible_access_point(ssid)? else {
            return Ok(false);
        };
        Ok(!ap_is_passwordless(ap.flags, ap.wpa_flags, ap.rsn_flags)
            && ap_supports_psk(ap.wpa_flags, ap.rsn_flags))
    }

    pub(crate) fn wifi_activation_status(
        &self,
        ssid: &str,
    ) -> Result<Option<WifiActivationStatus>> {
        let device = if let Some((device, _ap_path, _ap)) = self.visible_access_point(ssid)? {
            device
        } else {
            let Some(device) = self.wifi_devices()?.into_iter().next() else {
                return Ok(None);
            };
            device
        };
        self.device_activation_status(&device).map(Some)
    }

    fn device_activation_status(&self, device: &WifiDevice) -> Result<WifiActivationStatus> {
        let device_proxy = self.proxy_path(&device.path, DEVICE_IFACE)?;
        let device_state = device_proxy
            .get_property("State")
            .with_context(|| format!("read State for {}", device.iface))?;
        let device_state_reason = device_proxy
            .get_property("StateReason")
            .with_context(|| format!("read StateReason for {}", device.iface))?;
        let active_connection_path: OwnedObjectPath = device_proxy
            .get_property("ActiveConnection")
            .with_context(|| format!("read ActiveConnection for {}", device.iface))?;
        let active_connection_state = self.active_connection_state(&active_connection_path);
        Ok(WifiActivationStatus {
            iface: device.iface.clone(),
            device_state,
            device_state_reason,
            active_connection_state,
        })
    }

    fn active_connection_state(&self, path: &OwnedObjectPath) -> Option<u32> {
        if path.as_str() == "/" {
            return None;
        }
        self.proxy_path(path, ACTIVE_CONNECTION_IFACE)
            .and_then(|proxy| {
                proxy
                    .get_property("State")
                    .context("read ActiveConnection State")
            })
            .ok()
    }

    fn saved_wifi_activation_target(
        &self,
        ssid: &str,
    ) -> Result<Option<(OwnedObjectPath, OwnedObjectPath, OwnedObjectPath)>> {
        if let Some((device, ap_path, _ap)) = self.visible_access_point(ssid)?
            && let Some(connection_path) =
                self.saved_wifi_connection_for_ssid_on_device(ssid, &device)?
        {
            return Ok(Some((connection_path, device.path, ap_path)));
        }

        let Some(connection_path) = self.saved_wifi_connection_for_ssid(ssid)? else {
            return Ok(None);
        };
        let Some(device) = self.wifi_devices()?.into_iter().next() else {
            bail!("no Wi-Fi devices found");
        };
        Ok(Some((connection_path, device.path, root_object_path()?)))
    }

    fn saved_wifi_connection_for_ssid_on_device(
        &self,
        ssid: &str,
        device: &WifiDevice,
    ) -> Result<Option<OwnedObjectPath>> {
        for path in self.available_connections(device)? {
            if self.connection_matches_ssid(&path, ssid)? {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    fn saved_wifi_connection_for_ssid(&self, ssid: &str) -> Result<Option<OwnedObjectPath>> {
        for path in self.saved_connections()? {
            if self.connection_matches_ssid(&path, ssid)? {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    fn connection_matches_ssid(&self, path: &OwnedObjectPath, ssid: &str) -> Result<bool> {
        let settings = self.connection_settings(path)?;
        Ok(settings_match_wifi_ssid(&settings, ssid))
    }

    fn saved_connections(&self) -> Result<Vec<OwnedObjectPath>> {
        let settings = self.proxy(SETTINGS_PATH, SETTINGS_IFACE)?;
        settings
            .call("ListConnections", &())
            .context("ListConnections")
    }

    fn connection_settings(&self, path: &OwnedObjectPath) -> Result<ConnectionSettings> {
        let connection = self.proxy_path(path, SETTINGS_CONNECTION_IFACE)?;
        connection
            .call("GetSettings", &())
            .with_context(|| format!("GetSettings for {path}"))
    }

    fn available_connections(&self, device: &WifiDevice) -> Result<Vec<OwnedObjectPath>> {
        let device_proxy = self.proxy_path(&device.path, DEVICE_IFACE)?;
        device_proxy
            .get_property("AvailableConnections")
            .with_context(|| format!("read AvailableConnections for {}", device.iface))
    }

    fn visible_access_point(
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

    fn device_access_points(&self, device: &WifiDevice) -> Result<Vec<OwnedObjectPath>> {
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

fn psk_wifi_connection_settings(ap: &AccessPoint, password: &str) -> Result<ConnectionSettings> {
    let mut settings = ConnectionSettings::new();
    settings.insert(
        "802-11-wireless-security".to_string(),
        HashMap::from([
            (
                "key-mgmt".to_string(),
                owned_value(psk_key_mgmt(ap).to_string())?,
            ),
            ("psk".to_string(), owned_value(password.to_string())?),
        ]),
    );
    Ok(settings)
}

fn psk_key_mgmt(ap: &AccessPoint) -> &'static str {
    let flags = ap.wpa_flags | ap.rsn_flags;
    if flags & NM_AP_SEC_KEY_MGMT_SAE != 0 && flags & NM_AP_SEC_KEY_MGMT_PSK == 0 {
        "sae"
    } else {
        "wpa-psk"
    }
}

fn owned_value<T>(value: T) -> Result<OwnedValue>
where
    T: Into<Value<'static>> + DynamicType,
{
    OwnedValue::try_from(Value::new(value)).context("create D-Bus variant value")
}

fn settings_match_wifi_ssid(settings: &ConnectionSettings, ssid: &str) -> bool {
    let Some(wireless) = settings.get("802-11-wireless") else {
        return false;
    };
    if settings
        .get("connection")
        .and_then(|connection| setting_string(connection, "type"))
        .is_some_and(|connection_type| connection_type != "802-11-wireless")
    {
        return false;
    }
    wireless
        .get("ssid")
        .and_then(setting_bytes)
        .is_some_and(|saved_ssid| ssid_bytes_match(&saved_ssid, ssid))
}

fn setting_string(settings: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    settings.get(key)?.try_clone().ok()?.try_into().ok()
}

fn setting_bytes(value: &OwnedValue) -> Option<Vec<u8>> {
    value.try_clone().ok()?.try_into().ok()
}

fn ssid_bytes_match(saved_ssid: &[u8], ssid: &str) -> bool {
    saved_ssid == ssid.as_bytes() || String::from_utf8_lossy(saved_ssid) == ssid
}

fn root_object_path() -> Result<OwnedObjectPath> {
    OwnedObjectPath::try_from("/").context("create root object path")
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectionSettings, psk_key_mgmt, psk_wifi_connection_settings, setting_string,
        settings_match_wifi_ssid, ssid_bytes_match,
    };
    use crate::model::{AccessPoint, NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE};
    use std::collections::HashMap;
    use zvariant::{OwnedValue, Value};

    #[test]
    fn ssid_bytes_match_exact_utf8() {
        assert!(ssid_bytes_match(b"Example", "Example"));
    }

    #[test]
    fn ssid_bytes_match_lossy_decoded_names() {
        assert!(ssid_bytes_match(&[0xff], "�"));
    }

    #[test]
    fn settings_match_wireless_ssid() {
        let settings = wifi_settings("Example", "802-11-wireless");

        assert!(settings_match_wifi_ssid(&settings, "Example"));
        assert!(!settings_match_wifi_ssid(&settings, "Other"));
    }

    #[test]
    fn settings_reject_non_wireless_profiles() {
        let settings = wifi_settings("Example", "ethernet");

        assert!(!settings_match_wifi_ssid(&settings, "Example"));
    }

    #[test]
    fn psk_wifi_settings_include_password_and_key_mgmt() {
        let ap = test_ap(NM_AP_SEC_KEY_MGMT_PSK);
        let settings = psk_wifi_connection_settings(&ap, "secret123").expect("settings");

        assert_eq!(
            settings
                .get("802-11-wireless-security")
                .and_then(|section| setting_string(section, "key-mgmt"))
                .as_deref(),
            Some("wpa-psk")
        );
        assert_eq!(
            settings
                .get("802-11-wireless-security")
                .and_then(|section| setting_string(section, "psk"))
                .as_deref(),
            Some("secret123")
        );
    }

    #[test]
    fn sae_only_networks_use_sae_key_mgmt() {
        assert_eq!(psk_key_mgmt(&test_ap(NM_AP_SEC_KEY_MGMT_SAE)), "sae");
        assert_eq!(
            psk_key_mgmt(&test_ap(NM_AP_SEC_KEY_MGMT_SAE | NM_AP_SEC_KEY_MGMT_PSK)),
            "wpa-psk"
        );
    }

    fn test_ap(rsn_flags: u32) -> AccessPoint {
        AccessPoint {
            ssid: "Example".to_string(),
            active: false,
            security: "WPA2/3".to_string(),
            strength: 50,
            frequency: 2412,
            bssid: "00:11:22:33:44:55".to_string(),
            last_seen: 0,
            flags: 0,
            wpa_flags: 0,
            rsn_flags,
        }
    }

    fn wifi_settings(ssid: &str, connection_type: &str) -> ConnectionSettings {
        let mut settings = ConnectionSettings::new();
        settings.insert(
            "connection".to_string(),
            HashMap::from([(
                "type".to_string(),
                owned_value(Value::new(connection_type.to_string())),
            )]),
        );
        settings.insert(
            "802-11-wireless".to_string(),
            HashMap::from([(
                "ssid".to_string(),
                owned_value(Value::new(ssid.as_bytes().to_vec())),
            )]),
        );
        settings
    }

    fn owned_value(value: Value<'_>) -> OwnedValue {
        OwnedValue::try_from(value).expect("owned value")
    }
}
