use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use zvariant::{DynamicType, OwnedObjectPath, OwnedValue, Value};

use super::{ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, NM_IFACE, NM_PATH, Nm};
use crate::model::{
    AccessPoint, NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE, WepKeyType, WifiConnectTarget,
    ap_is_passwordless, ap_supports_psk, ap_uses_wep,
};

impl Nm {
    pub(crate) fn activate_saved_wifi_connection_for(
        &self,
        target: &WifiConnectTarget,
    ) -> Result<bool> {
        let Some((connection_path, device_path, specific_object)) =
            self.saved_wifi_activation_target_for(target)?
        else {
            return Ok(false);
        };
        let nm = self.proxy(NM_PATH, NM_IFACE)?;
        let _active_connection: OwnedObjectPath = nm
            .call(
                "ActivateConnection",
                &(connection_path, device_path, specific_object),
            )
            .with_context(|| {
                format!("ActivateConnection for saved Wi-Fi profile {}", target.ssid)
            })?;
        Ok(true)
    }

    pub(crate) fn add_and_activate_wifi_connection_for(
        &self,
        target: &WifiConnectTarget,
        password: Option<&str>,
        wep_key_type: Option<WepKeyType>,
    ) -> Result<Option<OwnedObjectPath>> {
        if target.hidden {
            return self.add_and_activate_hidden_wifi_connection(target, password, wep_key_type);
        }

        let Some((device, ap_path, ap)) = self.visible_access_point_for(
            &target.ssid,
            target.ap_path.as_deref(),
            target.bssid.as_deref(),
        )?
        else {
            return Ok(None);
        };
        let settings = if ap_is_passwordless(ap.flags, ap.wpa_flags, ap.rsn_flags) {
            ConnectionSettings::new()
        } else if ap_supports_psk(ap.wpa_flags, ap.rsn_flags) {
            let Some(password) = password else {
                return Ok(None);
            };
            psk_wifi_connection_settings(&ap, password)?
        } else if ap_uses_wep(ap.flags, ap.wpa_flags, ap.rsn_flags) {
            let Some(password) = password else {
                return Ok(None);
            };
            wep_wifi_connection_settings(password, wep_key_type.unwrap_or(WepKeyType::Key))?
        } else {
            return Ok(None);
        };

        self.add_and_activate(&target.ssid, settings, device.path, ap_path)
            .map(Some)
    }

    fn add_and_activate_hidden_wifi_connection(
        &self,
        target: &WifiConnectTarget,
        password: Option<&str>,
        wep_key_type: Option<WepKeyType>,
    ) -> Result<Option<OwnedObjectPath>> {
        let Some(device) = self.wifi_devices()?.into_iter().next() else {
            return Ok(None);
        };
        self.request_hidden_scan(&device, &target.ssid)?;
        let settings = hidden_wifi_connection_settings(&target.ssid, password, wep_key_type)?;
        self.add_and_activate(&target.ssid, settings, device.path, root_object_path()?)
            .map(Some)
    }

    fn add_and_activate(
        &self,
        ssid: &str,
        settings: ConnectionSettings,
        device_path: OwnedObjectPath,
        specific_object: OwnedObjectPath,
    ) -> Result<OwnedObjectPath> {
        let nm = self.proxy(NM_PATH, NM_IFACE)?;
        let (connection_path, _active_path): (OwnedObjectPath, OwnedObjectPath) = nm
            .call(
                "AddAndActivateConnection",
                &(settings, device_path, specific_object),
            )
            .with_context(|| format!("AddAndActivateConnection for Wi-Fi network {ssid}"))?;
        Ok(connection_path)
    }

    pub(crate) fn needs_wifi_password_for(&self, target: &WifiConnectTarget) -> Result<bool> {
        if self.saved_wifi_activation_target_for(target)?.is_some() {
            return Ok(false);
        }
        if target.hidden {
            return Ok(false);
        }
        let Some((_device, _ap_path, ap)) = self.visible_access_point_for(
            &target.ssid,
            target.ap_path.as_deref(),
            target.bssid.as_deref(),
        )?
        else {
            return Ok(false);
        };
        Ok(!ap_is_passwordless(ap.flags, ap.wpa_flags, ap.rsn_flags)
            && (ap_supports_psk(ap.wpa_flags, ap.rsn_flags)
                || ap_uses_wep(ap.flags, ap.wpa_flags, ap.rsn_flags)))
    }

    pub(crate) fn wifi_activation_status_for(
        &self,
        target: &WifiConnectTarget,
    ) -> Result<Option<super::WifiActivationStatus>> {
        let device = if let Some((device, _ap_path, _ap)) = self.visible_access_point_for(
            &target.ssid,
            target.ap_path.as_deref(),
            target.bssid.as_deref(),
        )? {
            device
        } else {
            let Some(device) = self.wifi_devices()?.into_iter().next() else {
                return Ok(None);
            };
            device
        };
        self.device_activation_status(&device).map(Some)
    }

    fn device_activation_status(
        &self,
        device: &crate::model::WifiDevice,
    ) -> Result<super::WifiActivationStatus> {
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
        Ok(super::WifiActivationStatus {
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
}

fn psk_wifi_connection_settings(ap: &AccessPoint, password: &str) -> Result<ConnectionSettings> {
    let key_mgmt = psk_key_mgmt(ap);
    if key_mgmt == "wpa-psk" {
        validate_wpa_psk(password)?;
    }
    wireless_security_settings(key_mgmt, password)
}

fn hidden_wifi_connection_settings(
    ssid: &str,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<ConnectionSettings> {
    let mut settings = base_wifi_connection_settings(ssid, true)?;
    if let Some(password) = password {
        let security = if let Some(wep_key_type) = wep_key_type {
            wep_security_section(password, wep_key_type)?
        } else {
            validate_wpa_psk(password)?;
            wireless_security_section("wpa-psk", password)?
        };
        settings.insert("802-11-wireless-security".to_string(), security);
    }
    Ok(settings)
}

fn base_wifi_connection_settings(ssid: &str, hidden: bool) -> Result<ConnectionSettings> {
    let mut settings = ConnectionSettings::new();
    settings.insert(
        "connection".to_string(),
        HashMap::from([
            ("id".to_string(), owned_value(ssid.to_string())?),
            (
                "type".to_string(),
                owned_value("802-11-wireless".to_string())?,
            ),
        ]),
    );
    settings.insert(
        "802-11-wireless".to_string(),
        HashMap::from([
            ("ssid".to_string(), owned_value(ssid.as_bytes().to_vec())?),
            (
                "mode".to_string(),
                owned_value("infrastructure".to_string())?,
            ),
            ("hidden".to_string(), owned_value(hidden)?),
        ]),
    );
    settings.insert(
        "ipv4".to_string(),
        HashMap::from([("method".to_string(), owned_value("auto".to_string())?)]),
    );
    settings.insert(
        "ipv6".to_string(),
        HashMap::from([("method".to_string(), owned_value("auto".to_string())?)]),
    );
    Ok(settings)
}

fn wireless_security_settings(key_mgmt: &str, password: &str) -> Result<ConnectionSettings> {
    let mut settings = ConnectionSettings::new();
    settings.insert(
        "802-11-wireless-security".to_string(),
        wireless_security_section(key_mgmt, password)?,
    );
    Ok(settings)
}

fn wep_wifi_connection_settings(
    password: &str,
    wep_key_type: WepKeyType,
) -> Result<ConnectionSettings> {
    let mut settings = ConnectionSettings::new();
    settings.insert(
        "802-11-wireless-security".to_string(),
        wep_security_section(password, wep_key_type)?,
    );
    Ok(settings)
}

fn wireless_security_section(
    key_mgmt: &str,
    password: &str,
) -> Result<HashMap<String, OwnedValue>> {
    Ok(HashMap::from([
        ("key-mgmt".to_string(), owned_value(key_mgmt.to_string())?),
        ("psk".to_string(), owned_value(password.to_string())?),
    ]))
}

fn wep_security_section(
    password: &str,
    wep_key_type: WepKeyType,
) -> Result<HashMap<String, OwnedValue>> {
    validate_wep_key(password, wep_key_type)?;
    Ok(HashMap::from([
        ("key-mgmt".to_string(), owned_value("none".to_string())?),
        ("wep-key0".to_string(), owned_value(password.to_string())?),
        (
            "wep-key-type".to_string(),
            owned_value(wep_key_type.nm_value())?,
        ),
    ]))
}

fn psk_key_mgmt(ap: &AccessPoint) -> &'static str {
    let flags = ap.wpa_flags | ap.rsn_flags;
    if flags & NM_AP_SEC_KEY_MGMT_SAE != 0 && flags & NM_AP_SEC_KEY_MGMT_PSK == 0 {
        "sae"
    } else {
        "wpa-psk"
    }
}

fn validate_wpa_psk(password: &str) -> Result<()> {
    let len = password.len();
    if (8..=63).contains(&len) || (len == 64 && password.chars().all(|ch| ch.is_ascii_hexdigit())) {
        return Ok(());
    }
    bail!("WPA-PSK password must be 8-63 characters, or 64 hexadecimal characters")
}

fn validate_wep_key(password: &str, wep_key_type: WepKeyType) -> Result<()> {
    match wep_key_type {
        WepKeyType::Key if wep_key_is_valid(password) => Ok(()),
        WepKeyType::Key => {
            bail!("WEP key must be 5 or 13 ASCII characters, or 10 or 26 hexadecimal characters")
        }
        WepKeyType::Phrase if (8..=64).contains(&password.len()) => Ok(()),
        WepKeyType::Phrase => bail!("WEP passphrase must be 8-64 characters"),
    }
}

fn wep_key_is_valid(password: &str) -> bool {
    matches!(password.len(), 5 | 13)
        || (matches!(password.len(), 10 | 26) && password.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn owned_value<T>(value: T) -> Result<OwnedValue>
where
    T: Into<Value<'static>> + DynamicType,
{
    OwnedValue::try_from(Value::new(value)).context("create D-Bus variant value")
}

fn root_object_path() -> Result<OwnedObjectPath> {
    OwnedObjectPath::try_from("/").context("create root object path")
}

#[cfg(test)]
mod tests {
    use super::{psk_key_mgmt, psk_wifi_connection_settings, validate_wep_key, validate_wpa_psk};
    use crate::model::{AccessPoint, NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE, WepKeyType};

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

    #[test]
    fn wpa_psk_validation_matches_nmcli_shape() {
        assert!(validate_wpa_psk("12345678").is_ok());
        assert!(validate_wpa_psk(&"a".repeat(63)).is_ok());
        assert!(validate_wpa_psk(&"a".repeat(64)).is_ok());
        assert!(validate_wpa_psk("short").is_err());
        assert!(validate_wpa_psk(&"g".repeat(64)).is_err());
        assert!(validate_wpa_psk(&"a".repeat(65)).is_err());
    }

    #[test]
    fn wep_validation_matches_nmcli_shape() {
        assert!(validate_wep_key("abcde", WepKeyType::Key).is_ok());
        assert!(validate_wep_key("0011223344", WepKeyType::Key).is_ok());
        assert!(validate_wep_key("abc", WepKeyType::Key).is_err());
        assert!(validate_wep_key("not-hex-10", WepKeyType::Key).is_err());
        assert!(validate_wep_key("passphrase", WepKeyType::Phrase).is_ok());
        assert!(validate_wep_key("short", WepKeyType::Phrase).is_err());
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
            path: "/ap".to_string(),
            device_path: "/device".to_string(),
            flags: 0,
            wpa_flags: 0,
            rsn_flags,
        }
    }

    fn setting_string(
        settings: &std::collections::HashMap<String, zvariant::OwnedValue>,
        key: &str,
    ) -> Option<String> {
        settings.get(key)?.try_clone().ok()?.try_into().ok()
    }
}
