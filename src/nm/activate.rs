use std::collections::HashMap;

use anyhow::{Context, Result};
use zvariant::{DynamicType, OwnedObjectPath, OwnedValue, Value};

use super::{ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, NM_IFACE, NM_PATH, Nm};
use crate::model::{
    AccessPoint, NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE, ap_is_passwordless,
    ap_supports_psk,
};

impl Nm {
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
    ) -> Result<Option<super::WifiActivationStatus>> {
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

#[cfg(test)]
mod tests {
    use super::{psk_key_mgmt, psk_wifi_connection_settings};
    use crate::model::{AccessPoint, NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE};

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

    fn setting_string(
        settings: &std::collections::HashMap<String, zvariant::OwnedValue>,
        key: &str,
    ) -> Option<String> {
        settings.get(key)?.try_clone().ok()?.try_into().ok()
    }
}
