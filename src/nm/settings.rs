use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use zvariant::{OwnedObjectPath, OwnedValue};

use super::{
    ConnectionSettings, DEVICE_IFACE, Nm, SETTINGS_CONNECTION_IFACE, SETTINGS_IFACE, SETTINGS_PATH,
};
use crate::model::WifiDevice;

impl Nm {
    pub(super) fn saved_wifi_activation_target(
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
    use super::{ConnectionSettings, settings_match_wifi_ssid, ssid_bytes_match};
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
