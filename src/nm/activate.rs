use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use super::wifi_settings::{
    apply_target_profile_settings, cloned_wifi_connection_settings,
    enterprise_wifi_connection_settings, hidden_wifi_connection_settings,
    owe_wifi_connection_settings, psk_key_mgmt, psk_wifi_connection_settings,
    wep_wifi_connection_settings,
};
use super::{
    ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, NM_IFACE, NM_PATH, Nm, owned_value,
};
use crate::model::{
    WepKeyType, WifiConnectTarget, ap_is_passwordless, ap_supports_enterprise, ap_supports_psk,
    ap_uses_owe, ap_uses_wep,
};

impl Nm {
    pub(crate) fn activate_saved_wifi_connection_for(
        &self,
        target: &WifiConnectTarget,
        password: Option<&str>,
        _wep_key_type: Option<WepKeyType>,
    ) -> Result<bool> {
        if password.is_some() {
            tracing::info!(ssid = %target.ssid, "skipping saved-profile activation because caller supplied a password");
            return Ok(false);
        }
        let Some((connection_path, device_path, specific_object)) =
            self.saved_wifi_activation_target_for(target)?
        else {
            return Ok(false);
        };
        if self.saved_wifi_connection_needs_secret_agent(&connection_path, None)? {
            tracing::info!(ssid = %target.ssid, connection = %connection_path, "saved Wi-Fi profile needs a secret agent before activation");
            anyhow::bail!(
                "saved Wi-Fi profile for {} requires a secret agent or a newly supplied password",
                target.ssid
            );
        }
        tracing::info!(
            ssid = %target.ssid,
            connection = %connection_path,
            device = %device_path,
            specific_object = %specific_object,
            "activating saved Wi-Fi connection over D-Bus"
        );
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

        let Some((device, ap_path, ap)) = self.visible_access_point_for(target)? else {
            return Ok(None);
        };
        tracing::info!(
            ssid = %target.ssid,
            iface = %device.iface,
            ap_path = %ap_path,
            bssid = %ap.bssid,
            security = %ap.security,
            flags = ap.flags,
            wpa_flags = ap.wpa_flags,
            rsn_flags = ap.rsn_flags,
            "preparing D-Bus add-and-activate for visible Wi-Fi network"
        );
        if (password.is_some() || target.enterprise.is_some())
            && let Some(saved_settings) =
                self.saved_wifi_connection_settings_for_ap_on_device(&ap, &device)?
        {
            tracing::info!(ssid = %target.ssid, "cloning compatible saved profile settings for password/credential-supplied activation");
            let mut settings = cloned_wifi_connection_settings(
                saved_settings,
                target,
                &ap,
                password,
                wep_key_type,
            )?;
            apply_target_connection_metadata(&mut settings, target)?;
            return self
                .add_and_activate(&target.ssid, settings, device.path, ap_path)
                .map(Some);
        }

        let mut settings = if ap_is_passwordless(ap.flags, ap.wpa_flags, ap.rsn_flags) {
            if ap_uses_owe(ap.wpa_flags, ap.rsn_flags) {
                tracing::debug!(ssid = %target.ssid, "network uses OWE passwordless encryption");
                owe_wifi_connection_settings()?
            } else {
                tracing::debug!(ssid = %target.ssid, "network is open/passwordless");
                ConnectionSettings::new()
            }
        } else if ap_supports_psk(ap.wpa_flags, ap.rsn_flags) {
            let Some(password) = password else {
                tracing::info!(ssid = %target.ssid, "WPA/SAE network needs a password; no password supplied to D-Bus add-and-activate");
                return Ok(None);
            };
            tracing::debug!(ssid = %target.ssid, key_mgmt = %psk_key_mgmt(&ap), "network supports WPA/SAE personal authentication");
            psk_wifi_connection_settings(&ap, password)?
        } else if ap_uses_wep(ap.flags, ap.wpa_flags, ap.rsn_flags) {
            let Some(password) = password else {
                tracing::info!(ssid = %target.ssid, "WEP network needs a key/passphrase; no password supplied to D-Bus add-and-activate");
                return Ok(None);
            };
            tracing::debug!(ssid = %target.ssid, wep_key_type = ?wep_key_type, "network appears to use WEP authentication");
            wep_wifi_connection_settings(password, wep_key_type.unwrap_or(WepKeyType::Key))?
        } else if ap_supports_enterprise(ap.wpa_flags, ap.rsn_flags) {
            let Some(enterprise) = &target.enterprise else {
                tracing::info!(ssid = %target.ssid, "enterprise network needs structured 802.1X credentials; none supplied to D-Bus add-and-activate");
                return Ok(None);
            };
            tracing::debug!(ssid = %target.ssid, eap = ?enterprise.eap, "network supports WPA-Enterprise authentication");
            enterprise_wifi_connection_settings(&ap, enterprise, password)?
        } else {
            tracing::info!(ssid = %target.ssid, security = %ap.security, "unsupported visible network security for D-Bus add-and-activate");
            return Ok(None);
        };

        apply_target_connection_metadata(&mut settings, target)?;
        apply_target_profile_settings(&mut settings, target)?;
        self.add_and_activate(&target.ssid, settings, device.path, ap_path)
            .map(Some)
    }

    fn add_and_activate_hidden_wifi_connection(
        &self,
        target: &WifiConnectTarget,
        password: Option<&str>,
        wep_key_type: Option<WepKeyType>,
    ) -> Result<Option<OwnedObjectPath>> {
        let Some(device) = self.wifi_devices_for_target(target)?.into_iter().next() else {
            return Ok(None);
        };
        self.request_hidden_scan(&device, target.ssid_bytes().as_ref())?;
        let mut settings = hidden_wifi_connection_settings(target, password, wep_key_type)?;
        apply_target_connection_metadata(&mut settings, target)?;
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
        tracing::info!(ssid, device = %device_path, specific_object = %specific_object, "calling NetworkManager AddAndActivateConnection");
        let nm = self.proxy(NM_PATH, NM_IFACE)?;
        let (connection_path, _active_path): (OwnedObjectPath, OwnedObjectPath) = nm
            .call(
                "AddAndActivateConnection",
                &(settings, device_path, specific_object),
            )
            .with_context(|| format!("AddAndActivateConnection for Wi-Fi network {ssid}"))?;
        Ok(connection_path)
    }

    pub(crate) fn wifi_activation_status_for(
        &self,
        target: &WifiConnectTarget,
    ) -> Result<Option<super::WifiActivationStatus>> {
        let Some(device) = self.wifi_activation_device_for_target(target)? else {
            return Ok(None);
        };
        self.wifi_activation_status_for_device(&device).map(Some)
    }

    pub(crate) fn wifi_activation_device_for_target(
        &self,
        target: &WifiConnectTarget,
    ) -> Result<Option<crate::model::WifiDevice>> {
        if let Some((device, _ap_path, _ap)) = self.visible_access_point_for(target)? {
            Ok(Some(device))
        } else {
            Ok(self.wifi_devices_for_target(target)?.into_iter().next())
        }
    }

    pub(crate) fn wifi_activation_status_for_device(
        &self,
        device: &crate::model::WifiDevice,
    ) -> Result<super::WifiActivationStatus> {
        self.device_activation_status(device)
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

fn apply_target_connection_metadata(
    settings: &mut ConnectionSettings,
    target: &WifiConnectTarget,
) -> Result<()> {
    if target.connection_name.is_none() && !target.private {
        return Ok(());
    }
    let connection = settings.entry("connection".to_string()).or_default();
    if let Some(name) = target
        .connection_name
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        connection.insert("id".to_string(), owned_value(name.to_string())?);
        connection
            .entry("type".to_string())
            .or_insert(owned_value("802-11-wireless".to_string())?);
    }
    if target.private
        && let Some(user) = current_user_name()
    {
        connection.insert(
            "permissions".to_string(),
            owned_value(vec![format!("user:{user}:")])?,
        );
    }
    Ok(())
}

fn current_user_name() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("LOGNAME").ok())
        .filter(|value| !value.is_empty())
}

fn root_object_path() -> Result<OwnedObjectPath> {
    OwnedObjectPath::try_from("/").context("create root object path")
}
