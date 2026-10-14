use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use super::wifi_settings::{
    apply_saved_activation_settings, apply_target_connection_metadata,
    apply_target_profile_settings, cloned_wifi_connection_settings,
    hidden_wifi_connection_settings, visible_connection_settings,
};
use super::{ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, Nm};
use crate::error::DomainError;
use crate::model::{WepKeyType, WifiConnectTarget};

#[derive(Debug)]
pub(crate) struct WifiActivation {
    pub(crate) profile_path: OwnedObjectPath,
    pub(crate) active_path: OwnedObjectPath,
}

impl Nm {
    pub(crate) fn activate_saved_wifi_connection_for(
        &self,
        target: &WifiConnectTarget,
        password: Option<&str>,
        wep_key_type: Option<WepKeyType>,
    ) -> Result<Option<OwnedObjectPath>> {
        if target.profile.remember == Some(false) {
            return Ok(None); // Never update a saved profile for a temporary join.
        }
        let Some((connection_path, device_path, specific_object)) =
            self.saved_wifi_activation_target_for(target)?
        else {
            return Ok(None);
        };
        self.prepare_saved_activation(&connection_path, target, password, wep_key_type)?;
        tracing::info!(
            ssid = %target.ssid,
            connection = %connection_path,
            device = %device_path,
            specific_object = %specific_object,
            "activating saved Wi-Fi connection over D-Bus"
        );
        let nm = self.root_proxy();
        let active_connection: OwnedObjectPath = nm
            .call(
                "ActivateConnection",
                &(connection_path, device_path, specific_object),
            )
            .with_context(|| {
                format!("ActivateConnection for saved Wi-Fi profile {}", target.ssid)
            })?;
        Ok(Some(active_connection))
    }

    fn prepare_saved_activation(
        &self,
        connection_path: &OwnedObjectPath,
        target: &WifiConnectTarget,
        password: Option<&str>,
        wep_key_type: Option<WepKeyType>,
    ) -> Result<()> {
        if password.is_some() || target.enterprise.is_some() {
            let _transaction = self.begin_profile_transaction();
            let visible_ap = self
                .visible_access_point_for(target)?
                .map(|(_device, _path, ap)| ap);
            let mut settings = self.connection_settings(connection_path)?;
            apply_saved_activation_settings(
                &mut settings,
                target,
                visible_ap.as_ref(),
                password,
                wep_key_type,
            )?;
            apply_target_connection_metadata(&mut settings, target)?;
            tracing::info!(ssid = %target.ssid, connection = %connection_path, "updating compatible saved profile before activation");
            return self.update_connection_settings_for_activation(connection_path, settings);
        }
        super::profile_policy::validate_private_ca_paths(
            &self.connection_settings(connection_path)?,
            crate::error::ErrorOperation::Connect,
        )?;
        if !self.saved_wifi_connection_needs_secret_agent(connection_path, None)? {
            return Ok(());
        }
        tracing::info!(ssid = %target.ssid, connection = %connection_path, "saved Wi-Fi profile needs a secret agent before activation");
        Err(missing_saved_profile_password(target))
    }

    pub(crate) fn add_and_activate_wifi_connection_for(
        &self,
        target: &WifiConnectTarget,
        password: Option<&str>,
        wep_key_type: Option<WepKeyType>,
    ) -> Result<Option<WifiActivation>> {
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
        let Some(mut settings) =
            self.visible_activation_settings(&device, target, &ap, password, wep_key_type)?
        else {
            return Ok(None);
        };
        apply_target_connection_metadata(&mut settings, target)?;
        self.add_and_activate(target, settings, device.path, ap_path)
            .map(Some)
    }

    fn visible_activation_settings(
        &self,
        device: &crate::model::WifiDevice,
        target: &WifiConnectTarget,
        ap: &crate::model::AccessPoint,
        password: Option<&str>,
        wep_key_type: Option<WepKeyType>,
    ) -> Result<Option<ConnectionSettings>> {
        if (target.profile.remember == Some(false)
            || password.is_some()
            || target.enterprise.is_some())
            && let Some(saved) = self.saved_wifi_connection_settings_for_ap_on_device(ap, device)?
        {
            tracing::info!(ssid = %target.ssid, "cloning compatible saved profile settings for password/credential-supplied activation");
            return cloned_wifi_connection_settings(saved, target, ap, password, wep_key_type)
                .map(Some);
        }
        let Some(mut settings) = visible_connection_settings(target, ap, password, wep_key_type)?
        else {
            return Ok(None);
        };
        apply_target_profile_settings(&mut settings, target)?;
        Ok(Some(settings))
    }

    fn add_and_activate_hidden_wifi_connection(
        &self,
        target: &WifiConnectTarget,
        password: Option<&str>,
        wep_key_type: Option<WepKeyType>,
    ) -> Result<Option<WifiActivation>> {
        let Some(device) = self.wifi_devices_for_target(target)?.into_iter().next() else {
            return Ok(None);
        };
        self.request_hidden_scan(&device, target.ssid_bytes().as_ref())?;
        let mut settings = hidden_wifi_connection_settings(target, password, wep_key_type)?;
        apply_target_connection_metadata(&mut settings, target)?;
        self.add_and_activate(target, settings, device.path, root_object_path()?)
            .map(Some)
    }

    fn add_and_activate(
        &self,
        target: &WifiConnectTarget,
        mut settings: ConnectionSettings,
        device_path: OwnedObjectPath,
        specific_object: OwnedObjectPath,
    ) -> Result<WifiActivation> {
        let ssid = target.ssid.as_str();
        tracing::info!(ssid, device = %device_path, specific_object = %specific_object, "calling NetworkManager AddAndActivateConnection");
        let nm = self.root_proxy();
        if target.profile.remember == Some(false) {
            make_temporary(&mut settings)?;
            let options = crate::variant::value_map([("persist", "volatile".into())])?;
            let (profile_path, active_path, _result): (
                OwnedObjectPath,
                OwnedObjectPath,
                std::collections::HashMap<String, zvariant::OwnedValue>,
            ) = nm
                .call(
                    "AddAndActivateConnection2",
                    &(settings, device_path, specific_object, options),
                )
                .with_context(|| format!("temporary activation for Wi-Fi network {ssid}"))?;
            return Ok(WifiActivation {
                profile_path,
                active_path,
            });
        }
        let (profile_path, active_path): (OwnedObjectPath, OwnedObjectPath) = nm
            .call(
                "AddAndActivateConnection",
                &(settings, device_path, specific_object),
            )
            .with_context(|| format!("AddAndActivateConnection for Wi-Fi network {ssid}"))?;
        Ok(WifiActivation {
            profile_path,
            active_path,
        })
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
            active_connection_path: (active_connection_path.as_str() != "/")
                .then_some(active_connection_path),
            active_connection_state,
        })
    }

    pub(crate) fn active_connection_state(&self, path: &OwnedObjectPath) -> Option<u32> {
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

fn make_temporary(settings: &mut ConnectionSettings) -> Result<()> {
    let connection = settings.entry("connection".into()).or_default();
    connection.remove("uuid"); // A temporary clone must never replace a saved identity.
    connection.insert("autoconnect".into(), super::owned_value(false)?);
    for setting in ["802-11-wireless-security", "802-1x"] {
        if let Some(section) = settings.get_mut(setting) {
            for key in crate::daemon_secret::known_secret_keys(setting) {
                let flags = if key.starts_with("wep-key") {
                    "wep-key-flags".to_string()
                } else {
                    format!("{key}-flags")
                };
                section.insert(flags, super::owned_value(2_u32)?); // NOT_SAVED
            }
        }
    }
    Ok(())
}

fn missing_saved_profile_password(target: &WifiConnectTarget) -> anyhow::Error {
    DomainError::connect(
        crate::model::ConnectFailureReason::PasswordUnavailable,
        format!(
            "saved Wi-Fi profile for {} requires a secret agent or a newly supplied password",
            target.ssid
        ),
    )
    .with_detail("ssid", target.ssid.to_string())
    .into()
}

fn root_object_path() -> Result<OwnedObjectPath> {
    OwnedObjectPath::try_from("/").context("create root object path")
}

#[cfg(test)]
mod remember_tests {
    #[test]
    fn temporary_settings_do_not_reuse_identity_or_save_credentials() -> anyhow::Result<()> {
        use crate::variant::{setting, value_map};
        let mut settings = super::ConnectionSettings::from([
            (
                "connection".into(),
                value_map([("uuid", "saved-uuid".into()), ("autoconnect", true.into())])?,
            ),
            (
                "802-11-wireless-security".into(),
                value_map([("psk", "test-secret".into()), ("psk-flags", 1_u32.into())])?,
            ),
            (
                "802-1x".into(),
                value_map([("password", "enterprise-secret".into())])?,
            ),
        ]);
        super::make_temporary(&mut settings)?;
        assert!(!settings["connection"].contains_key("uuid"));
        assert_eq!(
            setting::<bool>(&settings["connection"], "autoconnect"),
            Some(false)
        );
        assert_eq!(
            setting::<u32>(&settings["802-11-wireless-security"], "psk-flags"),
            Some(2)
        );
        assert_eq!(
            setting::<u32>(&settings["802-1x"], "password-flags"),
            Some(2)
        );
        assert_eq!(
            setting::<&str>(&settings["802-11-wireless-security"], "psk"),
            Some("test-secret")
        );
        Ok(())
    }
}
