use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use super::settings::profile_secrets::{known_secret_keys, secret_flags_key};
use super::wifi_settings::{
    apply_saved_activation_settings, apply_target_connection_metadata,
    apply_target_profile_settings, cloned_wifi_connection_settings,
    hidden_wifi_connection_settings, visible_connection_settings,
};
use super::{ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, Nm};
use crate::model::{WepKeyType, WifiConnectTarget};

#[derive(Debug)]
pub(crate) struct WifiActivation {
    pub(crate) profile_path: OwnedObjectPath,
    pub(crate) active_path: OwnedObjectPath,
    pub(crate) scope: crate::activation::Guard,
}

impl Nm {
    pub(crate) fn activate_saved_wifi_connection_for(
        &self,
        target: &WifiConnectTarget,
        password: Option<&str>,
        wep_key_type: Option<WepKeyType>,
    ) -> Result<Option<WifiActivation>> {
        if target.profile.remember == Some(false) {
            return Ok(None); // Never update a saved profile for a temporary join.
        }
        let Some((connection_path, device_path, specific_object)) =
            self.saved_wifi_activation_target_for(target)?
        else {
            return Ok(None);
        };
        self.prepare_saved_activation(&connection_path, target, password, wep_key_type)?;
        let scope = self.activation_scope(
            &self.connection_settings(&connection_path)?,
            connection_path.as_str(),
        )?;
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
                &(connection_path.clone(), device_path, specific_object),
            )
            .with_context(|| format!("ActivateConnection for saved Wi-Fi profile {}", target.ssid))
            .map_err(|error| scope.state.activation_error(error))?;
        Ok(Some(WifiActivation {
            profile_path: connection_path,
            active_path: active_connection,
            scope,
        }))
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
        let settings = self.connection_settings(connection_path)?;
        super::profile_policy::validate_private_ca_paths(
            &settings,
            crate::error::ErrorOperation::Connect,
        )?;
        // Agent ownership describes where NM obtains credentials, not whether
        // activation can succeed. Never probe GetSecrets or rewrite a profile
        // just to connect: let ActivateConnection consult NM's registered agents.
        if super::settings::wifi_settings_need_secret_agent(&settings, None, None) {
            tracing::debug!(connection = %connection_path, "saved profile delegates credentials to NetworkManager agents");
        }
        Ok(())
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
        }
        // Supply a fresh UUID before activation so even an immediate GetSecrets
        // callback can bind to this exact profile and deadline.
        settings
            .entry("connection".into())
            .or_default()
            .entry("uuid".into())
            .or_insert(super::owned_value(uuid::Uuid::new_v4().to_string())?);
        let scope = self.activation_scope(&settings, "/")?;
        if target.profile.remember == Some(false) {
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
                .with_context(|| format!("temporary activation for Wi-Fi network {ssid}"))
                .map_err(|error| scope.state.activation_error(error))?;
            return Ok(WifiActivation {
                profile_path,
                active_path,
                scope,
            });
        }
        let (profile_path, active_path): (OwnedObjectPath, OwnedObjectPath) = nm
            .call(
                "AddAndActivateConnection",
                &(settings, device_path, specific_object),
            )
            .with_context(|| format!("AddAndActivateConnection for Wi-Fi network {ssid}"))
            .map_err(|error| scope.state.activation_error(error))?;
        Ok(WifiActivation {
            profile_path,
            active_path,
            scope,
        })
    }

    fn activation_scope(
        &self,
        settings: &ConnectionSettings,
        path: &str,
    ) -> Result<crate::activation::Guard> {
        let events = self.events.clone();
        Ok(crate::activation::Guard::new(
            self.current_owner()?,
            crate::activation::identity(settings, path),
            std::time::Instant::now() + crate::generated::ACTIVATION_TIMEOUT,
            move || events.notify(),
        ))
    }

    pub(crate) fn abort_requested_activation(&self, path: &OwnedObjectPath) -> Result<()> {
        self.ensure_current_owner()?;
        self.root_proxy()
            .call::<_, _, ()>("DeactivateConnection", &(path,))
            .context("abort owned Wi-Fi activation")
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
    for (setting, section) in settings
        .iter_mut()
        .filter(|(name, _)| matches!(name.as_str(), "802-11-wireless-security" | "802-1x"))
    {
        for key in known_secret_keys(setting) {
            section.insert(secret_flags_key(key), super::owned_value(2_u32)?); // NOT_SAVED
        }
    }
    Ok(())
}

fn root_object_path() -> Result<OwnedObjectPath> {
    OwnedObjectPath::try_from("/").context("create root object path")
}
