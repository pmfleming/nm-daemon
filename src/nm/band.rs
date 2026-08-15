use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use super::{ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, Nm};
use crate::connect_wait::wait_for_active_target;
use crate::error::{DomainError, ErrorOperation};
use crate::generated::WIFI_BAND_CHECKPOINT_TIMEOUT;
use crate::model::{
    InterfaceName, NmObjectPath, WifiBand, WifiBandSelectionResult, WifiBandStatus,
    connect_target_for_network_key, ssid_hex,
};
use crate::variant::value_string;

impl Nm {
    pub(crate) fn wifi_band_status(&self, path: &str) -> Result<WifiBandStatus> {
        let path = OwnedObjectPath::try_from(path).context("parse Wi-Fi profile path")?;
        let profile = self.saved_wifi_connection_by_path(&path)?;
        let device = self.active_wifi_device_for_profile(&path)?.ok_or_else(|| {
            DomainError::not_found(
                ErrorOperation::BandOperation,
                format!("Wi-Fi profile {} is not active", profile.id),
            )
            .with_detail("path", profile.path.clone())
        })?;
        let active_ap_path = self.active_access_point(&device)?.ok_or_else(|| {
            DomainError::not_found(
                ErrorOperation::BandOperation,
                format!("active access point is unavailable for {}", profile.id),
            )
        })?;
        let active_ap = self.access_point(&device, &active_ap_path, true)?;
        let current = WifiBand::from_frequency_label(&active_ap.band).ok_or_else(|| {
            DomainError::new(
                crate::error::ErrorCode::Unknown,
                ErrorOperation::BandOperation,
                crate::error::ErrorSource::NetworkManager,
                format!("unsupported active Wi-Fi band: {}", active_ap.band),
            )
        })?;
        let settings = self.connection_settings(&path)?;
        let selected = selected_band(&settings);
        let active_security =
            crate::model::security_class(active_ap.flags, active_ap.wpa_flags, active_ap.rsn_flags);
        let mut available = self
            .list_all_access_points()?
            .into_iter()
            .filter(|ap| {
                ap.device_iface == device.iface
                    && ap.ssid_bytes().as_ref() == profile.ssid_bytes
                    && crate::model::security_class(ap.flags, ap.wpa_flags, ap.rsn_flags)
                        == active_security
            })
            .filter_map(|ap| WifiBand::from_frequency_label(&ap.band))
            .collect::<BTreeSet<_>>();
        available.insert(current);

        Ok(WifiBandStatus {
            path: profile.path,
            id: profile.id,
            ssid: profile.ssid,
            device_iface: device.iface,
            current,
            selected,
            available: available.into_iter().collect(),
        })
    }

    pub(crate) fn select_wifi_band(
        &self,
        path: &str,
        requested: WifiBand,
        cancellation: Option<&AtomicBool>,
    ) -> Result<WifiBandSelectionResult> {
        check_band_cancelled(cancellation)?;
        let _transaction = self
            .profile_transaction
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        check_band_cancelled(cancellation)?;
        let before = self.wifi_band_status(path)?;
        if requested != WifiBand::Auto && !before.available.contains(&requested) {
            return Err(DomainError::validation(
                ErrorOperation::BandOperation,
                format!("requested Wi-Fi band is not available for {}", before.ssid),
            )
            .with_detail("path", before.path)
            .with_detail(
                "requested",
                serde_json::to_value(requested).unwrap_or_default(),
            )
            .with_detail(
                "available",
                serde_json::to_value(&before.available).unwrap_or_default(),
            )
            .into());
        }
        if before.selected == requested
            && (requested == WifiBand::Auto || before.current == requested)
        {
            return Ok(WifiBandSelectionResult {
                status: "unchanged",
                changed: false,
                message: format!("Wi-Fi band selection for {} is unchanged", before.ssid),
                band: before,
            });
        }

        let profile_path = OwnedObjectPath::try_from(path).context("parse Wi-Fi profile path")?;
        let device = self
            .wifi_devices()?
            .into_iter()
            .find(|device| device.iface == before.device_iface)
            .ok_or_else(|| {
                DomainError::not_found(
                    ErrorOperation::BandOperation,
                    format!("active Wi-Fi device {} disappeared", before.device_iface),
                )
            })?;
        let profile = self.saved_wifi_connection_by_path(&profile_path)?;
        let original = self.connection_settings(&profile_path)?;
        let checkpoint = self.create_band_checkpoint(&device.path)?;

        let change = self
            .apply_band_and_reactivate(
                &profile_path,
                &device,
                &before,
                &profile.ssid_bytes,
                requested,
                cancellation,
            )
            .and_then(|()| check_band_cancelled(cancellation));
        if let Err(error) = change {
            self.rollback_band_change(&checkpoint, &profile_path, original);
            if cancellation.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                return Err(DomainError::cancelled_operation(
                    ErrorOperation::BandOperation,
                    "Wi-Fi band selection cancelled",
                )
                .into());
            }
            return Err(error);
        }

        if let Err(error) = self.destroy_checkpoint(&checkpoint) {
            self.rollback_band_change(&checkpoint, &profile_path, original);
            return Err(error);
        }
        let after = self.wifi_band_status(path)?;
        Ok(WifiBandSelectionResult {
            status: "selected",
            changed: true,
            message: format!("Wi-Fi band selection updated for {}", after.ssid),
            band: after,
        })
    }

    fn apply_band_and_reactivate(
        &self,
        profile_path: &OwnedObjectPath,
        device: &crate::model::WifiDevice,
        before: &WifiBandStatus,
        ssid_bytes: &[u8],
        requested: WifiBand,
        cancellation: Option<&AtomicBool>,
    ) -> Result<()> {
        let mut settings = self.connection_settings(profile_path)?;
        set_selected_band(&mut settings, requested)?;
        self.update_connection_settings(profile_path, settings, "Wi-Fi band selection")?;
        check_band_cancelled(cancellation)?;

        let root = OwnedObjectPath::try_from("/").context("create root object path")?;
        let _: OwnedObjectPath = self
            .root_proxy()
            .call("ActivateConnection", &(profile_path, &device.path, root))
            .with_context(|| format!("reactivate {} after Wi-Fi band selection", before.ssid))?;

        let key = format!("ssid-hex:{}", ssid_hex(ssid_bytes));
        let mut target = connect_target_for_network_key(&key, None)?;
        target.ifname = Some(InterfaceName::parse(device.iface.clone())?);
        target.device_path = Some(NmObjectPath::parse(device.path.to_string())?);
        wait_for_active_target(self, &target, cancellation)?;

        let status = self.wifi_band_status(profile_path.as_str())?;
        if requested != WifiBand::Auto && status.current != requested {
            return Err(DomainError::new(
                crate::error::ErrorCode::ActivationFailed,
                ErrorOperation::BandOperation,
                crate::error::ErrorSource::NetworkManager,
                format!(
                    "NetworkManager reconnected {} on a different band",
                    status.ssid
                ),
            )
            .with_detail(
                "requested",
                serde_json::to_value(requested).unwrap_or_default(),
            )
            .with_detail(
                "current",
                serde_json::to_value(status.current).unwrap_or_default(),
            )
            .into());
        }
        Ok(())
    }

    fn active_wifi_device_for_profile(
        &self,
        profile_path: &OwnedObjectPath,
    ) -> Result<Option<crate::model::WifiDevice>> {
        for device in self.wifi_devices()? {
            let proxy = self.proxy_path(&device.path, DEVICE_IFACE)?;
            let active_path: OwnedObjectPath = proxy
                .get_property("ActiveConnection")
                .with_context(|| format!("read ActiveConnection for {}", device.iface))?;
            if active_path.as_str() == "/" {
                continue;
            }
            let active = self.proxy_path(&active_path, ACTIVE_CONNECTION_IFACE)?;
            let connection_path: OwnedObjectPath = active
                .get_property("Connection")
                .with_context(|| format!("read active profile for {}", device.iface))?;
            let matches = connection_path == *profile_path;
            drop(active);
            drop(proxy);
            if matches {
                return Ok(Some(device));
            }
        }
        Ok(None)
    }

    fn create_band_checkpoint(&self, device_path: &OwnedObjectPath) -> Result<OwnedObjectPath> {
        let timeout_seconds = WIFI_BAND_CHECKPOINT_TIMEOUT
            .as_secs()
            .min(u64::from(u32::MAX)) as u32;
        self.root_proxy()
            .call(
                "CheckpointCreate",
                &(vec![device_path.clone()], timeout_seconds, 0_u32),
            )
            .context("create NetworkManager checkpoint for Wi-Fi band selection")
    }

    fn rollback_band_change(
        &self,
        checkpoint: &OwnedObjectPath,
        profile_path: &OwnedObjectPath,
        original: ConnectionSettings,
    ) {
        if let Err(error) =
            self.update_connection_settings(profile_path, original, "Wi-Fi band selection rollback")
        {
            tracing::error!(profile = %profile_path, error = %crate::error::err_chain(&error), "failed to restore Wi-Fi profile after band selection failure");
        }
        let rollback: Result<HashMap<String, u32>> = self
            .root_proxy()
            .call("CheckpointRollback", &(checkpoint.clone(),))
            .with_context(|| format!("roll back NetworkManager checkpoint {checkpoint}"));
        if let Err(error) = rollback {
            tracing::error!(checkpoint = %checkpoint, error = %crate::error::err_chain(&error), "failed to roll back Wi-Fi band checkpoint");
        }
        if let Err(error) = self.destroy_checkpoint(checkpoint) {
            tracing::warn!(checkpoint = %checkpoint, error = %crate::error::err_chain(&error), "failed to destroy rolled-back Wi-Fi band checkpoint");
        }
    }

    fn destroy_checkpoint(&self, checkpoint: &OwnedObjectPath) -> Result<()> {
        self.root_proxy()
            .call::<_, _, ()>("CheckpointDestroy", &(checkpoint.clone(),))
            .with_context(|| format!("destroy NetworkManager checkpoint {checkpoint}"))
    }
}

fn check_band_cancelled(cancellation: Option<&AtomicBool>) -> Result<()> {
    if cancellation.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
        Err(DomainError::cancelled_operation(
            ErrorOperation::BandOperation,
            "Wi-Fi band selection cancelled",
        )
        .into())
    } else {
        Ok(())
    }
}

fn selected_band(settings: &ConnectionSettings) -> WifiBand {
    settings
        .get("802-11-wireless")
        .and_then(|wireless| wireless.get("band"))
        .and_then(value_string)
        .map(|value| WifiBand::from_nm_value(&value))
        .unwrap_or(WifiBand::Auto)
}

fn set_selected_band(settings: &mut ConnectionSettings, band: WifiBand) -> Result<()> {
    let wireless = settings.entry("802-11-wireless".to_string()).or_default();
    if let Some(value) = band.nm_value() {
        wireless.insert("band".to_string(), super::owned_value(value.to_string())?);
    } else {
        wireless.remove("band");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{selected_band, set_selected_band};
    use crate::model::WifiBand;
    use crate::nm::ConnectionSettings;

    #[test]
    fn band_setting_round_trips_and_auto_removes_the_constraint() {
        let mut settings = ConnectionSettings::new();
        set_selected_band(&mut settings, WifiBand::Ghz6).unwrap();
        assert_eq!(selected_band(&settings), WifiBand::Ghz6);

        set_selected_band(&mut settings, WifiBand::Auto).unwrap();
        assert_eq!(selected_band(&settings), WifiBand::Auto);
        assert!(!settings["802-11-wireless"].contains_key("band"));
    }
}
