use std::collections::BTreeSet;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use super::{ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, Nm};
use crate::connect_wait::wait_for_active_target;
use crate::error::{DomainError, ErrorOperation, cancellation_requested, check_cancellation};
use crate::model::{
    InterfaceName, NmObjectPath, WifiBand, WifiBandSelectionResult, WifiBandStatus, WifiDevice,
    connect_target_for_network_key, ssid_hex,
};
use crate::variant::value_string;

struct BandChange {
    profile_path: OwnedObjectPath,
    device: WifiDevice,
    before: WifiBandStatus,
    ssid_bytes: Vec<u8>,
    original: ConnectionSettings,
}

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
        let _transaction = self.begin_profile_transaction();
        check_band_cancelled(cancellation)?;
        let before = self.wifi_band_status(path)?;
        validate_requested_band(&before, requested)?;
        if band_selection_is_unchanged(&before, requested) {
            return Ok(unchanged_band_selection(before));
        }

        let change = self.prepare_band_change(path, before)?;
        self.commit_band_change(change, requested, cancellation)?;
        let after = self.wifi_band_status(path)?;
        Ok(WifiBandSelectionResult {
            status: "selected",
            changed: true,
            message: format!("Wi-Fi band selection updated for {}", after.ssid),
            band: after,
        })
    }

    fn prepare_band_change(&self, path: &str, before: WifiBandStatus) -> Result<BandChange> {
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
        let original = self.begin_credential_edit(&profile_path)?.settings;
        Ok(BandChange {
            profile_path,
            device,
            before,
            ssid_bytes: profile.ssid_bytes,
            original,
        })
    }

    fn commit_band_change(
        &self,
        change: BandChange,
        requested: WifiBand,
        cancellation: Option<&AtomicBool>,
    ) -> Result<()> {
        let mut edit = self.begin_credential_edit(&change.profile_path)?;
        ensure_same_band_target(&edit.settings, &change.original)?;
        anyhow::ensure!(
            selected_band(&edit.settings) == selected_band(&change.original),
            "band changed before update; retry explicitly"
        );
        set_selected_band(&mut edit.settings, requested)?;
        self.commit_credential_edit(edit, false)?;
        let result = self
            .reactivate_band(
                &change.profile_path,
                &change.device,
                &change.before,
                &change.ssid_bytes,
                requested,
                cancellation,
            )
            .and_then(|()| check_band_cancelled(cancellation));
        if let Err(error) = result {
            if let Err(rollback) = self.rollback_band_change(&change, requested) {
                return Err(error.context(format!("Band recovery was not confirmed; inspect the current connection before retrying: {rollback}")));
            }
            return Err(normalize_band_change_error(error, cancellation));
        }
        Ok(())
    }

    fn reactivate_band(
        &self,
        profile_path: &OwnedObjectPath,
        device: &crate::model::WifiDevice,
        before: &WifiBandStatus,
        ssid_bytes: &[u8],
        requested: WifiBand,
        cancellation: Option<&AtomicBool>,
    ) -> Result<()> {
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

    fn rollback_band_change(&self, change: &BandChange, requested: WifiBand) -> Result<()> {
        let mut edit = self.begin_credential_edit(&change.profile_path)?;
        ensure_same_band_target(&edit.settings, &change.original)?;
        restore_band_fields(&mut edit.settings, &change.original, requested)?;
        self.commit_credential_edit(edit, false)?;
        // A whole NM checkpoint can restore stale passwords, ACLs and IP policy.
        // Compensate only our band field, using the current profile and
        // a fresh version fence. Never restore a secret-bearing old snapshot.
        let device = self.proxy_path(&change.device.path, DEVICE_IFACE)?;
        let active: OwnedObjectPath = device.get_property("ActiveConnection")?;
        if active.as_str() != "/" {
            let active = self.proxy_path(&active, ACTIVE_CONNECTION_IFACE)?;
            let current: OwnedObjectPath = active.get_property("Connection")?;
            anyhow::ensure!(
                current == change.profile_path,
                "another profile is active; recovery will not reconnect it"
            );
        }
        let root = OwnedObjectPath::try_from("/")?;
        let _: OwnedObjectPath = self.root_proxy().call(
            "ActivateConnection",
            &(&change.profile_path, &change.device.path, root),
        )?;
        Ok(())
    }
}

fn ensure_same_band_target(
    current: &ConnectionSettings,
    original: &ConnectionSettings,
) -> Result<()> {
    for (section, key) in [("connection", "uuid"), ("802-11-wireless", "ssid")] {
        anyhow::ensure!(
            current.get(section).and_then(|s| s.get(key))
                == original.get(section).and_then(|s| s.get(key)),
            "profile identity changed; band operation cancelled"
        );
    }
    Ok(())
}

fn restore_band_fields(
    current: &mut ConnectionSettings,
    original: &ConnectionSettings,
    applied: WifiBand,
) -> Result<()> {
    anyhow::ensure!(
        selected_band(current) == applied,
        "band changed externally; recovery cancelled"
    );
    let before = original.get("802-11-wireless").and_then(|s| s.get("band"));
    let section = current.entry("802-11-wireless".into()).or_default();
    match before {
        Some(value) => {
            section.insert("band".into(), value.try_clone()?);
        }
        None => {
            section.remove("band");
        }
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn band_compensation_preserves_current_credentials_and_unrelated_edits() -> Result<()> {
    let mut original = ConnectionSettings::new();
    set_selected_band(&mut original, WifiBand::Auto)?;
    let mut current = original.clone();
    set_selected_band(&mut current, WifiBand::Ghz5)?;
    current.insert(
        "802-11-wireless-security".into(),
        crate::variant::value_map([("psk", "new-credential".into())])?,
    );
    current.insert(
        "connection".into(),
        crate::variant::value_map([("id", "concurrent-edit".into())])?,
    );
    let keep = current.clone();
    restore_band_fields(&mut current, &original, WifiBand::Ghz5)?;
    assert_eq!(current["connection"], keep["connection"]);
    assert_eq!(
        current["802-11-wireless-security"],
        keep["802-11-wireless-security"]
    );
    set_selected_band(&mut current, WifiBand::Ghz6)?;
    assert!(restore_band_fields(&mut current, &original, WifiBand::Ghz5).is_err());
    current.get_mut("802-11-wireless").unwrap().insert(
        "ssid".into(),
        super::owned_value(b"another-network".to_vec())?,
    );
    assert!(ensure_same_band_target(&current, &original).is_err());
    Ok(())
}

fn validate_requested_band(before: &WifiBandStatus, requested: WifiBand) -> Result<()> {
    if requested == WifiBand::Auto || before.available.contains(&requested) {
        return Ok(());
    }
    Err(DomainError::validation(
        ErrorOperation::BandOperation,
        format!("requested Wi-Fi band is not available for {}", before.ssid),
    )
    .with_detail("path", before.path.clone())
    .with_detail(
        "requested",
        serde_json::to_value(requested).unwrap_or_default(),
    )
    .with_detail(
        "available",
        serde_json::to_value(&before.available).unwrap_or_default(),
    )
    .into())
}

fn band_selection_is_unchanged(before: &WifiBandStatus, requested: WifiBand) -> bool {
    before.selected == requested && (requested == WifiBand::Auto || before.current == requested)
}

fn unchanged_band_selection(before: WifiBandStatus) -> WifiBandSelectionResult {
    WifiBandSelectionResult {
        status: "unchanged",
        changed: false,
        message: format!("Wi-Fi band selection for {} is unchanged", before.ssid),
        band: before,
    }
}

fn normalize_band_change_error(
    error: anyhow::Error,
    cancellation: Option<&AtomicBool>,
) -> anyhow::Error {
    if cancellation_requested(cancellation) {
        DomainError::cancelled_operation(
            ErrorOperation::BandOperation,
            "Wi-Fi band selection cancelled",
        )
        .into()
    } else {
        error
    }
}

fn check_band_cancelled(cancellation: Option<&AtomicBool>) -> Result<()> {
    check_cancellation(
        cancellation,
        ErrorOperation::BandOperation,
        "Wi-Fi band selection cancelled",
    )
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
