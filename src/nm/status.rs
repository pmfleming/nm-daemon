use anyhow::{Context, Result};
use zbus::blocking::Proxy;
use zvariant::{OwnedObjectPath, OwnedValue};

use super::inventory::{active_connection_state_name, device_state_name};
use super::{
    ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, NM_DEVICE_TYPE_MODEM,
    NM_DEVICE_TYPE_WIFI, Nm, RadioRestoreState, SETTINGS_CONNECTION_IFACE, WIFI_IFACE,
};
use crate::command::nmcli::Nmcli;
use crate::error::ErrorOperation;
use crate::model::{
    DisconnectResult, Ip4Status, LinkStateStatus, MeteredStatus, RadioPowerResult, RadioStatus,
    SavedWifiConnection, WifiDevice, WifiPowerResult, WifiStatus, WirelessStatus,
    device_state_reason,
};

#[derive(Clone, Copy)]
enum Radio {
    Wireless,
    Wwan,
}

#[derive(Clone, Copy)]
struct RadioSwitches {
    wireless: bool,
    wwan: bool,
}

impl RadioRestoreState {
    fn record_direct_change(&mut self, radio: Radio, enabled: bool) {
        if !self.airplane_mode || enabled {
            match radio {
                Radio::Wireless => self.wireless_enabled = enabled,
                Radio::Wwan => self.wwan_enabled = enabled,
            }
        }
        self.airplane_mode &= !enabled;
    }

    fn target_switches(&self, enabled: bool) -> Option<RadioSwitches> {
        if !enabled && !self.airplane_mode {
            return None;
        }
        Some(if enabled {
            RadioSwitches {
                wireless: false,
                wwan: false,
            }
        } else {
            RadioSwitches {
                wireless: self.wireless_enabled,
                wwan: self.wwan_enabled,
            }
        })
    }

    fn commit_airplane(&mut self, enabled: bool, current: RadioSwitches, target: RadioSwitches) {
        if enabled && !self.airplane_mode {
            self.wireless_enabled = current.wireless;
            self.wwan_enabled = current.wwan;
        } else if !enabled {
            self.wireless_enabled = target.wireless;
            self.wwan_enabled = target.wwan;
        }
        self.airplane_mode = enabled;
    }
}

impl Nm {
    pub(crate) fn wifi_status(&self) -> Result<WifiStatus> {
        let radios = self.radio_status()?;
        let enabled = radios.wireless_enabled;
        let profiles = self.saved_wifi_connections()?;
        let connectivity = self.connectivity_check().ok();

        for device in self.wifi_devices()? {
            if let Some(status) =
                self.wifi_status_for_device(&device, &profiles, &connectivity, &radios)?
            {
                return Ok(status);
            }
        }

        Ok(WifiStatus::inactive(enabled, radios, None, connectivity))
    }

    pub(crate) fn set_wireless_enabled(&self, enabled: bool) -> Result<WifiPowerResult> {
        set_radio_enabled(self, Radio::Wireless, "WirelessEnabled", enabled)?;
        Ok(WifiPowerResult {
            enabled,
            message: format!("Wi-Fi turned {}", if enabled { "on" } else { "off" }),
        })
    }

    pub(crate) fn radio_status(&self) -> Result<RadioStatus> {
        let root = self.root_proxy();
        let wireless_enabled = root
            .get_property("WirelessEnabled")
            .context("read NetworkManager WirelessEnabled")?;
        let wireless_hardware_enabled =
            root.get_property("WirelessHardwareEnabled").unwrap_or(true);
        let wwan_enabled = root.get_property("WwanEnabled").unwrap_or(false);
        let wwan_hardware_enabled = root.get_property("WwanHardwareEnabled").unwrap_or(true);
        let (wireless_available, wwan_available) = self.radio_device_availability()?;
        let mut restore = self.radio_restore_state();
        if restore.airplane_mode && (wireless_enabled || wwan_enabled) {
            tracing::info!(
                wireless_enabled,
                wwan_enabled,
                "clearing stale airplane-mode state after an external radio change"
            );
            restore.airplane_mode = false;
        }
        let airplane_mode = restore.airplane_mode;
        drop(restore);
        Ok(RadioStatus {
            wireless_enabled,
            wireless_hardware_enabled,
            wireless_available,
            wwan_enabled,
            wwan_hardware_enabled,
            wwan_available,
            airplane_mode,
        })
    }

    fn radio_device_availability(&self) -> Result<(bool, bool)> {
        let paths: Vec<OwnedObjectPath> = self
            .root_proxy()
            .call("GetDevices", &())
            .context("GetDevices for radio status")?;
        let mut wireless = false;
        let mut wwan = false;
        for path in paths {
            let device = self.proxy_path(&path, DEVICE_IFACE)?;
            let device_type: u32 = device.get_property("DeviceType").unwrap_or(0);
            wireless |= device_type == NM_DEVICE_TYPE_WIFI;
            wwan |= device_type == NM_DEVICE_TYPE_MODEM;
        }
        Ok((wireless, wwan))
    }

    pub(crate) fn set_wwan_enabled(&self, enabled: bool) -> Result<RadioPowerResult> {
        set_radio_enabled(self, Radio::Wwan, "WwanEnabled", enabled)?;
        Ok(RadioPowerResult {
            radios: self.radio_status()?,
            message: format!("Mobile data turned {}", if enabled { "on" } else { "off" }),
        })
    }

    pub(crate) fn set_airplane_mode(&self, enabled: bool) -> Result<RadioPowerResult> {
        let root = self.root_proxy();
        let mut restore = self.radio_restore_state();
        let target = restore.target_switches(enabled);
        if let Some(target) = target {
            let current = read_radio_switches(&root)?;
            apply_radio_switches(&root, current, target)?;
            restore.commit_airplane(enabled, current, target);
        }
        drop(restore);
        if target.is_some() {
            self.wake_waiters();
        }
        Ok(RadioPowerResult {
            radios: self.radio_status()?,
            message: format!(
                "Airplane mode {}",
                if enabled { "enabled" } else { "disabled" }
            ),
        })
    }

    fn wifi_status_for_device(
        &self,
        device: &WifiDevice,
        profiles: &[SavedWifiConnection],
        connectivity: &Option<crate::model::ConnectivityStatus>,
        radios: &RadioStatus,
    ) -> Result<Option<WifiStatus>> {
        let Some(active_connection_path) = self.device_active_connection_path(&device.path)? else {
            return Ok(None);
        };
        self.active_wifi_status(
            device,
            active_connection_path,
            profiles,
            connectivity,
            radios,
        )
    }

    fn active_wifi_status(
        &self,
        device: &WifiDevice,
        active_connection_path: OwnedObjectPath,
        profiles: &[SavedWifiConnection],
        connectivity: &Option<crate::model::ConnectivityStatus>,
        radios: &RadioStatus,
    ) -> Result<Option<WifiStatus>> {
        let Some(active_ap_path) = self.active_access_point(device)? else {
            return Ok(None);
        };
        let access_point = self.access_point(device, &active_ap_path, true)?;
        let entry = self
            .network_entries_for_access_points(vec![access_point.clone()])?
            .into_iter()
            .next();
        let active_profile_path = self.active_connection_profile_path(&active_connection_path);
        let profile = active_profile_path
            .as_ref()
            .and_then(|path| active_connection_profile(path, profiles))
            .or_else(|| entry.as_ref()?.primary_profile.clone());
        let active_since_ms = active_profile_path
            .as_ref()
            .and_then(|path| self.connection_timestamp_ms(path));

        Ok(Some(WifiStatus {
            enabled: radios.wireless_enabled,
            radios: radios.clone(),
            active: true,
            device_iface: Some(device.iface.clone()),
            device_path: Some(device.path.to_string()),
            active_connection_path: Some(active_connection_path.to_string()),
            access_point: Some(access_point),
            network: entry,
            profile,
            connectivity: connectivity.clone(),
            ip4: self.enriched_ip4_status(device),
            ip6: self.device_ip6_status(&device.path).ok().flatten(),
            wireless: self.wireless_status(device).ok(),
            metered: self.metered_status(&device.path).ok(),
            active_since_ms,
            link: self.link_state_status(device, &active_connection_path),
        }))
    }

    fn link_state_status(
        &self,
        device: &WifiDevice,
        active_connection_path: &OwnedObjectPath,
    ) -> Option<LinkStateStatus> {
        let device_proxy = self.proxy_path(&device.path, DEVICE_IFACE).ok()?;
        let device_state: u32 = device_proxy.get_property("State").ok()?;
        let (_, reason_code): (u32, u32) = device_proxy
            .get_property("StateReason")
            .unwrap_or((device_state, 0));
        drop(device_proxy);
        let active = self
            .proxy_path(active_connection_path, ACTIVE_CONNECTION_IFACE)
            .ok();
        let active_connection_state: Option<u32> = active
            .as_ref()
            .and_then(|proxy| proxy.get_property("State").ok());
        let primary = self
            .root_proxy()
            .get_property::<OwnedObjectPath>("PrimaryConnection")
            .is_ok_and(|primary| primary.as_str() == active_connection_path.as_str());
        Some(LinkStateStatus {
            device_state,
            device_state_name: device_state_name(device_state),
            device_state_reason: device_state_reason(reason_code),
            active_connection_state,
            active_connection_state_name: active_connection_state.map(active_connection_state_name),
            active_connection_state_flags: active
                .as_ref()
                .and_then(|proxy| proxy.get_property("StateFlags").ok()),
            primary,
            default4: active
                .as_ref()
                .and_then(|proxy| proxy.get_property("Default").ok())
                .unwrap_or(false),
            default6: active
                .as_ref()
                .and_then(|proxy| proxy.get_property("Default6").ok())
                .unwrap_or(false),
        })
    }

    fn enriched_ip4_status(&self, device: &WifiDevice) -> Option<Ip4Status> {
        let dbus_ip4 = self.device_ip4_status(&device.path).ok().flatten();
        if !ip4_status_needs_nmcli_fill(&dbus_ip4) {
            return dbus_ip4;
        }
        let nmcli_ip4 = Nmcli::new(self.command_runner())
            .device_ip4(&device.iface, ErrorOperation::Status)
            .inspect_err(|error| {
                tracing::debug!(error = %crate::error::err_chain(&error), "nmcli IPv4 enrichment unavailable")
            })
            .ok()
            .flatten();
        merged_ip4_status(dbus_ip4, nmcli_ip4)
    }

    pub(crate) fn disconnect_wifi(&self) -> Result<DisconnectResult> {
        let Some(active_connection_path) = self.active_wifi_connection_path()? else {
            return Ok(DisconnectResult {
                status: "noop",
                message: "No active Wi-Fi connection".to_string(),
            });
        };
        self.deactivate_wifi_connection(active_connection_path, "Disconnected Wi-Fi".to_string())
    }

    pub(crate) fn disconnect_wifi_for_ssid(&self, target_ssid: &[u8]) -> Result<DisconnectResult> {
        for device in self.wifi_devices()? {
            let Some(active_connection_path) = self.device_active_connection_path(&device.path)?
            else {
                continue;
            };
            if !self.active_connection_matches_ssid(&active_connection_path, target_ssid)? {
                continue;
            }
            return self.deactivate_wifi_connection(
                active_connection_path,
                format!(
                    "Cancelled connection to {}",
                    crate::model::display_ssid(target_ssid)
                ),
            );
        }
        Ok(DisconnectResult {
            status: "noop",
            message: format!(
                "Cancelled target {} is no longer active or activating",
                crate::model::display_ssid(target_ssid)
            ),
        })
    }

    fn deactivate_wifi_connection(
        &self,
        active_connection_path: OwnedObjectPath,
        message: String,
    ) -> Result<DisconnectResult> {
        tracing::info!(connection = %active_connection_path, "deactivating active Wi-Fi connection");
        let nm = self.root_proxy();
        nm.call::<_, _, ()>("DeactivateConnection", &(active_connection_path,))
            .context("DeactivateConnection for active Wi-Fi connection")?;
        Ok(DisconnectResult {
            status: "disconnected",
            message,
        })
    }

    fn active_connection_matches_ssid(
        &self,
        active_connection_path: &OwnedObjectPath,
        target_ssid: &[u8],
    ) -> Result<bool> {
        let Some(profile_path) = self.active_connection_profile_path(active_connection_path) else {
            tracing::debug!(connection = %active_connection_path, "could not verify active Wi-Fi profile; skipping targeted disconnect");
            return Ok(false);
        };
        self.connection_matches_ssid(&profile_path, target_ssid)
    }

    fn active_wifi_connection_path(&self) -> Result<Option<OwnedObjectPath>> {
        for device in self.wifi_devices()? {
            if let Some(path) = self.device_active_connection_path(&device.path)? {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    fn device_active_connection_path(
        &self,
        device_path: &OwnedObjectPath,
    ) -> Result<Option<OwnedObjectPath>> {
        let device = self.proxy_path(device_path, DEVICE_IFACE)?;
        let active_connection_path: OwnedObjectPath = device
            .get_property("ActiveConnection")
            .with_context(|| format!("read ActiveConnection for {device_path}"))?;
        Ok((active_connection_path.as_str() != "/").then_some(active_connection_path))
    }

    fn active_connection_profile_path(
        &self,
        active_connection_path: &OwnedObjectPath,
    ) -> Option<OwnedObjectPath> {
        self.proxy_path(active_connection_path, ACTIVE_CONNECTION_IFACE)
            .and_then(|proxy| {
                proxy
                    .get_property("Connection")
                    .context("read active profile path")
            })
            .ok()
    }

    fn connection_timestamp_ms(&self, connection_path: &OwnedObjectPath) -> Option<u64> {
        let connection = self
            .proxy_path(connection_path, SETTINGS_CONNECTION_IFACE)
            .ok()?;
        let settings: ConnectionSettings = connection.call("GetSettings", &()).ok()?;
        settings
            .get("connection")?
            .get("timestamp")
            .and_then(value_u64)
            .map(|seconds| seconds.saturating_mul(1000))
    }

    fn wireless_status(&self, device: &crate::model::WifiDevice) -> Result<WirelessStatus> {
        let wifi = self.proxy_path(&device.path, WIFI_IFACE)?;
        let bitrate_kbps: Option<u32> = wifi.get_property("Bitrate").ok();
        let directional_bitrates = self
            .wireless_telemetry()
            .link_bitrates(&device.iface)
            .inspect_err(|error| {
                tracing::debug!(error = %crate::error::err_chain(&error), "nl80211 bitrate enrichment unavailable")
            })
            .unwrap_or_default();
        Ok(WirelessStatus {
            bitrate_mbps: bitrate_kbps.map(|value| value / 1000),
            tx_bitrate_mbps: directional_bitrates.tx_mbps,
            rx_bitrate_mbps: directional_bitrates.rx_mbps,
            mac_address: wifi.get_property("HwAddress").ok(),
        })
    }

    fn metered_status(&self, device_path: &OwnedObjectPath) -> Result<MeteredStatus> {
        let device = self.proxy_path(device_path, DEVICE_IFACE)?;
        let metered_code = device
            .get_property("Metered")
            .with_context(|| format!("read Metered for {device_path}"))?;
        Ok(MeteredStatus::from_nm_code(metered_code))
    }
}

fn set_radio_enabled(nm: &Nm, radio: Radio, property: &str, enabled: bool) -> Result<()> {
    let mut state = nm.radio_restore_state();
    nm.root_proxy()
        .set_property(property, enabled)
        .with_context(|| format!("set NetworkManager {property}"))?;
    state.record_direct_change(radio, enabled);
    drop(state);
    nm.wake_waiters();
    Ok(())
}

fn read_radio_switches(root: &Proxy<'_>) -> Result<RadioSwitches> {
    Ok(RadioSwitches {
        wireless: root
            .get_property("WirelessEnabled")
            .context("read Wi-Fi before airplane-mode change")?,
        wwan: root
            .get_property("WwanEnabled")
            .context("read WWAN before airplane-mode change")?,
    })
}

fn apply_radio_switches(
    root: &Proxy<'_>,
    current: RadioSwitches,
    target: RadioSwitches,
) -> Result<()> {
    root.set_property("WirelessEnabled", target.wireless)
        .context("set Wi-Fi for airplane mode")?;
    root.set_property("WwanEnabled", target.wwan)
        .inspect_err(|_| rollback_wireless(root, current.wireless))
        .context("set WWAN for airplane mode")
}

fn rollback_wireless(root: &Proxy<'_>, enabled: bool) {
    if let Err(error) = root.set_property("WirelessEnabled", enabled) {
        tracing::error!(%error, "failed to roll back Wi-Fi after airplane-mode WWAN update failed");
    }
}

fn ip4_status_needs_nmcli_fill(status: &Option<Ip4Status>) -> bool {
    let Some(status) = status else {
        return true;
    };
    status.address.as_deref().is_none_or(str::is_empty)
        || status.gateway.as_deref().is_none_or(str::is_empty)
        || status.dns.is_empty()
}

fn merged_ip4_status(dbus: Option<Ip4Status>, nmcli: Option<Ip4Status>) -> Option<Ip4Status> {
    match dbus {
        Some(mut dbus) => {
            if let Some(nmcli) = nmcli {
                fill_missing_ip4_fields(&mut dbus, nmcli);
            }
            Some(dbus)
        }
        None => nmcli,
    }
}

fn fill_missing_ip4_fields(dbus: &mut Ip4Status, mut fallback: Ip4Status) {
    if dbus.address.as_deref().is_none_or(str::is_empty) {
        dbus.address = fallback.address.take();
        dbus.prefix = fallback.prefix;
    }
    if dbus.gateway.as_deref().is_none_or(str::is_empty) {
        dbus.gateway = fallback.gateway.take();
    }
    if dbus.dns.is_empty() {
        dbus.dns = fallback.dns;
    }
}

fn active_connection_profile(
    connection_path: &OwnedObjectPath,
    profiles: &[SavedWifiConnection],
) -> Option<SavedWifiConnection> {
    profiles
        .iter()
        .find(|profile| profile.path == connection_path.to_string())
        .cloned()
}

fn value_u64(value: &OwnedValue) -> Option<u64> {
    value.try_clone().ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::{Radio, ip4_status_needs_nmcli_fill};
    use crate::model::Ip4Status;
    use crate::nm::RadioRestoreState;

    #[test]
    fn direct_radio_changes_preserve_and_exit_airplane_restore_state() {
        let mut state = RadioRestoreState {
            airplane_mode: true,
            wireless_enabled: true,
            wwan_enabled: true,
        };
        state.record_direct_change(Radio::Wireless, false);
        assert!(state.airplane_mode && state.wireless_enabled);
        state.record_direct_change(Radio::Wireless, true);
        assert!(!state.airplane_mode && state.wireless_enabled);
    }

    fn empty_ip4() -> Ip4Status {
        Ip4Status {
            address: None,
            prefix: None,
            addresses: Vec::new(),
            gateway: None,
            dns: Vec::new(),
            domains: Vec::new(),
            searches: Vec::new(),
            routes: Vec::new(),
            dhcp_lease: None,
        }
    }

    #[test]
    fn fills_ip4_from_nmcli_only_when_dbus_status_is_incomplete() {
        assert!(ip4_status_needs_nmcli_fill(&None));
        assert!(ip4_status_needs_nmcli_fill(&Some(Ip4Status {
            address: Some("10.0.0.2".to_string()),
            prefix: Some(24),
            gateway: None,
            dns: vec!["10.0.0.1".to_string()],
            dhcp_lease: None,
            ..empty_ip4()
        })));
        assert!(!ip4_status_needs_nmcli_fill(&Some(Ip4Status {
            address: Some("10.0.0.2".to_string()),
            prefix: Some(24),
            gateway: Some("10.0.0.1".to_string()),
            dns: vec!["10.0.0.1".to_string()],
            dhcp_lease: None,
            ..empty_ip4()
        })));
    }
}
