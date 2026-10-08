use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use zvariant::{OwnedObjectPath, OwnedValue};

use super::inventory::device_state_name;
use super::{
    ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE,
    NM_ACTIVE_CONNECTION_STATE_ACTIVATED, Nm, WIFI_IFACE, owned_value,
};
use crate::error::{DomainError, ErrorOperation, check_cancellation};
use crate::model::{
    HotspotCapabilities, HotspotDevice, HotspotSecurity, HotspotShare, HotspotStartResult,
    HotspotStatus, HotspotStopResult, HotspotUnavailableReason, WifiBand, display_ssid, ssid_hex,
    validate_ssid_bytes, wifi_qr_payload,
};
use crate::random::{random_passphrase, random_uuid_v4};
use crate::variant::{insert_optional_value, setting, value_list, value_map};

/// NM_WIFI_DEVICE_CAP_* bits this module depends on.
const CAP_AP: u32 = 0x40;
const CAP_FREQ_2GHZ: u32 = 0x200;
const CAP_FREQ_5GHZ: u32 = 0x400;
/// NM_802_11_MODE_AP.
const WIFI_MODE_AP: u32 = 3;
const GENERATED_PASSPHRASE_LEN: usize = 12;
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(20);
const ACTIVATION_POLL: Duration = Duration::from_millis(200);

/// Validated hotspot start request; secrets stay in memory and are never logged.
pub(crate) struct HotspotRequest {
    pub(crate) ssid: Option<String>,
    pub(crate) passphrase: Option<String>,
    pub(crate) security: HotspotSecurity,
    pub(crate) band: WifiBand,
    pub(crate) channel: Option<u32>,
    pub(crate) hidden: bool,
    pub(crate) device: Option<String>,
}

struct ResolvedHotspot {
    ssid: String,
    ssid_bytes: Vec<u8>,
    passphrase: String,
    generated_passphrase: bool,
    generated_ssid: bool,
    device: HotspotDevice,
    band: WifiBand,
    channel: Option<u32>,
}

impl Nm {
    pub(crate) fn hotspot_capabilities(&self) -> Result<HotspotCapabilities> {
        let devices = self.hotspot_devices()?;
        let wireless_enabled: bool = self
            .root_proxy()
            .get_property("WirelessEnabled")
            .unwrap_or(false);
        let recommended = devices
            .iter()
            .find(|device| available_hotspot_device(device));
        let (unsupported_reason, message) =
            hotspot_availability(&devices, wireless_enabled, recommended.is_some());
        Ok(HotspotCapabilities {
            supported: unsupported_reason.is_none(),
            unsupported_reason,
            message,
            recommended_device: recommended.map(|device| device.path.clone()),
            supported_bands: vec![WifiBand::Auto, WifiBand::Ghz2_4, WifiBand::Ghz5],
            supported_security: vec![HotspotSecurity::WpaPsk, HotspotSecurity::Sae],
            devices,
        })
    }

    pub(crate) fn hotspot_status(&self) -> Result<HotspotStatus> {
        for device in self.hotspot_devices()? {
            if let Some(status) = self.hotspot_status_for_device(device)? {
                return Ok(status);
            }
        }
        Ok(HotspotStatus::default())
    }

    pub(crate) fn start_hotspot(
        &self,
        request: &HotspotRequest,
        cancellation: Option<&AtomicBool>,
    ) -> Result<HotspotStartResult> {
        let _transaction = self.begin_profile_transaction();
        if let Some(active) = self.hotspot_status()?.ssid {
            return Err(DomainError::validation(
                ErrorOperation::HotspotOperation,
                format!("a hotspot is already running for {active}"),
            )
            .into());
        }
        let resolved = self.resolve_hotspot(request)?;
        check_cancellation(
            cancellation,
            ErrorOperation::HotspotOperation,
            "hotspot start was cancelled",
        )?;
        let settings = hotspot_connection_settings(&resolved, request)?;
        tracing::info!(
            ssid = %resolved.ssid,
            iface = %resolved.device.interface,
            band = ?resolved.band,
            security = ?request.security,
            hidden = request.hidden,
            "starting NetworkManager Wi-Fi hotspot"
        );
        let (profile_path, active_path) = self.add_and_activate_hotspot(&resolved, settings)?;
        match self.await_hotspot_activation(&active_path, cancellation) {
            Ok(()) => Ok(Self::started_hotspot_result(
                request,
                resolved,
                profile_path,
                active_path,
            )),
            Err(error) => {
                self.roll_back_hotspot(&profile_path, &active_path);
                Err(error)
            }
        }
    }

    pub(crate) fn stop_hotspot(&self) -> Result<HotspotStopResult> {
        let status = self.hotspot_status()?;
        let (Some(active_connection), Some(ssid)) = (status.active_connection, status.ssid) else {
            return Ok(HotspotStopResult {
                status: "noop",
                message: "No hotspot is running".to_string(),
                ssid: None,
                device_iface: None,
            });
        };
        let active_path =
            OwnedObjectPath::try_from(active_connection.as_str()).context("parse hotspot path")?;
        let profile_path = status
            .profile_path
            .as_deref()
            .and_then(|path| OwnedObjectPath::try_from(path).ok());
        tracing::info!(ssid = %ssid, "stopping NetworkManager Wi-Fi hotspot");
        self.root_proxy()
            .call::<_, _, ()>("DeactivateConnection", &(active_path,))
            .context("DeactivateConnection for hotspot")?;
        if let Some(profile_path) = profile_path {
            self.remove_hotspot_profile(&profile_path);
        }
        Ok(HotspotStopResult {
            status: "stopped",
            message: format!("Hotspot {ssid} stopped"),
            ssid: Some(ssid),
            device_iface: status.device_iface,
        })
    }

    fn hotspot_devices(&self) -> Result<Vec<HotspotDevice>> {
        self.wifi_devices()?
            .into_iter()
            .map(|device| {
                let device_proxy = self.proxy_path(&device.path, DEVICE_IFACE)?;
                let state: u32 = device_proxy.get_property("State").unwrap_or(0);
                let active_connection: OwnedObjectPath = device_proxy
                    .get_property("ActiveConnection")
                    .unwrap_or_default();
                drop(device_proxy);
                let wifi = self.proxy_path(&device.path, WIFI_IFACE)?;
                let capabilities: u32 = wifi.get_property("WirelessCapabilities").unwrap_or(0);
                let mode: u32 = wifi.get_property("Mode").unwrap_or(0);
                Ok(HotspotDevice {
                    path: device.path.to_string(),
                    interface: device.iface,
                    ap_capable: capabilities & CAP_AP != 0,
                    in_use: active_connection.as_str() != "/",
                    state,
                    state_name: device_state_name(state),
                    mode: wifi_mode_name(mode),
                    bands: capability_bands(capabilities),
                })
            })
            .collect()
    }

    fn hotspot_status_for_device(&self, device: HotspotDevice) -> Result<Option<HotspotStatus>> {
        let wifi = self.proxy(&device.path, WIFI_IFACE)?;
        if wifi.get_property::<u32>("Mode").unwrap_or(0) != WIFI_MODE_AP {
            return Ok(None);
        }
        drop(wifi);
        let device_proxy = self.proxy(&device.path, DEVICE_IFACE)?;
        let active_path: OwnedObjectPath = device_proxy
            .get_property("ActiveConnection")
            .unwrap_or_default();
        drop(device_proxy);
        if active_path.as_str() == "/" {
            return Ok(None);
        }
        let active = self.proxy(active_path.as_str(), ACTIVE_CONNECTION_IFACE)?;
        let state: u32 = active.get_property("State").unwrap_or(0);
        let profile_path: OwnedObjectPath = active.get_property("Connection").unwrap_or_default();
        drop(active);
        let settings = self.connection_settings(&profile_path)?;
        Ok(Some(HotspotStatus {
            active: true,
            device_path: Some(device.path),
            device_iface: Some(device.interface),
            profile_path: Some(profile_path.to_string()),
            active_connection: Some(active_path.to_string()),
            state: Some(state),
            state_name: Some(super::inventory::active_connection_state_name(state)),
            ..hotspot_profile_status(&settings)
        }))
    }

    fn resolve_hotspot(&self, request: &HotspotRequest) -> Result<ResolvedHotspot> {
        let capabilities = self.hotspot_capabilities()?;
        if let Some(reason) = capabilities.unsupported_reason {
            return Err(DomainError::validation(
                ErrorOperation::HotspotOperation,
                capabilities.message,
            )
            .with_detail("unsupported_reason", serde_json::json!(reason))
            .into());
        }
        let device = select_hotspot_device(capabilities.devices, request.device.as_deref())?;
        let generated_ssid = request.ssid.is_none();
        let ssid = match &request.ssid {
            Some(ssid) => ssid.clone(),
            None => default_hotspot_ssid(),
        };
        let ssid_bytes = ssid.as_bytes().to_vec();
        validate_ssid_bytes(&ssid_bytes).map_err(|error| {
            DomainError::validation(ErrorOperation::HotspotOperation, &error)
                .with_detail("field", "ssid")
                .with_cause(error)
        })?;
        let generated_passphrase = request.passphrase.is_none();
        let passphrase = match &request.passphrase {
            Some(passphrase) => {
                validate_passphrase(passphrase, request.security)?;
                passphrase.clone()
            }
            None => random_passphrase(GENERATED_PASSPHRASE_LEN)
                .context("generate hotspot passphrase")?,
        };
        let band = resolve_band(request.band, &device)?;
        Ok(ResolvedHotspot {
            ssid,
            ssid_bytes,
            passphrase,
            generated_passphrase,
            generated_ssid,
            device,
            band,
            channel: request.channel,
        })
    }

    fn add_and_activate_hotspot(
        &self,
        resolved: &ResolvedHotspot,
        settings: ConnectionSettings,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let device_path = OwnedObjectPath::try_from(resolved.device.path.as_str())
            .context("parse hotspot device path")?;
        let specific_object = OwnedObjectPath::default();
        // "volatile" keeps the generated profile — and its passphrase — out of
        // persistent NetworkManager storage once the hotspot goes away.
        let options =
            HashMap::from([("persist".to_string(), owned_value("volatile".to_string())?)]);
        let (profile_path, active_path, _result): (
            OwnedObjectPath,
            OwnedObjectPath,
            HashMap<String, OwnedValue>,
        ) = self
            .root_proxy()
            .call(
                "AddAndActivateConnection2",
                &(settings, device_path, specific_object, options),
            )
            .with_context(|| format!("AddAndActivateConnection2 for hotspot {}", resolved.ssid))?;
        Ok((profile_path, active_path))
    }

    fn await_hotspot_activation(
        &self,
        active_path: &OwnedObjectPath,
        cancellation: Option<&AtomicBool>,
    ) -> Result<()> {
        let deadline = Instant::now() + ACTIVATION_TIMEOUT;
        loop {
            check_cancellation(
                cancellation,
                ErrorOperation::HotspotOperation,
                "hotspot start was cancelled",
            )?;
            let state: u32 = self
                .proxy(active_path.as_str(), ACTIVE_CONNECTION_IFACE)
                .and_then(|proxy| {
                    proxy
                        .get_property("State")
                        .context("read hotspot activation state")
                })
                .unwrap_or(0);
            if state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED {
                return Ok(());
            }
            if state >= 3 {
                return Err(DomainError::new(
                    crate::error::ErrorCode::ActivationFailed,
                    ErrorOperation::HotspotOperation,
                    crate::error::ErrorSource::NetworkManager,
                    "NetworkManager deactivated the hotspot during activation",
                )
                .into());
            }
            if Instant::now() >= deadline {
                return Err(DomainError::timeout(
                    ErrorOperation::HotspotOperation,
                    "timed out waiting for the hotspot to activate",
                )
                .into());
            }
            std::thread::sleep(ACTIVATION_POLL);
        }
    }

    fn started_hotspot_result(
        request: &HotspotRequest,
        resolved: ResolvedHotspot,
        profile_path: OwnedObjectPath,
        active_path: OwnedObjectPath,
    ) -> HotspotStartResult {
        let share = HotspotShare {
            ssid: resolved.ssid.clone(),
            auth_type: request.security.qr_auth_type(),
            hidden: request.hidden,
            qr_payload: wifi_qr_payload(
                request.security.qr_auth_type(),
                &resolved.ssid,
                Some(&resolved.passphrase),
                request.hidden,
            ),
        };
        HotspotStartResult {
            status: "started",
            message: format!("Hotspot {} is running", resolved.ssid),
            generated_passphrase: resolved.generated_passphrase,
            generated_ssid: resolved.generated_ssid,
            passphrase: resolved.passphrase,
            hotspot: HotspotStatus {
                active: true,
                device_path: Some(resolved.device.path),
                device_iface: Some(resolved.device.interface),
                ssid: Some(resolved.ssid),
                ssid_hex: Some(ssid_hex(&resolved.ssid_bytes)),
                band: Some(resolved.band),
                channel: resolved.channel,
                security: Some(request.security),
                hidden: request.hidden,
                profile_path: Some(profile_path.to_string()),
                active_connection: Some(active_path.to_string()),
                state: Some(NM_ACTIVE_CONNECTION_STATE_ACTIVATED),
                state_name: Some("activated"),
                share: Some(share),
            },
        }
    }

    /// Best-effort cleanup after a cancelled or failed hotspot activation.
    fn roll_back_hotspot(&self, profile_path: &OwnedObjectPath, active_path: &OwnedObjectPath) {
        if let Err(error) = self
            .root_proxy()
            .call::<_, _, ()>("DeactivateConnection", &(active_path,))
        {
            tracing::debug!(%error, "hotspot activation was already inactive during rollback");
        }
        self.remove_hotspot_profile(profile_path);
    }

    /// Volatile profiles usually disappear on deactivation; delete explicitly so
    /// a generated passphrase can never survive a partial start.
    fn remove_hotspot_profile(&self, profile_path: &OwnedObjectPath) {
        if profile_path.as_str() == "/" {
            return;
        }
        match self.delete_connection(profile_path) {
            Ok(()) => tracing::info!(profile = %profile_path, "removed hotspot profile"),
            Err(error) => tracing::debug!(
                profile = %profile_path,
                error = %crate::error::err_chain(&error),
                "hotspot profile was already removed by NetworkManager"
            ),
        }
    }
}

/// Decode saved profile fields independently of active-device identity.
fn hotspot_profile_status(settings: &ConnectionSettings) -> HotspotStatus {
    let empty = HashMap::new();
    let wireless = settings.get("802-11-wireless").unwrap_or(&empty);
    let ssid_bytes = wireless
        .get("ssid")
        .and_then(value_list)
        .unwrap_or_default();
    HotspotStatus {
        ssid: Some(display_ssid(&ssid_bytes)),
        ssid_hex: Some(ssid_hex(&ssid_bytes)),
        band: setting::<&str>(wireless, "band").map(WifiBand::from_nm_value),
        channel: setting::<u32>(wireless, "channel").filter(|channel| *channel > 0),
        security: match settings
            .get("802-11-wireless-security")
            .and_then(|section| setting(section, "key-mgmt"))
        {
            Some("sae") => Some(HotspotSecurity::Sae),
            Some("wpa-psk") => Some(HotspotSecurity::WpaPsk),
            _ => None,
        },
        hidden: setting(wireless, "hidden").unwrap_or(false),
        ..HotspotStatus::default()
    }
}

fn hotspot_connection_settings(
    resolved: &ResolvedHotspot,
    request: &HotspotRequest,
) -> Result<ConnectionSettings> {
    let connection = value_map([
        ("id", resolved.ssid.as_str().into()),
        (
            "uuid",
            random_uuid_v4()
                .context("generate hotspot profile uuid")?
                .into(),
        ),
        ("type", "802-11-wireless".into()),
        ("autoconnect", false.into()),
        ("interface-name", resolved.device.interface.as_str().into()),
    ])?;
    let mut wireless = value_map([
        ("ssid", resolved.ssid_bytes.as_slice().into()),
        ("mode", "ap".into()),
        ("hidden", request.hidden.into()),
    ])?;
    insert_optional_value(&mut wireless, "band", resolved.band.nm_value())?;
    insert_optional_value(&mut wireless, "channel", resolved.channel)?;
    let security = value_map([
        ("key-mgmt", request.security.key_management().into()),
        ("psk", resolved.passphrase.as_str().into()),
        ("proto", vec!["rsn"].into()),
        ("pairwise", vec!["ccmp"].into()),
        ("group", vec!["ccmp"].into()),
    ])?;

    Ok(ConnectionSettings::from([
        ("connection".to_string(), connection),
        ("802-11-wireless".to_string(), wireless),
        ("802-11-wireless-security".to_string(), security),
        (
            "ipv4".to_string(),
            value_map([("method", "shared".into())])?,
        ),
        (
            "ipv6".to_string(),
            value_map([("method", "ignore".into())])?,
        ),
    ]))
}

fn hotspot_availability(
    devices: &[HotspotDevice],
    wireless_enabled: bool,
    has_preferred: bool,
) -> (Option<HotspotUnavailableReason>, String) {
    if devices.is_empty() {
        return (
            Some(HotspotUnavailableReason::NoWifiDevice),
            "NetworkManager reports no Wi-Fi device".to_string(),
        );
    }
    if !devices.iter().any(|device| device.ap_capable) {
        return (
            Some(HotspotUnavailableReason::ApModeUnsupported),
            "No Wi-Fi device advertises access-point mode".to_string(),
        );
    }
    if !wireless_enabled {
        return (
            Some(HotspotUnavailableReason::WifiDisabled),
            "The Wi-Fi radio is turned off".to_string(),
        );
    }
    if !has_preferred {
        return (
            Some(HotspotUnavailableReason::DeviceBusy),
            "Every access-point-capable Wi-Fi device is already in use".to_string(),
        );
    }
    (None, "A Wi-Fi hotspot can be started".to_string())
}

fn available_hotspot_device(device: &HotspotDevice) -> bool {
    device.ap_capable && !device.in_use
}

fn select_hotspot_device(
    devices: Vec<HotspotDevice>,
    requested: Option<&str>,
) -> Result<HotspotDevice> {
    let Some(requested) = requested else {
        return devices
            .into_iter()
            .find(available_hotspot_device)
            .ok_or_else(|| {
                DomainError::not_found(
                    ErrorOperation::HotspotOperation,
                    "no unused access-point-capable Wi-Fi device is available",
                )
                .into()
            });
    };
    let device = devices
        .into_iter()
        .find(|device| device.path == requested || device.interface == requested)
        .ok_or_else(|| {
            DomainError::not_found(
                ErrorOperation::HotspotOperation,
                "requested Wi-Fi device does not exist",
            )
            .with_detail("device", requested)
        })?;
    if !device.ap_capable {
        return Err(DomainError::validation(
            ErrorOperation::HotspotOperation,
            format!("{} does not support access-point mode", device.interface),
        )
        .with_detail(
            "unsupported_reason",
            serde_json::json!(HotspotUnavailableReason::ApModeUnsupported),
        )
        .into());
    }
    Ok(device)
}

fn resolve_band(requested: WifiBand, device: &HotspotDevice) -> Result<WifiBand> {
    if requested == WifiBand::Auto {
        return Ok(WifiBand::Auto);
    }
    if device.bands.contains(&requested) {
        return Ok(requested);
    }
    Err(DomainError::validation(
        ErrorOperation::HotspotOperation,
        format!(
            "{} cannot host a hotspot on the requested band",
            device.interface
        ),
    )
    .with_detail("requested_band", serde_json::json!(requested))
    .with_detail("available_bands", serde_json::json!(device.bands))
    .into())
}

fn validate_passphrase(passphrase: &str, security: HotspotSecurity) -> Result<()> {
    let minimum = security.minimum_passphrase_len();
    let length = passphrase.chars().count();
    if length < minimum || length > 63 {
        return Err(DomainError::validation(
            ErrorOperation::HotspotOperation,
            format!("hotspot passphrase must be {minimum}-63 characters"),
        )
        .with_detail("field", "passphrase")
        .into());
    }
    Ok(())
}

fn default_hotspot_ssid() -> String {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|host| host.trim().to_string())
        .filter(|host| !host.is_empty() && host.len() <= 24);
    match host {
        Some(host) => format!("{host}-hotspot"),
        None => "nm-daemon-hotspot".to_string(),
    }
}

fn capability_bands(capabilities: u32) -> Vec<WifiBand> {
    let mut bands = Vec::new();
    if capabilities & CAP_FREQ_2GHZ != 0 {
        bands.push(WifiBand::Ghz2_4);
    }
    if capabilities & CAP_FREQ_5GHZ != 0 {
        bands.push(WifiBand::Ghz5);
    }
    bands
}

fn wifi_mode_name(mode: u32) -> &'static str {
    match mode {
        1 => "adhoc",
        2 => "infrastructure",
        3 => "access-point",
        4 => "mesh",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HotspotRequest, ResolvedHotspot, capability_bands, hotspot_connection_settings,
        resolve_band, select_hotspot_device,
    };
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
    use crate::model::{HotspotDevice, HotspotSecurity, WifiBand};

    fn device(interface: &str, ap_capable: bool, in_use: bool) -> HotspotDevice {
        HotspotDevice {
            path: format!("/org/freedesktop/NetworkManager/Devices/{interface}"),
            interface: interface.to_string(),
            ap_capable,
            in_use,
            state: 30,
            state_name: "disconnected",
            mode: "infrastructure",
            bands: vec![WifiBand::Ghz2_4, WifiBand::Ghz5],
        }
    }

    #[test]
    fn hotspot_settings_preserve_security_and_optional_radio_constraints() -> anyhow::Result<()> {
        for (security, band, channel) in [
            (HotspotSecurity::WpaPsk, WifiBand::Auto, None),
            (HotspotSecurity::Sae, WifiBand::Ghz5, Some(36)),
        ] {
            let request = HotspotRequest {
                ssid: None,
                passphrase: None,
                device: None,
                security,
                band,
                channel,
                hidden: true,
            };
            let resolved = ResolvedHotspot {
                ssid: "tést".into(),
                ssid_bytes: "tést".as_bytes().to_vec(),
                passphrase: "correct horse".into(),
                generated_passphrase: false,
                generated_ssid: false,
                device: device("wlan0", true, false),
                band,
                channel,
            };
            let settings = hotspot_connection_settings(&resolved, &request)?;
            let status = super::hotspot_profile_status(&settings);
            assert_eq!(status.ssid.as_deref(), Some("tést"));
            assert_eq!(status.security, Some(security));
            assert_eq!(status.band, band.nm_value().map(WifiBand::from_nm_value));
            assert_eq!(status.channel, channel);
            assert!(status.hidden);
            let text = |section: &str, key: &str| {
                settings[section]
                    .get(key)
                    .and_then(crate::variant::value_string)
            };
            assert_eq!(
                text("connection", "type").as_deref(),
                Some("802-11-wireless")
            );
            assert!(!bool::try_from(&settings["connection"]["autoconnect"])?);
            let wireless = &settings["802-11-wireless"];
            assert_eq!(
                Vec::<u8>::try_from(wireless["ssid"].try_clone()?)?,
                resolved.ssid_bytes
            );
            assert!(bool::try_from(&wireless["hidden"])?);
            assert_eq!(text("802-11-wireless", "band").as_deref(), band.nm_value());
            assert_eq!(
                wireless.get("channel").map(u32::try_from).transpose()?,
                channel
            );
            assert_eq!(
                text("802-11-wireless-security", "key-mgmt").as_deref(),
                Some(security.key_management())
            );
            assert_eq!(
                text("802-11-wireless-security", "psk").as_deref(),
                Some("correct horse")
            );
            assert_eq!(text("ipv4", "method").as_deref(), Some("shared"));
            assert_eq!(text("ipv6", "method").as_deref(), Some("ignore"));
        }
        Ok(())
    }

    #[test]
    fn malformed_hotspot_fields_keep_strict_defaults() -> anyhow::Result<()> {
        use super::{ConnectionSettings, hotspot_profile_status, value_map};
        for settings in [
            ConnectionSettings::new(),
            ConnectionSettings::from([
                (
                    "802-11-wireless".into(),
                    value_map([
                        ("ssid", "not bytes".into()),
                        ("band", b"a".as_slice().into()),
                        ("channel", 0_u32.into()),
                        ("hidden", 1_u32.into()),
                    ])?,
                ),
                (
                    "802-11-wireless-security".into(),
                    value_map([("key-mgmt", "none".into())])?,
                ),
            ]),
        ] {
            let status = hotspot_profile_status(&settings);
            assert_eq!(status.ssid.as_deref(), Some(""));
            assert_eq!(
                (status.band, status.channel, status.security),
                (None, None, None)
            );
            assert!(!status.hidden);
        }
        Ok(())
    }

    #[test]
    fn hotspot_sharing_uses_unquoted_hex_export() {
        let request = HotspotRequest {
            ssid: None,
            passphrase: None,
            device: None,
            security: HotspotSecurity::WpaPsk,
            band: WifiBand::Auto,
            channel: None,
            hidden: true,
        };
        let resolved = ResolvedHotspot {
            ssid: "CAFE".into(),
            ssid_bytes: b"CAFE".to_vec(),
            passphrase: "ABCD1234".into(),
            generated_passphrase: false,
            generated_ssid: false,
            device: device("wlan0", true, false),
            band: WifiBand::Auto,
            channel: None,
        };
        let result = super::Nm::started_hotspot_result(
            &request,
            resolved,
            "/test/profile".try_into().unwrap(),
            "/test/active".try_into().unwrap(),
        );
        assert_eq!(
            result.hotspot.share.unwrap().qr_payload,
            "WIFI:T:WPA;S:CAFE;P:ABCD1234;H:true;;"
        );
    }

    #[test]
    fn requesting_a_non_access_point_device_is_a_typed_validation_error() {
        let devices = || vec![device("wlan1", false, false)];
        let error = select_hotspot_device(devices(), Some("wlan1")).unwrap_err();
        let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::ValidationError);
        assert_eq!(report.details["unsupported_reason"], "ap-mode-unsupported");

        let missing = select_hotspot_device(devices(), Some("wlan9")).unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&missing, ErrorOperation::Unknown).code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn bands_come_from_driver_capabilities_and_unavailable_bands_are_rejected() {
        assert_eq!(capability_bands(0x200), vec![WifiBand::Ghz2_4]);
        assert_eq!(
            capability_bands(0x600),
            vec![WifiBand::Ghz2_4, WifiBand::Ghz5]
        );
        assert!(capability_bands(0).is_empty());

        let mut only_2ghz = device("wlan0", true, false);
        only_2ghz.bands = vec![WifiBand::Ghz2_4];
        assert_eq!(
            resolve_band(WifiBand::Auto, &only_2ghz).unwrap(),
            WifiBand::Auto
        );
        assert_eq!(
            resolve_band(WifiBand::Ghz2_4, &only_2ghz).unwrap(),
            WifiBand::Ghz2_4
        );
        let error = resolve_band(WifiBand::Ghz5, &only_2ghz).unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&error, ErrorOperation::Unknown).code,
            ErrorCode::ValidationError
        );
    }
}
