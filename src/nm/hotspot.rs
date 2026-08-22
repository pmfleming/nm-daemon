use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use zvariant::{OwnedObjectPath, OwnedValue, Value};

use super::inventory::device_state_name;
use super::{
    ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE,
    NM_ACTIVE_CONNECTION_STATE_ACTIVATED, Nm, WIFI_IFACE, owned_value,
};
use crate::error::{DomainError, ErrorOperation};
use crate::model::{
    HotspotCapabilities, HotspotDevice, HotspotSecurity, HotspotShare, HotspotStartResult,
    HotspotStatus, HotspotStopResult, HotspotUnavailableReason, WifiBand, display_ssid, ssid_hex,
    validate_ssid_bytes, wifi_qr_payload,
};
use crate::random::{random_passphrase, random_uuid_v4};
use crate::variant::value_string;

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
#[derive(Debug, Clone)]
pub(crate) struct HotspotRequest {
    pub(crate) ssid: Option<String>,
    pub(crate) passphrase: Option<String>,
    pub(crate) security: HotspotSecurity,
    pub(crate) band: WifiBand,
    pub(crate) channel: Option<u32>,
    pub(crate) hidden: bool,
    pub(crate) device: Option<String>,
}

impl Default for HotspotRequest {
    fn default() -> Self {
        Self {
            ssid: None,
            passphrase: None,
            security: HotspotSecurity::WpaPsk,
            band: WifiBand::Auto,
            channel: None,
            hidden: false,
            device: None,
        }
    }
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
        let recommended = preferred_hotspot_device(&devices);
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
            if let Some(status) = self.hotspot_status_for_device(&device)? {
                return Ok(status);
            }
        }
        Ok(inactive_hotspot_status())
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
        check_cancelled(cancellation)?;
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
            Ok(()) => Ok(self.started_hotspot_result(request, resolved, profile_path, active_path)),
            Err(error) => {
                self.roll_back_hotspot(&profile_path, &active_path);
                Err(error)
            }
        }
    }

    pub(crate) fn stop_hotspot(&self) -> Result<HotspotStopResult> {
        let status = self.hotspot_status()?;
        let (Some(active_connection), Some(ssid)) = (&status.active_connection, &status.ssid)
        else {
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
            ssid: Some(ssid.clone()),
            device_iface: status.device_iface.clone(),
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
                    .unwrap_or_else(|_| root_path());
                drop(device_proxy);
                let wifi = self.proxy_path(&device.path, WIFI_IFACE)?;
                let capabilities: u32 = wifi.get_property("WirelessCapabilities").unwrap_or(0);
                let mode: u32 = wifi.get_property("Mode").unwrap_or(0);
                Ok(HotspotDevice {
                    path: device.path.to_string(),
                    interface: device.iface.clone(),
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

    fn hotspot_status_for_device(&self, device: &HotspotDevice) -> Result<Option<HotspotStatus>> {
        let wifi = self.proxy(&device.path, WIFI_IFACE)?;
        if wifi.get_property::<u32>("Mode").unwrap_or(0) != WIFI_MODE_AP {
            return Ok(None);
        }
        drop(wifi);
        let device_proxy = self.proxy(&device.path, DEVICE_IFACE)?;
        let active_path: OwnedObjectPath = device_proxy
            .get_property("ActiveConnection")
            .unwrap_or_else(|_| root_path());
        drop(device_proxy);
        if active_path.as_str() == "/" {
            return Ok(None);
        }
        let active = self.proxy(active_path.as_str(), ACTIVE_CONNECTION_IFACE)?;
        let state: u32 = active.get_property("State").unwrap_or(0);
        let profile_path: OwnedObjectPath = active
            .get_property("Connection")
            .unwrap_or_else(|_| root_path());
        drop(active);
        let settings = self.connection_settings(&profile_path)?;
        let wireless = settings.get("802-11-wireless");
        let ssid_bytes = wireless
            .and_then(|section| section.get("ssid"))
            .and_then(|value| Vec::<u8>::try_from(value.clone()).ok())
            .unwrap_or_default();
        Ok(Some(HotspotStatus {
            active: true,
            device_path: Some(device.path.clone()),
            device_iface: Some(device.interface.clone()),
            ssid: Some(display_ssid(&ssid_bytes)),
            ssid_hex: Some(ssid_hex(&ssid_bytes)),
            band: wireless
                .and_then(|section| section.get("band"))
                .and_then(value_string)
                .map(|band| WifiBand::from_nm_value(&band)),
            channel: wireless
                .and_then(|section| section.get("channel"))
                .and_then(|value| u32::try_from(value.clone()).ok())
                .filter(|channel| *channel > 0),
            security: settings
                .get("802-11-wireless-security")
                .and_then(|section| section.get("key-mgmt"))
                .and_then(value_string)
                .and_then(|key_mgmt| match key_mgmt.as_str() {
                    "sae" => Some(HotspotSecurity::Sae),
                    "wpa-psk" => Some(HotspotSecurity::WpaPsk),
                    _ => None,
                }),
            hidden: wireless
                .and_then(|section| section.get("hidden"))
                .and_then(|value| bool::try_from(value.clone()).ok())
                .unwrap_or(false),
            profile_path: Some(profile_path.to_string()),
            active_connection: Some(active_path.to_string()),
            state: Some(state),
            state_name: Some(super::inventory::active_connection_state_name(state)),
            share: None,
        }))
    }

    fn resolve_hotspot(&self, request: &HotspotRequest) -> Result<ResolvedHotspot> {
        let capabilities = self.hotspot_capabilities()?;
        if let Some(reason) = capabilities.unsupported_reason {
            return Err(DomainError::validation(
                ErrorOperation::HotspotOperation,
                capabilities.message.clone(),
            )
            .with_detail("unsupported_reason", serde_json::json!(reason))
            .into());
        }
        let device = select_hotspot_device(&capabilities.devices, request.device.as_deref())?;
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
        let specific_object = root_path();
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
            check_cancelled(cancellation)?;
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
        &self,
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
            passphrase: resolved.passphrase.clone(),
            hotspot: HotspotStatus {
                active: true,
                device_path: Some(resolved.device.path.clone()),
                device_iface: Some(resolved.device.interface.clone()),
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
            .call::<_, _, ()>("DeactivateConnection", &(active_path.clone(),))
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

fn hotspot_connection_settings(
    resolved: &ResolvedHotspot,
    request: &HotspotRequest,
) -> Result<ConnectionSettings> {
    let mut connection = HashMap::from([
        ("id".to_string(), owned_value(resolved.ssid.clone())?),
        (
            "uuid".to_string(),
            owned_value(random_uuid_v4().context("generate hotspot profile uuid")?)?,
        ),
        (
            "type".to_string(),
            owned_value("802-11-wireless".to_string())?,
        ),
        ("autoconnect".to_string(), owned_value(false)?),
    ]);
    connection.insert(
        "interface-name".to_string(),
        owned_value(resolved.device.interface.clone())?,
    );

    let mut wireless = HashMap::from([
        (
            "ssid".to_string(),
            OwnedValue::try_from(Value::from(resolved.ssid_bytes.clone()))
                .context("encode hotspot SSID")?,
        ),
        ("mode".to_string(), owned_value("ap".to_string())?),
        ("hidden".to_string(), owned_value(request.hidden)?),
    ]);
    if let Some(band) = resolved.band.nm_value() {
        wireless.insert("band".to_string(), owned_value(band.to_string())?);
    }
    if let Some(channel) = resolved.channel {
        wireless.insert("channel".to_string(), owned_value(channel)?);
    }

    let security = HashMap::from([
        (
            "key-mgmt".to_string(),
            owned_value(request.security.key_management().to_string())?,
        ),
        ("psk".to_string(), owned_value(resolved.passphrase.clone())?),
        ("proto".to_string(), owned_value(vec!["rsn".to_string()])?),
        (
            "pairwise".to_string(),
            owned_value(vec!["ccmp".to_string()])?,
        ),
        ("group".to_string(), owned_value(vec!["ccmp".to_string()])?),
    ]);

    Ok(ConnectionSettings::from([
        ("connection".to_string(), connection),
        ("802-11-wireless".to_string(), wireless),
        ("802-11-wireless-security".to_string(), security),
        (
            "ipv4".to_string(),
            HashMap::from([("method".to_string(), owned_value("shared".to_string())?)]),
        ),
        (
            "ipv6".to_string(),
            HashMap::from([("method".to_string(), owned_value("ignore".to_string())?)]),
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

/// Prefers an unused AP-capable device, then any AP-capable device.
fn preferred_hotspot_device(devices: &[HotspotDevice]) -> Option<&HotspotDevice> {
    devices
        .iter()
        .find(|device| device.ap_capable && !device.in_use)
}

fn select_hotspot_device(
    devices: &[HotspotDevice],
    requested: Option<&str>,
) -> Result<HotspotDevice> {
    let Some(requested) = requested else {
        return preferred_hotspot_device(devices).cloned().ok_or_else(|| {
            DomainError::not_found(
                ErrorOperation::HotspotOperation,
                "no unused access-point-capable Wi-Fi device is available",
            )
            .into()
        });
    };
    let device = devices
        .iter()
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
    Ok(device.clone())
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

fn inactive_hotspot_status() -> HotspotStatus {
    HotspotStatus {
        active: false,
        device_path: None,
        device_iface: None,
        ssid: None,
        ssid_hex: None,
        band: None,
        channel: None,
        security: None,
        hidden: false,
        profile_path: None,
        active_connection: None,
        state: None,
        state_name: None,
        share: None,
    }
}

fn root_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("root object path is always valid")
}

fn check_cancelled(cancellation: Option<&AtomicBool>) -> Result<()> {
    if cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return Err(DomainError::cancelled_operation(
            ErrorOperation::HotspotOperation,
            "hotspot start was cancelled",
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        HotspotSecurity, HotspotUnavailableReason, capability_bands, default_hotspot_ssid,
        hotspot_availability, preferred_hotspot_device, resolve_band, select_hotspot_device,
        validate_passphrase, wifi_mode_name,
    };
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
    use crate::model::{HotspotDevice, WifiBand};

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
    fn availability_reports_the_specific_blocking_reason() {
        assert_eq!(
            hotspot_availability(&[], true, false).0,
            Some(HotspotUnavailableReason::NoWifiDevice)
        );
        assert_eq!(
            hotspot_availability(&[device("wlan0", false, false)], true, false).0,
            Some(HotspotUnavailableReason::ApModeUnsupported)
        );
        assert_eq!(
            hotspot_availability(&[device("wlan0", true, false)], false, true).0,
            Some(HotspotUnavailableReason::WifiDisabled)
        );
        assert_eq!(
            hotspot_availability(&[device("wlan0", true, true)], true, false).0,
            Some(HotspotUnavailableReason::DeviceBusy)
        );
        assert_eq!(
            hotspot_availability(&[device("wlan0", true, false)], true, true).0,
            None
        );
    }

    #[test]
    fn device_selection_prefers_an_unused_access_point_capable_radio() {
        let devices = vec![
            device("wlan0", true, true),
            device("wlan1", false, false),
            device("wlan2", true, false),
        ];
        assert_eq!(
            preferred_hotspot_device(&devices).map(|device| device.interface.as_str()),
            Some("wlan2")
        );
        assert_eq!(
            select_hotspot_device(&devices, None).unwrap().interface,
            "wlan2"
        );
        assert_eq!(
            select_hotspot_device(&devices, Some("wlan0"))
                .unwrap()
                .interface,
            "wlan0"
        );
    }

    #[test]
    fn requesting_a_non_access_point_device_is_a_typed_validation_error() {
        let devices = vec![device("wlan1", false, false)];
        let error = select_hotspot_device(&devices, Some("wlan1")).unwrap_err();
        let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::ValidationError);
        assert_eq!(report.details["unsupported_reason"], "ap-mode-unsupported");

        let missing = select_hotspot_device(&devices, Some("wlan9")).unwrap_err();
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

    #[test]
    fn passphrases_shorter_than_wpa_minimum_are_rejected() {
        assert!(validate_passphrase("correcthorse", HotspotSecurity::WpaPsk).is_ok());
        assert!(validate_passphrase("short", HotspotSecurity::WpaPsk).is_err());
        assert!(validate_passphrase(&"a".repeat(64), HotspotSecurity::Sae).is_err());
    }

    #[test]
    fn generated_ssid_and_mode_names_are_stable() {
        assert!(default_hotspot_ssid().ends_with("hotspot"));
        assert_eq!(wifi_mode_name(3), "access-point");
        assert_eq!(wifi_mode_name(1), "adhoc");
        assert_eq!(wifi_mode_name(99), "unknown");
    }
}
