//! Cross-type NetworkManager inventory, VPN, hotspot, telemetry, and connectivity DTOs.

use serde::{Deserialize, Serialize};

use super::{RadioStatus, TypedReason, WifiBand};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NetworkInventory {
    pub(crate) networking_enabled: bool,
    pub(crate) primary_connection: Option<String>,
    pub(crate) activating_connection: Option<String>,
    pub(crate) devices: Vec<NetworkDeviceSummary>,
    pub(crate) connections: Vec<NetworkConnectionSummary>,
    pub(crate) active_connections: Vec<ActiveConnectionSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NetworkDeviceSummary {
    pub(crate) path: String,
    pub(crate) interface: String,
    pub(crate) ip_interface: Option<String>,
    pub(crate) device_type: u32,
    pub(crate) type_name: &'static str,
    pub(crate) state: u32,
    pub(crate) state_name: &'static str,
    pub(crate) state_reason: TypedReason,
    pub(crate) managed: bool,
    pub(crate) autoconnect: bool,
    pub(crate) driver: Option<String>,
    pub(crate) firmware_version: Option<String>,
    pub(crate) hw_address: Option<String>,
    pub(crate) mtu: Option<u32>,
    /// Physical link presence for wired-capable devices.
    pub(crate) carrier: Option<bool>,
    /// Negotiated wired link speed in Mb/s, when the device reports one.
    pub(crate) speed_mbps: Option<u32>,
    pub(crate) active_connection: Option<String>,
    pub(crate) available_connections: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NetworkConnectionSummary {
    pub(crate) path: String,
    pub(crate) id: String,
    pub(crate) uuid: String,
    pub(crate) connection_type: String,
    pub(crate) type_name: &'static str,
    pub(crate) autoconnect: bool,
    pub(crate) autoconnect_priority: i32,
    pub(crate) timestamp_ms: Option<u64>,
    pub(crate) interface_name: Option<String>,
    pub(crate) permissions: Vec<String>,
    pub(crate) available_devices: Vec<String>,
    pub(crate) active_connection: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ActiveConnectionSummary {
    pub(crate) path: String,
    pub(crate) id: String,
    pub(crate) uuid: String,
    pub(crate) connection_type: String,
    pub(crate) state: u32,
    pub(crate) state_name: &'static str,
    pub(crate) state_flags: u32,
    pub(crate) vpn: bool,
    pub(crate) default4: bool,
    pub(crate) default6: bool,
    pub(crate) profile_path: Option<String>,
    pub(crate) specific_object: Option<String>,
    pub(crate) devices: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VpnProfileSummary {
    pub(crate) path: String,
    pub(crate) id: String,
    pub(crate) uuid: String,
    pub(crate) connection_type: String,
    pub(crate) type_name: &'static str,
    /// NetworkManager VPN plugin service, e.g. `org.freedesktop.NetworkManager.openvpn`.
    pub(crate) service_type: Option<String>,
    /// Short plugin name derived from `service_type`, or `wireguard`.
    pub(crate) plugin: Option<String>,
    pub(crate) autoconnect: bool,
    pub(crate) timestamp_ms: Option<u64>,
    pub(crate) permissions: Vec<String>,
    /// True when activating this profile will need a SecretAgent prompt.
    pub(crate) requires_secrets: bool,
    /// Plugin secret names this profile references, for prompt labelling.
    pub(crate) secret_names: Vec<String>,
    pub(crate) active_connection: Option<String>,
    pub(crate) state: Option<u32>,
    pub(crate) state_name: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VpnActiveStatus {
    pub(crate) path: String,
    pub(crate) id: String,
    pub(crate) uuid: String,
    pub(crate) connection_type: String,
    pub(crate) service_type: Option<String>,
    pub(crate) plugin: Option<String>,
    /// Login banner returned by the VPN plugin, when it sends one.
    pub(crate) banner: Option<String>,
    /// VPN-specific state; absent for WireGuard, which has no VPN plugin.
    pub(crate) vpn_state: Option<u32>,
    pub(crate) vpn_state_name: Option<&'static str>,
    pub(crate) reason: Option<TypedReason>,
    pub(crate) active_state: u32,
    pub(crate) active_state_name: &'static str,
    pub(crate) profile_path: Option<String>,
    /// The connection this VPN runs over.
    pub(crate) specific_object: Option<String>,
    pub(crate) devices: Vec<String>,
    pub(crate) activated_at_ms: Option<u64>,
    pub(crate) duration_ms: Option<u64>,
    pub(crate) default4: bool,
    pub(crate) default6: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VpnStatus {
    pub(crate) active: Vec<VpnActiveStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VpnActivationResult {
    pub(crate) status: &'static str,
    pub(crate) message: String,
    pub(crate) vpn: VpnActiveStatus,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VpnDisconnectResult {
    pub(crate) status: &'static str,
    pub(crate) message: String,
    pub(crate) id: Option<String>,
    pub(crate) uuid: Option<String>,
    pub(crate) path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HotspotUnavailableReason {
    NoWifiDevice,
    ApModeUnsupported,
    WifiDisabled,
    DeviceBusy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub(crate) enum HotspotSecurity {
    /// WPA2-Personal; the widest-compatibility secure option.
    WpaPsk,
    /// WPA3-Personal.
    Sae,
}

impl HotspotSecurity {
    pub(crate) fn key_management(self) -> &'static str {
        match self {
            Self::WpaPsk => "wpa-psk",
            Self::Sae => "sae",
        }
    }

    /// Wi-Fi QR authentication token for this security type.
    pub(crate) fn qr_auth_type(self) -> &'static str {
        match self {
            Self::WpaPsk => "WPA",
            Self::Sae => "SAE",
        }
    }

    pub(crate) fn minimum_passphrase_len(self) -> usize {
        match self {
            Self::WpaPsk | Self::Sae => 8,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HotspotCapabilities {
    pub(crate) supported: bool,
    pub(crate) unsupported_reason: Option<HotspotUnavailableReason>,
    pub(crate) message: String,
    pub(crate) devices: Vec<HotspotDevice>,
    pub(crate) recommended_device: Option<String>,
    pub(crate) supported_security: Vec<HotspotSecurity>,
    pub(crate) supported_bands: Vec<WifiBand>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HotspotDevice {
    pub(crate) path: String,
    pub(crate) interface: String,
    /// True when the driver advertises NM_WIFI_DEVICE_CAP_AP.
    pub(crate) ap_capable: bool,
    /// True while the device already carries an active connection.
    pub(crate) in_use: bool,
    pub(crate) state: u32,
    pub(crate) state_name: &'static str,
    pub(crate) mode: &'static str,
    pub(crate) bands: Vec<WifiBand>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct HotspotStatus {
    pub(crate) active: bool,
    pub(crate) device_path: Option<String>,
    pub(crate) device_iface: Option<String>,
    pub(crate) ssid: Option<String>,
    pub(crate) ssid_hex: Option<String>,
    pub(crate) band: Option<WifiBand>,
    pub(crate) channel: Option<u32>,
    pub(crate) security: Option<HotspotSecurity>,
    pub(crate) hidden: bool,
    pub(crate) profile_path: Option<String>,
    pub(crate) active_connection: Option<String>,
    pub(crate) state: Option<u32>,
    pub(crate) state_name: Option<&'static str>,
    /// Present only when the caller started this hotspot in the current daemon
    /// session; NetworkManager does not hand secrets back for a running profile.
    pub(crate) share: Option<HotspotShare>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HotspotShare {
    pub(crate) ssid: String,
    pub(crate) auth_type: &'static str,
    pub(crate) hidden: bool,
    pub(crate) qr_payload: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HotspotStartResult {
    pub(crate) status: &'static str,
    pub(crate) message: String,
    /// True when the daemon generated the passphrase because none was supplied.
    pub(crate) generated_passphrase: bool,
    /// True when the daemon generated the SSID because none was supplied.
    pub(crate) generated_ssid: bool,
    pub(crate) passphrase: String,
    pub(crate) hotspot: HotspotStatus,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HotspotStopResult {
    pub(crate) status: &'static str,
    pub(crate) message: String,
    pub(crate) ssid: Option<String>,
    pub(crate) device_iface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct DeviceStatisticsSample {
    pub(crate) rx_bytes: u64,
    pub(crate) tx_bytes: u64,
    /// Derived from the previous sample; absent on the first sample and after a
    /// NetworkManager counter reset.
    pub(crate) rx_bytes_per_second: Option<f64>,
    pub(crate) tx_bytes_per_second: Option<f64>,
    /// Milliseconds between this sample and the previous one.
    pub(crate) interval_ms: u128,
    pub(crate) sampled_at_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NetworkStateSummary {
    pub(crate) state: u32,
    pub(crate) state_name: &'static str,
    pub(crate) networking_enabled: bool,
    pub(crate) radios: RadioStatus,
    pub(crate) connectivity: ConnectivityStatus,
    pub(crate) connectivity_check_uri: Option<String>,
    pub(crate) connectivity_check_enabled: bool,
    pub(crate) primary_connection: Option<ActiveConnectionSummary>,
    pub(crate) primary_connection_type: Option<String>,
    pub(crate) activating_connection: Option<ActiveConnectionSummary>,
    pub(crate) default4: Option<String>,
    pub(crate) default6: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProfileActivationResult {
    pub(crate) status: &'static str,
    pub(crate) profile_path: String,
    pub(crate) id: String,
    pub(crate) uuid: String,
    pub(crate) connection_type: String,
    pub(crate) type_name: &'static str,
    pub(crate) active_connection: Option<String>,
    pub(crate) device: Option<String>,
    pub(crate) state: u32,
    pub(crate) state_name: &'static str,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NetworkDeactivateResult {
    pub(crate) status: &'static str,
    pub(crate) path: String,
    pub(crate) id: String,
    pub(crate) uuid: String,
    pub(crate) connection_type: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ConnectivityStatus {
    pub(crate) code: u32,
    pub(crate) state: &'static str,
    pub(crate) captive_portal: bool,
    pub(crate) full: bool,
    /// NetworkManager's connectivity-check URI, so a portal flow opens the same
    /// URL NetworkManager probed instead of guessing one.
    pub(crate) check_uri: Option<String>,
    pub(crate) check_enabled: bool,
    pub(crate) check_available: bool,
    /// Identity of the connection the portal verdict applies to. Boxed so the
    /// portal context does not inflate every value that embeds connectivity.
    pub(crate) primary_connection: Option<Box<PrimaryConnectionIdentity>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PrimaryConnectionIdentity {
    pub(crate) path: String,
    pub(crate) id: String,
    pub(crate) uuid: String,
    pub(crate) connection_type: String,
    pub(crate) type_name: Option<String>,
    pub(crate) device_iface: Option<String>,
}

impl ConnectivityStatus {
    pub(crate) fn from_nm_code(code: u32) -> Self {
        let state = match code {
            1 => "none",
            2 => "portal",
            3 => "limited",
            4 => "full",
            _ => "unknown",
        };
        Self {
            code,
            state,
            captive_portal: code == 2,
            full: code == 4,
            check_uri: None,
            check_enabled: false,
            check_available: false,
            primary_connection: None,
        }
    }

    /// Attaches the portal context a frontend needs to act on this verdict.
    pub(crate) fn with_portal_context(
        mut self,
        check_uri: Option<String>,
        check_enabled: bool,
        check_available: bool,
        primary_connection: Option<PrimaryConnectionIdentity>,
    ) -> Self {
        self.check_uri = check_uri.filter(|uri| !uri.is_empty());
        self.check_enabled = check_enabled;
        self.check_available = check_available;
        self.primary_connection = primary_connection.map(Box::new);
        self
    }
}
