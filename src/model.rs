use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Duration;

pub(crate) use crate::qr::wifi_qr_payload;

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zvariant::OwnedObjectPath;

mod identity;
mod reason;
mod wire_v1;

pub(crate) use identity::{Bssid, InterfaceName, NmObjectPath, Ssid};
pub(crate) use reason::{
    TypedReason, active_connection_state_reason, device_state_reason, vpn_state_name,
    vpn_state_reason,
};

pub(crate) const NM_AP_FLAGS_PRIVACY: u32 = 0x1;
pub(crate) const NM_AP_SEC_PAIR_WEP40: u32 = 0x0000_0001;
pub(crate) const NM_AP_SEC_PAIR_WEP104: u32 = 0x0000_0002;
pub(crate) const NM_AP_SEC_PAIR_TKIP: u32 = 0x0000_0004;
pub(crate) const NM_AP_SEC_PAIR_CCMP: u32 = 0x0000_0008;
pub(crate) const NM_AP_SEC_GROUP_WEP40: u32 = 0x0000_0010;
pub(crate) const NM_AP_SEC_GROUP_WEP104: u32 = 0x0000_0020;
pub(crate) const NM_AP_SEC_GROUP_TKIP: u32 = 0x0000_0040;
pub(crate) const NM_AP_SEC_GROUP_CCMP: u32 = 0x0000_0080;
pub(crate) const NM_AP_SEC_KEY_MGMT_PSK: u32 = 0x0000_0100;
pub(crate) const NM_AP_SEC_KEY_MGMT_802_1X: u32 = 0x0000_0200;
pub(crate) const NM_AP_SEC_KEY_MGMT_SAE: u32 = 0x0000_0400;
pub(crate) const NM_AP_SEC_KEY_MGMT_OWE: u32 = 0x0000_0800;
pub(crate) const NM_AP_SEC_KEY_MGMT_OWE_TM: u32 = 0x0000_1000;
pub(crate) const NM_AP_SEC_KEY_MGMT_EAP_SUITE_B_192: u32 = 0x0000_2000;

#[derive(Debug, Clone)]
pub(crate) struct ScanRequestOptions {
    pub(crate) timeout: Duration,
    pub(crate) ifname: Option<InterfaceName>,
    pub(crate) ssid_bytes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConnectFailureReason {
    SecretRequired,
    WrongPassword,
    PasswordUnavailable,
    AuthorizationRequired,
    UnsupportedAuth,
    ValidationError,
    NotFound,
    Timeout,
    DhcpFailed,
    ActivationFailed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConnectEnginePath {
    AlreadyActive,
    Dbus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConnectPhase {
    Starting,
    CheckingActive,
    ActivatingSavedProfile,
    CreatingProfile,
    Rescanning,
    Verifying,
    Connected,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ConnectTargetIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) network_key: Option<String>,
    pub(crate) ssid: String,
    pub(crate) ssid_bytes: Vec<u8>,
    pub(crate) ssid_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) device_iface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) device_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) access_point_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) bssid: Option<String>,
}

impl ConnectTargetIdentity {
    pub(crate) fn from_target(target: &WifiConnectTarget, network_key: Option<&str>) -> Self {
        Self {
            network_key: network_key.map(ToString::to_string),
            ssid: target.ssid.to_string(),
            ssid_bytes: target.ssid_bytes().to_vec(),
            ssid_hex: ssid_hex(target.ssid_bytes()),
            device_iface: target
                .ifname
                .as_ref()
                .map(|value| value.as_str().to_string()),
            device_path: target
                .device_path
                .as_ref()
                .map(|value| value.as_str().to_string()),
            access_point_path: target
                .ap_path
                .as_ref()
                .map(|value| value.as_str().to_string()),
            bssid: target
                .bssid
                .as_ref()
                .map(|value| value.as_str().to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NetworkSnapshotSource {
    Cache,
    NetworkManager,
    Scan,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NetworkSnapshotMetadata {
    pub(crate) source: NetworkSnapshotSource,
    pub(crate) updated_at_ms: u128,
    pub(crate) age_ms: u64,
    pub(crate) stale: bool,
    pub(crate) scanning: bool,
    pub(crate) refresh_requested: bool,
}

impl NetworkSnapshotMetadata {
    pub(crate) fn live(source: NetworkSnapshotSource) -> Self {
        Self {
            source,
            updated_at_ms: crate::cache::now_ms(),
            age_ms: 0,
            stale: false,
            scanning: false,
            refresh_requested: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ConnectResult {
    pub(crate) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<ConnectFailureReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<ConnectEnginePath>,
    pub(crate) ssid: String,
    pub(crate) message: String,
    pub(crate) connectivity: Option<ConnectivityStatus>,
    pub(crate) suggest_open_portal: bool,
}

impl ConnectResult {
    pub(crate) fn connected(
        ssid: impl Into<String>,
        message: impl Into<String>,
        path: ConnectEnginePath,
        connectivity: Option<ConnectivityStatus>,
    ) -> Self {
        let suggest_open_portal = connectivity
            .as_ref()
            .is_some_and(|status| status.captive_portal);
        Self {
            status: "connected",
            reason: None,
            path: Some(path),
            ssid: ssid.into(),
            message: message.into(),
            connectivity,
            suggest_open_portal,
        }
    }

    pub(crate) fn failed(
        ssid: impl Into<String>,
        reason: ConnectFailureReason,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status: "error",
            reason: Some(reason),
            path: None,
            ssid: ssid.into(),
            message: message.into(),
            connectivity: None,
            suggest_open_portal: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DisconnectResult {
    pub(crate) status: &'static str,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WifiPowerResult {
    pub(crate) enabled: bool,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RadioStatus {
    pub(crate) wireless_enabled: bool,
    pub(crate) wireless_hardware_enabled: bool,
    pub(crate) wireless_available: bool,
    pub(crate) wwan_enabled: bool,
    pub(crate) wwan_hardware_enabled: bool,
    pub(crate) wwan_available: bool,
    pub(crate) airplane_mode: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RadioPowerResult {
    pub(crate) radios: RadioStatus,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WifiStatus {
    pub(crate) enabled: bool,
    pub(crate) radios: RadioStatus,
    pub(crate) active: bool,
    pub(crate) device_iface: Option<String>,
    pub(crate) device_path: Option<String>,
    pub(crate) active_connection_path: Option<String>,
    pub(crate) access_point: Option<AccessPoint>,
    pub(crate) network: Option<NetworkEntry>,
    pub(crate) profile: Option<SavedWifiConnection>,
    pub(crate) connectivity: Option<ConnectivityStatus>,
    pub(crate) ip4: Option<Ip4Status>,
    pub(crate) ip6: Option<Ip6Status>,
    pub(crate) wireless: Option<WirelessStatus>,
    pub(crate) metered: Option<MeteredStatus>,
    pub(crate) active_since_ms: Option<u64>,
    /// Device and active-connection transition detail for the active link.
    pub(crate) link: Option<LinkStateStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LinkStateStatus {
    pub(crate) device_state: u32,
    pub(crate) device_state_name: &'static str,
    pub(crate) device_state_reason: TypedReason,
    pub(crate) active_connection_state: Option<u32>,
    pub(crate) active_connection_state_name: Option<&'static str>,
    pub(crate) active_connection_state_flags: Option<u32>,
    /// True while this active connection is NetworkManager's primary connection.
    pub(crate) primary: bool,
    pub(crate) default4: bool,
    pub(crate) default6: bool,
}

impl WifiStatus {
    pub(crate) fn inactive(
        enabled: bool,
        radios: RadioStatus,
        device_iface: Option<String>,
        connectivity: Option<ConnectivityStatus>,
    ) -> Self {
        Self {
            enabled,
            radios,
            active: false,
            device_iface,
            device_path: None,
            active_connection_path: None,
            access_point: None,
            network: None,
            profile: None,
            connectivity,
            ip4: None,
            ip6: None,
            wireless: None,
            metered: None,
            active_since_ms: None,
            link: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ConnectionDetails {
    pub(crate) ip4: Option<Ip4Status>,
    #[serde(default)]
    pub(crate) ip6: Option<Ip6Status>,
    pub(crate) wireless: Option<WirelessStatus>,
    pub(crate) metered: Option<MeteredStatus>,
    pub(crate) active_since_ms: Option<u64>,
    pub(crate) updated_at_ms: u128,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Ip4Status {
    /// First active address; kept beside `addresses` for existing clients.
    pub(crate) address: Option<String>,
    /// Prefix length of `address`.
    pub(crate) prefix: Option<u32>,
    #[serde(default)]
    pub(crate) addresses: Vec<IpAddressEntry>,
    pub(crate) gateway: Option<String>,
    pub(crate) dns: Vec<String>,
    #[serde(default)]
    pub(crate) domains: Vec<String>,
    #[serde(default)]
    pub(crate) searches: Vec<String>,
    #[serde(default)]
    pub(crate) routes: Vec<IpRouteEntry>,
    pub(crate) dhcp_lease: Option<DhcpLeaseStatus>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Ip6Status {
    /// First active address; mirrors `Ip4Status` so clients share one shape.
    pub(crate) address: Option<String>,
    pub(crate) prefix: Option<u32>,
    #[serde(default)]
    pub(crate) addresses: Vec<IpAddressEntry>,
    pub(crate) gateway: Option<String>,
    pub(crate) dns: Vec<String>,
    #[serde(default)]
    pub(crate) domains: Vec<String>,
    #[serde(default)]
    pub(crate) searches: Vec<String>,
    #[serde(default)]
    pub(crate) routes: Vec<IpRouteEntry>,
    pub(crate) dhcp_lease: Option<DhcpLeaseStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct IpAddressEntry {
    pub(crate) address: String,
    pub(crate) prefix: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct IpRouteEntry {
    pub(crate) dest: String,
    pub(crate) prefix: u32,
    pub(crate) next_hop: Option<String>,
    pub(crate) metric: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct DhcpLeaseStatus {
    pub(crate) server_identifier: Option<String>,
    pub(crate) domain_name: Option<String>,
    pub(crate) lease_time_seconds: Option<u64>,
    pub(crate) expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WirelessStatus {
    /// NetworkManager's single current wireless bitrate, when exposed by the device.
    pub(crate) bitrate_mbps: Option<u32>,
    /// Directional transmit bitrate measured directly via nl80211 when available.
    pub(crate) tx_bitrate_mbps: Option<f64>,
    /// Directional receive bitrate measured directly via nl80211 when available.
    pub(crate) rx_bitrate_mbps: Option<f64>,
    pub(crate) mac_address: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct MeteredStatus {
    pub(crate) code: u32,
    pub(crate) state: String,
    pub(crate) metered: Option<bool>,
    pub(crate) guessed: bool,
}

impl MeteredStatus {
    pub(crate) fn from_nm_code(code: u32) -> Self {
        let (state, metered, guessed) = match code {
            1 => ("yes", Some(true), false),
            2 => ("no", Some(false), false),
            3 => ("guess-yes", Some(true), true),
            4 => ("guess-no", Some(false), true),
            _ => ("unknown", None, false),
        };
        Self {
            code,
            state: state.to_string(),
            metered,
            guessed,
        }
    }
}

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

#[derive(Debug, Clone, Serialize)]
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
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WepKeyType {
    Key,
    Phrase,
}

impl WepKeyType {
    pub(crate) fn nm_value(self) -> u32 {
        match self {
            Self::Key => 1,
            Self::Phrase => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WifiDevice {
    pub(crate) path: OwnedObjectPath,
    pub(crate) iface: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WifiSharePayload {
    pub(crate) status: &'static str,
    pub(crate) shareable: bool,
    pub(crate) reason: Option<String>,
    pub(crate) path: String,
    pub(crate) id: String,
    pub(crate) ssid: String,
    pub(crate) auth_type: Option<String>,
    pub(crate) qr_payload: Option<String>,
}

impl WifiSharePayload {
    pub(crate) fn shareable(
        profile: &SavedWifiConnection,
        auth_type: &str,
        password: Option<&str>,
        hidden: bool,
    ) -> Self {
        Self {
            status: "ok",
            shareable: true,
            reason: None,
            path: profile.path.clone(),
            id: profile.id.clone(),
            ssid: profile.ssid.clone(),
            auth_type: Some(auth_type.to_string()),
            qr_payload: Some(wifi_qr_payload(auth_type, &profile.ssid, password, hidden)),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct SavedWifiConnection {
    pub(crate) path: String,
    pub(crate) id: String,
    /// Human-readable display form of the SSID. This may be lossy for non-UTF-8 SSIDs.
    pub(crate) ssid: String,
    /// Exact SSID bytes used for identity/matching.
    pub(crate) ssid_bytes: Vec<u8>,
    pub(crate) autoconnect: bool,
    #[serde(default)]
    pub(crate) privacy: ProfilePrivacy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ProfilePrivacy {
    pub(crate) mac_address_policy: String,
    pub(crate) randomized_mac: bool,
    pub(crate) send_hostname: bool,
}

impl Default for ProfilePrivacy {
    fn default() -> Self {
        Self {
            mac_address_policy: "default".to_string(),
            randomized_mac: false,
            send_hostname: true,
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, clap::ValueEnum,
)]
pub(crate) enum WifiBand {
    #[serde(rename = "auto")]
    #[clap(name = "auto")]
    Auto,
    #[serde(rename = "2.4")]
    #[clap(name = "2.4")]
    Ghz2_4,
    #[serde(rename = "5")]
    #[clap(name = "5")]
    Ghz5,
    #[serde(rename = "6")]
    #[clap(name = "6")]
    Ghz6,
}

impl WifiBand {
    pub(crate) fn nm_value(self) -> Option<&'static str> {
        match self {
            Self::Auto => None,
            Self::Ghz2_4 => Some("bg"),
            Self::Ghz5 => Some("a"),
            Self::Ghz6 => Some("6GHz"),
        }
    }

    pub(crate) fn from_nm_value(value: &str) -> Self {
        match value {
            "bg" => Self::Ghz2_4,
            "a" => Self::Ghz5,
            "6GHz" => Self::Ghz6,
            _ => Self::Auto,
        }
    }

    pub(crate) fn from_frequency_label(value: &str) -> Option<Self> {
        match value {
            "2.4 GHz" => Some(Self::Ghz2_4),
            "5 GHz" => Some(Self::Ghz5),
            "6 GHz" => Some(Self::Ghz6),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WifiBandStatus {
    pub(crate) path: String,
    pub(crate) id: String,
    pub(crate) ssid: String,
    pub(crate) device_iface: String,
    pub(crate) current: WifiBand,
    pub(crate) selected: WifiBand,
    pub(crate) available: Vec<WifiBand>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WifiBandSelectionResult {
    pub(crate) status: &'static str,
    pub(crate) changed: bool,
    pub(crate) band: WifiBandStatus,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WifiProfileDetails {
    pub(crate) path: String,
    pub(crate) id: String,
    pub(crate) uuid: String,
    pub(crate) ssid: String,
    /// Optimistic-concurrency token for this profile's current settings.
    /// Pass it back as `expected_version` to reject a stale overwrite.
    pub(crate) version: String,
    pub(crate) autoconnect: bool,
    pub(crate) autoconnect_priority: i32,
    pub(crate) metered: String,
    pub(crate) hidden: bool,
    pub(crate) mac_address_policy: String,
    /// Exact cloned MAC when the policy is a literal address rather than a keyword.
    pub(crate) cloned_mac_address: Option<String>,
    /// Restricts the profile to one adapter by permanent MAC.
    pub(crate) mac_address: Option<String>,
    /// Restricts the profile to one access point.
    pub(crate) bssid: Option<String>,
    pub(crate) mtu: Option<u32>,
    pub(crate) mode: String,
    pub(crate) band: WifiBand,
    pub(crate) channel: Option<u32>,
    pub(crate) send_hostname: bool,
    pub(crate) permissions: Vec<String>,
    pub(crate) firewall_zone: Option<String>,
    /// Secondary connection UUIDs, typically a VPN started with this profile.
    pub(crate) secondaries: Vec<String>,
    pub(crate) security_type: String,
    pub(crate) enterprise: Option<ProfileEnterpriseSettings>,
    pub(crate) ipv4: ProfileIpSettings,
    pub(crate) ipv6: ProfileIpSettings,
}

/// NetworkManager secret storage flags, rendered as named booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub(crate) struct SecretFlags {
    pub(crate) code: u32,
    pub(crate) agent_owned: bool,
    pub(crate) not_saved: bool,
    pub(crate) not_required: bool,
}

impl SecretFlags {
    pub(crate) fn from_code(code: u32) -> Self {
        Self {
            code,
            agent_owned: code & 0x1 != 0,
            not_saved: code & 0x2 != 0,
            not_required: code & 0x4 != 0,
        }
    }
}

/// Complete existing 802.1X configuration for a saved profile. Secret values
/// are never included here; only their storage flags are.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct ProfileEnterpriseSettings {
    pub(crate) eap: Vec<String>,
    pub(crate) identity: Option<String>,
    pub(crate) anonymous_identity: Option<String>,
    pub(crate) domain_suffix_match: Option<String>,
    pub(crate) domain_match: Option<String>,
    pub(crate) subject_match: Option<String>,
    pub(crate) altsubject_matches: Vec<String>,
    pub(crate) ca_cert: Option<String>,
    pub(crate) ca_path: Option<String>,
    pub(crate) system_ca_certs: bool,
    pub(crate) client_cert: Option<String>,
    pub(crate) private_key: Option<String>,
    pub(crate) phase1_peapver: Option<String>,
    pub(crate) phase1_peaplabel: Option<String>,
    pub(crate) phase1_fast_provisioning: Option<String>,
    pub(crate) phase1_auth_flags: Option<u32>,
    pub(crate) phase2_auth: Option<String>,
    pub(crate) phase2_autheap: Option<String>,
    pub(crate) phase2_ca_cert: Option<String>,
    pub(crate) phase2_client_cert: Option<String>,
    pub(crate) phase2_private_key: Option<String>,
    pub(crate) phase2_domain_suffix_match: Option<String>,
    pub(crate) phase2_subject_match: Option<String>,
    pub(crate) phase2_altsubject_matches: Vec<String>,
    pub(crate) pac_file: Option<String>,
    pub(crate) password_flags: SecretFlags,
    pub(crate) private_key_password_flags: SecretFlags,
    pub(crate) phase2_private_key_password_flags: SecretFlags,
    pub(crate) ca_cert_password_flags: SecretFlags,
    pub(crate) client_cert_password_flags: SecretFlags,
    pub(crate) pin_flags: SecretFlags,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct ProfileIpSettings {
    pub(crate) method: String,
    pub(crate) addresses: Vec<TargetIpAddress>,
    pub(crate) gateway: Option<String>,
    pub(crate) dns: Vec<String>,
    pub(crate) routes: Vec<TargetIpRoute>,
    pub(crate) ignore_auto_dns: bool,
    pub(crate) ignore_auto_routes: bool,
    pub(crate) never_default: bool,
    /// False means this address family must succeed for the connection to activate.
    pub(crate) may_fail: bool,
    pub(crate) dns_search: Vec<String>,
    pub(crate) route_metric: Option<i64>,
    pub(crate) dhcp_hostname: Option<String>,
    /// IPv4 only.
    pub(crate) dhcp_client_id: Option<String>,
    /// IPv4 duplicate-address-detection timeout in milliseconds; -1 is the default.
    pub(crate) dad_timeout: Option<i32>,
    /// IPv6 only: -1 unknown, 0 disabled, 1 prefer public, 2 prefer temporary.
    pub(crate) ip6_privacy: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WifiProfileSecret {
    pub(crate) path: String,
    pub(crate) available: bool,
    pub(crate) kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) setting_name: Option<String>,
    pub(crate) secret_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) primary_secret_key: Option<String>,
    /// Named secret values for multi-field WEP and 802.1X profile editors.
    pub(crate) values: BTreeMap<String, String>,
    /// Compatibility alias for the primary secret value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) password: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct WifiProfileUpdate {
    pub(crate) autoconnect: bool,
    pub(crate) metered: String,
    pub(crate) hidden: bool,
    pub(crate) mac_address_policy: String,
    pub(crate) send_hostname: bool,
    pub(crate) ipv4: TargetIpSettings,
    pub(crate) ipv6: TargetIpSettings,
    /// Compatibility input for replacing the profile's primary secret.
    pub(crate) password: Option<String>,
    /// Named replacements for supported security-setting secrets.
    pub(crate) secrets: BTreeMap<String, String>,
    /// Rejects the update when the profile changed since this token was read.
    pub(crate) expected_version: Option<String>,
    pub(crate) advanced: WifiProfileAdvancedUpdate,
}

/// Advanced profile fields. Every field is optional; `None` leaves the saved
/// value untouched, and an explicit `Some(None)`-style clear uses an empty
/// string or zero as documented per field.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct WifiProfileAdvancedUpdate {
    pub(crate) autoconnect_priority: Option<i32>,
    /// Empty string clears the restriction.
    pub(crate) bssid: Option<String>,
    /// Empty string clears the adapter restriction.
    pub(crate) mac_address: Option<String>,
    /// Exact cloned MAC; overrides `mac_address_policy` when set.
    pub(crate) cloned_mac_address: Option<String>,
    /// Zero restores NetworkManager's automatic MTU.
    pub(crate) mtu: Option<u32>,
    pub(crate) mode: Option<String>,
    pub(crate) band: Option<WifiBand>,
    /// Zero clears the channel lock.
    pub(crate) channel: Option<u32>,
    /// Empty list makes the profile available to every user.
    pub(crate) permissions: Option<Vec<String>>,
    /// Empty string restores the default firewall zone.
    pub(crate) firewall_zone: Option<String>,
    pub(crate) secondaries: Option<Vec<String>>,
    pub(crate) ipv4_dhcp_client_id: Option<String>,
    pub(crate) ipv4_dhcp_hostname: Option<String>,
    /// Seconds; -1 restores NetworkManager's default duplicate-address detection.
    pub(crate) ipv4_dad_timeout: Option<i32>,
    pub(crate) ipv4_never_default: Option<bool>,
    pub(crate) ipv6_never_default: Option<bool>,
    pub(crate) ipv4_ignore_auto_routes: Option<bool>,
    pub(crate) ipv6_ignore_auto_routes: Option<bool>,
    /// False marks the address family required for the connection to succeed.
    pub(crate) ipv4_may_fail: Option<bool>,
    pub(crate) ipv6_may_fail: Option<bool>,
    /// NetworkManager ip6-privacy: -1 unknown, 0 disabled, 1 prefer public, 2 prefer temporary.
    pub(crate) ipv6_privacy: Option<i32>,
    pub(crate) enterprise: Option<ProfileEnterpriseUpdate>,
}

/// 802.1X fields a frontend can round-trip. Secret values move through the
/// existing `secrets` map, never through this structure.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ProfileEnterpriseUpdate {
    pub(crate) eap: Option<Vec<String>>,
    pub(crate) identity: Option<String>,
    pub(crate) anonymous_identity: Option<String>,
    pub(crate) domain_suffix_match: Option<String>,
    pub(crate) domain_match: Option<String>,
    pub(crate) subject_match: Option<String>,
    pub(crate) altsubject_matches: Option<Vec<String>>,
    pub(crate) ca_cert: Option<String>,
    pub(crate) ca_path: Option<String>,
    pub(crate) system_ca_certs: Option<bool>,
    pub(crate) client_cert: Option<String>,
    pub(crate) private_key: Option<String>,
    pub(crate) phase1_peapver: Option<String>,
    pub(crate) phase1_peaplabel: Option<String>,
    pub(crate) phase1_fast_provisioning: Option<String>,
    pub(crate) phase1_auth_flags: Option<u32>,
    pub(crate) phase2_auth: Option<String>,
    pub(crate) phase2_autheap: Option<String>,
    pub(crate) phase2_ca_cert: Option<String>,
    pub(crate) phase2_client_cert: Option<String>,
    pub(crate) phase2_private_key: Option<String>,
    pub(crate) phase2_domain_suffix_match: Option<String>,
    pub(crate) phase2_subject_match: Option<String>,
    pub(crate) phase2_altsubject_matches: Option<Vec<String>>,
    pub(crate) pac_file: Option<String>,
    pub(crate) password_flags: Option<u32>,
    pub(crate) private_key_password_flags: Option<u32>,
    pub(crate) phase2_private_key_password_flags: Option<u32>,
    pub(crate) ca_cert_password_flags: Option<u32>,
    pub(crate) client_cert_password_flags: Option<u32>,
    pub(crate) pin_flags: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Security {
    Open,
    Owe,
    OweTransition,
    Wpa,
    Wpa2Or3,
    Wep,
    Enterprise,
    Other(String),
}

impl Security {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Open => "--",
            Self::Owe => "OWE",
            Self::OweTransition => "OWE-TM",
            Self::Wpa => "WPA",
            Self::Wpa2Or3 => "WPA2/3",
            Self::Wep => "WEP",
            Self::Enterprise => "Enterprise",
            Self::Other(value) => value,
        }
    }
}

impl Default for Security {
    fn default() -> Self {
        Self::Other(String::new())
    }
}

impl std::fmt::Display for Security {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Security {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Security {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "--" | "open" | "none" => Self::Open,
            "OWE" | "owe" => Self::Owe,
            "OWE-TM" | "owe-tm" => Self::OweTransition,
            "WPA" => Self::Wpa,
            "WPA2/3" => Self::Wpa2Or3,
            "WEP" | "wep" => Self::Wep,
            "Enterprise" => Self::Enterprise,
            _ => Self::Other(value),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SecurityClass {
    Open,
    EnhancedOpen,
    Legacy,
    Personal,
    Enterprise,
    Unknown,
}

#[derive(Debug, Clone)]
pub(crate) struct WifiConnectTarget {
    pub(crate) ssid: Ssid,
    pub(crate) ap_path: Option<NmObjectPath>,
    pub(crate) bssid: Option<Bssid>,
    pub(crate) ifname: Option<InterfaceName>,
    pub(crate) device_path: Option<NmObjectPath>,
    /// Optional NetworkManager connection id requested by the frontend.
    pub(crate) connection_name: Option<String>,
    /// Restrict a newly-created connection to the current user when supported.
    pub(crate) private: bool,
    pub(crate) hidden: bool,
    pub(crate) security: Option<Security>,
    /// NetworkManager key-management hint for hidden or ambiguous targets.
    pub(crate) key_mgmt: Option<String>,
    /// Optional structured 802.1X/EAP credentials for enterprise Wi-Fi creation.
    pub(crate) enterprise: Option<EnterpriseAuth>,
    /// Optional profile/IP settings to apply when creating cloned/new profiles.
    pub(crate) profile: TargetProfileSettings,
}

#[cfg(test)]
pub(crate) fn example_connect_target(hidden: bool) -> WifiConnectTarget {
    WifiConnectTarget {
        ssid: Ssid::from_display("Example".to_string()).expect("valid example SSID"),
        ap_path: None,
        bssid: None,
        ifname: None,
        device_path: None,
        connection_name: None,
        private: false,
        hidden,
        security: None,
        key_mgmt: None,
        enterprise: None,
        profile: Default::default(),
    }
}

impl WifiConnectTarget {
    pub(crate) fn ssid_bytes(&self) -> &[u8] {
        self.ssid.as_bytes()
    }

    pub(crate) fn has_specific_ap(&self) -> bool {
        self.ap_path.is_some() || self.bssid.is_some()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.hidden && self.bssid.is_none() && looks_like_bssid(self.ssid.as_str()) {
            bail!(
                "hidden Wi-Fi target must be an SSID, but '{}' looks like a BSSID",
                self.ssid
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConnectionReadiness {
    Ready,
    NeedsPassword,
    NeedsEnterpriseCredentials,
    Unsupported { reason: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkCapabilities {
    pub(crate) readiness: ConnectionReadiness,
    pub(crate) has_profile: bool,
    pub(crate) can_share_qr: bool,
}

impl NetworkCapabilities {
    fn v1_readiness(&self) -> (bool, bool, bool, bool, bool, bool, bool, Option<&str>) {
        match &self.readiness {
            ConnectionReadiness::Ready => (true, true, false, false, false, false, true, None),
            ConnectionReadiness::NeedsPassword => {
                (true, false, true, true, false, false, true, None)
            }
            ConnectionReadiness::NeedsEnterpriseCredentials => {
                (true, false, false, false, true, true, true, None)
            }
            ConnectionReadiness::Unsupported { reason } => (
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                reason.as_deref(),
            ),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct EnterpriseAuth {
    /// NetworkManager 802.1X EAP methods, e.g. ["peap"], ["ttls"], ["tls"], ["pwd"].
    pub(crate) eap: Vec<String>,
    pub(crate) identity: Option<String>,
    pub(crate) anonymous_identity: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) phase2_auth: Option<String>,
    pub(crate) ca_cert: Option<String>,
    pub(crate) ca_path: Option<String>,
    pub(crate) domain_suffix_match: Option<String>,
    pub(crate) subject_match: Option<String>,
    pub(crate) altsubject_matches: Vec<String>,
    pub(crate) openssl_ciphers: Option<String>,
    pub(crate) phase1_peapver: Option<String>,
    pub(crate) phase1_peaplabel: Option<String>,
    pub(crate) phase1_fast_provisioning: Option<String>,
    pub(crate) client_cert: Option<String>,
    pub(crate) private_key: Option<String>,
    pub(crate) private_key_password: Option<String>,
    pub(crate) pin: Option<String>,
    pub(crate) pac_file: Option<String>,
    /// Optional override for unusual hidden-network cases. Visible APs derive this from AP flags.
    pub(crate) key_mgmt: Option<String>,
    pub(crate) system_ca_certs: Option<bool>,
    pub(crate) password_flags: Option<u32>,
    pub(crate) private_key_password_flags: Option<u32>,
    pub(crate) pin_flags: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct TargetProfileSettings {
    pub(crate) autoconnect: Option<bool>,
    pub(crate) autoconnect_priority: Option<i32>,
    pub(crate) metered: Option<String>,
    pub(crate) cloned_mac_address: Option<String>,
    pub(crate) send_hostname: Option<bool>,
    pub(crate) ipv4: Option<TargetIpSettings>,
    pub(crate) ipv6: Option<TargetIpSettings>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct TargetIpSettings {
    pub(crate) method: Option<String>,
    pub(crate) addresses: Vec<TargetIpAddress>,
    pub(crate) gateway: Option<String>,
    pub(crate) dns: Vec<String>,
    pub(crate) routes: Vec<TargetIpRoute>,
    pub(crate) route_metric: Option<i64>,
    pub(crate) ignore_auto_dns: Option<bool>,
    pub(crate) dns_search: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct TargetIpAddress {
    pub(crate) address: String,
    pub(crate) prefix: u32,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct TargetIpRoute {
    pub(crate) dest: String,
    pub(crate) prefix: u32,
    pub(crate) next_hop: Option<String>,
    pub(crate) metric: Option<u32>,
    pub(crate) table: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AuthKind {
    SavedProfile,
    Open,
    Owe,
    WpaPersonal,
    Wep,
    WpaEnterprise,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkAuth {
    pub(crate) kind: AuthKind,
    pub(crate) key_management: Vec<String>,
    pub(crate) required_fields: Vec<String>,
    pub(crate) optional_fields: Vec<String>,
    pub(crate) note: Option<String>,
}

impl NetworkAuth {
    pub(crate) fn new(
        kind: AuthKind,
        key_management: Vec<String>,
        required_fields: Vec<String>,
        optional_fields: Vec<String>,
        note: Option<String>,
    ) -> Self {
        Self {
            kind,
            key_management,
            required_fields,
            optional_fields,
            note,
        }
    }

    pub(crate) fn supported(&self) -> bool {
        self.kind != AuthKind::Unsupported
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PromptKind {
    None,
    Password,
    Enterprise,
    Unsupported,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct NetworkConnectPrompt {
    pub(crate) kind: PromptKind,
    pub(crate) required_fields: Vec<String>,
    pub(crate) optional_fields: Vec<String>,
    pub(crate) message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) enterprise_defaults: Option<EnterpriseAuth>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct NetworkShareHint {
    pub(crate) shareable: bool,
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) requires_profile_secret_check: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) profile_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) qr_payload: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct NetworkPortalHint {
    pub(crate) auto_open_on_connect: bool,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct NetworkEntry {
    #[serde(flatten)]
    pub(crate) access_point: AccessPoint,
    pub(crate) security_class: SecurityClass,
    /// Stable frontend selection key.
    pub(crate) key: String,
    /// Exact APs in this group; `access_point` is the preferred AP.
    #[serde(default)]
    pub(crate) access_points: Vec<AccessPoint>,
    pub(crate) primary_profile: Option<SavedWifiConnection>,
    pub(crate) profiles: Vec<SavedWifiConnection>,
    pub(crate) capabilities: NetworkCapabilities,
    pub(crate) auth: NetworkAuth,
    pub(crate) connect_prompt: NetworkConnectPrompt,
    pub(crate) share: NetworkShareHint,
    pub(crate) portal_hint: NetworkPortalHint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_connection: Option<ConnectionDetails>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct AccessPoint {
    /// Human-readable display form of the SSID. This may be lossy for non-UTF-8 SSIDs.
    pub(crate) ssid: String,
    /// Exact SSID bytes used for identity/matching. Empty only for legacy cache records.
    #[serde(default)]
    pub(crate) ssid_bytes: Vec<u8>,
    pub(crate) active: bool,
    pub(crate) security: Security,
    pub(crate) strength: u8,
    pub(crate) frequency: u32,
    #[serde(default)]
    pub(crate) channel: u32,
    #[serde(default)]
    pub(crate) band: String,
    #[serde(default)]
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) max_bitrate_mbps: u32,
    #[serde(default)]
    pub(crate) bandwidth_mhz: u32,
    #[serde(default)]
    pub(crate) ssid_hex: String,
    #[serde(default)]
    pub(crate) wpa_flags_label: String,
    #[serde(default)]
    pub(crate) rsn_flags_label: String,
    pub(crate) bssid: String,
    pub(crate) last_seen: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_seen_age_ms: Option<u64>,
    #[serde(default)]
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) device_path: String,
    #[serde(default)]
    pub(crate) device_iface: String,
    #[serde(default)]
    pub(crate) flags: u32,
    #[serde(default)]
    pub(crate) wpa_flags: u32,
    #[serde(default)]
    pub(crate) rsn_flags: u32,
}

impl AccessPoint {
    pub(crate) fn ssid_bytes(&self) -> Cow<'_, [u8]> {
        ssid_bytes_or_display(&self.ssid_bytes, &self.ssid)
    }
}

fn ssid_bytes_or_display<'a>(ssid_bytes: &'a [u8], display_ssid: &'a str) -> Cow<'a, [u8]> {
    if ssid_bytes.is_empty() {
        Cow::Borrowed(display_ssid.as_bytes())
    } else {
        Cow::Borrowed(ssid_bytes)
    }
}

pub(crate) fn validate_ssid_bytes(ssid_bytes: &[u8]) -> Result<()> {
    if ssid_bytes.is_empty() || ssid_bytes.len() > 32 {
        bail!(
            "Wi-Fi SSID must be 1-32 bytes; got {} bytes",
            ssid_bytes.len()
        );
    }
    Ok(())
}

fn validate_bssid(bssid: &str) -> Result<()> {
    if looks_like_bssid(bssid) {
        Ok(())
    } else {
        bail!("invalid BSSID '{bssid}'; expected six hexadecimal octets")
    }
}

fn looks_like_bssid(value: &str) -> bool {
    let separators = value.matches(':').count() + value.matches('-').count();
    separators == 5
        && value
            .split([':', '-'])
            .all(|part| part.len() == 2 && part.chars().all(|ch| ch.is_ascii_hexdigit()))
}

pub(crate) fn network_entries_with_profile_matches(
    access_points: Vec<AccessPoint>,
    profile_matches_by_ap_path: &std::collections::BTreeMap<String, Vec<SavedWifiConnection>>,
) -> Vec<NetworkEntry> {
    grouped_access_points(access_points)
        .into_iter()
        .filter_map(|group| {
            let profiles = profiles_for_access_point_group(&group, profile_matches_by_ap_path);
            network_entry_with_profiles(group, profiles)
        })
        .collect()
}

fn grouped_access_points(access_points: Vec<AccessPoint>) -> Vec<Vec<AccessPoint>> {
    // SSID alone is not a network identity. Different adapters can see unrelated
    // networks with the same name, and an open evil twin must never inherit the
    // readiness/profile state of a secured AP. Keep only roaming-compatible APs
    // on the same device in one frontend entry.
    let mut groups =
        std::collections::BTreeMap::<(Vec<u8>, SecurityClass, String), Vec<AccessPoint>>::new();
    for access_point in access_points {
        let key = (
            access_point.ssid_bytes().into_owned(),
            security_class(
                access_point.flags,
                access_point.wpa_flags,
                access_point.rsn_flags,
            ),
            access_point.device_iface.clone(),
        );
        groups.entry(key).or_default().push(access_point);
    }
    groups.into_values().collect()
}

fn network_entry_with_profiles(
    access_points: Vec<AccessPoint>,
    profiles: Vec<SavedWifiConnection>,
) -> Option<NetworkEntry> {
    let access_point = preferred_access_point(&access_points)?;
    let primary_profile = profiles.first().cloned();
    let has_profile = primary_profile.is_some();
    let share = network_share_hint_for(&access_point, primary_profile.as_ref());
    let capabilities = network_capabilities(&access_point, has_profile, &share);
    let auth = auth_capability_for(&access_point, has_profile);
    Some(NetworkEntry {
        key: network_key_for(&access_point),
        security_class: security_class(
            access_point.flags,
            access_point.wpa_flags,
            access_point.rsn_flags,
        ),
        connect_prompt: connect_prompt_for(&access_point, &auth, has_profile),
        share,
        portal_hint: portal_hint_for(&access_point),
        access_point,
        access_points,
        primary_profile,
        capabilities,
        profiles,
        auth,
        last_connection: None,
    })
}

fn network_capabilities(
    access_point: &AccessPoint,
    has_profile: bool,
    share: &NetworkShareHint,
) -> NetworkCapabilities {
    NetworkCapabilities {
        readiness: connection_readiness(access_point, has_profile),
        has_profile,
        can_share_qr: share.shareable || share.requires_profile_secret_check,
    }
}

fn connection_readiness(access_point: &AccessPoint, has_profile: bool) -> ConnectionReadiness {
    if access_point.ssid_bytes().is_empty() {
        ConnectionReadiness::Unsupported {
            reason: Some("network has no usable SSID".to_string()),
        }
    } else {
        known_identity_readiness(access_point, has_profile)
    }
}

fn known_identity_readiness(access_point: &AccessPoint, has_profile: bool) -> ConnectionReadiness {
    use crate::auth::WifiAuthentication;

    if has_profile {
        return ConnectionReadiness::Ready;
    }
    match crate::auth::classify(
        access_point.flags,
        access_point.wpa_flags,
        access_point.rsn_flags,
    ) {
        WifiAuthentication::Open | WifiAuthentication::Owe => ConnectionReadiness::Ready,
        WifiAuthentication::Personal | WifiAuthentication::Wep => {
            ConnectionReadiness::NeedsPassword
        }
        WifiAuthentication::Enterprise => ConnectionReadiness::NeedsEnterpriseCredentials,
        WifiAuthentication::Unsupported => ConnectionReadiness::Unsupported {
            reason: Some(unsupported_auth_reason(access_point)),
        },
    }
}

fn access_point_is_passwordless(access_point: &AccessPoint) -> bool {
    ap_is_passwordless(
        access_point.flags,
        access_point.wpa_flags,
        access_point.rsn_flags,
    )
}

fn preferred_access_point(access_points: &[AccessPoint]) -> Option<AccessPoint> {
    access_points
        .iter()
        .max_by(|left, right| {
            left.active
                .cmp(&right.active)
                .then_with(|| left.strength.cmp(&right.strength))
        })
        .cloned()
}

fn profiles_for_access_point_group(
    access_points: &[AccessPoint],
    profile_matches_by_ap_path: &std::collections::BTreeMap<String, Vec<SavedWifiConnection>>,
) -> Vec<SavedWifiConnection> {
    let mut seen_paths = std::collections::BTreeSet::new();
    access_points
        .iter()
        .filter_map(|access_point| profile_matches_by_ap_path.get(&access_point.path))
        .flatten()
        .filter(|profile| seen_paths.insert(profile.path.clone()))
        .cloned()
        .collect()
}

pub(crate) fn display_ssid(ssid_bytes: &[u8]) -> String {
    String::from_utf8_lossy(ssid_bytes).into_owned()
}

pub(crate) fn ssid_hex(ssid_bytes: &[u8]) -> String {
    ssid_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn frequency_channel(frequency: u32) -> u32 {
    crate::generated::WIFI_CHANNELS
        .iter()
        .find_map(|(candidate, channel)| (*candidate == frequency).then_some(*channel))
        .unwrap_or(0)
}

/// True when a NetworkManager channel number belongs to the given band.
/// The generated channel table is the authority, so this stays correct as the
/// regulatory channel list changes.
pub(crate) fn channel_is_in_band(channel: u32, band: WifiBand) -> bool {
    let label = match band {
        WifiBand::Auto => return true,
        WifiBand::Ghz2_4 => "2.4 GHz",
        WifiBand::Ghz5 => "5 GHz",
        WifiBand::Ghz6 => "6 GHz",
    };
    crate::generated::WIFI_CHANNELS
        .iter()
        .any(|(frequency, candidate)| *candidate == channel && frequency_band(*frequency) == label)
}

pub(crate) fn frequency_band(frequency: u32) -> &'static str {
    use crate::generated::{
        WIFI_BAND_2_4_MAX_MHZ, WIFI_BAND_2_4_MIN_MHZ, WIFI_BAND_5_MAX_MHZ, WIFI_BAND_5_MIN_MHZ,
        WIFI_BAND_6_MAX_MHZ, WIFI_BAND_6_MIN_MHZ,
    };

    match frequency {
        WIFI_BAND_2_4_MIN_MHZ..=WIFI_BAND_2_4_MAX_MHZ => "2.4 GHz",
        WIFI_BAND_5_MIN_MHZ..=WIFI_BAND_5_MAX_MHZ => "5 GHz",
        WIFI_BAND_6_MIN_MHZ..=WIFI_BAND_6_MAX_MHZ => "6 GHz",
        _ => "",
    }
}

pub(crate) fn wifi_mode_label(mode: u32) -> &'static str {
    match mode {
        1 => "Ad-Hoc",
        2 => "Infra",
        4 => "Mesh",
        _ => "N/A",
    }
}

pub(crate) fn security_flags_label(flags: u32) -> String {
    let labels = [
        (NM_AP_SEC_PAIR_WEP40, "pair_wep40"),
        (NM_AP_SEC_PAIR_WEP104, "pair_wep104"),
        (NM_AP_SEC_PAIR_TKIP, "pair_tkip"),
        (NM_AP_SEC_PAIR_CCMP, "pair_ccmp"),
        (NM_AP_SEC_GROUP_WEP40, "group_wep40"),
        (NM_AP_SEC_GROUP_WEP104, "group_wep104"),
        (NM_AP_SEC_GROUP_TKIP, "group_tkip"),
        (NM_AP_SEC_GROUP_CCMP, "group_ccmp"),
        (NM_AP_SEC_KEY_MGMT_PSK, "psk"),
        (NM_AP_SEC_KEY_MGMT_802_1X, "802.1X"),
        (NM_AP_SEC_KEY_MGMT_SAE, "sae"),
        (NM_AP_SEC_KEY_MGMT_OWE, "owe"),
        (NM_AP_SEC_KEY_MGMT_OWE_TM, "owe-tm"),
        (NM_AP_SEC_KEY_MGMT_EAP_SUITE_B_192, "wpa-eap-suite-b-192"),
    ];
    let value = labels
        .into_iter()
        .filter_map(|(bit, label)| (flags & bit != 0).then_some(label))
        .collect::<Vec<_>>()
        .join(" ");
    if value.is_empty() {
        "(none)".to_string()
    } else {
        value
    }
}

pub(crate) fn security_label(flags: u32, wpa_flags: u32, rsn_flags: u32) -> Security {
    if ap_is_passwordless(flags, wpa_flags, rsn_flags) {
        return passwordless_security(wpa_flags, rsn_flags);
    }
    secured_network_label(wpa_flags, rsn_flags)
}

pub(crate) fn security_class(flags: u32, wpa_flags: u32, rsn_flags: u32) -> SecurityClass {
    match security_label(flags, wpa_flags, rsn_flags) {
        Security::Open | Security::OweTransition => SecurityClass::Open,
        Security::Owe => SecurityClass::EnhancedOpen,
        Security::Wep => SecurityClass::Legacy,
        Security::Wpa | Security::Wpa2Or3 if ap_supports_enterprise(wpa_flags, rsn_flags) => {
            SecurityClass::Enterprise
        }
        Security::Wpa | Security::Wpa2Or3 if ap_supports_psk(wpa_flags, rsn_flags) => {
            SecurityClass::Personal
        }
        Security::Enterprise => SecurityClass::Enterprise,
        Security::Wpa | Security::Wpa2Or3 | Security::Other(_) => SecurityClass::Unknown,
    }
}

fn passwordless_security(wpa_flags: u32, rsn_flags: u32) -> Security {
    let flags = wpa_flags | rsn_flags;
    if flags & NM_AP_SEC_KEY_MGMT_OWE != 0 {
        Security::Owe
    } else if flags & NM_AP_SEC_KEY_MGMT_OWE_TM != 0 {
        Security::OweTransition
    } else {
        Security::Open
    }
}

fn secured_network_label(wpa_flags: u32, rsn_flags: u32) -> Security {
    match (rsn_flags != 0, wpa_flags != 0) {
        (true, _) => Security::Wpa2Or3,
        (false, true) => Security::Wpa,
        (false, false) => Security::Wep,
    }
}

pub(crate) fn ap_is_passwordless(flags: u32, wpa_flags: u32, rsn_flags: u32) -> bool {
    let privacy = flags & NM_AP_FLAGS_PRIVACY != 0;
    ap_uses_owe(wpa_flags, rsn_flags)
        || (!privacy && flags_are_passwordless(wpa_flags) && flags_are_passwordless(rsn_flags))
}

pub(crate) fn ap_uses_owe(wpa_flags: u32, rsn_flags: u32) -> bool {
    (wpa_flags | rsn_flags) & NM_AP_SEC_KEY_MGMT_OWE != 0
}

pub(crate) fn ap_supports_psk(wpa_flags: u32, rsn_flags: u32) -> bool {
    let flags = wpa_flags | rsn_flags;
    flags & (NM_AP_SEC_KEY_MGMT_PSK | NM_AP_SEC_KEY_MGMT_SAE) != 0
}

pub(crate) fn ap_supports_enterprise(wpa_flags: u32, rsn_flags: u32) -> bool {
    let flags = wpa_flags | rsn_flags;
    flags & (NM_AP_SEC_KEY_MGMT_802_1X | NM_AP_SEC_KEY_MGMT_EAP_SUITE_B_192) != 0
}

pub(crate) fn enterprise_key_mgmt(wpa_flags: u32, rsn_flags: u32) -> &'static str {
    let flags = wpa_flags | rsn_flags;
    if flags & NM_AP_SEC_KEY_MGMT_EAP_SUITE_B_192 != 0 {
        "wpa-eap-suite-b-192"
    } else {
        "wpa-eap"
    }
}

fn unsupported_auth_reason(access_point: &AccessPoint) -> String {
    format!(
        "unsupported authentication flags for '{}': flags={}, wpa='{}', rsn='{}'; supported profile creation covers open/OWE, WEP, WPA/SAE-Personal, WPA-Enterprise, and saved profiles",
        access_point.ssid,
        access_point.flags,
        access_point.wpa_flags_label,
        access_point.rsn_flags_label,
    )
}

fn network_key_for(access_point: &AccessPoint) -> String {
    let class = security_class(
        access_point.flags,
        access_point.wpa_flags,
        access_point.rsn_flags,
    );
    format!(
        "ssid-hex:{}|security:{}|ifname:{}",
        ssid_hex(access_point.ssid_bytes().as_ref()),
        security_class_key(class),
        ssid_hex(access_point.device_iface.as_bytes()),
    )
}

fn security_class_key(class: SecurityClass) -> &'static str {
    match class {
        SecurityClass::Open => "open",
        SecurityClass::EnhancedOpen => "enhanced-open",
        SecurityClass::Legacy => "legacy",
        SecurityClass::Personal => "personal",
        SecurityClass::Enterprise => "enterprise",
        SecurityClass::Unknown => "unknown",
    }
}

pub(crate) fn ssid_for_network_key(key: &str) -> Result<Ssid> {
    // The suffix was added without changing protocol v1. Accept old SSID-only
    // keys so queued calls and older frontends remain compatible.
    let encoded = key
        .strip_prefix("ssid-hex:")
        .and_then(|value| value.split('|').next())
        .ok_or_else(|| anyhow::anyhow!("invalid Wi-Fi network key"))?;
    if encoded.len() % 2 != 0 {
        bail!("invalid Wi-Fi network key");
    }
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let octet = std::str::from_utf8(pair)
                .map_err(|_| anyhow::anyhow!("invalid Wi-Fi network key"))?;
            u8::from_str_radix(octet, 16).map_err(|_| anyhow::anyhow!("invalid Wi-Fi network key"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ssid::from_bytes(bytes)
}

pub(crate) fn connect_target_for_network(
    network: &NetworkEntry,
    enterprise_identity: Option<String>,
) -> Result<WifiConnectTarget> {
    let access_point = &network.access_point;
    let mut target =
        connect_target_for_ssid(Ssid::from_bytes(access_point.ssid_bytes().into_owned())?);
    target.ap_path = (!access_point.path.is_empty())
        .then(|| NmObjectPath::parse(access_point.path.clone()))
        .transpose()?;
    target.bssid = (!access_point.bssid.is_empty())
        .then(|| Bssid::parse(access_point.bssid.clone()))
        .transpose()?;
    target.ifname = (!access_point.device_iface.is_empty())
        .then(|| InterfaceName::parse(access_point.device_iface.clone()))
        .transpose()?;
    target.device_path = (!access_point.device_path.is_empty())
        .then(|| NmObjectPath::parse(access_point.device_path.clone()))
        .transpose()?;
    target.security = Some(access_point.security.clone());
    target.key_mgmt = network.auth.key_management.first().cloned();
    target.enterprise = enterprise_auth_for_network(network, enterprise_identity);
    Ok(target)
}

pub(crate) fn connect_target_for_network_key(
    key: &str,
    enterprise_identity: Option<String>,
) -> Result<WifiConnectTarget> {
    let mut target = connect_target_for_ssid(ssid_for_network_key(key)?);
    if let Some(identity) = enterprise_identity {
        target.enterprise = Some(default_enterprise_auth(identity));
    }
    Ok(target)
}

fn connect_target_for_ssid(ssid: Ssid) -> WifiConnectTarget {
    WifiConnectTarget {
        ssid,
        ap_path: None,
        bssid: None,
        ifname: None,
        device_path: None,
        connection_name: None,
        private: false,
        hidden: false,
        security: None,
        key_mgmt: None,
        enterprise: None,
        profile: TargetProfileSettings::default(),
    }
}

fn enterprise_auth_for_network(
    network: &NetworkEntry,
    identity: Option<String>,
) -> Option<EnterpriseAuth> {
    identity.map(|identity| {
        let mut enterprise = network
            .connect_prompt
            .enterprise_defaults
            .clone()
            .unwrap_or_else(|| default_enterprise_auth(identity.clone()));
        enterprise.identity = Some(identity);
        enterprise
    })
}

fn default_enterprise_auth(identity: String) -> EnterpriseAuth {
    EnterpriseAuth {
        eap: vec!["peap".to_string()],
        identity: Some(identity),
        phase2_auth: Some("mschapv2".to_string()),
        ..EnterpriseAuth::default()
    }
}

fn auth_capability_for(access_point: &AccessPoint, has_profile: bool) -> NetworkAuth {
    if has_profile {
        return saved_profile_auth();
    }
    unsaved_auth_capability(access_point)
}

fn unsaved_auth_capability(access_point: &AccessPoint) -> NetworkAuth {
    use crate::auth::WifiAuthentication;

    match crate::auth::classify(
        access_point.flags,
        access_point.wpa_flags,
        access_point.rsn_flags,
    ) {
        WifiAuthentication::Open => passwordless_auth(AuthKind::Open),
        WifiAuthentication::Owe => passwordless_auth(AuthKind::Owe),
        WifiAuthentication::Personal => personal_auth(access_point),
        WifiAuthentication::Wep => wep_auth(),
        WifiAuthentication::Enterprise => enterprise_auth_capability(access_point),
        WifiAuthentication::Unsupported => unsupported_auth(),
    }
}

fn saved_profile_auth() -> NetworkAuth {
    NetworkAuth::new(
        AuthKind::SavedProfile,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some("A compatible saved NetworkManager profile can be activated without collecting new credentials".to_string()),
    )
}

fn passwordless_auth(kind: AuthKind) -> NetworkAuth {
    NetworkAuth::new(kind, Vec::new(), Vec::new(), Vec::new(), None)
}

fn personal_auth(access_point: &AccessPoint) -> NetworkAuth {
    NetworkAuth::new(
        AuthKind::WpaPersonal,
        vec![
            crate::auth::personal_key_management(access_point.wpa_flags, access_point.rsn_flags)
                .to_string(),
        ],
        vec!["password".to_string()],
        Vec::new(),
        None,
    )
}

fn wep_auth() -> NetworkAuth {
    NetworkAuth::new(
        AuthKind::Wep,
        vec!["none".to_string()],
        vec!["password".to_string()],
        vec!["wep_key_type".to_string()],
        None,
    )
}

fn enterprise_auth_capability(access_point: &AccessPoint) -> NetworkAuth {
    NetworkAuth::new(
        AuthKind::WpaEnterprise,
        vec![enterprise_key_mgmt(access_point.wpa_flags, access_point.rsn_flags).to_string()],
        enterprise_required_fields(),
        enterprise_optional_fields(),
        Some("Provide an enterprise credential object to connect-target; password may be supplied with --password-stdin".to_string()),
    )
}

fn enterprise_required_fields() -> Vec<String> {
    ["enterprise.eap", "enterprise.identity"]
        .map(str::to_string)
        .to_vec()
}

fn enterprise_optional_fields() -> Vec<String> {
    [
        "password",
        "enterprise.anonymous_identity",
        "enterprise.phase2_auth",
        "enterprise.ca_cert",
        "enterprise.domain_suffix_match",
        "enterprise.client_cert",
        "enterprise.private_key",
        "enterprise.private_key_password",
    ]
    .map(str::to_string)
    .to_vec()
}

fn unsupported_auth() -> NetworkAuth {
    NetworkAuth::new(
        AuthKind::Unsupported,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some("No nm-daemon creation path is known for this visible network yet".to_string()),
    )
}

fn connect_prompt_for(
    access_point: &AccessPoint,
    auth: &NetworkAuth,
    has_profile: bool,
) -> NetworkConnectPrompt {
    if has_profile || auth.required_fields.is_empty() {
        return no_credentials_prompt(auth);
    }
    if requires_enterprise_fields(auth) {
        return enterprise_prompt(access_point, auth);
    }
    if requires_password(auth) {
        return password_prompt(auth);
    }
    prompt_from_auth(PromptKind::Unsupported, auth, auth.note.clone(), None)
}

fn prompt_from_auth(
    kind: PromptKind,
    auth: &NetworkAuth,
    message: Option<String>,
    enterprise_defaults: Option<EnterpriseAuth>,
) -> NetworkConnectPrompt {
    NetworkConnectPrompt {
        kind,
        required_fields: if kind == PromptKind::None {
            Vec::new()
        } else {
            auth.required_fields.clone()
        },
        optional_fields: auth.optional_fields.clone(),
        message,
        enterprise_defaults,
    }
}

fn no_credentials_prompt(auth: &NetworkAuth) -> NetworkConnectPrompt {
    let kind = if auth.supported() {
        PromptKind::None
    } else {
        PromptKind::Unsupported
    };
    prompt_from_auth(kind, auth, auth.note.clone(), None)
}

fn requires_enterprise_fields(auth: &NetworkAuth) -> bool {
    auth.required_fields
        .iter()
        .any(|field| field.starts_with("enterprise."))
}

fn enterprise_prompt(access_point: &AccessPoint, auth: &NetworkAuth) -> NetworkConnectPrompt {
    let message = auth
        .note
        .clone()
        .or_else(|| Some("Enter enterprise Wi-Fi credentials.".to_string()));
    let defaults = EnterpriseAuth {
        eap: vec!["peap".to_string()],
        phase2_auth: Some("mschapv2".to_string()),
        key_mgmt: Some(
            enterprise_key_mgmt(access_point.wpa_flags, access_point.rsn_flags).to_string(),
        ),
        ..Default::default()
    };
    prompt_from_auth(PromptKind::Enterprise, auth, message, Some(defaults))
}

fn requires_password(auth: &NetworkAuth) -> bool {
    auth.required_fields.iter().any(|field| field == "password")
}

fn password_prompt(auth: &NetworkAuth) -> NetworkConnectPrompt {
    let message = auth
        .note
        .clone()
        .or_else(|| Some("Enter the Wi-Fi password, then press Enter.".to_string()));
    prompt_from_auth(PromptKind::Password, auth, message, None)
}

fn network_share_hint_for(
    access_point: &AccessPoint,
    primary_profile: Option<&SavedWifiConnection>,
) -> NetworkShareHint {
    if is_shareable_passwordless_network(access_point) {
        return passwordless_network_share_hint(access_point);
    }
    if let Some(profile) = primary_profile {
        return profile_share_hint(profile);
    }
    unshareable_hint(
        "Wi-Fi QR sharing requires an open network or a saved profile with a readable password.",
    )
}

fn is_shareable_passwordless_network(access_point: &AccessPoint) -> bool {
    !access_point.ssid_bytes().is_empty() && access_point_is_passwordless(access_point)
}

fn passwordless_network_share_hint(access_point: &AccessPoint) -> NetworkShareHint {
    NetworkShareHint {
        shareable: true,
        reason: None,
        requires_profile_secret_check: false,
        profile_path: None,
        qr_payload: Some(wifi_qr_payload("nopass", &access_point.ssid, None, false)),
    }
}

fn unshareable_hint(reason: &str) -> NetworkShareHint {
    NetworkShareHint {
        shareable: false,
        reason: Some(reason.to_string()),
        requires_profile_secret_check: false,
        profile_path: None,
        qr_payload: None,
    }
}

fn profile_share_hint(profile: &SavedWifiConnection) -> NetworkShareHint {
    NetworkShareHint {
        shareable: false,
        reason: Some(
            "Saved profile password availability must be checked before sharing".to_string(),
        ),
        requires_profile_secret_check: true,
        profile_path: Some(profile.path.clone()),
        qr_payload: None,
    }
}

fn portal_hint_for(access_point: &AccessPoint) -> NetworkPortalHint {
    let auto_open_on_connect = ap_is_passwordless(
        access_point.flags,
        access_point.wpa_flags,
        access_point.rsn_flags,
    ) && !ap_uses_owe(access_point.wpa_flags, access_point.rsn_flags);
    NetworkPortalHint {
        auto_open_on_connect,
        reason: auto_open_on_connect
            .then(|| "open network may require captive-portal sign-in".to_string()),
    }
}

pub(crate) fn ap_uses_wep(flags: u32, wpa_flags: u32, rsn_flags: u32) -> bool {
    flags & NM_AP_FLAGS_PRIVACY != 0 && wpa_flags == 0 && rsn_flags == 0
}

fn flags_are_passwordless(flags: u32) -> bool {
    let secret_key_mgmt = NM_AP_SEC_KEY_MGMT_PSK
        | NM_AP_SEC_KEY_MGMT_802_1X
        | NM_AP_SEC_KEY_MGMT_SAE
        | NM_AP_SEC_KEY_MGMT_EAP_SUITE_B_192;
    flags & secret_key_mgmt == 0 && (flags == 0 || has_owe(flags))
}

fn has_owe(flags: u32) -> bool {
    flags & (NM_AP_SEC_KEY_MGMT_OWE | NM_AP_SEC_KEY_MGMT_OWE_TM) != 0
}

#[cfg(test)]
#[path = "../test_support/model_unit.rs"]
mod tests;
