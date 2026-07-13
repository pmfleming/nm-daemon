use std::borrow::Cow;
use std::time::Duration;

use crate::qr::wifi_qr_payload;

use anyhow::{Result, bail};
use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zvariant::OwnedObjectPath;

mod identity;

pub(crate) use identity::{Bssid, InterfaceName, NmObjectPath, Ssid};

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
pub(crate) struct ScanStreamOptions {
    pub(crate) timeout: Duration,
    pub(crate) retries: u32,
    pub(crate) cache: bool,
    pub(crate) ifname: Option<InterfaceName>,
    pub(crate) ssid_bytes: Vec<Vec<u8>>,
}

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
    NmcliFallback,
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
pub(crate) struct WifiStatus {
    pub(crate) active: bool,
    pub(crate) device_iface: Option<String>,
    pub(crate) active_connection_path: Option<String>,
    pub(crate) access_point: Option<AccessPoint>,
    pub(crate) network: Option<NetworkEntry>,
    pub(crate) profile: Option<SavedWifiConnection>,
    pub(crate) connectivity: Option<ConnectivityStatus>,
    pub(crate) ip4: Option<Ip4Status>,
    pub(crate) wireless: Option<WirelessStatus>,
    pub(crate) metered: Option<MeteredStatus>,
    pub(crate) active_since_ms: Option<u64>,
}

impl WifiStatus {
    pub(crate) fn inactive(
        device_iface: Option<String>,
        connectivity: Option<ConnectivityStatus>,
    ) -> Self {
        Self {
            active: false,
            device_iface,
            active_connection_path: None,
            access_point: None,
            network: None,
            profile: None,
            connectivity,
            ip4: None,
            wireless: None,
            metered: None,
            active_since_ms: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ConnectionDetails {
    pub(crate) ip4: Option<Ip4Status>,
    pub(crate) wireless: Option<WirelessStatus>,
    pub(crate) metered: Option<MeteredStatus>,
    pub(crate) active_since_ms: Option<u64>,
    pub(crate) updated_at_ms: u128,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Ip4Status {
    pub(crate) address: Option<String>,
    pub(crate) prefix: Option<u32>,
    pub(crate) gateway: Option<String>,
    pub(crate) dns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WirelessStatus {
    /// NetworkManager's single current wireless bitrate, when exposed by the device.
    pub(crate) bitrate_mbps: Option<u32>,
    /// Directional transmit bitrate measured via nl80211/iw when available.
    pub(crate) tx_bitrate_mbps: Option<f64>,
    /// Directional receive bitrate measured via nl80211/iw when available.
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
            captive_portal: matches!(code, 2 | 3),
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

    pub(crate) fn nmcli_value(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Phrase => "phrase",
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Security {
    Open,
    Owe,
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
            "WPA" => Self::Wpa,
            "WPA2/3" => Self::Wpa2Or3,
            "WEP" | "wep" => Self::Wep,
            "Enterprise" => Self::Enterprise,
            _ => Self::Other(value),
        })
    }
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
    /// Optional key-management/security hint for hidden or otherwise ambiguous targets.
    /// Values follow NetworkManager setting names where possible: open/none, owe,
    /// wpa-psk, sae, wep, wpa-eap, or wpa-eap-suite-b-192.
    pub(crate) key_mgmt: Option<String>,
    /// Optional structured 802.1X/EAP credentials for enterprise Wi-Fi creation.
    pub(crate) enterprise: Option<EnterpriseAuth>,
    /// Optional profile/IP settings to apply when creating cloned/new profiles.
    pub(crate) profile: TargetProfileSettings,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WifiConnectTargetV1 {
    ssid: String,
    #[serde(default)]
    ssid_bytes: Vec<u8>,
    #[serde(default, alias = "path")]
    ap_path: Option<NmObjectPath>,
    #[serde(default)]
    bssid: Option<Bssid>,
    #[serde(default, alias = "device_iface")]
    ifname: Option<InterfaceName>,
    #[serde(default)]
    device_path: Option<NmObjectPath>,
    #[serde(default, alias = "name")]
    connection_name: Option<String>,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    security: Option<Security>,
    #[serde(default)]
    key_mgmt: Option<String>,
    #[serde(default)]
    enterprise: Option<EnterpriseAuth>,
    #[serde(default)]
    profile: TargetProfileSettings,
}

impl Serialize for WifiConnectTarget {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("WifiConnectTarget", 13)?;
        state.serialize_field("ssid", self.ssid.as_str())?;
        state.serialize_field("ssid_bytes", self.ssid.as_bytes())?;
        state.serialize_field("ap_path", &self.ap_path)?;
        state.serialize_field("bssid", &self.bssid)?;
        state.serialize_field("ifname", &self.ifname)?;
        state.serialize_field("device_path", &self.device_path)?;
        state.serialize_field("connection_name", &self.connection_name)?;
        state.serialize_field("private", &self.private)?;
        state.serialize_field("hidden", &self.hidden)?;
        state.serialize_field("security", &self.security)?;
        state.serialize_field("key_mgmt", &self.key_mgmt)?;
        state.serialize_field("enterprise", &self.enterprise)?;
        state.serialize_field("profile", &self.profile)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for WifiConnectTarget {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WifiConnectTargetV1::deserialize(deserializer)?;
        let bytes = if wire.ssid_bytes.is_empty() {
            wire.ssid.as_bytes().to_vec()
        } else {
            wire.ssid_bytes
        };
        let ssid = Ssid::from_bytes(bytes).map_err(D::Error::custom)?;
        if ssid.as_str() != wire.ssid {
            return Err(D::Error::custom(
                "ssid display does not match the exact ssid_bytes identity",
            ));
        }
        Ok(Self {
            ssid,
            ap_path: wire.ap_path,
            bssid: wire.bssid,
            ifname: wire.ifname,
            device_path: wire.device_path,
            connection_name: wire.connection_name,
            private: wire.private,
            hidden: wire.hidden,
            security: wire.security,
            key_mgmt: wire.key_mgmt,
            enterprise: wire.enterprise,
            profile: wire.profile,
        })
    }
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

#[derive(Deserialize)]
struct NetworkCapabilitiesV1 {
    can_connect: bool,
    can_connect_now: bool,
    can_connect_with_password: bool,
    needs_password: bool,
    #[serde(default)]
    can_connect_with_credentials: bool,
    #[serde(default)]
    needs_credentials: bool,
    can_forget: bool,
    can_toggle_autoconnect: bool,
    #[serde(default)]
    can_set_mac_randomization: bool,
    #[serde(default)]
    can_set_send_hostname: bool,
    #[serde(default)]
    can_share_qr: bool,
    supported_auth: bool,
    unsupported_reason: Option<String>,
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

impl Serialize for NetworkCapabilities {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (
            can_connect,
            can_connect_now,
            with_password,
            needs_password,
            with_credentials,
            needs_credentials,
            supported_auth,
            unsupported_reason,
        ) = self.v1_readiness();
        let mut state = serializer.serialize_struct("NetworkCapabilities", 13)?;
        state.serialize_field("can_connect", &can_connect)?;
        state.serialize_field("can_connect_now", &can_connect_now)?;
        state.serialize_field("can_connect_with_password", &with_password)?;
        state.serialize_field("needs_password", &needs_password)?;
        state.serialize_field("can_connect_with_credentials", &with_credentials)?;
        state.serialize_field("needs_credentials", &needs_credentials)?;
        state.serialize_field("can_forget", &self.has_profile)?;
        state.serialize_field("can_toggle_autoconnect", &self.has_profile)?;
        state.serialize_field("can_set_mac_randomization", &self.has_profile)?;
        state.serialize_field("can_set_send_hostname", &self.has_profile)?;
        state.serialize_field("can_share_qr", &self.can_share_qr)?;
        state.serialize_field("supported_auth", &supported_auth)?;
        state.serialize_field("unsupported_reason", &unsupported_reason)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for NetworkCapabilities {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = NetworkCapabilitiesV1::deserialize(deserializer)?;
        let profile_flags = [
            wire.can_forget,
            wire.can_toggle_autoconnect,
            wire.can_set_mac_randomization,
            wire.can_set_send_hostname,
        ];
        if profile_flags.iter().any(|flag| *flag != profile_flags[0]) {
            return Err(D::Error::custom(
                "profile mutation capability flags must agree",
            ));
        }
        let readiness = match (
            wire.can_connect,
            wire.can_connect_now,
            wire.can_connect_with_password,
            wire.needs_password,
            wire.can_connect_with_credentials,
            wire.needs_credentials,
            wire.supported_auth,
        ) {
            (true, true, false, false, false, false, true) => ConnectionReadiness::Ready,
            (true, false, true, true, false, false, true) => ConnectionReadiness::NeedsPassword,
            (true, false, false, false, true, true, true) => {
                ConnectionReadiness::NeedsEnterpriseCredentials
            }
            (false, false, false, false, false, false, false) => ConnectionReadiness::Unsupported {
                reason: wire.unsupported_reason,
            },
            _ => {
                return Err(D::Error::custom(
                    "contradictory v1 network readiness capability flags",
                ));
            }
        };
        Ok(Self {
            readiness,
            has_profile: profile_flags[0],
            can_share_qr: wire.can_share_qr,
        })
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

#[derive(Deserialize, Serialize)]
struct NetworkAuthV1 {
    kind: AuthKind,
    key_management: Vec<String>,
    supported: bool,
    required_fields: Vec<String>,
    optional_fields: Vec<String>,
    note: Option<String>,
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

impl Serialize for NetworkAuth {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        NetworkAuthV1 {
            kind: self.kind,
            key_management: self.key_management.clone(),
            supported: self.supported(),
            required_fields: self.required_fields.clone(),
            optional_fields: self.optional_fields.clone(),
            note: self.note.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NetworkAuth {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = NetworkAuthV1::deserialize(deserializer)?;
        if wire.supported != (wire.kind != AuthKind::Unsupported) {
            return Err(D::Error::custom(
                "authentication kind contradicts supported flag",
            ));
        }
        Ok(Self::new(
            wire.kind,
            wire.key_management,
            wire.required_fields,
            wire.optional_fields,
            wire.note,
        ))
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
    /// Stable frontend key for preserving selection without reimplementing AP matching.
    pub(crate) key: String,
    /// Exact APs for this displayed network group. The flattened access_point is
    /// the preferred/default AP; frontends can use this list for exact BSSID,
    /// band, and device selection.
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
        .map(|group| {
            let profiles = profiles_for_access_point_group(&group, profile_matches_by_ap_path);
            network_entry_with_profiles(group, profiles)
        })
        .collect()
}

fn grouped_access_points(access_points: Vec<AccessPoint>) -> Vec<Vec<AccessPoint>> {
    let mut groups = std::collections::BTreeMap::<Vec<u8>, Vec<AccessPoint>>::new();
    for access_point in access_points {
        groups
            .entry(access_point.ssid_bytes().into_owned())
            .or_default()
            .push(access_point);
    }
    groups.into_values().collect()
}

fn network_entry_with_profiles(
    access_points: Vec<AccessPoint>,
    profiles: Vec<SavedWifiConnection>,
) -> NetworkEntry {
    let access_point = preferred_access_point(&access_points);
    let key = network_key_for(&access_point);
    let primary_profile = profiles.first().cloned();
    let has_identity = !access_point.ssid_bytes().is_empty();
    let has_profile = primary_profile.is_some();
    let passwordless = ap_is_passwordless(
        access_point.flags,
        access_point.wpa_flags,
        access_point.rsn_flags,
    );
    let supports_password_auth = ap_supports_psk(access_point.wpa_flags, access_point.rsn_flags)
        || ap_uses_wep(
            access_point.flags,
            access_point.wpa_flags,
            access_point.rsn_flags,
        );
    let supports_enterprise_auth =
        ap_supports_enterprise(access_point.wpa_flags, access_point.rsn_flags);
    let readiness = if !has_identity {
        ConnectionReadiness::Unsupported {
            reason: Some("network has no usable SSID".to_string()),
        }
    } else if has_profile || passwordless {
        ConnectionReadiness::Ready
    } else if supports_password_auth {
        ConnectionReadiness::NeedsPassword
    } else if supports_enterprise_auth {
        ConnectionReadiness::NeedsEnterpriseCredentials
    } else {
        ConnectionReadiness::Unsupported {
            reason: Some(unsupported_auth_reason(&access_point)),
        }
    };
    let auth = auth_capability_for(&access_point, has_profile);
    let connect_prompt = connect_prompt_for(&access_point, &auth, has_profile);
    let share = network_share_hint_for(&access_point, primary_profile.as_ref());
    let portal_hint = portal_hint_for(&access_point);
    NetworkEntry {
        access_point,
        key,
        access_points,
        primary_profile,
        capabilities: NetworkCapabilities {
            readiness,
            has_profile,
            can_share_qr: share.shareable || share.requires_profile_secret_check,
        },
        profiles,
        auth,
        connect_prompt,
        share,
        portal_hint,
        last_connection: None,
    }
}

fn preferred_access_point(access_points: &[AccessPoint]) -> AccessPoint {
    access_points
        .iter()
        .max_by(|left, right| {
            left.active
                .cmp(&right.active)
                .then_with(|| left.strength.cmp(&right.strength))
        })
        .cloned()
        .expect("network entries require at least one access point")
}

fn profiles_for_access_point_group(
    access_points: &[AccessPoint],
    profile_matches_by_ap_path: &std::collections::BTreeMap<String, Vec<SavedWifiConnection>>,
) -> Vec<SavedWifiConnection> {
    let mut seen_paths = std::collections::BTreeSet::new();
    let mut profiles = Vec::new();
    for access_point in access_points {
        let Some(matches) = profile_matches_by_ap_path.get(&access_point.path) else {
            continue;
        };
        for profile in matches {
            if seen_paths.insert(profile.path.clone()) {
                profiles.push(profile.clone());
            }
        }
    }
    profiles
}

#[derive(Debug)]
pub(crate) enum ScanEvent {
    WatcherReady,
    WatcherWarning(String),
    AccessPointsChanged,
    LastScanChanged { device_path: String, value: i64 },
}

pub(crate) fn display_ssid(ssid_bytes: &[u8]) -> String {
    String::from_utf8_lossy(ssid_bytes).into_owned()
}

pub(crate) fn ssid_hex(ssid_bytes: &[u8]) -> String {
    ssid_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

pub(crate) fn frequency_channel(frequency: u32) -> u32 {
    match frequency {
        2412..=2472 => (frequency - 2407) / 5,
        2484 => 14,
        5000..=5900 => (frequency - 5000) / 5,
        5955..=7115 => ((frequency - 5955) / 5) + 1,
        _ => 0,
    }
}

pub(crate) fn frequency_band(frequency: u32) -> &'static str {
    match frequency {
        2400..=2500 => "2.4 GHz",
        4900..=5900 => "5 GHz",
        5925..=7125 => "6 GHz",
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
        if has_owe(wpa_flags | rsn_flags) {
            Security::Owe
        } else {
            Security::Open
        }
    } else if rsn_flags != 0 {
        Security::Wpa2Or3
    } else if wpa_flags != 0 {
        Security::Wpa
    } else {
        Security::Wep
    }
}

pub(crate) fn ap_is_passwordless(flags: u32, wpa_flags: u32, rsn_flags: u32) -> bool {
    let privacy = flags & NM_AP_FLAGS_PRIVACY != 0;
    ap_uses_owe(wpa_flags, rsn_flags)
        || (!privacy && flags_are_passwordless(wpa_flags) && flags_are_passwordless(rsn_flags))
}

pub(crate) fn ap_uses_owe(wpa_flags: u32, rsn_flags: u32) -> bool {
    has_owe(wpa_flags | rsn_flags)
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
    if !access_point.path.is_empty() {
        return access_point.path.clone();
    }
    if !access_point.ssid_hex.is_empty() {
        return format!("ssid-hex:{}", access_point.ssid_hex);
    }
    format!("ssid:{}", access_point.ssid)
}

fn auth_capability_for(access_point: &AccessPoint, has_profile: bool) -> NetworkAuth {
    if has_profile {
        return NetworkAuth::new(
            AuthKind::SavedProfile,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some("A compatible saved NetworkManager profile can be activated without collecting new credentials".to_string()),
        );
    }

    if ap_is_passwordless(
        access_point.flags,
        access_point.wpa_flags,
        access_point.rsn_flags,
    ) {
        return NetworkAuth::new(
            if has_owe(access_point.wpa_flags | access_point.rsn_flags) {
                AuthKind::Owe
            } else {
                AuthKind::Open
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
        );
    }

    if ap_supports_psk(access_point.wpa_flags, access_point.rsn_flags) {
        return NetworkAuth::new(
            AuthKind::WpaPersonal,
            vec![
                if (access_point.wpa_flags | access_point.rsn_flags) & NM_AP_SEC_KEY_MGMT_SAE != 0
                    && (access_point.wpa_flags | access_point.rsn_flags) & NM_AP_SEC_KEY_MGMT_PSK
                        == 0
                {
                    "sae".to_string()
                } else {
                    "wpa-psk".to_string()
                },
            ],
            vec!["password".to_string()],
            Vec::new(),
            None,
        );
    }

    if ap_uses_wep(
        access_point.flags,
        access_point.wpa_flags,
        access_point.rsn_flags,
    ) {
        return NetworkAuth::new(
            AuthKind::Wep,
            vec!["none".to_string()],
            vec!["password".to_string()],
            vec!["wep_key_type".to_string()],
            None,
        );
    }

    if ap_supports_enterprise(access_point.wpa_flags, access_point.rsn_flags) {
        return NetworkAuth::new(
            AuthKind::WpaEnterprise,
            vec![enterprise_key_mgmt(
                access_point.wpa_flags,
                access_point.rsn_flags,
            )
            .to_string()],
            vec!["enterprise.eap".to_string(), "enterprise.identity".to_string()],
            vec![
                "password".to_string(),
                "enterprise.anonymous_identity".to_string(),
                "enterprise.phase2_auth".to_string(),
                "enterprise.ca_cert".to_string(),
                "enterprise.domain_suffix_match".to_string(),
                "enterprise.client_cert".to_string(),
                "enterprise.private_key".to_string(),
                "enterprise.private_key_password".to_string(),
            ],
            Some("Provide an enterprise credential object to connect-target; password may be supplied with --password-stdin".to_string()),
        );
    }

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
        return NetworkConnectPrompt {
            kind: if auth.supported() {
                PromptKind::None
            } else {
                PromptKind::Unsupported
            },
            required_fields: Vec::new(),
            optional_fields: auth.optional_fields.clone(),
            message: auth.note.clone(),
            enterprise_defaults: None,
        };
    }

    if auth
        .required_fields
        .iter()
        .any(|field| field.starts_with("enterprise."))
    {
        return NetworkConnectPrompt {
            kind: PromptKind::Enterprise,
            required_fields: auth.required_fields.clone(),
            optional_fields: auth.optional_fields.clone(),
            message: auth
                .note
                .clone()
                .or_else(|| Some("Enter enterprise Wi-Fi credentials.".to_string())),
            enterprise_defaults: Some(EnterpriseAuth {
                eap: vec!["peap".to_string()],
                phase2_auth: Some("mschapv2".to_string()),
                key_mgmt: Some(
                    enterprise_key_mgmt(access_point.wpa_flags, access_point.rsn_flags).to_string(),
                ),
                ..Default::default()
            }),
        };
    }

    if auth.required_fields.iter().any(|field| field == "password") {
        return NetworkConnectPrompt {
            kind: PromptKind::Password,
            required_fields: auth.required_fields.clone(),
            optional_fields: auth.optional_fields.clone(),
            message: auth
                .note
                .clone()
                .or_else(|| Some("Enter the Wi-Fi password, then press Enter.".to_string())),
            enterprise_defaults: None,
        };
    }

    NetworkConnectPrompt {
        kind: PromptKind::Unsupported,
        required_fields: auth.required_fields.clone(),
        optional_fields: auth.optional_fields.clone(),
        message: auth.note.clone(),
        enterprise_defaults: None,
    }
}

fn network_share_hint_for(
    access_point: &AccessPoint,
    primary_profile: Option<&SavedWifiConnection>,
) -> NetworkShareHint {
    if !access_point.ssid_bytes().is_empty()
        && ap_is_passwordless(
            access_point.flags,
            access_point.wpa_flags,
            access_point.rsn_flags,
        )
        && !ap_uses_owe(access_point.wpa_flags, access_point.rsn_flags)
    {
        return NetworkShareHint {
            shareable: true,
            reason: None,
            requires_profile_secret_check: false,
            profile_path: None,
            qr_payload: Some(wifi_qr_payload("nopass", &access_point.ssid, None, false)),
        };
    }

    if ap_uses_owe(access_point.wpa_flags, access_point.rsn_flags) {
        return NetworkShareHint {
            shareable: false,
            reason: Some(
                "OWE/enhanced-open QR sharing is not supported by the standard Wi-Fi QR format"
                    .to_string(),
            ),
            requires_profile_secret_check: false,
            profile_path: None,
            qr_payload: None,
        };
    }

    if let Some(profile) = primary_profile {
        return NetworkShareHint {
            shareable: false,
            reason: Some(
                "Saved profile password availability must be checked before sharing".to_string(),
            ),
            requires_profile_secret_check: true,
            profile_path: Some(profile.path.clone()),
            qr_payload: None,
        };
    }

    NetworkShareHint {
        shareable: false,
        reason: Some("Wi-Fi QR sharing requires an open network or a saved profile with a readable password.".to_string()),
        requires_profile_secret_check: false,
        profile_path: None,
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

pub(crate) fn retry_delay(attempts: u32) -> Duration {
    Duration::from_secs(2_u64.pow(attempts.saturating_sub(1).min(3)))
}

#[cfg(test)]
mod tests {
    include!("../test_support/model_unit.rs");
}
