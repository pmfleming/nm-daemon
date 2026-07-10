use std::borrow::Cow;
use std::time::Duration;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use zvariant::OwnedObjectPath;

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
    pub(crate) ifname: Option<String>,
    pub(crate) ssid_bytes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanRequestOptions {
    pub(crate) timeout: Duration,
    pub(crate) ifname: Option<String>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WifiConnectTarget {
    /// Human-readable display form of the SSID. This may be lossy for non-UTF-8 SSIDs.
    pub(crate) ssid: String,
    /// Exact SSID bytes used for identity/matching. Empty only for legacy cache/action records.
    #[serde(default)]
    pub(crate) ssid_bytes: Vec<u8>,
    #[serde(alias = "path")]
    pub(crate) ap_path: Option<String>,
    pub(crate) bssid: Option<String>,
    #[serde(default, alias = "device_iface")]
    pub(crate) ifname: Option<String>,
    #[serde(default)]
    pub(crate) device_path: Option<String>,
    /// Optional NetworkManager connection id requested by the frontend.
    #[serde(default, alias = "name")]
    pub(crate) connection_name: Option<String>,
    /// Restrict a newly-created connection to the current user when supported.
    #[serde(default)]
    pub(crate) private: bool,
    #[serde(default)]
    pub(crate) hidden: bool,
    #[serde(default)]
    pub(crate) security: Option<String>,
    /// Optional key-management/security hint for hidden or otherwise ambiguous targets.
    /// Values follow NetworkManager setting names where possible: open/none, owe,
    /// wpa-psk, sae, wep, wpa-eap, or wpa-eap-suite-b-192.
    #[serde(default)]
    pub(crate) key_mgmt: Option<String>,
    /// Optional structured 802.1X/EAP credentials for enterprise Wi-Fi creation.
    #[serde(default)]
    pub(crate) enterprise: Option<EnterpriseAuth>,
    /// Optional profile/IP settings to apply when creating cloned/new profiles.
    #[serde(default)]
    pub(crate) profile: TargetProfileSettings,
}

#[cfg(test)]
pub(crate) fn example_connect_target(hidden: bool) -> WifiConnectTarget {
    WifiConnectTarget {
        ssid: "Example".to_string(),
        ssid_bytes: b"Example".to_vec(),
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
    pub(crate) fn ssid_bytes(&self) -> Cow<'_, [u8]> {
        ssid_bytes_or_display(&self.ssid_bytes, &self.ssid)
    }

    pub(crate) fn has_specific_ap(&self) -> bool {
        self.ap_path
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            || self.bssid.as_deref().is_some_and(|value| !value.is_empty())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_ssid_bytes(self.ssid_bytes().as_ref())?;
        if let Some(bssid) = self.bssid.as_deref().filter(|value| !value.is_empty()) {
            validate_bssid(bssid)?;
        }
        if self.hidden
            && self.bssid.as_deref().is_none_or(str::is_empty)
            && looks_like_bssid(&self.ssid)
        {
            bail!(
                "hidden Wi-Fi target must be an SSID, but '{}' looks like a BSSID",
                self.ssid
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct NetworkCapabilities {
    /// Backend has a supported activation flow for this network. Unsaved PSK/WEP
    /// networks may still require the caller to provide a password.
    pub(crate) can_connect: bool,
    /// Backend can connect without prompting for any additional secret.
    pub(crate) can_connect_now: bool,
    /// Backend can connect if the caller supplies a password/key.
    pub(crate) can_connect_with_password: bool,
    pub(crate) needs_password: bool,
    /// Backend can connect if the caller supplies a structured credential set
    /// described by `NetworkEntry::auth`.
    #[serde(default)]
    pub(crate) can_connect_with_credentials: bool,
    #[serde(default)]
    pub(crate) needs_credentials: bool,
    pub(crate) can_forget: bool,
    pub(crate) can_toggle_autoconnect: bool,
    #[serde(default)]
    pub(crate) can_set_mac_randomization: bool,
    #[serde(default)]
    pub(crate) can_set_send_hostname: bool,
    #[serde(default)]
    pub(crate) can_share_qr: bool,
    pub(crate) supported_auth: bool,
    pub(crate) unsupported_reason: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct NetworkAuth {
    pub(crate) kind: String,
    pub(crate) key_management: Vec<String>,
    pub(crate) supported: bool,
    pub(crate) required_fields: Vec<String>,
    pub(crate) optional_fields: Vec<String>,
    pub(crate) note: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct NetworkConnectPrompt {
    /// One of: none, password, enterprise, unsupported.
    pub(crate) kind: String,
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
    pub(crate) security: String,
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
    let supported_auth =
        has_profile || passwordless || supports_password_auth || supports_enterprise_auth;
    let needs_password = has_identity && !has_profile && supports_password_auth;
    let needs_credentials = has_identity && !has_profile && supports_enterprise_auth;
    let can_connect_now = has_identity && (has_profile || passwordless);
    let can_connect_with_password = has_identity && !has_profile && supports_password_auth;
    let can_connect_with_credentials = has_identity && !has_profile && supports_enterprise_auth;
    let unsupported_reason = (!supported_auth).then(|| unsupported_auth_reason(&access_point));
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
            can_connect: has_identity && supported_auth,
            can_connect_now,
            can_connect_with_password,
            needs_password,
            can_connect_with_credentials,
            needs_credentials,
            can_forget: has_profile,
            can_toggle_autoconnect: has_profile,
            can_set_mac_randomization: has_profile,
            can_set_send_hostname: has_profile,
            can_share_qr: share.shareable || share.requires_profile_secret_check,
            supported_auth,
            unsupported_reason,
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

pub(crate) fn security_label(flags: u32, wpa_flags: u32, rsn_flags: u32) -> String {
    if ap_is_passwordless(flags, wpa_flags, rsn_flags) {
        if has_owe(wpa_flags | rsn_flags) {
            "OWE".to_string()
        } else {
            "--".to_string()
        }
    } else if rsn_flags != 0 {
        "WPA2/3".to_string()
    } else if wpa_flags != 0 {
        "WPA".to_string()
    } else {
        "WEP".to_string()
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
        return NetworkAuth {
            kind: "saved-profile".to_string(),
            key_management: Vec::new(),
            supported: true,
            required_fields: Vec::new(),
            optional_fields: Vec::new(),
            note: Some("A compatible saved NetworkManager profile can be activated without collecting new credentials".to_string()),
        };
    }

    if ap_is_passwordless(
        access_point.flags,
        access_point.wpa_flags,
        access_point.rsn_flags,
    ) {
        return NetworkAuth {
            kind: if has_owe(access_point.wpa_flags | access_point.rsn_flags) {
                "owe".to_string()
            } else {
                "open".to_string()
            },
            key_management: Vec::new(),
            supported: true,
            required_fields: Vec::new(),
            optional_fields: Vec::new(),
            note: None,
        };
    }

    if ap_supports_psk(access_point.wpa_flags, access_point.rsn_flags) {
        return NetworkAuth {
            kind: "wpa-personal".to_string(),
            key_management: vec![if (access_point.wpa_flags | access_point.rsn_flags)
                & NM_AP_SEC_KEY_MGMT_SAE
                != 0
                && (access_point.wpa_flags | access_point.rsn_flags) & NM_AP_SEC_KEY_MGMT_PSK == 0
            {
                "sae".to_string()
            } else {
                "wpa-psk".to_string()
            }],
            supported: true,
            required_fields: vec!["password".to_string()],
            optional_fields: Vec::new(),
            note: None,
        };
    }

    if ap_uses_wep(
        access_point.flags,
        access_point.wpa_flags,
        access_point.rsn_flags,
    ) {
        return NetworkAuth {
            kind: "wep".to_string(),
            key_management: vec!["none".to_string()],
            supported: true,
            required_fields: vec!["password".to_string()],
            optional_fields: vec!["wep_key_type".to_string()],
            note: None,
        };
    }

    if ap_supports_enterprise(access_point.wpa_flags, access_point.rsn_flags) {
        return NetworkAuth {
            kind: "wpa-enterprise".to_string(),
            key_management: vec![enterprise_key_mgmt(
                access_point.wpa_flags,
                access_point.rsn_flags,
            )
            .to_string()],
            supported: true,
            required_fields: vec!["enterprise.eap".to_string(), "enterprise.identity".to_string()],
            optional_fields: vec![
                "password".to_string(),
                "enterprise.anonymous_identity".to_string(),
                "enterprise.phase2_auth".to_string(),
                "enterprise.ca_cert".to_string(),
                "enterprise.domain_suffix_match".to_string(),
                "enterprise.client_cert".to_string(),
                "enterprise.private_key".to_string(),
                "enterprise.private_key_password".to_string(),
            ],
            note: Some("Provide an enterprise credential object to connect-target; password may be supplied with --password-stdin".to_string()),
        };
    }

    NetworkAuth {
        kind: "unsupported".to_string(),
        key_management: Vec::new(),
        supported: false,
        required_fields: Vec::new(),
        optional_fields: Vec::new(),
        note: Some("No nm-daemon creation path is known for this visible network yet".to_string()),
    }
}

fn connect_prompt_for(
    access_point: &AccessPoint,
    auth: &NetworkAuth,
    has_profile: bool,
) -> NetworkConnectPrompt {
    if has_profile || auth.required_fields.is_empty() {
        return NetworkConnectPrompt {
            kind: if auth.supported {
                "none"
            } else {
                "unsupported"
            }
            .to_string(),
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
            kind: "enterprise".to_string(),
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
            kind: "password".to_string(),
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
        kind: "unsupported".to_string(),
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

fn wifi_qr_payload(auth_type: &str, ssid: &str, password: Option<&str>, hidden: bool) -> String {
    let password = password
        .map(|password| format!(";P:{}", wifi_qr_escape(password)))
        .unwrap_or_default();
    let hidden = if hidden { ";H:true" } else { "" };
    format!(
        "WIFI:T:{};S:{}{}{};;",
        auth_type,
        wifi_qr_escape(ssid),
        password,
        hidden
    )
}

fn wifi_qr_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' | ';' | ',' | ':' | '"' => vec!['\\', ch],
            ch => vec![ch],
        })
        .collect()
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
