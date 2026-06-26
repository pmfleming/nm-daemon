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
    AuthorizationRequired,
    UnsupportedAuth,
    ValidationError,
    Timeout,
    ActivationFailed,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ConnectResult {
    pub(crate) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<ConnectFailureReason>,
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

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Ip4Status {
    pub(crate) address: Option<String>,
    pub(crate) prefix: Option<u32>,
    pub(crate) gateway: Option<String>,
    pub(crate) dns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WirelessStatus {
    /// NetworkManager's single current wireless bitrate, when exposed by the device.
    pub(crate) bitrate_mbps: Option<u32>,
    /// Directional transmit bitrate measured via nl80211/iw when available.
    pub(crate) tx_bitrate_mbps: Option<f64>,
    /// Directional receive bitrate measured via nl80211/iw when available.
    pub(crate) rx_bitrate_mbps: Option<f64>,
    pub(crate) mac_address: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MeteredStatus {
    pub(crate) code: u32,
    pub(crate) state: &'static str,
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
            state,
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

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
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
    /// Optional structured 802.1X/EAP credentials for enterprise Wi-Fi creation.
    #[serde(default)]
    pub(crate) enterprise: Option<EnterpriseAuth>,
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
    pub(crate) supported_auth: bool,
    pub(crate) unsupported_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct EnterpriseAuth {
    /// NetworkManager 802.1X EAP methods, e.g. ["peap"], ["ttls"], ["tls"], ["pwd"].
    #[serde(default)]
    pub(crate) eap: Vec<String>,
    #[serde(default)]
    pub(crate) identity: Option<String>,
    #[serde(default)]
    pub(crate) anonymous_identity: Option<String>,
    #[serde(default)]
    pub(crate) password: Option<String>,
    #[serde(default)]
    pub(crate) phase2_auth: Option<String>,
    #[serde(default)]
    pub(crate) ca_cert: Option<String>,
    #[serde(default)]
    pub(crate) domain_suffix_match: Option<String>,
    #[serde(default)]
    pub(crate) altsubject_matches: Vec<String>,
    #[serde(default)]
    pub(crate) client_cert: Option<String>,
    #[serde(default)]
    pub(crate) private_key: Option<String>,
    #[serde(default)]
    pub(crate) private_key_password: Option<String>,
    #[serde(default)]
    pub(crate) pin: Option<String>,
    #[serde(default)]
    pub(crate) pac_file: Option<String>,
    /// Optional override for unusual hidden-network cases. Visible APs derive this from AP flags.
    #[serde(default)]
    pub(crate) key_mgmt: Option<String>,
    #[serde(default)]
    pub(crate) system_ca_certs: Option<bool>,
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
pub(crate) struct NetworkEntry {
    #[serde(flatten)]
    pub(crate) access_point: AccessPoint,
    /// Exact APs for this displayed network group. The flattened access_point is
    /// the preferred/default AP; frontends can use this list for exact BSSID,
    /// band, and device selection.
    #[serde(default)]
    pub(crate) access_points: Vec<AccessPoint>,
    pub(crate) primary_profile: Option<SavedWifiConnection>,
    pub(crate) profiles: Vec<SavedWifiConnection>,
    pub(crate) capabilities: NetworkCapabilities,
    pub(crate) auth: NetworkAuth,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    let access_point = access_points
        .first()
        .cloned()
        .expect("network entries require at least one access point");
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
    let unsupported_reason = (!supported_auth).then(|| {
        "unsupported authentication; open/OWE, WEP, WPA/SAE-Personal, WPA-Enterprise, and saved profiles are supported"
            .to_string()
    });
    let auth = auth_capability_for(&access_point, has_profile);
    NetworkEntry {
        access_point,
        access_points,
        primary_profile,
        capabilities: NetworkCapabilities {
            can_connect: has_identity && (supported_auth && !needs_credentials),
            can_connect_now,
            can_connect_with_password,
            needs_password,
            can_connect_with_credentials,
            needs_credentials,
            can_forget: has_profile,
            can_toggle_autoconnect: has_profile,
            supported_auth,
            unsupported_reason,
        },
        profiles,
        auth,
    }
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
    !privacy && flags_are_passwordless(wpa_flags) && flags_are_passwordless(rsn_flags)
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
        note: Some("No nm-wifi creation path is known for this visible network yet".to_string()),
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
    use std::time::Duration;

    use super::{
        AccessPoint, ConnectivityStatus, MeteredStatus, NM_AP_FLAGS_PRIVACY,
        NM_AP_SEC_KEY_MGMT_802_1X, NM_AP_SEC_KEY_MGMT_OWE, NM_AP_SEC_KEY_MGMT_PSK,
        NM_AP_SEC_KEY_MGMT_SAE, ProfilePrivacy, SavedWifiConnection, WifiConnectTarget,
        ap_is_passwordless, ap_supports_enterprise, ap_supports_psk, ap_uses_wep,
        network_entries_with_profile_matches, retry_delay, security_flags_label, security_label,
    };

    #[test]
    fn retry_delay_uses_bounded_exponential_backoff() {
        assert_eq!(retry_delay(1), Duration::from_secs(1));
        assert_eq!(retry_delay(2), Duration::from_secs(2));
        assert_eq!(retry_delay(3), Duration::from_secs(4));
        assert_eq!(retry_delay(4), Duration::from_secs(8));
        assert_eq!(retry_delay(99), Duration::from_secs(8));
    }

    #[test]
    fn security_label_identifies_open_networks() {
        assert_eq!(security_label(0, 0, 0), "--");
    }

    #[test]
    fn security_label_prefers_rsn_over_wpa() {
        assert_eq!(security_label(NM_AP_FLAGS_PRIVACY, 1, 1), "WPA2/3");
        assert_eq!(security_label(NM_AP_FLAGS_PRIVACY, 1, 0), "WPA");
        assert_eq!(security_label(NM_AP_FLAGS_PRIVACY, 0, 0), "WEP");
    }

    #[test]
    fn owe_is_passwordless_but_psk_is_not() {
        assert!(ap_is_passwordless(0, 0, NM_AP_SEC_KEY_MGMT_OWE));
        assert_eq!(security_label(0, 0, NM_AP_SEC_KEY_MGMT_OWE), "OWE");
        assert!(!ap_is_passwordless(0, 0, NM_AP_SEC_KEY_MGMT_PSK));
    }

    #[test]
    fn psk_support_includes_sae() {
        assert!(ap_supports_psk(NM_AP_SEC_KEY_MGMT_PSK, 0));
        assert!(ap_supports_psk(0, NM_AP_SEC_KEY_MGMT_SAE));
        assert!(!ap_supports_psk(0, NM_AP_SEC_KEY_MGMT_OWE));
    }

    #[test]
    fn wep_detection_requires_privacy_without_wpa_or_rsn() {
        assert!(ap_uses_wep(NM_AP_FLAGS_PRIVACY, 0, 0));
        assert!(!ap_uses_wep(0, 0, 0));
        assert!(!ap_uses_wep(NM_AP_FLAGS_PRIVACY, NM_AP_SEC_KEY_MGMT_PSK, 0));
    }

    #[test]
    fn network_capabilities_distinguish_promptable_from_ready_connections() {
        assert_eq!(
            capabilities_for(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_PSK),
            expected_capabilities(true, false, true, true, true, false)
        );
    }

    #[test]
    fn network_capabilities_advertise_unsaved_enterprise_credentials() {
        let capabilities = capabilities_for(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_802_1X);
        assert!(!capabilities.can_connect);
        assert!(!capabilities.can_connect_now);
        assert!(!capabilities.can_connect_with_password);
        assert!(capabilities.can_connect_with_credentials);
        assert!(capabilities.needs_credentials);
        assert!(capabilities.supported_auth);
        assert!(capabilities.unsupported_reason.is_none());
        assert!(ap_supports_enterprise(0, NM_AP_SEC_KEY_MGMT_802_1X));
    }

    #[test]
    fn compatible_profile_matches_are_used_across_grouped_access_points() {
        let mut first_ap = test_ap(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_PSK);
        first_ap.path = "/ap/1".to_string();
        first_ap.strength = 80;
        let mut second_ap = test_ap(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_PSK);
        second_ap.path = "/ap/2".to_string();
        second_ap.strength = 40;
        let profile = test_profile();
        let matches =
            std::collections::BTreeMap::from([(second_ap.path.clone(), vec![profile.clone()])]);

        let [entry] = network_entries_with_profile_matches(vec![first_ap, second_ap], &matches)
            .try_into()
            .expect("one grouped network entry");

        assert_eq!(
            entry.primary_profile.as_ref().map(|profile| &profile.path),
            Some(&profile.path)
        );
        assert!(entry.capabilities.can_connect_now);
        assert!(!entry.capabilities.needs_password);
    }

    #[test]
    fn connectivity_status_maps_networkmanager_codes() {
        let portal = ConnectivityStatus::from_nm_code(2);
        assert_eq!(portal.state, "portal");
        assert!(portal.captive_portal);
        assert!(!portal.full);

        let full = ConnectivityStatus::from_nm_code(4);
        assert_eq!(full.state, "full");
        assert!(!full.captive_portal);
        assert!(full.full);
    }

    #[test]
    fn metered_status_maps_networkmanager_codes() {
        let yes = MeteredStatus::from_nm_code(1);
        assert_eq!(yes.state, "yes");
        assert_eq!(yes.metered, Some(true));
        assert!(!yes.guessed);

        let guess_no = MeteredStatus::from_nm_code(4);
        assert_eq!(guess_no.state, "guess-no");
        assert_eq!(guess_no.metered, Some(false));
        assert!(guess_no.guessed);

        let unknown = MeteredStatus::from_nm_code(0);
        assert_eq!(unknown.state, "unknown");
        assert_eq!(unknown.metered, None);
    }

    #[test]
    fn connect_target_validation_rejects_bad_identity() {
        let mut target = WifiConnectTarget {
            ssid: "Example".to_string(),
            ssid_bytes: b"Example".to_vec(),
            ap_path: None,
            bssid: Some("not-a-mac".to_string()),
            ifname: None,
            device_path: None,
            connection_name: None,
            private: false,
            hidden: false,
            security: None,
            enterprise: None,
        };
        assert!(target.validate().is_err());

        target.bssid = None;
        target.ssid_bytes = vec![b'x'; 33];
        assert!(target.validate().is_err());
    }

    #[test]
    fn connect_target_accepts_network_entry_path_alias() {
        let target: WifiConnectTarget = serde_json::from_str(
            r#"{
                "ssid": "Cafe",
                "ssid_bytes": [67, 97, 102, 101],
                "path": "/org/freedesktop/NetworkManager/AccessPoint/1",
                "bssid": "00:11:22:33:44:55",
                "device_iface": "wlan0"
            }"#,
        )
        .expect("target JSON");

        assert_eq!(target.ssid, "Cafe");
        assert_eq!(target.ssid_bytes, b"Cafe");
        assert_eq!(
            target.ap_path.as_deref(),
            Some("/org/freedesktop/NetworkManager/AccessPoint/1")
        );
        assert_eq!(target.bssid.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(target.ifname.as_deref(), Some("wlan0"));
        assert!(!target.hidden);
    }

    fn capabilities_for(flags: u32, wpa_flags: u32, rsn_flags: u32) -> super::NetworkCapabilities {
        let [entry] = network_entries_with_profile_matches(
            vec![test_ap(flags, wpa_flags, rsn_flags)],
            &std::collections::BTreeMap::new(),
        )
        .try_into()
        .expect("one entry");
        entry.capabilities
    }

    fn expected_capabilities(
        can_connect: bool,
        can_connect_now: bool,
        can_connect_with_password: bool,
        needs_password: bool,
        supported_auth: bool,
        has_unsupported_reason: bool,
    ) -> super::NetworkCapabilities {
        super::NetworkCapabilities {
            can_connect,
            can_connect_now,
            can_connect_with_password,
            needs_password,
            can_connect_with_credentials: false,
            needs_credentials: false,
            can_forget: false,
            can_toggle_autoconnect: false,
            supported_auth,
            unsupported_reason: has_unsupported_reason.then(|| {
                "unsupported authentication; open/OWE, WEP, WPA/SAE-Personal, WPA-Enterprise, and saved profiles are supported".to_string()
            }),
        }
    }

    fn test_profile() -> SavedWifiConnection {
        SavedWifiConnection {
            path: "/profile/1".to_string(),
            id: "Example".to_string(),
            ssid: "Example".to_string(),
            ssid_bytes: b"Example".to_vec(),
            autoconnect: true,
            privacy: ProfilePrivacy::default(),
        }
    }

    fn test_ap(flags: u32, wpa_flags: u32, rsn_flags: u32) -> AccessPoint {
        AccessPoint {
            ssid: "Example".to_string(),
            ssid_bytes: b"Example".to_vec(),
            active: false,
            security: security_label(flags, wpa_flags, rsn_flags),
            strength: 50,
            frequency: 2412,
            channel: 1,
            band: "2.4 GHz".to_string(),
            mode: "Infra".to_string(),
            max_bitrate_mbps: 0,
            bandwidth_mhz: 0,
            ssid_hex: "4578616d706c65".to_string(),
            wpa_flags_label: security_flags_label(wpa_flags),
            rsn_flags_label: security_flags_label(rsn_flags),
            bssid: "00:11:22:33:44:55".to_string(),
            last_seen: 0,
            last_seen_age_ms: None,
            path: "/ap".to_string(),
            device_path: "/device".to_string(),
            device_iface: "wlan0".to_string(),
            flags,
            wpa_flags,
            rsn_flags,
        }
    }
}
