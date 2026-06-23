use std::time::Duration;

use serde::{Deserialize, Serialize};
use zvariant::OwnedObjectPath;

pub(crate) const NM_AP_FLAGS_PRIVACY: u32 = 0x1;
pub(crate) const NM_AP_SEC_KEY_MGMT_PSK: u32 = 0x0000_0100;
pub(crate) const NM_AP_SEC_KEY_MGMT_802_1X: u32 = 0x0000_0200;
pub(crate) const NM_AP_SEC_KEY_MGMT_SAE: u32 = 0x0000_0400;
pub(crate) const NM_AP_SEC_KEY_MGMT_OWE: u32 = 0x0000_0800;
pub(crate) const NM_AP_SEC_KEY_MGMT_OWE_TM: u32 = 0x0000_1000;
pub(crate) const NM_AP_SEC_KEY_MGMT_EAP_SUITE_B_192: u32 = 0x0000_2000;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ScanStreamOptions {
    pub(crate) timeout: Duration,
    pub(crate) retries: u32,
    pub(crate) cache: bool,
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
pub(crate) struct WifiConnectTarget {
    pub(crate) ssid: String,
    pub(crate) ap_path: Option<String>,
    pub(crate) bssid: Option<String>,
    pub(crate) hidden: bool,
}

impl WifiConnectTarget {
    pub(crate) fn visible(ssid: impl Into<String>) -> Self {
        Self {
            ssid: ssid.into(),
            ap_path: None,
            bssid: None,
            hidden: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct AccessPoint {
    pub(crate) ssid: String,
    pub(crate) active: bool,
    pub(crate) security: String,
    pub(crate) strength: u8,
    pub(crate) frequency: u32,
    pub(crate) bssid: String,
    pub(crate) last_seen: i32,
    #[serde(default)]
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) device_path: String,
    #[serde(default)]
    pub(crate) flags: u32,
    #[serde(default)]
    pub(crate) wpa_flags: u32,
    #[serde(default)]
    pub(crate) rsn_flags: u32,
}

#[derive(Debug)]
pub(crate) enum ScanEvent {
    WatcherReady,
    WatcherWarning(String),
    AccessPointsChanged,
    LastScanChanged { device_path: String, value: i64 },
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
        NM_AP_FLAGS_PRIVACY, NM_AP_SEC_KEY_MGMT_OWE, NM_AP_SEC_KEY_MGMT_PSK,
        NM_AP_SEC_KEY_MGMT_SAE, ap_is_passwordless, ap_supports_psk, ap_uses_wep, retry_delay,
        security_label,
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
}
