use crate::model::{NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE, SecurityClass, security_class};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WifiAuthentication {
    Open,
    Owe,
    Personal,
    Wep,
    Enterprise,
    Unsupported,
}

pub(crate) fn classify(flags: u32, wpa_flags: u32, rsn_flags: u32) -> WifiAuthentication {
    match security_class(flags, wpa_flags, rsn_flags) {
        SecurityClass::Open => WifiAuthentication::Open,
        SecurityClass::EnhancedOpen => WifiAuthentication::Owe,
        SecurityClass::Personal => WifiAuthentication::Personal,
        SecurityClass::Legacy => WifiAuthentication::Wep,
        SecurityClass::Enterprise => WifiAuthentication::Enterprise,
        SecurityClass::Unknown => WifiAuthentication::Unsupported,
    }
}

/// Returns `sae` only for SAE-only APs; PSK/SAE transition networks remain `wpa-psk`.
pub(crate) fn personal_key_management(wpa_flags: u32, rsn_flags: u32) -> &'static str {
    let flags = wpa_flags | rsn_flags;
    if flags & NM_AP_SEC_KEY_MGMT_SAE != 0 && flags & NM_AP_SEC_KEY_MGMT_PSK == 0 {
        "sae"
    } else {
        "wpa-psk"
    }
}
