use crate::model::{
    NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE, ap_is_passwordless, ap_supports_enterprise,
    ap_supports_psk, ap_uses_owe, ap_uses_wep,
};

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
    if ap_is_passwordless(flags, wpa_flags, rsn_flags) {
        return match ap_uses_owe(wpa_flags, rsn_flags) {
            true => WifiAuthentication::Owe,
            false => WifiAuthentication::Open,
        };
    }
    if ap_supports_psk(wpa_flags, rsn_flags) {
        return WifiAuthentication::Personal;
    }
    if ap_uses_wep(flags, wpa_flags, rsn_flags) {
        return WifiAuthentication::Wep;
    }
    if ap_supports_enterprise(wpa_flags, rsn_flags) {
        return WifiAuthentication::Enterprise;
    }
    WifiAuthentication::Unsupported
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
