use crate::error::{DomainError, ErrorOperation};
use crate::model::{
    NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE, SecurityClass, WepKeyType, security_class,
};

/// Native profile credentials use byte lengths; QR intake has a separate
/// compatibility contract and deliberately does not use this validator.
pub(crate) enum WifiPasswordFormat {
    WpaPsk,
    Wep(WepKeyType),
}

impl WifiPasswordFormat {
    pub(crate) fn validate(
        self,
        value: &str,
        operation: ErrorOperation,
        field: &str,
    ) -> anyhow::Result<()> {
        let message = match self {
            Self::WpaPsk
                if (8..=63).contains(&value.len())
                    || (value.len() == 64 && value.bytes().all(|ch| ch.is_ascii_hexdigit())) =>
            {
                return Ok(());
            }
            Self::WpaPsk => {
                "WPA-PSK password must be 8-63 characters, or 64 hexadecimal characters"
            }
            Self::Wep(WepKeyType::Key)
                if (matches!(value.len(), 5 | 13) && value.is_ascii())
                    || (matches!(value.len(), 10 | 26)
                        && value.bytes().all(|ch| ch.is_ascii_hexdigit())) =>
            {
                return Ok(());
            }
            Self::Wep(WepKeyType::Key) => {
                "WEP key must be 5 or 13 ASCII characters, or 10 or 26 hexadecimal characters"
            }
            Self::Wep(WepKeyType::Phrase) if (8..=64).contains(&value.len()) => return Ok(()),
            Self::Wep(WepKeyType::Phrase) => "WEP passphrase must be 8-64 characters",
        };
        Err(DomainError::validation(operation, message)
            .with_detail("field", field)
            .into())
    }
}

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
