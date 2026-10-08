//! Producer-owned hidden-network and credential-recovery descriptors. Labels,
//! focus and unsaved field transactions remain consumer presentation concerns.
use super::{ConnectFailureReason, NetworkConnectPrompt, PromptKind, Security, WepKeyType};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Field {
    key: &'static str,
    required: bool,
    password: bool,
    value: &'static str,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SecurityChoice {
    id: &'static str,
    security: Security,
    key_mgmt: &'static str,
    wep_key_type: Option<WepKeyType>,
    enterprise: bool,
    required_fields: Vec<&'static str>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct HiddenPrompt {
    fields: Vec<Field>,
    security_modes: Vec<SecurityChoice>,
}
impl Default for HiddenPrompt {
    fn default() -> Self {
        let fields = [
            ("ssid", true, false, ""),
            ("security", true, false, "wpa-psk"),
            ("password", false, true, ""),
            ("enterprise.eap", false, false, "peap"),
            ("enterprise.identity", false, false, ""),
            ("enterprise.anonymous_identity", false, false, ""),
            ("enterprise.phase2_auth", false, false, "mschapv2"),
            ("enterprise.ca_cert", false, false, ""),
        ]
        .into_iter()
        .map(|(key, required, password, value)| Field {
            key,
            required,
            password,
            value,
        })
        .collect();
        let security_modes = [
            ("open", Security::Open, "open", None),
            ("owe", Security::Owe, "owe", None),
            ("wpa-psk", Security::Wpa2Or3, "wpa-psk", None),
            ("sae", Security::Wpa2Or3, "sae", None),
            ("wep-key", Security::Wep, "wep", Some(WepKeyType::Key)),
            ("wep-phrase", Security::Wep, "wep", Some(WepKeyType::Phrase)),
            ("wpa-eap", Security::Enterprise, "wpa-eap", None),
        ]
        .into_iter()
        .map(|(id, security, key_mgmt, wep_key_type)| SecurityChoice {
            id,
            security,
            key_mgmt,
            wep_key_type,
            enterprise: id == "wpa-eap",
            required_fields: match id {
                "open" | "owe" => vec![],
                "wpa-eap" => vec!["enterprise.identity", "enterprise.eap"],
                _ => vec!["password"],
            },
        })
        .collect();
        Self {
            fields,
            security_modes,
        }
    }
}

pub(crate) fn recovery(reason: ConnectFailureReason) -> Option<NetworkConnectPrompt> {
    let message = match reason {
        ConnectFailureReason::WrongPassword => "Wrong password. Enter a new Wi-Fi password.",
        ConnectFailureReason::PasswordUnavailable | ConnectFailureReason::SecretRequired => {
            "Saved password failed. Enter a new Wi-Fi password."
        }
        _ => return None,
    };
    Some(NetworkConnectPrompt {
        kind: PromptKind::Password,
        required_fields: vec!["password".into()],
        optional_fields: vec![],
        message: Some(message.into()),
        enterprise_defaults: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hidden_modes_have_explicit_key_management_and_conditional_requirements() {
        let prompt = HiddenPrompt::default();
        assert_eq!(prompt.security_modes.len(), 7);
        let phrase = prompt
            .security_modes
            .iter()
            .find(|v| v.id == "wep-phrase")
            .unwrap();
        assert_eq!(phrase.key_mgmt, "wep");
        assert_eq!(phrase.wep_key_type, Some(WepKeyType::Phrase));
        assert_eq!(phrase.required_fields, ["password"]);
        assert!(prompt.security_modes[0].required_fields.is_empty());
        assert!(recovery(ConnectFailureReason::WrongPassword).is_some());
        assert!(recovery(ConnectFailureReason::Timeout).is_none());
        assert!(recovery(ConnectFailureReason::AuthorizationRequired).is_none());
    }
}
