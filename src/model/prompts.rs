//! Producer-owned hidden-network and credential-recovery descriptors. Labels,
//! focus and unsaved field transactions remain consumer presentation concerns.
use super::{ConnectFailureReason, NetworkConnectPrompt, PromptKind, Security, WepKeyType};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub(crate) struct Field {
    key: &'static str,
    required: bool,
    password: bool,
    value: &'static str,
}
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub(crate) struct SecurityChoice {
    id: &'static str,
    security: Security,
    key_mgmt: &'static str,
    wep_key_type: Option<WepKeyType>,
    enterprise: bool,
    #[cfg_attr(test, serde(deserialize_with = "static_fields"))]
    required_fields: &'static [&'static str],
}
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(
    test,
    derive(serde::Deserialize),
    serde(bound(deserialize = "'de: 'static"))
)]
pub(crate) struct HiddenPrompt {
    fields: Vec<Field>,
    security_modes: Vec<SecurityChoice>,
}
// Test-only decoding of the producer's static descriptor table. The input
// fixture is retained for the unit-test process; production never deserializes it.
#[cfg(test)]
fn static_fields<D: serde::Deserializer<'static>>(
    d: D,
) -> Result<&'static [&'static str], D::Error> {
    use serde::Deserialize;
    Ok(Vec::<&'static str>::deserialize(d)?.leak())
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
                "open" | "owe" => &[],
                "wpa-eap" => &["enterprise.identity", "enterprise.eap"],
                _ => &["password"],
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
            "NetworkManager could not obtain credentials. Connect again or explicitly update the saved credentials."
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
