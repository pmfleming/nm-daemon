use std::collections::HashMap;

mod profile;

use anyhow::Result;
use zvariant::OwnedValue;

use super::{ConnectionSettings, owned_value};
use crate::error::{DomainError, ErrorOperation};
use crate::model::{
    AccessPoint, EnterpriseAuth, WepKeyType, WifiConnectTarget, ap_uses_owe, enterprise_key_mgmt,
};
use crate::variant::{insert_optional_strings, insert_optional_u32s, insert_string};
pub(super) use profile::apply_target_profile_settings;

pub(super) fn psk_wifi_connection_settings(
    ap: &AccessPoint,
    password: &str,
) -> Result<ConnectionSettings> {
    let key_mgmt = crate::auth::personal_key_management(ap.wpa_flags, ap.rsn_flags);
    if key_mgmt == "wpa-psk" {
        validate_wpa_psk(password)?;
    }
    Ok(security_connection_settings(wireless_security_section(
        key_mgmt, password,
    )?))
}

pub(super) fn owe_wifi_connection_settings() -> Result<ConnectionSettings> {
    Ok(security_connection_settings(HashMap::from([(
        "key-mgmt".to_string(),
        owned_value("owe".to_string())?,
    )])))
}

pub(super) fn hidden_wifi_connection_settings(
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<ConnectionSettings> {
    let mut settings =
        base_wifi_connection_settings(target.ssid.as_str(), target.ssid_bytes(), true)?;
    if let Some(security) = security_settings_for_target_hint(target, password, wep_key_type)? {
        settings.extend(security);
    }
    apply_target_profile_settings(&mut settings, target)?;
    Ok(settings)
}

pub(super) fn cloned_wifi_connection_settings(
    mut settings: ConnectionSettings,
    target: &WifiConnectTarget,
    ap: &AccessPoint,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<ConnectionSettings> {
    sanitize_cloned_settings(&mut settings)?;
    ensure_wireless_settings(&mut settings, target, false)?;
    if let Some(security) = security_settings_for_visible_ap(ap, target, password, wep_key_type)? {
        settings.extend(security);
    }
    apply_target_profile_settings(&mut settings, target)?;
    Ok(settings)
}

pub(super) fn enterprise_wifi_connection_settings(
    ap: &AccessPoint,
    enterprise: &EnterpriseAuth,
    password: Option<&str>,
) -> Result<ConnectionSettings> {
    enterprise_wifi_connection_settings_with_key_mgmt(
        enterprise,
        password,
        enterprise_key_mgmt(ap.wpa_flags, ap.rsn_flags),
    )
}

fn security_settings_for_visible_ap(
    ap: &AccessPoint,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<Option<ConnectionSettings>> {
    if let Some(enterprise) = &target.enterprise {
        return enterprise_wifi_connection_settings(ap, enterprise, password).map(Some);
    }
    let Some(password) = password else {
        return Ok(None);
    };
    if crate::model::ap_uses_wep(ap.flags, ap.wpa_flags, ap.rsn_flags) {
        return wep_wifi_connection_settings(password, wep_key_type.unwrap_or(WepKeyType::Key))
            .map(Some);
    }
    if crate::model::ap_supports_psk(ap.wpa_flags, ap.rsn_flags) {
        return psk_wifi_connection_settings(ap, password).map(Some);
    }
    if ap_uses_owe(ap.wpa_flags, ap.rsn_flags) {
        return owe_wifi_connection_settings().map(Some);
    }
    Ok(None)
}

fn security_settings_for_target_hint(
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<Option<ConnectionSettings>> {
    let key_mgmt = target_key_mgmt(target);
    if let Some(enterprise) = &target.enterprise {
        let key_mgmt = key_mgmt.as_deref().unwrap_or("wpa-eap");
        return enterprise_wifi_connection_settings_with_key_mgmt(enterprise, password, key_mgmt)
            .map(Some);
    }

    match key_mgmt.as_deref() {
        None => security_settings_without_hint(password, wep_key_type),
        Some("open" | "none" | "--") => Ok(None),
        Some("owe") => owe_wifi_connection_settings().map(Some),
        Some("wep") => hidden_wep_settings(password, wep_key_type),
        Some(key @ ("sae" | "wpa-psk")) => hidden_personal_settings(key, password),
        Some("wpa-eap" | "wpa-eap-suite-b-192") => Err(DomainError::connect(
            crate::model::ConnectFailureReason::SecretRequired,
            "hidden enterprise network requires an enterprise credential object",
        )
        .into()),
        Some(other) => Err(DomainError::connect(
            crate::model::ConnectFailureReason::UnsupportedAuth,
            format!("unsupported hidden key management '{other}'"),
        )
        .with_detail("key_management", other)
        .into()),
    }
}

fn target_key_mgmt(target: &WifiConnectTarget) -> Option<String> {
    target
        .key_mgmt
        .as_deref()
        .or_else(|| target.enterprise.as_ref()?.key_mgmt.as_deref())
        .map(normalized_key_mgmt)
}

fn security_settings_without_hint(
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<Option<ConnectionSettings>> {
    let Some(password) = password else {
        return Ok(None);
    };
    if let Some(wep_key_type) = wep_key_type {
        return wep_wifi_connection_settings(password, wep_key_type).map(Some);
    }
    validate_wpa_psk(password)?;
    Ok(Some(security_connection_settings(
        wireless_security_section("wpa-psk", password)?,
    )))
}

fn hidden_wep_settings(
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<Option<ConnectionSettings>> {
    let password =
        required_hidden_password(password, "hidden WEP network requires a password/key")?;
    wep_wifi_connection_settings(password, wep_key_type.unwrap_or(WepKeyType::Key)).map(Some)
}

fn hidden_personal_settings(
    key_mgmt: &str,
    password: Option<&str>,
) -> Result<Option<ConnectionSettings>> {
    let password =
        required_hidden_password(password, "hidden WPA/SAE network requires a password")?;
    validate_wpa_psk(password)?;
    Ok(Some(security_connection_settings(
        wireless_security_section(key_mgmt, password)?,
    )))
}

fn required_hidden_password<'a>(password: Option<&'a str>, message: &str) -> Result<&'a str> {
    password.ok_or_else(|| {
        DomainError::connect(crate::model::ConnectFailureReason::SecretRequired, message).into()
    })
}

fn enterprise_wifi_connection_settings_with_key_mgmt(
    enterprise: &EnterpriseAuth,
    password: Option<&str>,
    key_mgmt: &str,
) -> Result<ConnectionSettings> {
    let security = enterprise_security_section(key_mgmt)?;
    let mut dot1x = enterprise_dot1x_section(enterprise, password)?;
    insert_enterprise_certificate_settings(&mut dot1x, enterprise)?;
    insert_enterprise_flag_settings(&mut dot1x, enterprise)?;

    Ok(ConnectionSettings::from([
        ("802-11-wireless-security".to_string(), security),
        ("802-1x".to_string(), dot1x),
    ]))
}

fn enterprise_security_section(key_mgmt: &str) -> Result<HashMap<String, OwnedValue>> {
    Ok(HashMap::from([(
        "key-mgmt".to_string(),
        owned_value(key_mgmt.to_string())?,
    )]))
}

fn enterprise_dot1x_section(
    enterprise: &EnterpriseAuth,
    password: Option<&str>,
) -> Result<HashMap<String, OwnedValue>> {
    let eap = enterprise_eap_methods(enterprise);
    let mut dot1x = HashMap::from([("eap".to_string(), owned_value(eap)?)]);
    insert_required_string(&mut dot1x, "identity", enterprise.identity.as_deref())?;
    insert_optional_strings(
        &mut dot1x,
        &[
            (
                "anonymous-identity",
                enterprise.anonymous_identity.as_deref(),
            ),
            ("password", enterprise.password.as_deref().or(password)),
            ("phase2-auth", enterprise.phase2_auth.as_deref()),
            ("ca-cert", enterprise.ca_cert.as_deref()),
            ("ca-path", enterprise.ca_path.as_deref()),
            (
                "domain-suffix-match",
                enterprise.domain_suffix_match.as_deref(),
            ),
            ("subject-match", enterprise.subject_match.as_deref()),
            ("openssl-ciphers", enterprise.openssl_ciphers.as_deref()),
            ("phase1-peapver", enterprise.phase1_peapver.as_deref()),
            ("phase1-peaplabel", enterprise.phase1_peaplabel.as_deref()),
            (
                "phase1-fast-provisioning",
                enterprise.phase1_fast_provisioning.as_deref(),
            ),
        ],
    )?;
    Ok(dot1x)
}

fn enterprise_eap_methods(enterprise: &EnterpriseAuth) -> Vec<String> {
    if enterprise.eap.is_empty() {
        vec!["peap".to_string()]
    } else {
        enterprise.eap.clone()
    }
}

fn insert_enterprise_certificate_settings(
    dot1x: &mut HashMap<String, OwnedValue>,
    enterprise: &EnterpriseAuth,
) -> Result<()> {
    if !enterprise.altsubject_matches.is_empty() {
        dot1x.insert(
            "altsubject-matches".to_string(),
            owned_value(enterprise.altsubject_matches.clone())?,
        );
    }
    insert_optional_strings(
        dot1x,
        &[
            ("client-cert", enterprise.client_cert.as_deref()),
            ("private-key", enterprise.private_key.as_deref()),
            (
                "private-key-password",
                enterprise.private_key_password.as_deref(),
            ),
            ("pin", enterprise.pin.as_deref()),
            ("pac-file", enterprise.pac_file.as_deref()),
        ],
    )?;
    if let Some(system_ca_certs) = enterprise.system_ca_certs {
        dot1x.insert("system-ca-certs".to_string(), owned_value(system_ca_certs)?);
    }
    Ok(())
}

fn insert_enterprise_flag_settings(
    dot1x: &mut HashMap<String, OwnedValue>,
    enterprise: &EnterpriseAuth,
) -> Result<()> {
    insert_optional_u32s(
        dot1x,
        &[
            ("password-flags", enterprise.password_flags),
            (
                "private-key-password-flags",
                enterprise.private_key_password_flags,
            ),
            ("pin-flags", enterprise.pin_flags),
        ],
    )
}

pub(super) fn wep_wifi_connection_settings(
    password: &str,
    wep_key_type: WepKeyType,
) -> Result<ConnectionSettings> {
    Ok(security_connection_settings(wep_security_section(
        password,
        wep_key_type,
    )?))
}

fn sanitize_cloned_settings(settings: &mut ConnectionSettings) -> Result<()> {
    let connection = settings.entry("connection".to_string()).or_default();
    connection.remove("uuid");
    connection.remove("timestamp");
    connection.insert(
        "type".to_string(),
        owned_value("802-11-wireless".to_string())?,
    );
    Ok(())
}

fn ensure_wireless_settings(
    settings: &mut ConnectionSettings,
    target: &WifiConnectTarget,
    hidden: bool,
) -> Result<()> {
    let connection = settings.entry("connection".to_string()).or_default();
    connection
        .entry("id".to_string())
        .or_insert(owned_value(target.ssid.to_string())?);
    connection
        .entry("type".to_string())
        .or_insert(owned_value("802-11-wireless".to_string())?);

    let wireless = settings.entry("802-11-wireless".to_string()).or_default();
    wireless.insert(
        "ssid".to_string(),
        owned_value(target.ssid_bytes().to_vec())?,
    );
    wireless.insert(
        "mode".to_string(),
        owned_value("infrastructure".to_string())?,
    );
    wireless.insert("hidden".to_string(), owned_value(hidden)?);
    Ok(())
}

fn base_wifi_connection_settings(
    ssid: &str,
    ssid_bytes: &[u8],
    hidden: bool,
) -> Result<ConnectionSettings> {
    Ok(ConnectionSettings::from([
        ("connection".to_string(), base_connection_section(ssid)?),
        (
            "802-11-wireless".to_string(),
            base_wireless_section(ssid_bytes, hidden)?,
        ),
        ("ipv4".to_string(), automatic_ip_section()?),
        ("ipv6".to_string(), automatic_ip_section()?),
    ]))
}

fn base_connection_section(ssid: &str) -> Result<HashMap<String, OwnedValue>> {
    Ok(HashMap::from([
        ("id".to_string(), owned_value(ssid.to_string())?),
        (
            "type".to_string(),
            owned_value("802-11-wireless".to_string())?,
        ),
    ]))
}

fn base_wireless_section(ssid_bytes: &[u8], hidden: bool) -> Result<HashMap<String, OwnedValue>> {
    Ok(HashMap::from([
        ("ssid".to_string(), owned_value(ssid_bytes.to_vec())?),
        (
            "mode".to_string(),
            owned_value("infrastructure".to_string())?,
        ),
        ("hidden".to_string(), owned_value(hidden)?),
    ]))
}

fn automatic_ip_section() -> Result<HashMap<String, OwnedValue>> {
    Ok(HashMap::from([(
        "method".to_string(),
        owned_value("auto".to_string())?,
    )]))
}

fn security_connection_settings(section: HashMap<String, OwnedValue>) -> ConnectionSettings {
    ConnectionSettings::from([("802-11-wireless-security".to_string(), section)])
}

fn normalized_key_mgmt(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "" | "--" | "open" => "open".to_string(),
        "none" | "wep" => "wep".to_string(),
        "psk" | "wpa-personal" | "wpa_psk" | "wpa-psk" => "wpa-psk".to_string(),
        "sae" => "sae".to_string(),
        "owe" => "owe".to_string(),
        "802.1x" | "802-1x" | "enterprise" | "wpa-eap" => "wpa-eap".to_string(),
        "suite-b" | "wpa-eap-suite-b-192" => "wpa-eap-suite-b-192".to_string(),
        other => other.to_string(),
    }
}

fn wireless_security_section(
    key_mgmt: &str,
    password: &str,
) -> Result<HashMap<String, OwnedValue>> {
    Ok(HashMap::from([
        ("key-mgmt".to_string(), owned_value(key_mgmt.to_string())?),
        ("psk".to_string(), owned_value(password.to_string())?),
    ]))
}

fn wep_security_section(
    password: &str,
    wep_key_type: WepKeyType,
) -> Result<HashMap<String, OwnedValue>> {
    validate_wep_key(password, wep_key_type)?;
    Ok(HashMap::from([
        ("key-mgmt".to_string(), owned_value("none".to_string())?),
        ("wep-key0".to_string(), owned_value(password.to_string())?),
        (
            "wep-key-type".to_string(),
            owned_value(wep_key_type.nm_value())?,
        ),
    ]))
}

fn insert_required_string(
    settings: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<&str>,
) -> Result<()> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Err(DomainError::validation(
            ErrorOperation::Connect,
            format!("enterprise Wi-Fi field '{key}' is required"),
        )
        .with_detail("field", key)
        .into());
    };
    insert_string(settings, key, value)
}

pub(super) fn validate_wpa_psk(password: &str) -> Result<()> {
    let len = password.len();
    if (8..=63).contains(&len) || (len == 64 && password.chars().all(|ch| ch.is_ascii_hexdigit())) {
        return Ok(());
    }
    Err(DomainError::validation(
        ErrorOperation::Connect,
        "WPA-PSK password must be 8-63 characters, or 64 hexadecimal characters",
    )
    .with_detail("field", "password")
    .into())
}

fn validate_wep_key(password: &str, wep_key_type: WepKeyType) -> Result<()> {
    match wep_key_type {
        WepKeyType::Key if wep_key_is_valid(password) => Ok(()),
        WepKeyType::Key => Err(DomainError::validation(
            ErrorOperation::Connect,
            "WEP key must be 5 or 13 ASCII characters, or 10 or 26 hexadecimal characters",
        )
        .with_detail("field", "password")
        .into()),
        WepKeyType::Phrase if (8..=64).contains(&password.len()) => Ok(()),
        WepKeyType::Phrase => Err(DomainError::validation(
            ErrorOperation::Connect,
            "WEP passphrase must be 8-64 characters",
        )
        .with_detail("field", "password")
        .into()),
    }
}

fn wep_key_is_valid(password: &str) -> bool {
    (matches!(password.len(), 5 | 13) && password.is_ascii())
        || (matches!(password.len(), 10 | 26) && password.chars().all(|ch| ch.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests;
