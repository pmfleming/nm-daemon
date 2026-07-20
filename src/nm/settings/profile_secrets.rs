use std::collections::BTreeMap;

use anyhow::Result;

use super::{
    ConnectionSettings, has_wep_settings, owned_value, setting_string, setting_string_list,
    setting_u32,
};
use crate::error::{DomainError, ErrorOperation};
use crate::model::WifiProfileUpdate;

pub(super) struct ProfileSecretSpec {
    pub(super) kind: &'static str,
    pub(super) setting_name: Option<&'static str>,
    pub(super) secret_keys: Vec<String>,
    pub(super) primary_secret_key: Option<String>,
}

pub(super) fn profile_secret_spec(settings: &ConnectionSettings) -> ProfileSecretSpec {
    let security = settings.get("802-11-wireless-security");
    let key_mgmt = security
        .and_then(|section| setting_string(section, "key-mgmt"))
        .unwrap_or_default();
    let leap = key_mgmt == "ieee8021x"
        && security
            .and_then(|section| setting_string(section, "auth-alg"))
            .is_some_and(|auth| auth == "leap");
    if matches!(key_mgmt.as_str(), "wpa-psk" | "sae") {
        return profile_secret_spec_for("password", "802-11-wireless-security", &["psk"], "psk");
    }
    if leap {
        return profile_secret_spec_for(
            "enterprise",
            "802-11-wireless-security",
            &["leap-password"],
            "leap-password",
        );
    }
    if matches!(key_mgmt.as_str(), "none" | "") && has_wep_settings(settings, None) {
        let index = security
            .and_then(|section| section.get("wep-tx-keyidx"))
            .and_then(setting_u32)
            .unwrap_or(0)
            .min(3);
        return profile_secret_spec_for(
            "wep-key",
            "802-11-wireless-security",
            &["wep-key0", "wep-key1", "wep-key2", "wep-key3"],
            &format!("wep-key{index}"),
        );
    }
    if key_mgmt.contains("eap") || settings.contains_key("802-1x") {
        return profile_secret_spec_for(
            "enterprise",
            "802-1x",
            &["password", "private-key-password", "pin"],
            "password",
        );
    }
    ProfileSecretSpec {
        kind: "none",
        setting_name: None,
        secret_keys: Vec::new(),
        primary_secret_key: None,
    }
}

fn profile_secret_spec_for(
    kind: &'static str,
    setting_name: &'static str,
    keys: &[&str],
    primary: &str,
) -> ProfileSecretSpec {
    ProfileSecretSpec {
        kind,
        setting_name: Some(setting_name),
        secret_keys: keys.iter().map(|key| (*key).to_string()).collect(),
        primary_secret_key: Some(primary.to_string()),
    }
}

pub(super) fn setting_secret_string(
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
    setting_name: &str,
    key: &str,
) -> Option<String> {
    secrets
        .and_then(|secrets| secrets.get(setting_name))
        .and_then(|section| setting_string(section, key))
        .or_else(|| {
            settings
                .get(setting_name)
                .and_then(|section| setting_string(section, key))
        })
        .filter(|value| !value.is_empty())
}

pub(super) fn profile_secret_values(
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
    spec: &ProfileSecretSpec,
) -> BTreeMap<String, String> {
    let Some(setting_name) = spec.setting_name else {
        return BTreeMap::new();
    };
    spec.secret_keys
        .iter()
        .filter_map(|key| {
            setting_secret_string(settings, secrets, setting_name, key)
                .map(|value| (key.clone(), value))
        })
        .collect()
}

pub(super) fn update_profile_secrets(
    settings: &mut ConnectionSettings,
    update: &WifiProfileUpdate,
) -> Result<()> {
    let spec = profile_secret_spec(settings);
    let mut replacements = update.secrets.clone();
    if let (Some(primary), Some(password)) = (
        spec.primary_secret_key.as_ref(),
        update.password.as_ref().filter(|value| !value.is_empty()),
    ) {
        replacements
            .entry(primary.clone())
            .or_insert_with(|| password.clone());
    }
    if replacements.is_empty() {
        return Ok(());
    }
    let Some(setting_name) = spec.setting_name else {
        return Err(DomainError::validation(
            ErrorOperation::ProfileOperation,
            "this Wi-Fi profile does not have editable secrets",
        )
        .with_detail("field", "secrets")
        .into());
    };
    for (key, value) in &replacements {
        if !spec.secret_keys.contains(key) {
            return Err(DomainError::validation(
                ErrorOperation::ProfileOperation,
                format!("secret '{key}' is not valid for this Wi-Fi profile"),
            )
            .with_detail("field", format!("secrets.{key}"))
            .with_detail("allowed_secret_keys", spec.secret_keys.clone())
            .into());
        }
        if value.is_empty() {
            return Err(DomainError::validation(
                ErrorOperation::ProfileOperation,
                format!("secret '{key}' must not be empty"),
            )
            .with_detail("field", format!("secrets.{key}"))
            .into());
        }
        validate_profile_secret(settings, &spec, key, value)?;
    }
    let section = settings.entry(setting_name.to_string()).or_default();
    for (key, value) in replacements {
        section.insert(key.clone(), owned_value(value)?);
        section.insert(format!("{key}-flags"), owned_value(0_u32)?);
    }
    Ok(())
}

fn validate_profile_secret(
    settings: &ConnectionSettings,
    spec: &ProfileSecretSpec,
    key: &str,
    value: &str,
) -> Result<()> {
    match (spec.kind, key) {
        ("password", "psk") => validate_profile_wpa_psk(value),
        ("wep-key", key) if key.starts_with("wep-key") => validate_profile_wep_key(settings, value),
        _ => Ok(()),
    }
}

fn validate_profile_wpa_psk(value: &str) -> Result<()> {
    let len = value.len();
    if (8..=63).contains(&len) || (len == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())) {
        return Ok(());
    }
    Err(DomainError::validation(
        ErrorOperation::ProfileOperation,
        "WPA-PSK password must be 8-63 characters, or 64 hexadecimal characters",
    )
    .with_detail("field", "secrets.psk")
    .into())
}

fn validate_profile_wep_key(settings: &ConnectionSettings, value: &str) -> Result<()> {
    let key_type = settings
        .get("802-11-wireless-security")
        .and_then(|section| section.get("wep-key-type"))
        .and_then(setting_u32)
        .unwrap_or(1);
    let valid = match key_type {
        2 => (8..=64).contains(&value.len()),
        _ => {
            (matches!(value.len(), 5 | 13) && value.is_ascii())
                || (matches!(value.len(), 10 | 26)
                    && value.chars().all(|ch| ch.is_ascii_hexdigit()))
        }
    };
    if valid {
        return Ok(());
    }
    Err(DomainError::validation(
        ErrorOperation::ProfileOperation,
        if key_type == 2 {
            "WEP passphrase must be 8-64 characters"
        } else {
            "WEP key must be 5 or 13 ASCII characters, or 10 or 26 hexadecimal characters"
        },
    )
    .with_detail("field", "secrets")
    .into())
}

pub(super) fn enterprise_secret_needs_agent(
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
) -> bool {
    let Some(section) = settings.get("802-1x") else {
        return true;
    };
    let eap = section
        .get("eap")
        .and_then(setting_string_list)
        .unwrap_or_default();
    let password_method = eap.is_empty()
        || eap
            .iter()
            .any(|method| matches!(method.as_str(), "fast" | "leap" | "peap" | "pwd" | "ttls"));
    [
        ("password", "password-flags", password_method),
        (
            "private-key-password",
            "private-key-password-flags",
            section.contains_key("private-key-password")
                || section.contains_key("private-key-password-flags"),
        ),
        (
            "pin",
            "pin-flags",
            section.contains_key("pin") || section.contains_key("pin-flags"),
        ),
    ]
    .into_iter()
    .filter(|(_, _, relevant)| *relevant)
    .any(|(secret_key, flags_key, _)| {
        required_secret_needs_agent(settings, secrets, "802-1x", secret_key, flags_key)
    })
}

pub(super) fn required_secret_needs_agent(
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
    setting_name: &str,
    secret_key: &str,
    flags_key: &str,
) -> bool {
    let flags = secret_flags(settings, setting_name, flags_key);
    if flags & super::NM_SECRET_FLAG_NOT_REQUIRED != 0 {
        return false;
    }
    if flags & (super::NM_SECRET_FLAG_AGENT_OWNED | super::NM_SECRET_FLAG_NOT_SAVED) != 0 {
        return true;
    }
    secrets.is_some()
        && setting_secret_string(settings, secrets, setting_name, secret_key).is_none()
}

fn secret_flags(settings: &ConnectionSettings, setting_name: &str, flags_key: &str) -> u32 {
    settings
        .get(setting_name)
        .and_then(|section| section.get(flags_key))
        .and_then(setting_u32)
        .unwrap_or(0)
}
