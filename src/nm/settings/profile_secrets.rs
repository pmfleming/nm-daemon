use std::collections::BTreeMap;

use anyhow::Result;

use crate::auth::WifiPasswordFormat;
use crate::variant::setting_text;

use super::{
    ConnectionSettings, WEP_KEYS, WifiSecretKind, has_wep_settings, setting_string_list,
    setting_u32, wep_secret_key, wifi_secret_kind,
};
use crate::error::{DomainError, ErrorOperation};
use crate::model::{WepKeyType, WifiProfileUpdate};

/// NetworkManager's built-in secret names; plugin-defined hints are handled by the agent.
pub(crate) fn known_secret_keys(setting_name: &str) -> &'static [&'static str] {
    crate::network_credentials::known_keys(setting_name)
}

pub(crate) fn secret_flags_key(key: &str) -> String {
    crate::network_credentials::flags_key(key)
}

pub(super) struct ProfileSecretSpec {
    pub(super) kind: &'static str,
    pub(super) setting_name: Option<&'static str>,
    pub(super) secret_keys: &'static [&'static str],
    pub(super) primary_secret_key: Option<&'static str>,
}

pub(super) fn profile_secret_spec(settings: &ConnectionSettings) -> ProfileSecretSpec {
    let security = settings.get("802-11-wireless-security");
    let kind = security.map(|security| wifi_secret_kind(security, None));
    match kind {
        Some(WifiSecretKind::Personal) => {
            profile_secret_spec_for("password", "802-11-wireless-security", &["psk"], "psk")
        }
        Some(WifiSecretKind::Leap) => profile_secret_spec_for(
            "enterprise",
            "802-11-wireless-security",
            &["leap-password"],
            "leap-password",
        ),
        Some(WifiSecretKind::Wep) if has_wep_settings(settings, None) => profile_secret_spec_for(
            "wep-key",
            "802-11-wireless-security",
            &WEP_KEYS,
            wep_secret_key(security),
        ),
        Some(WifiSecretKind::Enterprise) => enterprise_profile_secret_spec(),
        _ if settings.contains_key("802-1x") => enterprise_profile_secret_spec(),
        _ => ProfileSecretSpec {
            kind: "none",
            setting_name: None,
            secret_keys: &[],
            primary_secret_key: None,
        },
    }
}

fn enterprise_profile_secret_spec() -> ProfileSecretSpec {
    profile_secret_spec_for(
        "enterprise",
        "802-1x",
        crate::network_credentials::known_keys("802-1x"),
        "password",
    )
}

fn profile_secret_spec_for(
    kind: &'static str,
    setting_name: &'static str,
    secret_keys: &'static [&'static str],
    primary: &'static str,
) -> ProfileSecretSpec {
    ProfileSecretSpec {
        kind,
        setting_name: Some(setting_name),
        secret_keys,
        primary_secret_key: Some(primary),
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
        .and_then(|section| setting_text(section, key))
        .or_else(|| {
            settings
                .get(setting_name)
                .and_then(|section| setting_text(section, key))
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
                .map(|value| (key.to_string(), value))
        })
        .collect()
}

pub(super) fn update_profile_secrets(
    settings: &mut ConnectionSettings,
    update: &WifiProfileUpdate,
) -> Result<()> {
    let spec = profile_secret_spec(settings);
    let replacements = secret_replacements(&spec, update);
    if replacements.is_empty() {
        anyhow::ensure!(
            update.password.as_deref().is_none_or(str::is_empty),
            "this Wi-Fi profile has no editable primary secret"
        );
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
        validate_replacement(settings, &spec, key, value)?;
    }
    for (key, value) in replacements {
        crate::network_credentials::set_system_owned(settings, setting_name, key)?;
        crate::network_credentials::set_text(settings, setting_name, key, value)?;
    }
    Ok(())
}

fn secret_replacements<'a>(
    spec: &'a ProfileSecretSpec,
    update: &'a WifiProfileUpdate,
) -> Vec<(&'a str, &'a str)> {
    let mut replacements = update
        .secrets
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let Some((primary, password)) = spec.primary_secret_key.zip(
        update
            .password
            .as_deref()
            .filter(|password| !password.is_empty()),
    ) else {
        return replacements;
    };
    if !update.secrets.contains_key(primary) {
        replacements.push((primary, password));
    }
    replacements
}

fn validate_replacement(
    settings: &ConnectionSettings,
    spec: &ProfileSecretSpec,
    key: &str,
    value: &str,
) -> Result<()> {
    if !spec.secret_keys.contains(&key) {
        return Err(DomainError::validation(
            ErrorOperation::ProfileOperation,
            format!("secret '{key}' is not valid for this Wi-Fi profile"),
        )
        .with_detail("field", format!("secrets.{key}"))
        .with_detail("allowed_secret_keys", spec.secret_keys.to_vec())
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
    validate_profile_secret(settings, spec, key, value)
}

fn validate_profile_secret(
    settings: &ConnectionSettings,
    spec: &ProfileSecretSpec,
    key: &str,
    value: &str,
) -> Result<()> {
    let format = match (spec.kind, key) {
        ("password", "psk") => WifiPasswordFormat::WpaPsk,
        ("wep-key", key) if key.starts_with("wep-key") => {
            let phrase = settings
                .get("802-11-wireless-security")
                .and_then(|section| section.get("wep-key-type"))
                .and_then(setting_u32)
                == Some(2);
            WifiPasswordFormat::Wep(if phrase {
                WepKeyType::Phrase
            } else {
                WepKeyType::Key
            })
        }
        _ => return Ok(()),
    };
    format.validate(
        value,
        ErrorOperation::ProfileOperation,
        if spec.kind == "password" {
            "secrets.psk"
        } else {
            "secrets"
        },
    )
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
