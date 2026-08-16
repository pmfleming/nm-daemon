use anyhow::Result;

use crate::error::{DomainError, ErrorOperation};
use crate::model::{TargetProfileSettings, WifiConnectTarget};
use crate::nm::ip_settings;
use crate::nm::{ConnectionSettings, owned_value};

pub(in crate::nm) fn apply_target_connection_metadata(
    settings: &mut ConnectionSettings,
    target: &WifiConnectTarget,
) -> Result<()> {
    apply_connection_name(settings, target.connection_name.as_deref())?;
    apply_private_connection(settings, target.private)
}

fn apply_connection_name(settings: &mut ConnectionSettings, name: Option<&str>) -> Result<()> {
    let Some(name) = name.filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let connection = settings.entry("connection".to_string()).or_default();
    connection.insert("id".to_string(), owned_value(name.to_string())?);
    connection
        .entry("type".to_string())
        .or_insert(owned_value("802-11-wireless".to_string())?);
    Ok(())
}

fn apply_private_connection(settings: &mut ConnectionSettings, private: bool) -> Result<()> {
    let Some(user) = private.then(current_user_name).flatten() else {
        return Ok(());
    };
    settings
        .entry("connection".to_string())
        .or_default()
        .insert(
            "permissions".to_string(),
            owned_value(vec![format!("user:{user}:")])?,
        );
    Ok(())
}

pub(in crate::nm) fn apply_target_profile_settings(
    settings: &mut ConnectionSettings,
    target: &WifiConnectTarget,
) -> Result<()> {
    apply_profile_settings(settings, &target.profile)
}

fn apply_profile_settings(
    settings: &mut ConnectionSettings,
    profile: &TargetProfileSettings,
) -> Result<()> {
    apply_connection_settings(settings, profile)?;
    apply_mac_policy(settings, profile)?;
    apply_hostname_policy(settings, profile)?;
    if let Some(ipv4) = &profile.ipv4 {
        ip_settings::overlay(settings, "ipv4", ipv4)?;
    }
    if let Some(ipv6) = &profile.ipv6 {
        ip_settings::overlay(settings, "ipv6", ipv6)?;
    }
    Ok(())
}

fn apply_connection_settings(
    settings: &mut ConnectionSettings,
    profile: &TargetProfileSettings,
) -> Result<()> {
    let connection = settings.entry("connection".to_string()).or_default();
    if let Some(autoconnect) = profile.autoconnect {
        connection.insert("autoconnect".to_string(), owned_value(autoconnect)?);
    }
    if let Some(priority) = profile.autoconnect_priority {
        connection.insert("autoconnect-priority".to_string(), owned_value(priority)?);
    }
    if let Some(metered) = profile.metered.as_deref().filter(|value| !value.is_empty()) {
        connection.insert("metered".to_string(), owned_value(metered_code(metered)?)?);
    }
    Ok(())
}

fn current_user_name() -> Option<String> {
    ["USER", "LOGNAME"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

fn metered_code(value: &str) -> Result<u32> {
    match value {
        "auto" | "unknown" => Ok(0),
        "yes" | "on" | "true" => Ok(1),
        "no" | "off" | "false" => Ok(2),
        _ => Err(DomainError::validation(
            ErrorOperation::Connect,
            "profile.metered must be auto, yes, or no",
        )
        .with_detail("field", "profile.metered")
        .with_detail("value", value)
        .into()),
    }
}

fn apply_mac_policy(
    settings: &mut ConnectionSettings,
    profile: &TargetProfileSettings,
) -> Result<()> {
    if let Some(cloned_mac) = profile
        .cloned_mac_address
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        settings
            .entry("802-11-wireless".to_string())
            .or_default()
            .insert(
                "assigned-mac-address".to_string(),
                owned_value(cloned_mac.to_string())?,
            );
    }
    Ok(())
}

fn apply_hostname_policy(
    settings: &mut ConnectionSettings,
    profile: &TargetProfileSettings,
) -> Result<()> {
    if let Some(enabled) = profile.send_hostname {
        ip_settings::set_send_hostname(settings, "ipv4", enabled)?;
        ip_settings::set_send_hostname(settings, "ipv6", enabled)?;
    }
    Ok(())
}
