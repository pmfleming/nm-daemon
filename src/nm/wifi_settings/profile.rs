use anyhow::Result;

use crate::model::{TargetProfileSettings, WifiConnectTarget};
use crate::nm::ip_settings;
use crate::nm::{ConnectionSettings, owned_value};

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
        connection.insert("metered".to_string(), owned_value(metered.to_string())?);
    }
    Ok(())
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
