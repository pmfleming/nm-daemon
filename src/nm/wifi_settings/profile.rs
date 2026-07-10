use std::collections::HashMap;

use anyhow::Result;
use zvariant::OwnedValue;

use crate::model::{
    TargetIpAddress, TargetIpRoute, TargetIpSettings, TargetProfileSettings, WifiConnectTarget,
};
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
    if let Some(enabled) = profile.send_hostname {
        apply_send_hostname(settings, "ipv4", enabled)?;
        apply_send_hostname(settings, "ipv6", enabled)?;
    }
    if let Some(ipv4) = &profile.ipv4 {
        apply_ip_settings(settings, "ipv4", ipv4)?;
    }
    if let Some(ipv6) = &profile.ipv6 {
        apply_ip_settings(settings, "ipv6", ipv6)?;
    }
    Ok(())
}

fn apply_ip_settings(
    settings: &mut ConnectionSettings,
    section: &str,
    ip: &TargetIpSettings,
) -> Result<()> {
    let values = settings.entry(section.to_string()).or_default();
    if let Some(method) = ip
        .method
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| (!ip.addresses.is_empty()).then_some("manual".to_string()))
    {
        values.insert("method".to_string(), owned_value(method)?);
    }
    if !ip.addresses.is_empty() {
        values.insert(
            "address-data".to_string(),
            owned_value(address_data(&ip.addresses)?)?,
        );
    }
    if let Some(gateway) = ip.gateway.as_deref().filter(|value| !value.is_empty()) {
        values.insert("gateway".to_string(), owned_value(gateway.to_string())?);
    }
    if !ip.dns.is_empty() {
        values.insert("dns-data".to_string(), owned_value(ip.dns.clone())?);
    }
    if !ip.routes.is_empty() {
        values.insert(
            "route-data".to_string(),
            owned_value(route_data(&ip.routes)?)?,
        );
    }
    if let Some(route_metric) = ip.route_metric {
        values.insert("route-metric".to_string(), owned_value(route_metric)?);
    }
    if let Some(ignore_auto_dns) = ip.ignore_auto_dns {
        values.insert("ignore-auto-dns".to_string(), owned_value(ignore_auto_dns)?);
    }
    if !ip.dns_search.is_empty() {
        values.insert(
            "dns-search".to_string(),
            owned_value(ip.dns_search.clone())?,
        );
    }
    Ok(())
}

fn address_data(addresses: &[TargetIpAddress]) -> Result<Vec<HashMap<String, OwnedValue>>> {
    addresses
        .iter()
        .map(|address| {
            Ok(HashMap::from([
                ("address".to_string(), owned_value(address.address.clone())?),
                ("prefix".to_string(), owned_value(address.prefix)?),
            ]))
        })
        .collect()
}

fn route_data(routes: &[TargetIpRoute]) -> Result<Vec<HashMap<String, OwnedValue>>> {
    routes
        .iter()
        .map(|route| {
            let mut entry = HashMap::from([
                ("dest".to_string(), owned_value(route.dest.clone())?),
                ("prefix".to_string(), owned_value(route.prefix)?),
            ]);
            if let Some(next_hop) = route.next_hop.as_deref().filter(|value| !value.is_empty()) {
                entry.insert("next-hop".to_string(), owned_value(next_hop.to_string())?);
            }
            if let Some(metric) = route.metric {
                entry.insert("metric".to_string(), owned_value(metric)?);
            }
            if let Some(table) = route.table {
                entry.insert("table".to_string(), owned_value(table)?);
            }
            Ok(entry)
        })
        .collect()
}

fn apply_send_hostname(
    settings: &mut ConnectionSettings,
    section: &str,
    enabled: bool,
) -> Result<()> {
    settings
        .entry(section.to_string())
        .or_default()
        .insert("dhcp-send-hostname".to_string(), owned_value(enabled)?);
    Ok(())
}
