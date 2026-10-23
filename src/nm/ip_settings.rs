use std::collections::HashMap;

use anyhow::Result;
use zvariant::OwnedValue;

use crate::model::{TargetIpAddress, TargetIpRoute, TargetIpSettings};
use crate::variant::{
    ConnectionSettings, insert_optional_string, insert_optional_value, owned_value, value_map,
};

const REPLACED_KEYS: [&str; 9] = [
    "address-data",
    "addresses",
    "gateway",
    "dns-data",
    "dns",
    "route-data",
    "route-metric",
    "ignore-auto-dns",
    "dns-search",
];

pub(super) fn overlay(
    settings: &mut ConnectionSettings,
    section: &str,
    update: &TargetIpSettings,
) -> Result<()> {
    let values = settings.entry(section.to_string()).or_default();
    let method = update
        .method
        .as_deref()
        .filter(|value| !value.is_empty())
        .or_else(|| (!update.addresses.is_empty()).then_some("manual"));
    insert_optional_value(values, "method", method)?;
    write_values(values, update, false)
}

pub(super) fn replace(
    settings: &mut ConnectionSettings,
    section: &str,
    update: &TargetIpSettings,
) -> Result<()> {
    let values = settings.entry(section.to_string()).or_default();
    REPLACED_KEYS.iter().for_each(|key| {
        values.remove(*key);
    });
    values.insert(
        "method".to_string(),
        owned_value(update.method.as_deref().unwrap_or("auto"))?,
    );
    write_values(values, update, true)
}

pub(super) fn set_send_hostname(
    settings: &mut ConnectionSettings,
    section: &str,
    enabled: bool,
) -> Result<()> {
    let values = settings.entry(section.to_string()).or_default();
    values
        .entry("method".to_string())
        .or_insert(owned_value("auto")?);
    values.insert("dhcp-send-hostname".to_string(), owned_value(enabled)?);
    Ok(())
}

fn write_values(
    values: &mut HashMap<String, OwnedValue>,
    update: &TargetIpSettings,
    replacing: bool,
) -> Result<()> {
    write_data(values, "address-data", &update.addresses, |addresses| {
        owned_value(address_data(addresses)?)
    })?;
    insert_optional_string(values, "gateway", update.gateway.as_deref())?;
    write_data(values, "dns-data", &update.dns, owned_value)?;
    write_data(values, "route-data", &update.routes, |routes| {
        owned_value(route_data(routes)?)
    })?;
    insert_optional_value(values, "route-metric", update.route_metric)?;
    insert_optional_value(
        values,
        "ignore-auto-dns",
        replacing
            .then_some(update.ignore_auto_dns.unwrap_or(false))
            .or(update.ignore_auto_dns),
    )?;
    write_data(values, "dns-search", &update.dns_search, owned_value)
}

fn write_data<'a, T>(
    values: &mut HashMap<String, OwnedValue>,
    key: &str,
    entries: &'a [T],
    encode: impl FnOnce(&'a [T]) -> Result<OwnedValue>,
) -> Result<()> {
    if !entries.is_empty() {
        values.insert(key.to_string(), encode(entries)?);
    }
    Ok(())
}

fn address_data(addresses: &[TargetIpAddress]) -> Result<Vec<HashMap<String, OwnedValue>>> {
    addresses
        .iter()
        .map(|address| {
            value_map([
                ("address", address.address.as_str().into()),
                ("prefix", address.prefix.into()),
            ])
        })
        .collect()
}

fn route_data(routes: &[TargetIpRoute]) -> Result<Vec<HashMap<String, OwnedValue>>> {
    routes
        .iter()
        .map(|route| {
            let mut values = value_map([
                ("dest", route.dest.as_str().into()),
                ("prefix", route.prefix.into()),
            ])?;
            insert_optional_string(&mut values, "next-hop", route.next_hop.as_deref())?;
            insert_optional_value(&mut values, "metric", route.metric)?;
            insert_optional_value(&mut values, "table", route.table)?;
            Ok(values)
        })
        .collect()
}
