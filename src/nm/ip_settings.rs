use std::collections::HashMap;

use anyhow::Result;
use zvariant::OwnedValue;

use super::{ConnectionSettings, owned_value};
use crate::model::{TargetIpAddress, TargetIpRoute, TargetIpSettings};
use crate::variant::{insert_optional_string, insert_optional_value};

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
        .map(ToString::to_string)
        .or_else(|| (!update.addresses.is_empty()).then_some("manual".to_string()));
    if let Some(method) = method {
        values.insert("method".to_string(), owned_value(method)?);
    }
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
        owned_value(update.method.as_deref().unwrap_or("auto").to_string())?,
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
        .or_insert(owned_value("auto".to_string())?);
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
    write_strings(values, "dns-data", &update.dns)?;
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
    write_strings(values, "dns-search", &update.dns_search)
}

fn write_data<T>(
    values: &mut HashMap<String, OwnedValue>,
    key: &str,
    entries: &[T],
    encode: impl FnOnce(&[T]) -> Result<OwnedValue>,
) -> Result<()> {
    if !entries.is_empty() {
        values.insert(key.to_string(), encode(entries)?);
    }
    Ok(())
}

fn write_strings(
    values: &mut HashMap<String, OwnedValue>,
    key: &str,
    entries: &[String],
) -> Result<()> {
    if !entries.is_empty() {
        values.insert(key.to_string(), owned_value(entries.to_vec())?);
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
            let mut values = HashMap::from([
                ("dest".to_string(), owned_value(route.dest.clone())?),
                ("prefix".to_string(), owned_value(route.prefix)?),
            ]);
            insert_optional_string(&mut values, "next-hop", route.next_hop.as_deref())?;
            insert_optional_value(&mut values, "metric", route.metric)?;
            insert_optional_value(&mut values, "table", route.table)?;
            Ok(values)
        })
        .collect()
}
