use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use zbus::blocking::Proxy;
use zvariant::{OwnedObjectPath, OwnedValue};

use super::{DEVICE_IFACE, Nm};
use crate::model::{DhcpLeaseStatus, Ip4Status, Ip6Status, IpAddressEntry, IpRouteEntry};
use crate::variant::value_string;

const IP4_CONFIG_IFACE: &str = "org.freedesktop.NetworkManager.IP4Config";
const IP6_CONFIG_IFACE: &str = "org.freedesktop.NetworkManager.IP6Config";
const DHCP4_CONFIG_IFACE: &str = "org.freedesktop.NetworkManager.DHCP4Config";
const DHCP6_CONFIG_IFACE: &str = "org.freedesktop.NetworkManager.DHCP6Config";

impl Nm {
    pub(super) fn device_ip4_status(
        &self,
        device_path: &OwnedObjectPath,
    ) -> Result<Option<Ip4Status>> {
        let Some(config) = self.ip_config_proxy(device_path, "Ip4Config", IP4_CONFIG_IFACE)? else {
            return Ok(None);
        };
        let routes = route_entries(&config);
        let addresses = address_entries(&config);
        let gateway = gateway_property(&config).or_else(|| default_route_next_hop(&routes));
        let dns = nameserver_entries(&config).unwrap_or_else(|| {
            config
                .get_property::<Vec<u32>>("Nameservers")
                .map(|values| values.into_iter().map(legacy_ipv4).collect())
                .unwrap_or_default()
        });
        Ok(Some(Ip4Status {
            address: addresses.first().map(|entry| entry.address.clone()),
            prefix: addresses.first().map(|entry| entry.prefix),
            addresses,
            gateway,
            dns,
            domains: string_list(&config, "Domains"),
            searches: string_list(&config, "Searches"),
            routes,
            dhcp_lease: self.dhcp_lease(device_path, "Dhcp4Config", DHCP4_CONFIG_IFACE),
        }))
    }

    pub(super) fn device_ip6_status(
        &self,
        device_path: &OwnedObjectPath,
    ) -> Result<Option<Ip6Status>> {
        let Some(config) = self.ip_config_proxy(device_path, "Ip6Config", IP6_CONFIG_IFACE)? else {
            return Ok(None);
        };
        let routes = route_entries(&config);
        let addresses = address_entries(&config);
        let gateway = gateway_property(&config).or_else(|| default_route_next_hop(&routes));
        Ok(Some(Ip6Status {
            address: addresses.first().map(|entry| entry.address.clone()),
            prefix: addresses.first().map(|entry| entry.prefix),
            addresses,
            gateway,
            dns: nameserver_entries(&config).unwrap_or_default(),
            domains: string_list(&config, "Domains"),
            searches: string_list(&config, "Searches"),
            routes,
            dhcp_lease: self.dhcp_lease(device_path, "Dhcp6Config", DHCP6_CONFIG_IFACE),
        }))
    }

    fn ip_config_proxy(
        &self,
        device_path: &OwnedObjectPath,
        property: &str,
        interface: &'static str,
    ) -> Result<Option<Proxy<'static>>> {
        let device = self.proxy_path(device_path, DEVICE_IFACE)?;
        let config_path: OwnedObjectPath = device
            .get_property(property)
            .with_context(|| format!("read {property} for {device_path}"))?;
        if config_path.as_str() == "/" {
            return Ok(None);
        }
        drop(device);
        self.owned_proxy(config_path.as_str(), interface).map(Some)
    }

    fn dhcp_lease(
        &self,
        device_path: &OwnedObjectPath,
        property: &str,
        interface: &'static str,
    ) -> Option<DhcpLeaseStatus> {
        let config = self
            .ip_config_proxy(device_path, property, interface)
            .ok()
            .flatten()?;
        let options: HashMap<String, OwnedValue> = config.get_property("Options").ok()?;
        dhcp_lease_from_options(&options)
    }
}

pub(super) fn dhcp_lease_from_options(
    options: &HashMap<String, OwnedValue>,
) -> Option<DhcpLeaseStatus> {
    let option_string = |key: &str| {
        options
            .get(key)
            .and_then(value_string)
            .filter(|value| !value.is_empty())
    };
    let option_u64 = |key: &str| {
        options.get(key).and_then(|value| {
            u64::try_from(value.clone())
                .ok()
                .or_else(|| value_u32(value).map(u64::from))
                .or_else(|| value_string(value)?.parse().ok())
        })
    };
    let lease = DhcpLeaseStatus {
        server_identifier: option_string("dhcp_server_identifier")
            .or_else(|| option_string("dhcp6_server_id")),
        domain_name: option_string("domain_name"),
        lease_time_seconds: option_u64("dhcp_lease_time").or_else(|| option_u64("max_life")),
        expires_at_ms: option_u64("expiry").map(|seconds| seconds.saturating_mul(1000)),
    };
    (lease.server_identifier.is_some()
        || lease.domain_name.is_some()
        || lease.lease_time_seconds.is_some()
        || lease.expires_at_ms.is_some())
    .then_some(lease)
}

fn address_entries(config: &Proxy<'_>) -> Vec<IpAddressEntry> {
    config
        .get_property::<Vec<HashMap<String, OwnedValue>>>("AddressData")
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| {
            Some(IpAddressEntry {
                address: entry.get("address").and_then(value_string)?,
                prefix: entry.get("prefix").and_then(value_u32)?,
            })
        })
        .collect()
}

fn route_entries(config: &Proxy<'_>) -> Vec<IpRouteEntry> {
    config
        .get_property::<Vec<HashMap<String, OwnedValue>>>("RouteData")
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| {
            Some(IpRouteEntry {
                dest: entry.get("dest").and_then(value_string)?,
                prefix: entry.get("prefix").and_then(value_u32)?,
                next_hop: entry.get("next-hop").and_then(value_string),
                metric: entry.get("metric").and_then(value_u32),
            })
        })
        .collect()
}

fn nameserver_entries(config: &Proxy<'_>) -> Option<Vec<String>> {
    let entries = config
        .get_property::<Vec<HashMap<String, OwnedValue>>>("NameserverData")
        .ok()?
        .iter()
        .filter_map(|entry| entry.get("address").and_then(value_string))
        .collect::<Vec<_>>();
    (!entries.is_empty()).then_some(entries)
}

fn gateway_property(config: &Proxy<'_>) -> Option<String> {
    config
        .get_property::<String>("Gateway")
        .ok()
        .filter(|value| !value.is_empty())
}

fn default_route_next_hop(routes: &[IpRouteEntry]) -> Option<String> {
    routes
        .iter()
        .find(|route| route.prefix == 0)
        .and_then(|route| route.next_hop.clone())
        .filter(|next_hop| !next_hop.is_empty())
}

fn string_list(config: &Proxy<'_>, name: &str) -> Vec<String> {
    config
        .get_property::<Vec<String>>(name)
        .unwrap_or_default()
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect()
}

fn value_u32(value: &OwnedValue) -> Option<u32> {
    u32::try_from(value.clone()).ok()
}

fn legacy_ipv4(value: u32) -> String {
    Ipv4Addr::from(u32::from_be(value)).to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use zvariant::OwnedValue;

    use super::{default_route_next_hop, dhcp_lease_from_options, legacy_ipv4};
    use crate::model::IpRouteEntry;

    fn route(dest: &str, prefix: u32, next_hop: Option<&str>) -> IpRouteEntry {
        IpRouteEntry {
            dest: dest.to_string(),
            prefix,
            next_hop: next_hop.map(ToString::to_string),
            metric: None,
        }
    }

    #[test]
    fn default_route_supplies_a_missing_gateway() {
        let routes = vec![
            route("192.0.2.0", 24, None),
            route("0.0.0.0", 0, Some("192.0.2.1")),
        ];
        assert_eq!(
            default_route_next_hop(&routes),
            Some("192.0.2.1".to_string())
        );
        assert_eq!(default_route_next_hop(&routes[..1]), None);
    }

    #[test]
    fn parses_networkmanager_dhcp4_lease_options() {
        let options = HashMap::from([
            (
                "dhcp_server_identifier".to_string(),
                string_value("192.0.2.1"),
            ),
            ("domain_name".to_string(), string_value("example.test")),
            ("dhcp_lease_time".to_string(), string_value("86400")),
            ("expiry".to_string(), string_value("1762086400")),
        ]);

        let lease = dhcp_lease_from_options(&options).expect("DHCP lease");
        assert_eq!(lease.server_identifier.as_deref(), Some("192.0.2.1"));
        assert_eq!(lease.domain_name.as_deref(), Some("example.test"));
        assert_eq!(lease.lease_time_seconds, Some(86_400));
        assert_eq!(lease.expires_at_ms, Some(1_762_086_400_000));
    }

    #[test]
    fn dhcpv6_options_reuse_the_shared_lease_shape() {
        let options = HashMap::from([
            ("max_life".to_string(), string_value("86400")),
            ("domain_name".to_string(), string_value("example.test")),
        ]);
        let lease = dhcp_lease_from_options(&options).expect("lease from DHCPv6 options");
        assert_eq!(lease.lease_time_seconds, Some(86_400));
        assert_eq!(lease.domain_name.as_deref(), Some("example.test"));
        assert_eq!(lease.server_identifier, None);
    }

    #[test]
    fn empty_dhcp_options_do_not_fabricate_a_lease() {
        assert!(dhcp_lease_from_options(&HashMap::new()).is_none());
    }

    fn string_value(value: &str) -> OwnedValue {
        OwnedValue::try_from(zvariant::Value::new(value.to_string())).expect("string variant")
    }

    #[test]
    fn legacy_nameservers_render_as_dotted_quads() {
        assert_eq!(legacy_ipv4(u32::from_ne_bytes([192, 0, 2, 1])), "192.0.2.1");
    }
}
