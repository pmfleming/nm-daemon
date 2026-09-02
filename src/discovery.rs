use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use zbus::blocking::{Connection, Proxy};

use crate::error::{DomainError, ErrorOperation, ensure_domain};

const RESOLVED_DESTINATION: &str = "org.freedesktop.resolve1";
const RESOLVED_PATH: &str = "/org/freedesktop/resolve1";
const RESOLVED_INTERFACE: &str = "org.freedesktop.resolve1.Manager";
const MDNS_DOMAIN: &str = "local";
const AF_UNSPEC: i32 = 0;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

type ResolvedAddress = (i32, i32, Vec<u8>);
type ResolvedService = (u16, u16, u16, String, Vec<ResolvedAddress>, String);
type ResolveServiceReply = (
    Vec<ResolvedService>,
    Vec<Vec<u8>>,
    String,
    String,
    String,
    u64,
);
type ResolvedRecord = (i32, u16, u16, Vec<u8>);
type ResolveRecordReply = (Vec<ResolvedRecord>, u64);

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_PTR: u16 = 12;
const MAX_DISCOVERY_INSTANCES: usize = 128;

#[derive(Debug, Clone)]
pub(crate) struct ServiceQuery {
    pub(crate) service_type: String,
    pub(crate) name: Option<String>,
    pub(crate) interface_index: i32,
    pub(crate) family: AddressFamily,
}

impl ServiceQuery {
    pub(crate) fn new(
        service_type: String,
        name: Option<String>,
        interface_index: Option<i32>,
        family: AddressFamily,
    ) -> Result<Self> {
        validate_service_type(&service_type)?;
        let name = name
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty());
        if name.as_ref().is_some_and(|name| name.len() > 255) {
            return Err(DomainError::validation(
                ErrorOperation::Discovery,
                "DNS-SD service instance names must not exceed 255 bytes",
            )
            .into());
        }
        let interface_index = interface_index.unwrap_or(0);
        if interface_index < 0 {
            return Err(DomainError::validation(
                ErrorOperation::Discovery,
                "discovery interface_index must be zero or a positive interface index",
            )
            .into());
        }
        Ok(Self {
            service_type,
            name,
            interface_index,
            family,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    fn resolved_value(self) -> i32 {
        match self {
            Self::Any => AF_UNSPEC,
            Self::Ipv4 => AF_INET,
            Self::Ipv6 => AF_INET6,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiscoverySnapshot {
    pub(crate) source: &'static str,
    pub(crate) service_type: String,
    pub(crate) domain: &'static str,
    pub(crate) instance: Option<String>,
    pub(crate) interface_index: i32,
    pub(crate) family: AddressFamily,
    pub(crate) response_flags: u64,
    pub(crate) services: Vec<DiscoveredService>,
    pub(crate) warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiscoveredService {
    pub(crate) instance: String,
    pub(crate) service_type: String,
    pub(crate) domain: String,
    pub(crate) hostname: String,
    pub(crate) canonical_hostname: String,
    pub(crate) port: u16,
    pub(crate) priority: u16,
    pub(crate) weight: u16,
    pub(crate) addresses: Vec<DiscoveryAddress>,
    pub(crate) txt: Vec<DiscoveryTxtRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiscoveryAddress {
    pub(crate) interface_index: i32,
    pub(crate) family: &'static str,
    pub(crate) address: String,
    pub(crate) raw_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiscoveryTxtRecord {
    pub(crate) key: Option<String>,
    pub(crate) value: Option<String>,
    pub(crate) raw_hex: String,
}

pub(crate) fn resolve_services(
    conn: Connection,
    query: &ServiceQuery,
) -> Result<DiscoverySnapshot> {
    let proxy = Proxy::new(
        &conn,
        RESOLVED_DESTINATION,
        RESOLVED_PATH,
        RESOLVED_INTERFACE,
    )
    .map_err(|error| ensure_domain(ErrorOperation::Discovery, error.into()))?;
    match query.name.as_deref() {
        Some(instance) => {
            resolve_one(&proxy, query, instance).map(|reply| snapshot_from_reply(query, reply))
        }
        None => browse(&proxy, query),
    }
}

fn resolve_one(
    proxy: &Proxy<'_>,
    query: &ServiceQuery,
    instance: &str,
) -> Result<ResolveServiceReply> {
    proxy
        .call(
            "ResolveService",
            &(
                query.interface_index,
                instance,
                query.service_type.as_str(),
                MDNS_DOMAIN,
                query.family.resolved_value(),
                0_u64,
            ),
        )
        .map_err(|error| ensure_domain(ErrorOperation::Discovery, error.into()))
}

fn browse(proxy: &Proxy<'_>, query: &ServiceQuery) -> Result<DiscoverySnapshot> {
    let record_name = format!("{}.{}", query.service_type, MDNS_DOMAIN);
    let reply: ResolveRecordReply = match proxy.call(
        "ResolveRecord",
        &(
            query.interface_index,
            record_name.as_str(),
            DNS_CLASS_IN,
            DNS_TYPE_PTR,
            0_u64,
        ),
    ) {
        Ok(reply) => reply,
        Err(error) if empty_browse_error(&error) => return Ok(empty_snapshot(query, 0)),
        Err(error) => return Err(ensure_domain(ErrorOperation::Discovery, error.into())),
    };

    let (records, mut response_flags) = reply;
    let mut instances = Vec::new();
    let mut warnings = Vec::new();
    for (_, class, record_type, bytes) in records {
        if class != DNS_CLASS_IN || record_type != DNS_TYPE_PTR {
            continue;
        }
        match ptr_instance(&bytes, &query.service_type, MDNS_DOMAIN) {
            Some(instance) if !instances.contains(&instance) => {
                if instances.len() == MAX_DISCOVERY_INSTANCES {
                    warnings.push(format!(
                        "limited DNS-SD resolution to {MAX_DISCOVERY_INSTANCES} instances"
                    ));
                    break;
                }
                instances.push(instance);
            }
            Some(_) => {}
            None => warnings.push("ignored one malformed DNS-SD PTR record".to_string()),
        }
    }

    let mut services = Vec::new();
    for instance in instances {
        match resolve_one(proxy, query, &instance) {
            Ok(reply) => {
                let snapshot = snapshot_from_reply(query, reply);
                response_flags |= snapshot.response_flags;
                services.extend(snapshot.services);
            }
            Err(error) => warnings.push(format!(
                "could not resolve DNS-SD instance {instance}: {error:#}"
            )),
        }
    }
    let mut snapshot = empty_snapshot(query, response_flags);
    snapshot.services = services;
    snapshot.warnings = warnings;
    Ok(snapshot)
}

fn empty_snapshot(query: &ServiceQuery, response_flags: u64) -> DiscoverySnapshot {
    DiscoverySnapshot {
        source: "systemd-resolved",
        service_type: query.service_type.clone(),
        domain: MDNS_DOMAIN,
        instance: query.name.clone(),
        interface_index: query.interface_index,
        family: query.family,
        response_flags,
        services: Vec::new(),
        warnings: Vec::new(),
    }
}

fn snapshot_from_reply(query: &ServiceQuery, reply: ResolveServiceReply) -> DiscoverySnapshot {
    let (services, txt, canonical_name, canonical_type, canonical_domain, response_flags) = reply;
    let txt = txt.into_iter().map(txt_record).collect::<Vec<_>>();
    let services = services
        .into_iter()
        .map(
            |(priority, weight, port, hostname, addresses, canonical_hostname)| DiscoveredService {
                instance: canonical_name.clone(),
                service_type: canonical_type.clone(),
                domain: canonical_domain.clone(),
                hostname,
                canonical_hostname,
                port,
                priority,
                weight,
                addresses: addresses.into_iter().map(discovery_address).collect(),
                txt: txt.clone(),
            },
        )
        .collect();
    DiscoverySnapshot {
        services,
        ..empty_snapshot(query, response_flags)
    }
}

fn empty_browse_error(error: &zbus::Error) -> bool {
    matches!(
        error,
        zbus::Error::MethodError(name, _, _)
            if matches!(
                name.as_str(),
                "org.freedesktop.resolve1.NoSuchRR"
                    | "org.freedesktop.resolve1.DnsError.NXDOMAIN"
                    | "org.freedesktop.resolve1.NoNameServers"
                    | "org.freedesktop.DBus.Error.Timeout"
            )
    )
}

fn ptr_instance(record: &[u8], service_type: &str, domain: &str) -> Option<String> {
    let mut offset = 0;
    dns_labels(record, &mut offset)?;
    let record_type = take_u16(record, &mut offset)?;
    let record_class = take_u16(record, &mut offset)?;
    take_u32(record, &mut offset)?;
    let data_length = usize::from(take_u16(record, &mut offset)?);
    let data_end = offset.checked_add(data_length)?;
    if record_type != DNS_TYPE_PTR || record_class != DNS_CLASS_IN || data_end != record.len() {
        return None;
    }
    let labels = dns_labels(&record[..data_end], &mut offset)?;
    if offset != data_end {
        return None;
    }
    let mut suffix = service_type
        .split('.')
        .map(str::as_bytes)
        .chain(std::iter::once(domain.as_bytes()))
        .collect::<Vec<_>>();
    if labels.len() != suffix.len() + 1 {
        return None;
    }
    let instance = labels.first()?;
    for (actual, expected) in labels[1..].iter().zip(suffix.drain(..)) {
        if !actual.eq_ignore_ascii_case(expected) {
            return None;
        }
    }
    String::from_utf8(instance.clone()).ok()
}

fn dns_labels(bytes: &[u8], offset: &mut usize) -> Option<Vec<Vec<u8>>> {
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*bytes.get(*offset)?);
        *offset += 1;
        if length == 0 {
            return Some(labels);
        }
        if length > 63 {
            return None;
        }
        let end = offset.checked_add(length)?;
        labels.push(bytes.get(*offset..end)?.to_vec());
        *offset = end;
    }
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let value = u16::from_be_bytes(bytes.get(*offset..end)?.try_into().ok()?);
    *offset = end;
    Some(value)
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let value = u32::from_be_bytes(bytes.get(*offset..end)?.try_into().ok()?);
    *offset = end;
    Some(value)
}

fn discovery_address((interface_index, family, bytes): ResolvedAddress) -> DiscoveryAddress {
    let (family_name, address) = match (family, bytes.as_slice()) {
        (AF_INET, [a, b, c, d]) => ("ipv4", Ipv4Addr::new(*a, *b, *c, *d).to_string()),
        (AF_INET6, bytes) if bytes.len() == 16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(bytes);
            ("ipv6", Ipv6Addr::from(octets).to_string())
        }
        _ => ("unknown", hex(&bytes)),
    };
    DiscoveryAddress {
        interface_index,
        family: family_name,
        address,
        raw_hex: hex(&bytes),
    }
}

fn txt_record(bytes: Vec<u8>) -> DiscoveryTxtRecord {
    let raw_hex = hex(&bytes);
    let text = String::from_utf8(bytes).ok();
    let (key, value) = match text.as_deref() {
        Some(text) => match text.split_once('=') {
            Some((key, value)) => (Some(key.to_string()), Some(value.to_string())),
            None => (Some(text.to_string()), None),
        },
        None => (None, None),
    };
    DiscoveryTxtRecord {
        key,
        value,
        raw_hex,
    }
}

fn validate_service_type(service_type: &str) -> Result<()> {
    let valid = service_type.len() <= 255
        && service_type
            .strip_suffix("._tcp")
            .or_else(|| service_type.strip_suffix("._udp"))
            .is_some_and(|label| {
                label.starts_with('_')
                    && (2..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            });
    if valid {
        Ok(())
    } else {
        Err(DomainError::validation(
            ErrorOperation::Discovery,
            "service_type must be one DNS-SD type such as _googlecast._tcp",
        )
        .into())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        AddressFamily, ServiceQuery, discovery_address, ptr_instance, snapshot_from_reply,
        txt_record,
    };

    #[test]
    fn query_accepts_dns_sd_types_and_rejects_non_service_names() {
        assert!(
            ServiceQuery::new(
                "_googlecast._tcp".to_string(),
                None,
                None,
                AddressFamily::Any,
            )
            .is_ok()
        );
        assert!(
            ServiceQuery::new(
                "googlecast.local".to_string(),
                None,
                None,
                AddressFamily::Any,
            )
            .is_err()
        );
        assert!(
            ServiceQuery::new(
                "_googlecast._tcp".to_string(),
                None,
                Some(-1),
                AddressFamily::Any,
            )
            .is_err()
        );
    }

    #[test]
    fn resolved_reply_becomes_a_frontend_safe_snapshot() {
        let query = ServiceQuery::new(
            "_googlecast._tcp".to_string(),
            Some("Living Room".to_string()),
            Some(3),
            AddressFamily::Any,
        )
        .unwrap();
        let snapshot = snapshot_from_reply(
            &query,
            (
                vec![(
                    0,
                    0,
                    8009,
                    "living-room.local".to_string(),
                    vec![(3, 2, vec![192, 0, 2, 10])],
                    "living-room.local".to_string(),
                )],
                vec![b"fn=Living Room".to_vec(), vec![0xff, 0x00]],
                "Living Room".to_string(),
                "_googlecast._tcp".to_string(),
                "local".to_string(),
                16,
            ),
        );
        assert_eq!(snapshot.services.len(), 1);
        assert_eq!(snapshot.services[0].port, 8009);
        assert_eq!(snapshot.services[0].addresses[0].address, "192.0.2.10");
        assert_eq!(snapshot.services[0].txt[0].key.as_deref(), Some("fn"));
        assert_eq!(
            snapshot.services[0].txt[0].value.as_deref(),
            Some("Living Room")
        );
        assert_eq!(snapshot.services[0].txt[1].raw_hex, "ff00");
        assert!(snapshot.warnings.is_empty());
    }

    #[test]
    fn ptr_records_provide_instances_and_reject_other_service_types() {
        let owner = dns_name(&["_googlecast", "_tcp", "local"]);
        let target = dns_name(&["Living Room", "_googlecast", "_tcp", "local"]);
        let mut record = owner;
        record.extend_from_slice(&12_u16.to_be_bytes());
        record.extend_from_slice(&1_u16.to_be_bytes());
        record.extend_from_slice(&120_u32.to_be_bytes());
        record.extend_from_slice(&(target.len() as u16).to_be_bytes());
        record.extend_from_slice(&target);

        assert_eq!(
            ptr_instance(&record, "_googlecast._tcp", "local").as_deref(),
            Some("Living Room")
        );
        assert!(ptr_instance(&record, "_spotify-connect._tcp", "local").is_none());
        record.pop();
        assert!(ptr_instance(&record, "_googlecast._tcp", "local").is_none());
    }

    #[test]
    fn address_and_txt_conversion_preserve_raw_bytes() {
        let address = discovery_address((2, 10, Ipv6Addr::LOCALHOST.octets().to_vec()));
        assert_eq!(address.family, "ipv6");
        assert_eq!(address.address, "::1");
        assert_eq!(address.raw_hex.len(), 32);

        let txt = txt_record(b"flag".to_vec());
        assert_eq!(txt.key.as_deref(), Some("flag"));
        assert_eq!(txt.value, None);
        assert_eq!(txt.raw_hex, "666c6167");
    }

    fn dns_name(labels: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in labels {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes
    }

    use std::net::Ipv6Addr;
}
