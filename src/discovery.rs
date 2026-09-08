use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::time::{Instant, timeout_at};

use anyhow::Result;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use zbus::{Connection, Proxy};

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
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(8);
const INSTANCE_TIMEOUT: Duration = Duration::from_secs(2);
// SD_RESOLVED_MDNS_IPV4 / SD_RESOLVED_MDNS_IPV6: never fall back to
// unicast DNS or LLMNR for this local-discovery API.
const MDNS_IPV4: u64 = 1 << 3;
const MDNS_IPV6: u64 = 1 << 4;

#[derive(Debug)]
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
        // An instance is one DNS label. Spaces (including leading/trailing
        // spaces) are meaningful and must not be trimmed.
        let name = name.filter(|name| !name.is_empty());
        if name.as_ref().is_some_and(|name| name.len() > 63) {
            return Err(DomainError::validation(
                ErrorOperation::Discovery,
                "DNS-SD service instance names must not exceed 63 bytes",
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
    fn mdns_flags(self) -> u64 {
        match self {
            Self::Any => MDNS_IPV4 | MDNS_IPV6,
            Self::Ipv4 => MDNS_IPV4,
            Self::Ipv6 => MDNS_IPV6,
        }
    }

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

pub(crate) async fn resolve_services(
    conn: Connection,
    query: &ServiceQuery,
) -> Result<DiscoverySnapshot> {
    let deadline = Instant::now() + DISCOVERY_TIMEOUT;
    let proxy = timeout_at(
        deadline,
        Proxy::new(
            &conn,
            RESOLVED_DESTINATION,
            RESOLVED_PATH,
            RESOLVED_INTERFACE,
        ),
    )
    .await
    .map_err(|_| discovery_timeout())?
    .map_err(|error| ensure_domain(ErrorOperation::Discovery, error.into()))?;
    resolve_with_proxy(&proxy, query, deadline).await
}

async fn resolve_with_proxy(
    proxy: &Proxy<'_>,
    query: &ServiceQuery,
    deadline: Instant,
) -> Result<DiscoverySnapshot> {
    match query.name.as_deref() {
        Some(instance) => resolve_one(proxy, query, query.interface_index, instance, deadline)
            .await
            .map(|reply| snapshot_from_reply(query, reply)),
        None => browse(proxy, query, deadline).await,
    }
}

async fn resolve_one(
    proxy: &Proxy<'_>,
    query: &ServiceQuery,
    interface_index: i32,
    instance: &str,
    deadline: Instant,
) -> Result<ResolveServiceReply> {
    timeout_at(
        deadline,
        proxy.call(
            "ResolveService",
            &(
                interface_index,
                instance,
                query.service_type.as_str(),
                MDNS_DOMAIN,
                query.family.resolved_value(),
                query.family.mdns_flags(),
            ),
        ),
    )
    .await
    .map_err(|_| discovery_timeout())?
    .map_err(|error| ensure_domain(ErrorOperation::Discovery, error.into()))
}

fn discovery_timeout() -> anyhow::Error {
    DomainError::timeout(
        ErrorOperation::Discovery,
        "mDNS discovery deadline exceeded",
    )
    .into()
}

async fn browse(
    proxy: &Proxy<'_>,
    query: &ServiceQuery,
    deadline: Instant,
) -> Result<DiscoverySnapshot> {
    let record_name = format!("{}.{}", query.service_type, MDNS_DOMAIN);
    let reply: ResolveRecordReply = match timeout_at(
        deadline,
        proxy.call(
            "ResolveRecord",
            &(
                query.interface_index,
                record_name.as_str(),
                DNS_CLASS_IN,
                DNS_TYPE_PTR,
                query.family.mdns_flags(),
            ),
        ),
    )
    .await
    .map_err(|_| discovery_timeout())?
    {
        Ok(reply) => reply,
        Err(error) if empty_browse_error(&error) => return Ok(empty_snapshot(query, 0)),
        Err(error) => return Err(ensure_domain(ErrorOperation::Discovery, error.into())),
    };

    let (records, response_flags) = reply;
    let (instances, mut warnings) = browse_instances(records, query);
    let (services, response_flags) = resolve_instances(
        proxy,
        query,
        instances,
        response_flags,
        &mut warnings,
        deadline,
    )
    .await;
    Ok(DiscoverySnapshot {
        services,
        warnings,
        ..empty_snapshot(query, response_flags)
    })
}

fn browse_instances(
    records: Vec<ResolvedRecord>,
    query: &ServiceQuery,
) -> (Vec<(i32, String)>, Vec<String>) {
    let mut instances = Vec::new();
    let mut seen = HashSet::new();
    let mut warnings = Vec::new();
    for (interface, class, record_type, bytes) in records {
        if interface <= 0 || (query.interface_index != 0 && interface != query.interface_index) {
            warnings.push("ignored a DNS-SD record from an unexpected interface".to_string());
            continue;
        }
        if class != DNS_CLASS_IN || record_type != DNS_TYPE_PTR {
            continue;
        }
        let Some(instance) = ptr_instance(&bytes, &query.service_type, MDNS_DOMAIN) else {
            warnings.push("ignored one malformed DNS-SD PTR record".to_string());
            continue;
        };
        if !seen.insert((interface, instance.to_ascii_lowercase())) {
            continue;
        }
        if instances.len() == MAX_DISCOVERY_INSTANCES {
            warnings.push(format!(
                "limited DNS-SD resolution to {MAX_DISCOVERY_INSTANCES} instances"
            ));
            break;
        }
        instances.push((interface, instance));
    }
    (instances, warnings)
}

async fn resolve_instances(
    proxy: &Proxy<'_>,
    query: &ServiceQuery,
    instances: Vec<(i32, String)>,
    mut response_flags: u64,
    warnings: &mut Vec<String>,
    deadline: Instant,
) -> (Vec<DiscoveredService>, u64) {
    let mut services = Vec::new();
    // A stale instance must not hold up every other device. Bound concurrency
    // as well as elapsed time; dropping the stream cancels outstanding calls.
    let mut resolutions = futures::stream::iter(instances)
        .map(|(interface_index, instance)| async move {
            let instance_deadline = deadline.min(Instant::now() + INSTANCE_TIMEOUT);
            let reply =
                resolve_one(proxy, query, interface_index, &instance, instance_deadline).await;
            (interface_index, instance, reply)
        })
        .buffer_unordered(8);
    loop {
        if Instant::now() >= deadline {
            warnings.push("mDNS discovery deadline exceeded; results are incomplete".to_string());
            break;
        }
        let Some((interface, instance, reply)) = resolutions.next().await else {
            break;
        };
        match reply {
            Ok(reply) => {
                let snapshot = snapshot_from_reply(query, reply);
                response_flags |= snapshot.response_flags;
                services.extend(snapshot.services);
            }
            Err(error) => warnings.push(format!(
                "could not resolve DNS-SD instance {instance} on interface {interface}: {error:#}"
            )),
        }
    }
    (services, response_flags)
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
            )
    )
}

fn ptr_instance(record: &[u8], service_type: &str, domain: &str) -> Option<String> {
    let mut offset = 0;
    let owner = dns_labels(record, &mut offset)?;
    let expected_owner = format!("{service_type}.{domain}");
    if !labels_match(&owner, &expected_owner) {
        return None;
    }
    let record_type = u16::from_be_bytes(take_bytes(record, &mut offset)?);
    let record_class = u16::from_be_bytes(take_bytes(record, &mut offset)?);
    take_bytes::<4>(record, &mut offset)?;
    let data_length = usize::from(u16::from_be_bytes(take_bytes(record, &mut offset)?));
    let data_end = offset.checked_add(data_length)?;
    if record_type != DNS_TYPE_PTR || record_class != DNS_CLASS_IN || data_end != record.len() {
        return None;
    }
    let labels = dns_labels(&record[..data_end], &mut offset)?;
    if offset != data_end {
        return None;
    }
    let (instance, suffix) = labels.split_first()?;
    if !labels_match(suffix, &expected_owner) {
        return None;
    }
    std::str::from_utf8(instance).ok().map(str::to_string)
}

fn labels_match(labels: &[&[u8]], name: &str) -> bool {
    labels.len() == name.split('.').count()
        && labels
            .iter()
            .zip(name.split('.'))
            .all(|(label, expected)| label.eq_ignore_ascii_case(expected.as_bytes()))
}

fn dns_labels<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<Vec<&'a [u8]>> {
    let start = *offset;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*bytes.get(*offset)?);
        *offset += 1;
        if length == 0 {
            return (*offset - start <= 255).then_some(labels);
        }
        if length > 63 || *offset - start + length >= 255 {
            return None;
        }
        let end = offset.checked_add(length)?;
        labels.push(bytes.get(*offset..end)?);
        *offset = end;
    }
}

fn take_bytes<const N: usize>(bytes: &[u8], offset: &mut usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let value = bytes.get(*offset..end)?.try_into().ok()?;
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
    // RFC 6763 / RFC 6335 service names: 1–15 ASCII letters, digits or
    // hyphens, with at least one letter and no edge/consecutive hyphens.
    let valid = service_type
        .strip_suffix("._tcp")
        .or_else(|| service_type.strip_suffix("._udp"))
        .and_then(|label| label.strip_prefix('_'))
        .is_some_and(|label| {
            (1..=15).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && !label.contains("--")
                && label.bytes().any(|byte| byte.is_ascii_alphabetic())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
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
    use super::{AddressFamily, ServiceQuery, ptr_instance, snapshot_from_reply};

    mod dbus;

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
        for name in [
            "_bad_name._tcp",
            "_-edge._tcp",
            "_123._udp",
            "_longerthan15chars._tcp",
            "_two--hyphens._tcp",
        ] {
            assert!(
                ServiceQuery::new(name.into(), None, None, AddressFamily::Any).is_err(),
                "{name}"
            );
        }
        assert!(
            ServiceQuery::new(
                "_googlecast._tcp".into(),
                Some("é".repeat(32)),
                None,
                AddressFamily::Any
            )
            .is_err()
        );
        let query = ServiceQuery::new(
            "_googlecast._tcp".into(),
            Some(" Living Room ".into()),
            None,
            AddressFamily::Any,
        )
        .unwrap();
        assert_eq!(query.name.as_deref(), Some(" Living Room "));
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
        record[1] = b'x';
        assert!(
            ptr_instance(&record, "_googlecast._tcp", "local").is_none(),
            "reject a PTR owned by a different service"
        );
        record[1] = b'_';
        record.pop();
        assert!(ptr_instance(&record, "_googlecast._tcp", "local").is_none());
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
}
