use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};
use std::time::Duration;

use tokio::time::Instant;
use zbus::Proxy;

use super::super::{
    AF_INET, AddressFamily, DISCOVERY_TIMEOUT, DNS_CLASS_IN, DNS_TYPE_PTR, MAX_DISCOVERY_INSTANCES,
    MDNS_IPV4, RESOLVED_INTERFACE, RESOLVED_PATH, ResolveRecordReply, ResolveServiceReply,
    ServiceQuery, browse_instances, ptr_instance, resolve_instances, resolve_with_proxy,
};
use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
use crate::test_support::TestPeer;

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.resolve1")]
enum ResolveError {
    NoNameServers(String),
    NoSuchRR(String),
}

struct Resolved(Arc<AtomicU8>);

#[zbus::interface(name = "org.freedesktop.resolve1.Manager")]
impl Resolved {
    async fn resolve_record(
        &self,
        interface: i32,
        name: &str,
        class: u16,
        kind: u16,
        flags: u64,
    ) -> std::result::Result<ResolveRecordReply, ResolveError> {
        assert_eq!(name, "_googlecast._tcp.local");
        assert_eq!((class, kind), (DNS_CLASS_IN, DNS_TYPE_PTR));
        assert_eq!(flags, MDNS_IPV4, "no unicast DNS or LLMNR fallback");
        match self.0.load(Ordering::Relaxed) {
            1 => return Err(ResolveError::NoNameServers("mDNS is disabled".into())),
            2 => return Err(ResolveError::NoSuchRR("no instances".into())),
            3 => tokio::time::sleep(Duration::from_secs(10)).await,
            _ => {}
        }
        let record = ptr("Living Room");
        // The same name on two links is two different discovery targets. A
        // duplicate record from IPv4/IPv6 on one link is not a third device.
        Ok((
            vec![
                (
                    if interface == 0 { 3 } else { interface },
                    class,
                    kind,
                    record.clone(),
                ),
                (
                    if interface == 0 { 3 } else { interface },
                    class,
                    kind,
                    ptr("LIVING ROOM"),
                ),
                (4, class, kind, record),
            ],
            flags,
        ))
    }

    async fn resolve_service(
        &self,
        interface: i32,
        instance: &str,
        kind: &str,
        domain: &str,
        family: i32,
        flags: u64,
    ) -> ResolveServiceReply {
        assert!(
            interface == 3 || interface == 4,
            "do not lose PTR interface scope"
        );
        assert_eq!(kind, "_googlecast._tcp");
        assert_eq!(domain, "local");
        assert_eq!(flags, MDNS_IPV4);
        assert_eq!(family, AF_INET);
        if instance == "slow" {
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
        (
            vec![(
                0,
                0,
                8009,
                "cast.local".into(),
                vec![(interface, AF_INET, vec![192, 0, 2, interface as u8])],
                "cast.local".into(),
            )],
            vec![],
            instance.into(),
            kind.into(),
            domain.into(),
            flags,
        )
    }
}

fn ptr(instance: &str) -> Vec<u8> {
    let mut record = super::dns_name(&["_googlecast", "_tcp", "local"]);
    let target = super::dns_name(&[instance, "_googlecast", "_tcp", "local"]);
    record.extend_from_slice(&DNS_TYPE_PTR.to_be_bytes());
    record.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    record.extend_from_slice(&120_u32.to_be_bytes());
    record.extend_from_slice(&(target.len() as u16).to_be_bytes());
    record.extend_from_slice(&target);
    record
}

#[test]
fn browse_limits_unique_targets_and_rejects_truncated_records() -> anyhow::Result<()> {
    let query = ServiceQuery::new("_googlecast._tcp".into(), None, None, AddressFamily::Any)?;
    let records = (0..=MAX_DISCOVERY_INSTANCES)
        .map(|index| {
            (
                3,
                DNS_CLASS_IN,
                DNS_TYPE_PTR,
                ptr(&format!("Device {index}")),
            )
        })
        .collect();
    let (instances, warnings) = browse_instances(records, &query);
    assert_eq!(instances.len(), MAX_DISCOVERY_INSTANCES);
    assert_eq!(instances[0], (3, "Device 0".into()));
    assert_eq!(warnings.len(), 1);
    let record = ptr("Living Room");
    for end in 0..record.len() {
        assert!(ptr_instance(&record[..end], "_googlecast._tcp", "local").is_none());
    }
    Ok(())
}

#[test]
fn browsing_is_link_scoped_mdns_only_and_reports_resolver_failures_and_deadlines()
-> anyhow::Result<()> {
    crate::test_support::workflows::isolated(
        concat!(
            module_path!(),
            "::browsing_is_link_scoped_mdns_only_and_reports_resolver_failures_and_deadlines"
        ),
        || {
            run_browsing_test();
            Ok(())
        },
    )
}

fn run_browsing_test() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let peer = TestPeer::new(":1.0", ":1.1");
    let mode = Arc::new(AtomicU8::new(0));
    peer.server
        .object_server()
        .at(RESOLVED_PATH, Resolved(mode.clone()))
        .unwrap();
    runtime.block_on(async {
        let proxy = Proxy::new(
            peer.client.inner(),
            ":1.0",
            RESOLVED_PATH,
            RESOLVED_INTERFACE,
        )
        .await
        .unwrap();
        let mut query =
            ServiceQuery::new("_googlecast._tcp".into(), None, None, AddressFamily::Ipv4).unwrap();
        let snapshot = resolve_with_proxy(&proxy, &query, Instant::now() + DISCOVERY_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(snapshot.services.len(), 2);
        assert!(
            snapshot
                .services
                .iter()
                .all(|service| service.instance == "Living Room")
        );
        let mut interfaces = snapshot
            .services
            .iter()
            .map(|service| service.addresses[0].interface_index)
            .collect::<Vec<_>>();
        interfaces.sort();
        assert_eq!(interfaces, vec![3, 4]);
        assert!(snapshot.warnings.is_empty());

        query.interface_index = 3;
        let snapshot = resolve_with_proxy(&proxy, &query, Instant::now() + DISCOVERY_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(snapshot.services.len(), 1);
        assert_eq!(
            snapshot.warnings.len(),
            1,
            "reject unexpected links from resolver"
        );

        let mut warnings = Vec::new();
        let (partial, _) = resolve_instances(
            &proxy,
            &query,
            vec![(3, "slow".into()), (4, "Living Room".into())],
            0,
            &mut warnings,
            Instant::now() + Duration::from_millis(100),
        )
        .await;
        assert_eq!(
            partial.len(),
            1,
            "a slow first instance must not hide later successful replies"
        );
        assert_eq!(partial[0].addresses[0].interface_index, 4);
        assert!(
            !warnings.is_empty(),
            "partial results must report their failure"
        );

        mode.store(1, Ordering::Relaxed);
        assert!(
            resolve_with_proxy(&proxy, &query, Instant::now() + DISCOVERY_TIMEOUT)
                .await
                .is_err(),
            "disabled mDNS must not look like a successful empty browse"
        );
        mode.store(2, Ordering::Relaxed);
        let empty = resolve_with_proxy(&proxy, &query, Instant::now() + DISCOVERY_TIMEOUT)
            .await
            .unwrap();
        assert!(empty.services.is_empty() && empty.warnings.is_empty());

        mode.store(3, Ordering::Relaxed);
        let error = resolve_with_proxy(&proxy, &query, Instant::now() + Duration::from_millis(30))
            .await
            .unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&error, ErrorOperation::Unknown).code,
            ErrorCode::Timeout
        );

        query.name = Some("slow".into());
        let error = resolve_with_proxy(&proxy, &query, Instant::now() + Duration::from_millis(30))
            .await
            .unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&error, ErrorOperation::Unknown).code,
            ErrorCode::Timeout
        );
    });
}
