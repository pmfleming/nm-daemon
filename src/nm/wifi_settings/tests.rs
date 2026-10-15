use std::collections::HashMap;
use zvariant::OwnedValue;

use super::{
    apply_saved_activation_settings, cloned_wifi_connection_settings,
    enterprise_wifi_connection_settings,
};
use crate::model::{
    AccessPoint, EnterpriseAuth, NM_AP_SEC_KEY_MGMT_802_1X, NM_AP_SEC_KEY_MGMT_PSK,
    TargetIpAddress, TargetIpRoute, TargetIpSettings, TargetProfileSettings,
    example_connect_target,
};
use crate::variant::{owned_value, value_map};

#[test]
fn profile_activation_replaces_credentials_without_losing_security_or_network_options()
-> anyhow::Result<()> {
    let mut target = example_connect_target(true);
    target.profile = TargetProfileSettings {
        autoconnect: Some(false),
        autoconnect_priority: Some(20),
        metered: Some("no".into()),
        cloned_mac_address: Some("stable".into()),
        send_hostname: Some(false),
        ipv4: Some(TargetIpSettings {
            addresses: vec![TargetIpAddress {
                address: "192.0.2.10".into(),
                prefix: 24,
            }],
            gateway: Some("192.0.2.1".into()),
            dns: vec!["1.1.1.1".into(), "9.9.9.9".into()],
            routes: vec![TargetIpRoute {
                dest: "198.51.100.0".into(),
                prefix: 24,
                next_hop: Some("192.0.2.1".into()),
                metric: Some(20),
                table: None,
            }],
            route_metric: Some(50),
            ignore_auto_dns: Some(true),
            dns_search: vec!["example.test".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut existing = super::base_wifi_connection_settings("Example", b"Example", false)?;
    existing.insert(
        "802-11-wireless-security".into(),
        value_map([
            ("key-mgmt", "wpa-psk".into()),
            ("pmf", 2_u32.into()),
            ("psk", "old-password".into()),
        ])?,
    );
    let settings = cloned_wifi_connection_settings(
        existing,
        &target,
        &test_ap(NM_AP_SEC_KEY_MGMT_PSK),
        Some("secret123"),
        None,
    )?;
    let security = &settings["802-11-wireless-security"];
    assert_eq!(
        setting::<String>(security, "key-mgmt").as_deref(),
        Some("wpa-psk")
    );
    assert_eq!(
        setting::<String>(security, "psk").as_deref(),
        Some("secret123")
    );
    assert_eq!(setting::<u32>(security, "pmf"), Some(2));
    let connection = &settings["connection"];
    assert_eq!(setting::<bool>(connection, "autoconnect"), Some(false));
    assert_eq!(setting::<i32>(connection, "mdns"), Some(0));
    assert_eq!(setting::<u32>(connection, "metered"), Some(2));
    assert_eq!(
        setting::<String>(&settings["802-11-wireless"], "assigned-mac-address").as_deref(),
        Some("stable")
    );
    let ip = &settings["ipv4"];
    assert_eq!(setting::<String>(ip, "method").as_deref(), Some("manual"));
    assert_eq!(
        setting::<String>(ip, "gateway").as_deref(),
        Some("192.0.2.1")
    );
    assert_eq!(setting::<i64>(ip, "route-metric"), Some(50));
    assert_eq!(
        setting::<Vec<String>>(ip, "dns-data").unwrap(),
        ["1.1.1.1", "9.9.9.9"]
    );
    let addresses = setting::<Vec<HashMap<String, OwnedValue>>>(ip, "address-data").unwrap();
    assert_eq!(
        setting::<String>(&addresses[0], "address").as_deref(),
        Some("192.0.2.10")
    );
    assert_eq!(setting::<u32>(&addresses[0], "prefix"), Some(24));
    let routes = setting::<Vec<HashMap<String, OwnedValue>>>(ip, "route-data").unwrap();
    assert_eq!(
        setting::<String>(&routes[0], "dest").as_deref(),
        Some("198.51.100.0")
    );
    assert_eq!(
        setting::<String>(&routes[0], "next-hop").as_deref(),
        Some("192.0.2.1")
    );
    for policy in [-1_i32, 0, 1, 2] {
        let mut inherited = settings.clone();
        inherited
            .get_mut("connection")
            .unwrap()
            .insert("mdns".into(), owned_value(policy)?);
        apply_saved_activation_settings(&mut inherited, &target, None, None, None)?;
        assert_eq!(
            setting::<i32>(&inherited["connection"], "mdns"),
            Some(policy.max(0))
        );
    }
    Ok(())
}

#[test]
fn enterprise_creation_and_reactivation_preserve_credentials_peap_and_certificate_trust()
-> anyhow::Result<()> {
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
    for label in [None, Some(""), Some("0"), Some("1")] {
        let auth = EnterpriseAuth {
            eap: vec!["peap".into()],
            identity: Some("test".into()),
            phase2_auth: Some("mschapv2".into()),
            phase1_peaplabel: label.map(str::to_owned),
            ca_cert: Some("file:///test/ca.pem".into()),
            client_cert: Some("file:///test/client.pem".into()),
            private_key: Some("pkcs11:object=client-key".into()),
            domain_suffix_match: Some("radius.example".into()),
            ..Default::default()
        };
        let mut target = example_connect_target(true);
        target.enterprise = Some(auth.clone());
        for mut settings in [
            enterprise_wifi_connection_settings(
                &test_ap(NM_AP_SEC_KEY_MGMT_802_1X),
                &auth,
                Some("test-password"),
            )?,
            super::hidden_wifi_connection_settings(&target, Some("test-password"), None)?,
        ] {
            assert_eq!(
                setting::<String>(&settings["802-11-wireless-security"], "key-mgmt").as_deref(),
                Some("wpa-eap")
            );
            let dot1x = &settings["802-1x"];
            assert_eq!(
                setting::<String>(dot1x, "identity").as_deref(),
                Some("test")
            );
            assert_eq!(
                setting::<String>(dot1x, "password").as_deref(),
                Some("test-password")
            );
            assert_eq!(
                setting::<String>(dot1x, "phase2-auth").as_deref(),
                Some("mschapv2")
            );
            assert_eq!(
                setting::<String>(dot1x, "phase1-peaplabel").as_deref(),
                label.filter(|value| !value.is_empty())
            );
            for (key, uri) in [
                ("ca-cert", auth.ca_cert.as_deref().unwrap()),
                ("client-cert", auth.client_cert.as_deref().unwrap()),
                ("private-key", auth.private_key.as_deref().unwrap()),
            ] {
                assert_eq!(
                    setting::<Vec<u8>>(dot1x, key).unwrap(),
                    [uri.as_bytes(), &[0]].concat(),
                    "NM requires ay for {key}"
                );
            }
            let before = dot1x.clone();
            target.enterprise = None;
            apply_saved_activation_settings(&mut settings, &target, None, None, None)?;
            assert_eq!(
                settings["802-1x"], before,
                "saved reactivation must retain trust and credentials"
            );
        }
    }
    for rejected in ["false", "true", "2", " 0", "0\0"] {
        let auth = EnterpriseAuth {
            identity: Some("test".into()),
            phase1_peaplabel: Some(rejected.into()),
            ..Default::default()
        };
        let error =
            enterprise_wifi_connection_settings(&test_ap(NM_AP_SEC_KEY_MGMT_802_1X), &auth, None)
                .unwrap_err();
        let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::ValidationError);
        assert_eq!(report.operation, ErrorOperation::Connect);
        assert_eq!(report.details["field"], "802-1x.phase1-peaplabel");
    }
    for invalid in ["https://example.test/ca.pem", "file:///safe.pem\0ignored"] {
        let auth = EnterpriseAuth {
            identity: Some("test".into()),
            ca_cert: Some(invalid.into()),
            ..Default::default()
        };
        assert!(
            enterprise_wifi_connection_settings(
                &test_ap(NM_AP_SEC_KEY_MGMT_802_1X),
                &auth,
                Some("secret123")
            )
            .is_err()
        );
    }
    Ok(())
}

fn test_ap(rsn_flags: u32) -> AccessPoint {
    AccessPoint {
        rsn_flags,
        ..crate::model::example_access_point()
    }
}

fn setting<T>(settings: &HashMap<String, OwnedValue>, key: &str) -> Option<T>
where
    OwnedValue: TryInto<T>,
{
    settings.get(key)?.try_clone().ok()?.try_into().ok()
}
