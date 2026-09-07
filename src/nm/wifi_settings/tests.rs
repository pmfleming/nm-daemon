use std::collections::HashMap;

use zvariant::OwnedValue;

use super::{
    apply_saved_activation_settings, cloned_wifi_connection_settings,
    enterprise_wifi_connection_settings, validate_wpa_psk,
};
use crate::model::{
    AccessPoint, EnterpriseAuth, NM_AP_SEC_KEY_MGMT_802_1X, NM_AP_SEC_KEY_MGMT_PSK,
    TargetIpAddress, TargetIpRoute, TargetIpSettings, TargetProfileSettings,
    example_connect_target,
};

#[test]
fn activation_pins_inherited_mdns_off_without_losing_explicit_policy() {
    let target = example_connect_target(true);
    for policy in [None, Some(-1), Some(0), Some(1), Some(2)] {
        let mut existing =
            super::base_wifi_connection_settings("Example", b"Example", false).unwrap();
        if let Some(policy) = policy {
            existing
                .get_mut("connection")
                .unwrap()
                .insert("mdns".into(), crate::nm::owned_value(policy).unwrap());
        }
        let settings = cloned_wifi_connection_settings(
            existing,
            &target,
            &test_ap(NM_AP_SEC_KEY_MGMT_PSK),
            Some("secret123"),
            None,
        )
        .unwrap();
        assert_eq!(
            setting::<i32>(&settings["connection"], "mdns"),
            Some(policy.unwrap_or(0).max(0))
        );
    }
}

#[test]
fn cloned_profile_settings_replace_secret_and_preserve_profile_options() {
    let mut target = example_connect_target(true);
    target.profile = TargetProfileSettings {
        autoconnect: Some(false),
        autoconnect_priority: Some(20),
        metered: Some("no".to_string()),
        cloned_mac_address: Some("stable".to_string()),
        send_hostname: Some(false),
        ipv4: Some(TargetIpSettings {
            addresses: vec![TargetIpAddress {
                address: "192.0.2.10".to_string(),
                prefix: 24,
            }],
            gateway: Some("192.0.2.1".to_string()),
            dns: vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()],
            routes: vec![TargetIpRoute {
                dest: "198.51.100.0".to_string(),
                prefix: 24,
                next_hop: Some("192.0.2.1".to_string()),
                metric: Some(20),
                table: None,
            }],
            route_metric: Some(50),
            ignore_auto_dns: Some(true),
            dns_search: vec!["example.test".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let existing =
        super::base_wifi_connection_settings("Example", b"Example", false).expect("base settings");
    let settings = cloned_wifi_connection_settings(
        existing,
        &target,
        &test_ap(NM_AP_SEC_KEY_MGMT_PSK),
        Some("secret123"),
        None,
    )
    .expect("settings");

    assert_eq!(
        settings
            .get("802-11-wireless-security")
            .and_then(|section| setting::<String>(section, "psk"))
            .as_deref(),
        Some("secret123")
    );
    assert_eq!(
        settings
            .get("connection")
            .and_then(|section| setting::<bool>(section, "autoconnect")),
        Some(false)
    );
    assert_eq!(
        settings
            .get("connection")
            .and_then(|section| setting::<i32>(section, "mdns")),
        Some(0)
    );
    assert_eq!(
        settings
            .get("802-11-wireless")
            .and_then(|section| setting::<String>(section, "assigned-mac-address"))
            .as_deref(),
        Some("stable")
    );
    assert_eq!(
        settings
            .get("connection")
            .and_then(|section| setting::<u32>(section, "metered")),
        Some(2)
    );
    assert_eq!(
        settings
            .get("ipv4")
            .and_then(|section| setting::<String>(section, "method"))
            .as_deref(),
        Some("manual")
    );
    assert_eq!(
        settings
            .get("ipv4")
            .and_then(|section| setting::<String>(section, "gateway"))
            .as_deref(),
        Some("192.0.2.1")
    );
    assert_eq!(
        settings
            .get("ipv4")
            .and_then(|section| setting::<i64>(section, "route-metric")),
        Some(50)
    );
    assert_eq!(
        settings
            .get("ipv4")
            .and_then(|section| setting::<Vec<String>>(section, "dns-data")),
        Some(vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()])
    );
    let address_data = settings
        .get("ipv4")
        .and_then(|section| setting::<Vec<HashMap<String, OwnedValue>>>(section, "address-data"))
        .expect("address-data");
    assert_eq!(
        setting::<String>(&address_data[0], "address").as_deref(),
        Some("192.0.2.10")
    );
    assert_eq!(setting::<u32>(&address_data[0], "prefix"), Some(24));
    let route_data = settings
        .get("ipv4")
        .and_then(|section| setting::<Vec<HashMap<String, OwnedValue>>>(section, "route-data"))
        .expect("route-data");
    assert_eq!(
        setting::<String>(&route_data[0], "dest").as_deref(),
        Some("198.51.100.0")
    );
    assert_eq!(
        setting::<String>(&route_data[0], "next-hop").as_deref(),
        Some("192.0.2.1")
    );
}

#[test]
fn saved_profile_password_update_preserves_security_options() {
    let target = example_connect_target(false);
    let mut settings =
        super::base_wifi_connection_settings("Example", b"Example", false).expect("base settings");
    settings.insert(
        "802-11-wireless-security".to_string(),
        HashMap::from([
            (
                "key-mgmt".to_string(),
                super::owned_value("wpa-psk".to_string()).expect("key management"),
            ),
            (
                "pmf".to_string(),
                super::owned_value(2_u32).expect("PMF setting"),
            ),
        ]),
    );

    apply_saved_activation_settings(
        &mut settings,
        &target,
        Some(&test_ap(NM_AP_SEC_KEY_MGMT_PSK)),
        Some("secret123"),
        None,
    )
    .expect("update saved settings");

    let security = settings
        .get("802-11-wireless-security")
        .expect("security settings");
    assert_eq!(
        setting::<String>(security, "key-mgmt").as_deref(),
        Some("wpa-psk")
    );
    assert_eq!(
        setting::<String>(security, "psk").as_deref(),
        Some("secret123")
    );
    assert_eq!(setting::<u32>(security, "pmf"), Some(2));
}

#[test]
fn enterprise_wifi_settings_include_8021x_credentials() {
    let mut auth = EnterpriseAuth {
        eap: vec!["peap".to_string()],
        identity: Some("laufan".to_string()),
        anonymous_identity: None,
        password: None,
        phase2_auth: Some("mschapv2".to_string()),
        ca_cert: Some("file:///etc/ssl/certs/company.pem".into()),
        client_cert: Some("file:///home/user/client.pem".into()),
        private_key: Some("pkcs11:object=client-key".into()),
        ..Default::default()
    };
    let settings = enterprise_wifi_connection_settings(
        &test_ap(NM_AP_SEC_KEY_MGMT_802_1X),
        &auth,
        Some("secret123"),
    )
    .expect("settings");

    assert_eq!(
        settings
            .get("802-11-wireless-security")
            .and_then(|section| setting::<String>(section, "key-mgmt"))
            .as_deref(),
        Some("wpa-eap")
    );
    assert_eq!(
        settings
            .get("802-1x")
            .and_then(|section| setting::<String>(section, "identity"))
            .as_deref(),
        Some("laufan")
    );
    assert_eq!(
        settings
            .get("802-1x")
            .and_then(|section| setting::<String>(section, "password"))
            .as_deref(),
        Some("secret123")
    );
    assert_eq!(
        settings
            .get("802-1x")
            .and_then(|section| setting::<String>(section, "phase2-auth"))
            .as_deref(),
        Some("mschapv2")
    );
    for (key, uri) in [
        ("ca-cert", auth.ca_cert.as_deref().unwrap()),
        ("client-cert", auth.client_cert.as_deref().unwrap()),
        ("private-key", auth.private_key.as_deref().unwrap()),
    ] {
        let bytes = setting::<Vec<u8>>(&settings["802-1x"], key).unwrap();
        assert_eq!(
            bytes,
            [uri.as_bytes(), &[0]].concat(),
            "NM requires ay for {key}"
        );
    }
    for invalid in ["https://example.test/ca.pem", "file:///safe.pem\0ignored"] {
        auth.ca_cert = Some(invalid.into());
        assert!(
            enterprise_wifi_connection_settings(
                &test_ap(NM_AP_SEC_KEY_MGMT_802_1X),
                &auth,
                Some("secret123"),
            )
            .is_err()
        );
    }
}

#[test]
fn wpa_psk_validation_matches_nmcli_shape() {
    assert!(validate_wpa_psk("12345678").is_ok());
    assert!(validate_wpa_psk(&"a".repeat(63)).is_ok());
    assert!(validate_wpa_psk(&"a".repeat(64)).is_ok());
    assert!(validate_wpa_psk("short").is_err());
    assert!(validate_wpa_psk(&"g".repeat(64)).is_err());
    assert!(validate_wpa_psk(&"a".repeat(65)).is_err());
}
fn test_ap(rsn_flags: u32) -> AccessPoint {
    AccessPoint {
        ssid: "Example".to_string(),
        ssid_bytes: b"Example".to_vec(),
        security: crate::model::Security::Wpa2Or3,
        strength: 50,
        frequency: 2412,
        band: "2.4 GHz".to_string(),
        mode: "Infra".to_string(),
        ssid_hex: "4578616d706c65".to_string(),
        bssid: "00:11:22:33:44:55".to_string(),
        path: "/ap".to_string(),
        device_path: "/device".to_string(),
        device_iface: "wlan0".to_string(),
        rsn_flags,
        ..Default::default()
    }
}

fn setting<T>(settings: &HashMap<String, OwnedValue>, key: &str) -> Option<T>
where
    OwnedValue: TryInto<T>,
{
    settings.get(key)?.try_clone().ok()?.try_into().ok()
}
