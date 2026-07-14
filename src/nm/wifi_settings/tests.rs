use std::collections::HashMap;

use zvariant::OwnedValue;

use super::{
    cloned_wifi_connection_settings, enterprise_wifi_connection_settings,
    hidden_wifi_connection_settings, owe_wifi_connection_settings, psk_wifi_connection_settings,
    validate_wep_key, validate_wpa_psk,
};
use crate::model::{
    AccessPoint, EnterpriseAuth, NM_AP_SEC_KEY_MGMT_802_1X, NM_AP_SEC_KEY_MGMT_PSK,
    NM_AP_SEC_KEY_MGMT_SAE, TargetIpAddress, TargetIpRoute, TargetIpSettings,
    TargetProfileSettings, WepKeyType, example_connect_target,
};

#[test]
fn psk_wifi_settings_include_password_and_key_mgmt() {
    let ap = test_ap(NM_AP_SEC_KEY_MGMT_PSK);
    let settings = psk_wifi_connection_settings(&ap, "secret123").expect("settings");

    assert_eq!(
        settings
            .get("802-11-wireless-security")
            .and_then(|section| setting::<String>(section, "key-mgmt"))
            .as_deref(),
        Some("wpa-psk")
    );
    assert_eq!(
        settings
            .get("802-11-wireless-security")
            .and_then(|section| setting::<String>(section, "psk"))
            .as_deref(),
        Some("secret123")
    );
}

#[test]
fn sae_only_networks_use_sae_key_mgmt() {
    assert_eq!(
        crate::auth::personal_key_management(0, NM_AP_SEC_KEY_MGMT_SAE),
        "sae"
    );
    assert_eq!(
        crate::auth::personal_key_management(0, NM_AP_SEC_KEY_MGMT_SAE | NM_AP_SEC_KEY_MGMT_PSK),
        "wpa-psk"
    );
}

#[test]
fn owe_wifi_settings_include_key_mgmt_without_secret() {
    let settings = owe_wifi_connection_settings().expect("settings");

    assert_eq!(
        settings
            .get("802-11-wireless-security")
            .and_then(|section| setting::<String>(section, "key-mgmt"))
            .as_deref(),
        Some("owe")
    );
    assert!(
        settings
            .get("802-11-wireless-security")
            .is_some_and(|section| !section.contains_key("psk"))
    );
}

#[test]
fn hidden_key_mgmt_hint_controls_security_shape() {
    let mut target = example_connect_target(true);
    target.key_mgmt = Some("sae".to_string());
    let settings =
        hidden_wifi_connection_settings(&target, Some("secret123"), None).expect("settings");

    assert_eq!(
        settings
            .get("802-11-wireless-security")
            .and_then(|section| setting::<String>(section, "key-mgmt"))
            .as_deref(),
        Some("sae")
    );

    target.key_mgmt = Some("open".to_string());
    let settings = hidden_wifi_connection_settings(&target, None, None).expect("settings");
    assert!(!settings.contains_key("802-11-wireless-security"));
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
            .get("802-11-wireless")
            .and_then(|section| setting::<String>(section, "assigned-mac-address"))
            .as_deref(),
        Some("stable")
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
fn enterprise_wifi_settings_include_8021x_credentials() {
    let auth = EnterpriseAuth {
        eap: vec!["peap".to_string()],
        identity: Some("laufan".to_string()),
        anonymous_identity: None,
        password: None,
        phase2_auth: Some("mschapv2".to_string()),
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

#[test]
fn wep_validation_matches_nmcli_shape() {
    assert!(validate_wep_key("abcde", WepKeyType::Key).is_ok());
    assert!(validate_wep_key("0011223344", WepKeyType::Key).is_ok());
    assert!(validate_wep_key("abc", WepKeyType::Key).is_err());
    assert!(validate_wep_key("éabc", WepKeyType::Key).is_err());
    assert!(validate_wep_key("not-hex-10", WepKeyType::Key).is_err());
    assert!(validate_wep_key("passphrase", WepKeyType::Phrase).is_ok());
    assert!(validate_wep_key("short", WepKeyType::Phrase).is_err());
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
