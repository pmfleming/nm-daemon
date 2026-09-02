use super::{
    ConnectionSettings, apply_mac_address_policy, casting_enabled_from_settings,
    privacy_from_settings, profile_ip_settings, profile_secret_spec, profile_secret_values,
    saved_wifi_profile_candidate_from_settings, set_casting_enabled, setting_string,
    settings_match_access_point, settings_match_wifi_ssid, ssid_bytes_match,
    update_profile_secrets, validate_profile_update, wifi_settings_need_secret_agent,
};
use crate::model::{AccessPoint, TargetIpAddress, TargetIpSettings, WifiProfileUpdate};
use crate::nm::ip_settings::replace as replace_ip_settings;
use std::collections::{BTreeMap, HashMap};
use zvariant::{OwnedObjectPath, OwnedValue, Value};

#[test]
fn ssid_bytes_match_exact_bytes() {
    assert!(ssid_bytes_match(b"Example", b"Example"));
    assert!(ssid_bytes_match(&[0xff], &[0xff]));
    assert!(!ssid_bytes_match(&[0xff], "�".as_bytes()));
}

#[test]
fn casting_uses_resolve_only_mdns_and_can_be_disabled_per_profile() {
    let mut settings = wifi_settings("Example", "802-11-wireless");
    assert!(!casting_enabled_from_settings(&settings));

    set_casting_enabled(&mut settings, false).expect("disable casting");
    assert!(!casting_enabled_from_settings(&settings));
    assert_eq!(
        i32::try_from(settings["connection"]["mdns"].clone()).unwrap(),
        0
    );

    set_casting_enabled(&mut settings, true).expect("enable casting");
    assert!(casting_enabled_from_settings(&settings));
    assert_eq!(
        i32::try_from(settings["connection"]["mdns"].clone()).unwrap(),
        1
    );
}

#[test]
fn settings_match_wireless_ssid() {
    let settings = wifi_settings("Example", "802-11-wireless");

    assert!(settings_match_wifi_ssid(&settings, b"Example"));
    assert!(!settings_match_wifi_ssid(&settings, b"Other"));
}

#[test]
fn settings_reject_non_wireless_profiles() {
    let settings = wifi_settings("Example", "ethernet");

    assert!(!settings_match_wifi_ssid(&settings, b"Example"));
}

#[test]
fn saved_profile_secret_agent_detection_uses_secret_flags_and_readable_secrets() {
    let mut settings = wifi_settings("Example", "802-11-wireless");
    settings.insert(
        "802-11-wireless-security".to_string(),
        HashMap::from([
            (
                "key-mgmt".to_string(),
                owned_value(Value::new("wpa-psk".to_string())),
            ),
            ("psk-flags".to_string(), owned_value(Value::new(1_u32))),
        ]),
    );
    assert!(wifi_settings_need_secret_agent(&settings, None, None));

    settings
        .get_mut("802-11-wireless-security")
        .expect("security settings")
        .insert("psk-flags".to_string(), owned_value(Value::new(4_u32)));
    assert!(!wifi_settings_need_secret_agent(&settings, None, None));

    settings
        .get_mut("802-11-wireless-security")
        .expect("security settings")
        .remove("psk-flags");
    let mut secrets = ConnectionSettings::new();
    secrets.insert("802-11-wireless-security".to_string(), HashMap::new());
    assert!(wifi_settings_need_secret_agent(
        &settings,
        Some(&secrets),
        None
    ));
    secrets
        .get_mut("802-11-wireless-security")
        .expect("secret settings")
        .insert(
            "psk".to_string(),
            owned_value(Value::new("correct horse battery staple".to_string())),
        );
    assert!(!wifi_settings_need_secret_agent(
        &settings,
        Some(&secrets),
        None
    ));
}

#[test]
fn advanced_profile_ip_settings_round_trip_and_validate_address_families() {
    let ipv4 = TargetIpSettings {
        method: Some("manual".to_string()),
        addresses: vec![TargetIpAddress {
            address: "192.0.2.20".to_string(),
            prefix: 24,
        }],
        gateway: Some("192.0.2.1".to_string()),
        dns: vec!["1.1.1.1".to_string()],
        ignore_auto_dns: Some(true),
        ..Default::default()
    };
    let update = WifiProfileUpdate {
        autoconnect: true,
        metered: "no".to_string(),
        hidden: false,
        mac_address_policy: "stable".to_string(),
        send_hostname: true,
        ipv4: ipv4.clone(),
        ipv6: TargetIpSettings {
            method: Some("auto".to_string()),
            ..Default::default()
        },
        password: None,
        secrets: BTreeMap::new(),
        expected_version: None,
        advanced: Default::default(),
    };
    validate_profile_update(&update).expect("valid advanced profile");

    let mut settings = ConnectionSettings::new();
    replace_ip_settings(&mut settings, "ipv4", &ipv4).expect("write IPv4 settings");
    let parsed = profile_ip_settings(&settings, "ipv4");
    assert_eq!(parsed.method, "manual");
    assert_eq!(parsed.addresses[0].address, "192.0.2.20");
    assert_eq!(parsed.addresses[0].prefix, 24);
    assert_eq!(parsed.gateway.as_deref(), Some("192.0.2.1"));
    assert_eq!(parsed.dns, vec!["1.1.1.1"]);
    assert!(parsed.ignore_auto_dns);

    let invalid = WifiProfileUpdate {
        ipv4: TargetIpSettings {
            dns: vec!["2001:db8::53".to_string()],
            ..ipv4
        },
        ..update
    };
    assert!(validate_profile_update(&invalid).is_err());
}

#[test]
fn enterprise_profile_secrets_use_the_8021x_section_and_support_named_updates() {
    let mut settings = wifi_settings("Example", "802-11-wireless");
    settings.insert(
        "802-11-wireless-security".to_string(),
        HashMap::from([(
            "key-mgmt".to_string(),
            owned_value(Value::new("wpa-eap".to_string())),
        )]),
    );
    settings.insert(
        "802-1x".to_string(),
        HashMap::from([("password-flags".to_string(), owned_value(Value::new(1_u32)))]),
    );
    let mut readable = ConnectionSettings::new();
    readable.insert(
        "802-1x".to_string(),
        HashMap::from([
            (
                "password".to_string(),
                owned_value(Value::new("old-password".to_string())),
            ),
            (
                "pin".to_string(),
                owned_value(Value::new("1234".to_string())),
            ),
        ]),
    );

    let spec = profile_secret_spec(&settings);
    assert_eq!(spec.setting_name, Some("802-1x"));
    assert_eq!(spec.primary_secret_key.as_deref(), Some("password"));
    let values = profile_secret_values(&settings, Some(&readable), &spec);
    assert_eq!(
        values.get("password").map(String::as_str),
        Some("old-password")
    );
    assert_eq!(values.get("pin").map(String::as_str), Some("1234"));
    assert!(wifi_settings_need_secret_agent(
        &settings,
        Some(&readable),
        None
    ));

    let update = WifiProfileUpdate {
        password: Some("new-password".to_string()),
        secrets: BTreeMap::from([(
            "private-key-password".to_string(),
            "private-secret".to_string(),
        )]),
        ..Default::default()
    };
    update_profile_secrets(&mut settings, &update).expect("update enterprise secrets");
    let enterprise = settings.get("802-1x").expect("802.1X section");
    assert_eq!(
        setting_string(enterprise, "password").as_deref(),
        Some("new-password")
    );
    assert_eq!(
        setting_string(enterprise, "private-key-password").as_deref(),
        Some("private-secret")
    );
    assert_eq!(
        enterprise
            .get("private-key-password-flags")
            .and_then(|value| value.try_clone().ok())
            .and_then(|value| u32::try_from(value).ok()),
        Some(0)
    );
}

#[test]
fn wep_profile_updates_validate_and_replace_the_active_named_key() {
    let mut settings = wifi_settings("Example", "802-11-wireless");
    settings.insert(
        "802-11-wireless-security".to_string(),
        HashMap::from([
            (
                "key-mgmt".to_string(),
                owned_value(Value::new("none".to_string())),
            ),
            ("wep-tx-keyidx".to_string(), owned_value(Value::new(2_u32))),
            ("wep-key-type".to_string(), owned_value(Value::new(1_u32))),
        ]),
    );
    let spec = profile_secret_spec(&settings);
    assert_eq!(spec.primary_secret_key.as_deref(), Some("wep-key2"));

    let update = WifiProfileUpdate {
        password: Some("abcde".to_string()),
        ..Default::default()
    };
    update_profile_secrets(&mut settings, &update).expect("update active WEP key");
    assert_eq!(
        settings
            .get("802-11-wireless-security")
            .and_then(|section| setting_string(section, "wep-key2"))
            .as_deref(),
        Some("abcde")
    );

    let invalid = WifiProfileUpdate {
        secrets: BTreeMap::from([("wep-key0".to_string(), "bad".to_string())]),
        ..Default::default()
    };
    assert!(update_profile_secrets(&mut settings, &invalid).is_err());
}

#[test]
fn profile_secret_updates_reject_keys_for_another_security_type() {
    let mut settings = wifi_settings("Example", "802-11-wireless");
    settings.insert(
        "802-11-wireless-security".to_string(),
        HashMap::from([(
            "key-mgmt".to_string(),
            owned_value(Value::new("wpa-psk".to_string())),
        )]),
    );
    let update = WifiProfileUpdate {
        secrets: BTreeMap::from([("pin".to_string(), "1234".to_string())]),
        ..Default::default()
    };
    assert!(update_profile_secrets(&mut settings, &update).is_err());
}

#[test]
fn system_default_mac_policy_omits_networkmanager_policy_properties() {
    let mut settings = wifi_settings("Example", "802-11-wireless");
    let wireless = settings
        .get_mut("802-11-wireless")
        .expect("wireless settings");
    wireless.insert(
        "assigned-mac-address".to_string(),
        owned_value(Value::new("permanent".to_string())),
    );
    wireless.insert(
        "cloned-mac-address".to_string(),
        owned_value(Value::new("random".to_string())),
    );
    wireless.insert(
        "mac-address-randomization".to_string(),
        owned_value(Value::new(1_u32)),
    );

    apply_mac_address_policy(&mut settings, "default").expect("apply system default policy");

    let wireless = settings.get("802-11-wireless").expect("wireless settings");
    assert!(!wireless.contains_key("assigned-mac-address"));
    assert!(!wireless.contains_key("cloned-mac-address"));
    assert!(!wireless.contains_key("mac-address-randomization"));
    assert_eq!(
        privacy_from_settings(&settings).mac_address_policy,
        "default"
    );

    apply_mac_address_policy(&mut settings, "stable").expect("apply stable policy");
    assert_eq!(
        privacy_from_settings(&settings).mac_address_policy,
        "stable"
    );
}

#[test]
fn cached_profile_candidate_matches_access_point_without_refetching_settings() {
    let mut settings = wifi_settings("Example", "802-11-wireless");
    settings
        .get_mut("802-11-wireless")
        .expect("wireless settings")
        .insert(
            "bssid".to_string(),
            owned_value(Value::new(vec![0x00_u8, 0x11, 0x22, 0x33, 0x44, 0x55])),
        );
    let path = OwnedObjectPath::try_from("/profile/1").expect("profile path");
    let candidate =
        saved_wifi_profile_candidate_from_settings(&path, &settings).expect("profile candidate");

    let matching_ap = test_ap("Example", "00:11:22:33:44:55");
    assert!(candidate.matches_access_point(&matching_ap));
    assert_eq!(
        candidate.matches_access_point(&matching_ap),
        settings_match_access_point(&settings, &matching_ap)
    );

    let wrong_bssid_ap = test_ap("Example", "66:77:88:99:aa:bb");
    assert!(!candidate.matches_access_point(&wrong_bssid_ap));
    assert_eq!(
        candidate.matches_access_point(&wrong_bssid_ap),
        settings_match_access_point(&settings, &wrong_bssid_ap)
    );

    let wrong_ssid_ap = test_ap("Other", "00:11:22:33:44:55");
    assert!(!candidate.matches_access_point(&wrong_ssid_ap));
}

fn wifi_settings(ssid: &str, connection_type: &str) -> ConnectionSettings {
    let mut settings = ConnectionSettings::new();
    settings.insert(
        "connection".to_string(),
        HashMap::from([(
            "type".to_string(),
            owned_value(Value::new(connection_type.to_string())),
        )]),
    );
    settings.insert(
        "802-11-wireless".to_string(),
        HashMap::from([(
            "ssid".to_string(),
            owned_value(Value::new(ssid.as_bytes().to_vec())),
        )]),
    );
    settings
}

fn test_ap(ssid: &str, bssid: &str) -> AccessPoint {
    AccessPoint {
        ssid: ssid.to_string(),
        ssid_bytes: ssid.as_bytes().to_vec(),
        active: false,
        security: crate::model::Security::Wpa2Or3,
        strength: 50,
        frequency: 2412,
        channel: 1,
        band: "2.4 GHz".to_string(),
        mode: "Infra".to_string(),
        max_bitrate_mbps: 0,
        bandwidth_mhz: 0,
        ssid_hex: String::new(),
        wpa_flags_label: String::new(),
        rsn_flags_label: String::new(),
        bssid: bssid.to_string(),
        last_seen: 0,
        last_seen_age_ms: None,
        path: "/ap/1".to_string(),
        device_path: "/device/1".to_string(),
        device_iface: "wlan0".to_string(),
        flags: 0,
        wpa_flags: 0,
        rsn_flags: 0,
    }
}

fn owned_value(value: Value<'_>) -> OwnedValue {
    OwnedValue::try_from(value).expect("owned value")
}
