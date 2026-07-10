use super::{
    ConnectionSettings, saved_wifi_profile_candidate_from_settings, settings_match_access_point,
    settings_match_wifi_ssid, ssid_bytes_match, wifi_settings_need_secret_agent,
};
use crate::model::AccessPoint;
use std::collections::HashMap;
use zvariant::{OwnedObjectPath, OwnedValue, Value};

#[test]
fn ssid_bytes_match_exact_bytes() {
    assert!(ssid_bytes_match(b"Example", b"Example"));
    assert!(ssid_bytes_match(&[0xff], &[0xff]));
    assert!(!ssid_bytes_match(&[0xff], "�".as_bytes()));
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
        .insert(
            "psk-flags".to_string(),
            owned_value(Value::new(4_u32)),
        );
    assert!(!wifi_settings_need_secret_agent(&settings, None, None));

    settings
        .get_mut("802-11-wireless-security")
        .expect("security settings")
        .remove("psk-flags");
    let mut secrets = ConnectionSettings::new();
    secrets.insert("802-11-wireless-security".to_string(), HashMap::new());
    assert!(wifi_settings_need_secret_agent(&settings, Some(&secrets), None));
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
        security: "WPA2/3".to_string(),
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
