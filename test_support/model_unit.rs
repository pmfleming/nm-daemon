use super::{
    AccessPoint, ConnectionReadiness, NM_AP_FLAGS_PRIVACY, NM_AP_SEC_KEY_MGMT_OWE,
    NM_AP_SEC_KEY_MGMT_PSK, ProfilePrivacy, SavedWifiConnection, Security, WifiConnectTarget,
    ap_is_passwordless, connect_target_for_network_key, frequency_band, frequency_channel,
    network_entries_with_profile_matches, security_flags_label, security_label,
    ssid_for_network_key,
};
#[test]
fn owe_is_passwordless_but_psk_is_not() {
    assert!(ap_is_passwordless(0, 0, NM_AP_SEC_KEY_MGMT_OWE));
    assert!(ap_is_passwordless(
        NM_AP_FLAGS_PRIVACY,
        0,
        NM_AP_SEC_KEY_MGMT_OWE
    ));
    assert_eq!(security_label(0, 0, NM_AP_SEC_KEY_MGMT_OWE), Security::Owe);
    assert_eq!(
        security_label(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_OWE),
        Security::Owe
    );
    let [owe] = network_entries_with_profile_matches(
        vec![test_ap(0, 0, NM_AP_SEC_KEY_MGMT_OWE)],
        &std::collections::BTreeMap::new(),
    )
    .try_into()
    .expect("one OWE network");
    assert!(owe.share.shareable);
    assert_eq!(
        owe.share.qr_payload.as_deref(),
        Some("WIFI:T:nopass;S:Example;;")
    );
    assert!(!ap_is_passwordless(0, 0, NM_AP_SEC_KEY_MGMT_PSK));
}
#[test]
fn wifi_band_and_channel_match_networkmanager_tables() {
    assert_eq!(frequency_band(2412), "2.4 GHz");
    assert_eq!(frequency_channel(2412), 1);
    assert_eq!(frequency_band(4915), "5 GHz");
    assert_eq!(frequency_channel(4915), 183);
    assert_eq!(frequency_band(5955), "6 GHz");
    assert_eq!(frequency_channel(5955), 1);
    assert_eq!(frequency_channel(6795), 0);
    assert_eq!(frequency_band(5900), "");
    assert_eq!(frequency_channel(5900), 0);
}

#[test]
fn compatible_profile_matches_are_used_across_grouped_access_points() {
    let mut first_ap = test_ap(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_PSK);
    first_ap.path = "/ap/1".to_string();
    first_ap.strength = 80;
    let mut second_ap = test_ap(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_PSK);
    second_ap.path = "/ap/2".to_string();
    second_ap.strength = 40;
    let profile = test_profile();
    let matches =
        std::collections::BTreeMap::from([(second_ap.path.clone(), vec![profile.clone()])]);

    let [entry] = network_entries_with_profile_matches(vec![first_ap, second_ap], &matches)
        .try_into()
        .expect("one grouped network entry");

    assert_eq!(
        entry.primary_profile.as_ref().map(|profile| &profile.path),
        Some(&profile.path)
    );
    assert!(matches!(
        entry.capabilities.readiness,
        ConnectionReadiness::Ready
    ));
}

#[test]
fn same_ssid_is_split_by_security_and_device() {
    let open = test_ap(0, 0, 0);
    let secured = test_ap(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_PSK);
    let mut other_device = test_ap(0, 0, 0);
    other_device.device_iface = "wlan1".to_string();
    other_device.device_path = "/device/2".to_string();

    let entries = network_entries_with_profile_matches(
        vec![open, secured, other_device],
        &std::collections::BTreeMap::new(),
    );

    assert_eq!(entries.len(), 3);
    let keys = entries
        .iter()
        .map(|entry| entry.key.as_str())
        .collect::<Vec<_>>();
    assert!(
        keys.iter()
            .any(|key| key.contains("security:open|ifname:776c616e30"))
    );
    assert!(
        keys.iter()
            .any(|key| key.contains("security:personal|ifname:776c616e30"))
    );
    assert!(
        keys.iter()
            .any(|key| key.contains("security:open|ifname:776c616e31"))
    );
}
#[test]
fn connect_target_validation_rejects_bad_identity() {
    assert!(
        serde_json::from_str::<WifiConnectTarget>(r#"{"ssid":"Example","bssid":"not-a-mac"}"#)
            .is_err()
    );
    assert!(
        serde_json::from_value::<WifiConnectTarget>(serde_json::json!({
            "ssid": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "ssid_bytes": vec![b'x'; 33],
        }))
        .is_err()
    );
}
#[test]
fn opaque_network_keys_are_stable_and_resolve_exact_ssid_bytes() {
    let [entry] = network_entries_with_profile_matches(
        vec![test_ap(0, 0, 0)],
        &std::collections::BTreeMap::new(),
    )
    .try_into()
    .expect("one entry");
    assert_eq!(
        entry.key,
        "ssid-hex:4578616d706c65|security:open|ifname:776c616e30"
    );
    assert_eq!(
        ssid_for_network_key(&entry.key).unwrap().as_bytes(),
        b"Example"
    );
    assert_eq!(
        connect_target_for_network_key(&entry.key, None)
            .unwrap()
            .ssid_bytes(),
        b"Example"
    );
    assert!(ssid_for_network_key("/org/freedesktop/NetworkManager/AccessPoint/1").is_err());
}

fn test_profile() -> SavedWifiConnection {
    SavedWifiConnection {
        path: "/profile/1".to_string(),
        id: "Example".to_string(),
        ssid: "Example".to_string(),
        ssid_bytes: b"Example".to_vec(),
        autoconnect: true,
        casting_enabled: false,
        privacy: ProfilePrivacy::default(),
    }
}

fn test_ap(flags: u32, wpa_flags: u32, rsn_flags: u32) -> AccessPoint {
    AccessPoint {
        ssid: "Example".to_string(),
        ssid_bytes: b"Example".to_vec(),
        active: false,
        security: security_label(flags, wpa_flags, rsn_flags),
        strength: 50,
        frequency: 2412,
        channel: 1,
        band: "2.4 GHz".to_string(),
        mode: "Infra".to_string(),
        max_bitrate_mbps: 0,
        bandwidth_mhz: 0,
        ssid_hex: "4578616d706c65".to_string(),
        wpa_flags_label: security_flags_label(wpa_flags),
        rsn_flags_label: security_flags_label(rsn_flags),
        bssid: "00:11:22:33:44:55".to_string(),
        last_seen: 0,
        last_seen_age_ms: None,
        path: "/ap".to_string(),
        device_path: "/device".to_string(),
        device_iface: "wlan0".to_string(),
        flags,
        wpa_flags,
        rsn_flags,
    }
}
