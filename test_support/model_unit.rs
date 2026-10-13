use super::{
    AccessPoint, ConnectionReadiness, NM_AP_FLAGS_PRIVACY, NM_AP_SEC_KEY_MGMT_OWE,
    NM_AP_SEC_KEY_MGMT_PSK, ProfilePrivacy, SavedWifiConnection, Security, WifiConnectTarget,
    connect_target_for_network_key, network_entries_with_profile_matches, security_flags_label,
    security_label, ssid_for_network_key,
};

#[test]
fn network_groups_preserve_device_security_and_compatible_profile_boundaries() {
    let mut primary = test_ap(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_PSK);
    primary.path = "/ap/1".into();
    primary.strength = 80;
    let mut alternate = primary.clone();
    alternate.path = "/ap/2".into();
    alternate.strength = 40;
    let mut other_device = test_ap(0, 0, 0);
    other_device.device_iface = "wlan1".into();
    other_device.device_path = "/device/2".into();
    let profile = SavedWifiConnection {
        path: "/profile/1".into(),
        id: "Example".into(),
        ssid: "Example".into(),
        ssid_bytes: b"Example".to_vec(),
        autoconnect: true,
        casting_enabled: false,
        privacy: ProfilePrivacy::default(),
    };
    let matches = std::collections::BTreeMap::from([(alternate.path.clone(), vec![profile])]);
    let entries = network_entries_with_profile_matches(
        vec![
            primary,
            alternate,
            test_ap(0, 0, 0),
            other_device,
            test_ap(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_OWE),
        ],
        &matches,
    );
    assert_eq!(entries.len(), 4, "only compatible APs may be grouped");
    let saved = entries
        .iter()
        .find(|entry| entry.primary_profile.is_some())
        .unwrap();
    assert_eq!(saved.access_points.len(), 2);
    assert_eq!(saved.primary_profile.as_ref().unwrap().path, "/profile/1");
    assert!(matches!(
        saved.capabilities.readiness,
        ConnectionReadiness::Ready
    ));
    let owe = entries
        .iter()
        .find(|entry| entry.access_point.security == Security::Owe)
        .unwrap();
    assert!(matches!(
        owe.capabilities.readiness,
        ConnectionReadiness::Ready
    ));
    assert!(owe.share.shareable);
    assert!(
        entries
            .iter()
            .any(|entry| entry.access_point.device_iface == "wlan1")
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

fn test_ap(flags: u32, wpa_flags: u32, rsn_flags: u32) -> AccessPoint {
    AccessPoint {
        security: security_label(flags, wpa_flags, rsn_flags),
        strength: 50,
        wpa_flags_label: security_flags_label(wpa_flags),
        rsn_flags_label: security_flags_label(rsn_flags),
        path: "/ap".into(),
        device_path: "/device".into(),
        flags,
        wpa_flags,
        rsn_flags,
        ..super::example_access_point()
    }
}
