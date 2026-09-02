use super::{
    AccessPoint, AuthKind, Bssid, ConnectionReadiness, ConnectivityStatus, InterfaceName,
    MeteredStatus, NM_AP_FLAGS_PRIVACY, NM_AP_SEC_KEY_MGMT_802_1X, NM_AP_SEC_KEY_MGMT_OWE,
    NM_AP_SEC_KEY_MGMT_OWE_TM, NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE, NetworkAuth,
    NetworkCapabilities, NmObjectPath, ProfilePrivacy, SavedWifiConnection, Security,
    SecurityClass, WifiConnectTarget, ap_is_passwordless, ap_supports_enterprise, ap_supports_psk,
    ap_uses_owe, ap_uses_wep, connect_target_for_network_key, frequency_band, frequency_channel,
    network_entries_with_profile_matches, security_class, security_flags_label, security_label,
    ssid_for_network_key,
};

#[test]
fn security_label_identifies_open_networks() {
    assert_eq!(security_label(0, 0, 0), Security::Open);
}

#[test]
fn security_label_prefers_rsn_over_wpa() {
    assert_eq!(security_label(NM_AP_FLAGS_PRIVACY, 1, 1), Security::Wpa2Or3);
    assert_eq!(security_label(NM_AP_FLAGS_PRIVACY, 1, 0), Security::Wpa);
    assert_eq!(security_label(NM_AP_FLAGS_PRIVACY, 0, 0), Security::Wep);
}

#[test]
fn security_classes_cover_frontend_presentation_types() {
    assert_eq!(security_class(0, 0, 0), SecurityClass::Open);
    assert_eq!(
        security_class(0, 0, NM_AP_SEC_KEY_MGMT_OWE),
        SecurityClass::EnhancedOpen
    );
    assert_eq!(
        security_class(NM_AP_FLAGS_PRIVACY, 0, 0),
        SecurityClass::Legacy
    );
    assert_eq!(
        security_class(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_PSK),
        SecurityClass::Personal
    );
    assert_eq!(
        security_class(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_802_1X),
        SecurityClass::Enterprise
    );
    assert_eq!(
        security_class(NM_AP_FLAGS_PRIVACY, 0, 0x4000),
        SecurityClass::Unknown
    );
}

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
fn owe_transition_bss_is_open_but_keeps_its_nmcli_security_label() {
    assert!(ap_is_passwordless(0, 0, NM_AP_SEC_KEY_MGMT_OWE_TM));
    assert!(!ap_uses_owe(0, NM_AP_SEC_KEY_MGMT_OWE_TM));
    assert_eq!(
        security_label(0, 0, NM_AP_SEC_KEY_MGMT_OWE_TM),
        Security::OweTransition
    );
    assert_eq!(
        security_class(0, 0, NM_AP_SEC_KEY_MGMT_OWE_TM),
        SecurityClass::Open
    );
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
fn psk_support_includes_sae() {
    assert!(ap_supports_psk(NM_AP_SEC_KEY_MGMT_PSK, 0));
    assert!(ap_supports_psk(0, NM_AP_SEC_KEY_MGMT_SAE));
    assert!(!ap_supports_psk(0, NM_AP_SEC_KEY_MGMT_OWE));
}

#[test]
fn wep_detection_requires_privacy_without_wpa_or_rsn() {
    assert!(ap_uses_wep(NM_AP_FLAGS_PRIVACY, 0, 0));
    assert!(!ap_uses_wep(0, 0, 0));
    assert!(!ap_uses_wep(NM_AP_FLAGS_PRIVACY, NM_AP_SEC_KEY_MGMT_PSK, 0));
}

#[test]
fn network_capabilities_distinguish_promptable_from_ready_connections() {
    assert_eq!(
        capabilities_for(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_PSK),
        super::NetworkCapabilities {
            readiness: ConnectionReadiness::NeedsPassword,
            has_profile: false,
            can_share_qr: false,
        }
    );
}

#[test]
fn network_capabilities_advertise_unsaved_enterprise_credentials() {
    let capabilities = capabilities_for(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_802_1X);
    assert_eq!(
        capabilities.readiness,
        ConnectionReadiness::NeedsEnterpriseCredentials
    );
    assert!(ap_supports_enterprise(0, NM_AP_SEC_KEY_MGMT_802_1X));
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
fn connectivity_status_maps_networkmanager_codes() {
    let portal = ConnectivityStatus::from_nm_code(2);
    assert_eq!(portal.state, "portal");
    assert!(portal.captive_portal);
    assert!(!portal.full);

    let limited = ConnectivityStatus::from_nm_code(3);
    assert_eq!(limited.state, "limited");
    assert!(!limited.captive_portal);
    assert!(!limited.full);

    let full = ConnectivityStatus::from_nm_code(4);
    assert_eq!(full.state, "full");
    assert!(!full.captive_portal);
    assert!(full.full);
}

#[test]
fn metered_status_maps_networkmanager_codes() {
    let yes = MeteredStatus::from_nm_code(1);
    assert_eq!(yes.state, "yes");
    assert_eq!(yes.metered, Some(true));
    assert!(!yes.guessed);

    let guess_no = MeteredStatus::from_nm_code(4);
    assert_eq!(guess_no.state, "guess-no");
    assert_eq!(guess_no.metered, Some(false));
    assert!(guess_no.guessed);

    let unknown = MeteredStatus::from_nm_code(0);
    assert_eq!(unknown.state, "unknown");
    assert_eq!(unknown.metered, None);
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
fn connect_target_accepts_network_entry_path_alias() {
    let target: WifiConnectTarget = serde_json::from_str(
        r#"{
                "ssid": "Cafe",
                "ssid_bytes": [67, 97, 102, 101],
                "path": "/org/freedesktop/NetworkManager/AccessPoint/1",
                "bssid": "00:11:22:33:44:55",
                "device_iface": "wlan0"
            }"#,
    )
    .expect("target JSON");

    assert_eq!(target.ssid.as_str(), "Cafe");
    assert_eq!(target.ssid_bytes(), b"Cafe");
    assert_eq!(
        target.ap_path.as_ref().map(NmObjectPath::as_str),
        Some("/org/freedesktop/NetworkManager/AccessPoint/1")
    );
    assert_eq!(
        target.bssid.as_ref().map(Bssid::as_str),
        Some("00:11:22:33:44:55")
    );
    assert_eq!(
        target.ifname.as_ref().map(InterfaceName::as_str),
        Some("wlan0")
    );
    assert!(!target.hidden);
}

#[test]
fn connect_target_legacy_ssid_wire_shape_becomes_one_exact_identity() {
    let target: WifiConnectTarget = serde_json::from_str(r#"{"ssid":"Cafe"}"#).unwrap();
    assert_eq!(target.ssid.as_str(), "Cafe");
    assert_eq!(target.ssid.as_bytes(), b"Cafe");

    let wire = serde_json::to_value(&target).unwrap();
    assert_eq!(wire["ssid"], "Cafe");
    assert_eq!(wire["ssid_bytes"], serde_json::json!([67, 97, 102, 101]));

    assert!(
        serde_json::from_str::<WifiConnectTarget>(
            r#"{"ssid":"Cafe","ssid_bytes":[79,116,104,101,114]}"#
        )
        .is_err()
    );
}

#[test]
fn readiness_serializes_v1_booleans_and_rejects_contradictions() {
    let capabilities = NetworkCapabilities {
        readiness: ConnectionReadiness::NeedsEnterpriseCredentials,
        has_profile: false,
        can_share_qr: false,
    };
    let wire = serde_json::to_value(&capabilities).unwrap();
    assert_eq!(wire["can_connect"], true);
    assert_eq!(wire["can_connect_now"], false);
    assert_eq!(wire["can_connect_with_credentials"], true);
    assert_eq!(wire["needs_credentials"], true);
    assert_eq!(wire["needs_password"], false);
    assert!(wire.get("readiness").is_none());

    let mut contradictory = wire;
    contradictory["needs_password"] = serde_json::json!(true);
    assert!(serde_json::from_value::<NetworkCapabilities>(contradictory).is_err());
}

#[test]
fn authentication_kind_derives_the_v1_supported_flag() {
    let auth = NetworkAuth::new(
        AuthKind::Unsupported,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some("unsupported".to_string()),
    );
    let wire = serde_json::to_value(&auth).unwrap();
    assert_eq!(wire["kind"], "unsupported");
    assert_eq!(wire["supported"], false);

    let mut contradictory = wire;
    contradictory["supported"] = serde_json::json!(true);
    assert!(serde_json::from_value::<NetworkAuth>(contradictory).is_err());
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

fn capabilities_for(flags: u32, wpa_flags: u32, rsn_flags: u32) -> super::NetworkCapabilities {
    let [entry] = network_entries_with_profile_matches(
        vec![test_ap(flags, wpa_flags, rsn_flags)],
        &std::collections::BTreeMap::new(),
    )
    .try_into()
    .expect("one entry");
    entry.capabilities
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
