use std::time::Duration;

use super::{
    AccessPoint, ConnectivityStatus, MeteredStatus, NM_AP_FLAGS_PRIVACY, NM_AP_SEC_KEY_MGMT_802_1X,
    NM_AP_SEC_KEY_MGMT_OWE, NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE, ProfilePrivacy,
    SavedWifiConnection, WifiConnectTarget, ap_is_passwordless, ap_supports_enterprise,
    ap_supports_psk, ap_uses_wep, network_entries_with_profile_matches, retry_delay,
    security_flags_label, security_label,
};

#[test]
fn retry_delay_uses_bounded_exponential_backoff() {
    assert_eq!(retry_delay(1), Duration::from_secs(1));
    assert_eq!(retry_delay(2), Duration::from_secs(2));
    assert_eq!(retry_delay(3), Duration::from_secs(4));
    assert_eq!(retry_delay(4), Duration::from_secs(8));
    assert_eq!(retry_delay(99), Duration::from_secs(8));
}

#[test]
fn security_label_identifies_open_networks() {
    assert_eq!(security_label(0, 0, 0), "--");
}

#[test]
fn security_label_prefers_rsn_over_wpa() {
    assert_eq!(security_label(NM_AP_FLAGS_PRIVACY, 1, 1), "WPA2/3");
    assert_eq!(security_label(NM_AP_FLAGS_PRIVACY, 1, 0), "WPA");
    assert_eq!(security_label(NM_AP_FLAGS_PRIVACY, 0, 0), "WEP");
}

#[test]
fn owe_is_passwordless_but_psk_is_not() {
    assert!(ap_is_passwordless(0, 0, NM_AP_SEC_KEY_MGMT_OWE));
    assert!(ap_is_passwordless(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_OWE));
    assert_eq!(security_label(0, 0, NM_AP_SEC_KEY_MGMT_OWE), "OWE");
    assert_eq!(security_label(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_OWE), "OWE");
    assert!(!ap_is_passwordless(0, 0, NM_AP_SEC_KEY_MGMT_PSK));
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
        expected_capabilities(true, false, true, true, true, false)
    );
}

#[test]
fn network_capabilities_advertise_unsaved_enterprise_credentials() {
    let capabilities = capabilities_for(NM_AP_FLAGS_PRIVACY, 0, NM_AP_SEC_KEY_MGMT_802_1X);
    assert!(capabilities.can_connect);
    assert!(!capabilities.can_connect_now);
    assert!(!capabilities.can_connect_with_password);
    assert!(capabilities.can_connect_with_credentials);
    assert!(capabilities.needs_credentials);
    assert!(capabilities.supported_auth);
    assert!(capabilities.unsupported_reason.is_none());
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
    assert!(entry.capabilities.can_connect_now);
    assert!(!entry.capabilities.needs_password);
}

#[test]
fn connectivity_status_maps_networkmanager_codes() {
    let portal = ConnectivityStatus::from_nm_code(2);
    assert_eq!(portal.state, "portal");
    assert!(portal.captive_portal);
    assert!(!portal.full);

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
    let mut target = WifiConnectTarget {
        ssid: "Example".to_string(),
        ssid_bytes: b"Example".to_vec(),
        ap_path: None,
        bssid: Some("not-a-mac".to_string()),
        ifname: None,
        device_path: None,
        connection_name: None,
        private: false,
        hidden: false,
        security: None,
        key_mgmt: None,
        enterprise: None,
        profile: Default::default(),
    };
    assert!(target.validate().is_err());

    target.bssid = None;
    target.ssid_bytes = vec![b'x'; 33];
    assert!(target.validate().is_err());
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

    assert_eq!(target.ssid, "Cafe");
    assert_eq!(target.ssid_bytes, b"Cafe");
    assert_eq!(
        target.ap_path.as_deref(),
        Some("/org/freedesktop/NetworkManager/AccessPoint/1")
    );
    assert_eq!(target.bssid.as_deref(), Some("00:11:22:33:44:55"));
    assert_eq!(target.ifname.as_deref(), Some("wlan0"));
    assert!(!target.hidden);
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

fn expected_capabilities(
    can_connect: bool,
    can_connect_now: bool,
    can_connect_with_password: bool,
    needs_password: bool,
    supported_auth: bool,
    has_unsupported_reason: bool,
) -> super::NetworkCapabilities {
    super::NetworkCapabilities {
            can_connect,
            can_connect_now,
            can_connect_with_password,
            needs_password,
            can_connect_with_credentials: false,
            needs_credentials: false,
            can_forget: false,
            can_toggle_autoconnect: false,
            can_set_mac_randomization: false,
            can_set_send_hostname: false,
            can_share_qr: false,
            supported_auth,
            unsupported_reason: has_unsupported_reason.then(|| {
                "unsupported authentication; open/OWE, WEP, WPA/SAE-Personal, WPA-Enterprise, and saved profiles are supported".to_string()
            }),
        }
}

fn test_profile() -> SavedWifiConnection {
    SavedWifiConnection {
        path: "/profile/1".to_string(),
        id: "Example".to_string(),
        ssid: "Example".to_string(),
        ssid_bytes: b"Example".to_vec(),
        autoconnect: true,
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
