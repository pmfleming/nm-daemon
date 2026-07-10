use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};

use crate::model::{
    AccessPoint, ConnectEnginePath, ConnectFailureReason, ConnectResult, ConnectivityStatus,
    EnterpriseAuth, Ip4Status, MeteredStatus, NetworkAuth, NetworkCapabilities,
    NetworkConnectPrompt, NetworkEntry, NetworkPortalHint, NetworkShareHint, ProfilePrivacy,
    SavedWifiConnection, WifiSharePayload, WifiStatus, WirelessStatus, security_flags_label,
    security_label,
};

#[derive(Serialize)]
struct ShelllistContractFixture {
    network: NetworkEntry,
    status: WifiStatus,
    connect_success: ConnectResult,
    connect_error: ConnectResult,
}

pub(crate) fn print_shelllist_contract_fixture() -> Result<()> {
    let fixture = shelllist_contract_fixture();
    crate::output::print_api_data(
        "fixture",
        &fixture,
        "serialize Shelllist contract fixture response",
    )
}

pub(crate) fn print_method_contract_fixtures() -> Result<()> {
    let fixtures = method_contract_fixtures();
    crate::output::print_api_data(
        "fixtures",
        &fixtures,
        "serialize method contract fixtures response",
    )
}

fn method_contract_fixtures() -> Value {
    let combined = shelllist_contract_fixture();
    let password_network = password_required_network();
    let enterprise_network = enterprise_required_network();
    json!({
        "wifi-networks.saved": {
            "networks": [combined.network],
        },
        "wifi-networks.password-required": {
            "networks": [password_network],
        },
        "wifi-networks.enterprise-required": {
            "networks": [enterprise_network],
        },
        "wifi-status.active": {
            "status": combined.status,
        },
        "wifi-status.inactive": {
            "status": inactive_status(),
        },
        "wifi-connect.success": {
            "result": combined.connect_success,
        },
        "wifi-connect.secret-required": {
            "result": combined.connect_error,
        },
        "wifi-scan.stream": {
            "events": scan_stream_events(),
        },
        "wifi-profile.share": {
            "payload": share_payload(),
        },
    })
}

fn shelllist_contract_fixture() -> ShelllistContractFixture {
    let access_point = contract_access_point();
    let profile = contract_profile();
    let network = NetworkEntry {
        access_point: access_point.clone(),
        key: access_point.path.clone(),
        access_points: vec![access_point.clone()],
        primary_profile: Some(profile.clone()),
        profiles: vec![profile.clone()],
        capabilities: NetworkCapabilities {
            can_connect: true,
            can_connect_now: true,
            can_connect_with_password: false,
            needs_password: false,
            can_connect_with_credentials: false,
            needs_credentials: false,
            can_forget: true,
            can_toggle_autoconnect: true,
            can_set_mac_randomization: true,
            can_set_send_hostname: true,
            can_share_qr: true,
            supported_auth: true,
            unsupported_reason: None,
        },
        auth: NetworkAuth {
            kind: "saved-profile".to_string(),
            key_management: Vec::new(),
            supported: true,
            required_fields: Vec::new(),
            optional_fields: Vec::new(),
            note: Some("A compatible saved NetworkManager profile can be activated without collecting new credentials".to_string()),
        },
        connect_prompt: NetworkConnectPrompt {
            kind: "none".to_string(),
            required_fields: Vec::new(),
            optional_fields: Vec::new(),
            message: Some("A compatible saved NetworkManager profile can be activated without collecting new credentials".to_string()),
            enterprise_defaults: None,
        },
        share: NetworkShareHint {
            shareable: false,
            reason: Some("Saved profile password availability must be checked before sharing".to_string()),
            requires_profile_secret_check: true,
            profile_path: Some(profile.path.clone()),
            qr_payload: None,
        },
        portal_hint: NetworkPortalHint {
            auto_open_on_connect: false,
            reason: None,
        },
        last_connection: None,
    };
    ShelllistContractFixture {
        network: network.clone(),
        status: WifiStatus {
            active: true,
            device_iface: Some("wlan0".to_string()),
            active_connection_path: Some(
                "/org/freedesktop/NetworkManager/ActiveConnection/1".to_string(),
            ),
            access_point: Some(access_point),
            network: Some(network),
            profile: Some(profile),
            connectivity: Some(ConnectivityStatus::from_nm_code(2)),
            ip4: Some(Ip4Status {
                address: Some("192.0.2.10".to_string()),
                prefix: Some(24),
                gateway: Some("192.0.2.1".to_string()),
                dns: vec!["192.0.2.1".to_string(), "1.1.1.1".to_string()],
            }),
            wireless: Some(WirelessStatus {
                bitrate_mbps: Some(144),
                tx_bitrate_mbps: Some(130.0),
                rx_bitrate_mbps: Some(144.4),
                mac_address: Some("02:00:00:00:00:01".to_string()),
            }),
            metered: Some(MeteredStatus::from_nm_code(4)),
            active_since_ms: Some(1_762_000_000_000),
        },
        connect_success: ConnectResult {
            status: "connected",
            reason: None,
            path: Some(ConnectEnginePath::Dbus),
            ssid: "Example".to_string(),
            message: "Connected to Example via D-Bus".to_string(),
            connectivity: Some(ConnectivityStatus::from_nm_code(4)),
            suggest_open_portal: false,
        },
        connect_error: ConnectResult {
            status: "error",
            reason: Some(ConnectFailureReason::SecretRequired),
            path: None,
            ssid: "Example".to_string(),
            message: "password required for Example".to_string(),
            connectivity: None,
            suggest_open_portal: false,
        },
    }
}

fn contract_access_point() -> AccessPoint {
    let rsn_flags = crate::model::NM_AP_SEC_KEY_MGMT_PSK;
    AccessPoint {
        ssid: "Example".to_string(),
        ssid_bytes: b"Example".to_vec(),
        active: true,
        security: security_label(crate::model::NM_AP_FLAGS_PRIVACY, 0, rsn_flags),
        strength: 82,
        frequency: 5180,
        channel: 36,
        band: "5 GHz".to_string(),
        mode: "Infra".to_string(),
        max_bitrate_mbps: 866,
        bandwidth_mhz: 80,
        ssid_hex: "4578616d706c65".to_string(),
        wpa_flags_label: security_flags_label(0),
        rsn_flags_label: security_flags_label(rsn_flags),
        bssid: "00:11:22:33:44:55".to_string(),
        last_seen: 1234,
        last_seen_age_ms: Some(2_500),
        path: "/org/freedesktop/NetworkManager/AccessPoint/1".to_string(),
        device_path: "/org/freedesktop/NetworkManager/Devices/1".to_string(),
        device_iface: "wlan0".to_string(),
        flags: crate::model::NM_AP_FLAGS_PRIVACY,
        wpa_flags: 0,
        rsn_flags,
    }
}

fn password_required_network() -> NetworkEntry {
    let mut access_point = contract_access_point();
    access_point.active = false;
    NetworkEntry {
        access_point: access_point.clone(),
        key: access_point.path.clone(),
        access_points: vec![access_point],
        primary_profile: None,
        profiles: Vec::new(),
        capabilities: NetworkCapabilities {
            can_connect: true,
            can_connect_now: false,
            can_connect_with_password: true,
            needs_password: true,
            can_connect_with_credentials: false,
            needs_credentials: false,
            can_forget: false,
            can_toggle_autoconnect: false,
            can_set_mac_randomization: false,
            can_set_send_hostname: false,
            can_share_qr: false,
            supported_auth: true,
            unsupported_reason: None,
        },
        auth: NetworkAuth {
            kind: "password".to_string(),
            key_management: vec!["wpa-psk".to_string()],
            supported: true,
            required_fields: vec!["password".to_string()],
            optional_fields: Vec::new(),
            note: Some("Provide a Wi-Fi password to connect".to_string()),
        },
        connect_prompt: NetworkConnectPrompt {
            kind: "password".to_string(),
            required_fields: vec!["password".to_string()],
            optional_fields: Vec::new(),
            message: Some("Provide a Wi-Fi password to connect".to_string()),
            enterprise_defaults: None,
        },
        share: NetworkShareHint {
            shareable: false,
            reason: Some("Wi-Fi QR sharing requires an open network or a saved profile with a readable password.".to_string()),
            requires_profile_secret_check: false,
            profile_path: None,
            qr_payload: None,
        },
        portal_hint: NetworkPortalHint {
            auto_open_on_connect: false,
            reason: None,
        },
        last_connection: None,
    }
}

fn enterprise_required_network() -> NetworkEntry {
    let mut access_point = contract_access_point();
    access_point.active = false;
    access_point.security = "Enterprise".to_string();
    access_point.rsn_flags = crate::model::NM_AP_SEC_KEY_MGMT_802_1X;
    access_point.rsn_flags_label = security_flags_label(access_point.rsn_flags);
    NetworkEntry {
        access_point: access_point.clone(),
        key: access_point.path.clone(),
        access_points: vec![access_point],
        primary_profile: None,
        profiles: Vec::new(),
        capabilities: NetworkCapabilities {
            can_connect: true,
            can_connect_now: false,
            can_connect_with_password: false,
            needs_password: false,
            can_connect_with_credentials: true,
            needs_credentials: true,
            can_forget: false,
            can_toggle_autoconnect: false,
            can_set_mac_randomization: false,
            can_set_send_hostname: false,
            can_share_qr: false,
            supported_auth: true,
            unsupported_reason: None,
        },
        auth: NetworkAuth {
            kind: "enterprise".to_string(),
            key_management: vec!["wpa-eap".to_string()],
            supported: true,
            required_fields: vec!["enterprise.identity".to_string(), "password".to_string()],
            optional_fields: vec!["enterprise.anonymous_identity".to_string()],
            note: Some("Provide enterprise credentials to connect".to_string()),
        },
        connect_prompt: NetworkConnectPrompt {
            kind: "enterprise".to_string(),
            required_fields: vec!["enterprise.identity".to_string(), "password".to_string()],
            optional_fields: vec!["enterprise.anonymous_identity".to_string()],
            message: Some("Provide enterprise credentials to connect".to_string()),
            enterprise_defaults: Some(EnterpriseAuth {
                eap: vec!["peap".to_string()],
                phase2_auth: Some("mschapv2".to_string()),
                key_mgmt: Some("wpa-eap".to_string()),
                ..Default::default()
            }),
        },
        share: NetworkShareHint {
            shareable: false,
            reason: Some("Wi-Fi QR sharing requires an open network or a saved profile with a readable password.".to_string()),
            requires_profile_secret_check: false,
            profile_path: None,
            qr_payload: None,
        },
        portal_hint: NetworkPortalHint {
            auto_open_on_connect: false,
            reason: None,
        },
        last_connection: None,
    }
}

fn inactive_status() -> WifiStatus {
    WifiStatus {
        active: false,
        device_iface: Some("wlan0".to_string()),
        active_connection_path: None,
        access_point: None,
        network: None,
        profile: None,
        connectivity: Some(ConnectivityStatus::from_nm_code(1)),
        ip4: None,
        wireless: None,
        metered: None,
        active_since_ms: None,
    }
}

fn scan_stream_events() -> Vec<Value> {
    json!([
        {
            "protocol": crate::output::API_PROTOCOL,
            "version": crate::output::API_VERSION,
            "stream": "wifi-scan",
            "event": "status",
            "message": "Scanning Wi-Fi networks"
        },
        {
            "protocol": crate::output::API_PROTOCOL,
            "version": crate::output::API_VERSION,
            "stream": "wifi-scan",
            "event": "snapshot",
            "scanning": true,
            "networks_found": 1,
            "networks": [password_required_network()]
        },
        {
            "protocol": crate::output::API_PROTOCOL,
            "version": crate::output::API_VERSION,
            "stream": "wifi-scan",
            "event": "complete",
            "timed_out": false,
            "networks_found": 1
        }
    ])
    .as_array()
    .cloned()
    .unwrap_or_default()
}

fn share_payload() -> WifiSharePayload {
    WifiSharePayload {
        status: "ok",
        shareable: true,
        reason: None,
        path: "/org/freedesktop/NetworkManager/Settings/1".to_string(),
        id: "Example".to_string(),
        ssid: "Example".to_string(),
        auth_type: Some("WPA".to_string()),
        qr_payload: Some("WIFI:T:WPA;S:Example;P:correct horse battery staple;;".to_string()),
    }
}

fn contract_profile() -> SavedWifiConnection {
    SavedWifiConnection {
        path: "/org/freedesktop/NetworkManager/Settings/1".to_string(),
        id: "Example".to_string(),
        ssid: "Example".to_string(),
        ssid_bytes: b"Example".to_vec(),
        autoconnect: true,
        privacy: ProfilePrivacy {
            mac_address_policy: "stable".to_string(),
            randomized_mac: true,
            send_hostname: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{method_contract_fixtures, shelllist_contract_fixture};

    #[test]
    fn shelllist_contract_fixture_contains_qml_boundary_fields() {
        let value = serde_json::to_value(shelllist_contract_fixture()).expect("fixture JSON");

        assert_eq!(value["network"]["capabilities"]["can_connect"], true);
        assert_eq!(value["network"]["capabilities"]["needs_password"], false);
        assert_eq!(value["network"]["capabilities"]["needs_credentials"], false);
        assert!(value["network"]["auth"]["note"].is_string());
        assert_eq!(value["network"]["connect_prompt"]["kind"], "none");
        assert_eq!(
            value["network"]["share"]["requires_profile_secret_check"],
            true
        );
        assert_eq!(
            value["network"]["portal_hint"]["auto_open_on_connect"],
            false
        );
        assert_eq!(value["status"]["connectivity"]["state"], "portal");
        assert_eq!(value["status"]["metered"]["state"], "guess-no");
        assert_eq!(value["status"]["wireless"]["tx_bitrate_mbps"], 130.0);
        assert_eq!(value["connect_success"]["suggest_open_portal"], false);
        assert_eq!(value["connect_success"]["path"], "dbus");
        assert_eq!(value["connect_error"]["reason"], "secret-required");
    }

    #[test]
    fn method_contract_fixtures_cover_frontend_api_shapes() {
        let value = method_contract_fixtures();

        assert!(value["wifi-networks.saved"]["networks"].is_array());
        assert_eq!(
            value["wifi-networks.password-required"]["networks"][0]["capabilities"]["needs_password"],
            true
        );
        assert_eq!(
            value["wifi-networks.enterprise-required"]["networks"][0]["capabilities"]["needs_credentials"],
            true
        );
        assert_eq!(
            value["wifi-networks.enterprise-required"]["networks"][0]["connect_prompt"]["kind"],
            "enterprise"
        );
        assert_eq!(value["wifi-status.inactive"]["status"]["active"], false);
        assert_eq!(
            value["wifi-connect.secret-required"]["result"]["reason"],
            "secret-required"
        );
        assert_eq!(value["wifi-scan.stream"]["events"][0]["protocol"], "nm-api");
        assert_eq!(value["wifi-profile.share"]["payload"]["shareable"], true);
    }
}
