use anyhow::{Context, Result};
use serde::Serialize;

use crate::model::{
    AccessPoint, ConnectFailureReason, ConnectResult, ConnectivityStatus, Ip4Status, MeteredStatus,
    NetworkAuth, NetworkCapabilities, NetworkEntry, ProfilePrivacy, SavedWifiConnection,
    WifiStatus, WirelessStatus, security_flags_label, security_label,
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
    serde_json::to_writer_pretty(std::io::stdout(), &fixture)
        .context("serialize Shelllist contract fixture")?;
    println!();
    Ok(())
}

fn shelllist_contract_fixture() -> ShelllistContractFixture {
    let access_point = contract_access_point();
    let profile = contract_profile();
    let network = NetworkEntry {
        access_point: access_point.clone(),
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
            ssid: "Example".to_string(),
            message: "Connected to Example via D-Bus".to_string(),
            connectivity: Some(ConnectivityStatus::from_nm_code(4)),
            suggest_open_portal: false,
        },
        connect_error: ConnectResult {
            status: "error",
            reason: Some(ConnectFailureReason::SecretRequired),
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
    use super::shelllist_contract_fixture;

    #[test]
    fn shelllist_contract_fixture_contains_qml_boundary_fields() {
        let value = serde_json::to_value(shelllist_contract_fixture()).expect("fixture JSON");

        assert_eq!(value["network"]["capabilities"]["can_connect"], true);
        assert_eq!(value["network"]["capabilities"]["needs_password"], false);
        assert_eq!(value["network"]["capabilities"]["needs_credentials"], false);
        assert!(value["network"]["auth"]["note"].is_string());
        assert_eq!(value["status"]["connectivity"]["state"], "portal");
        assert_eq!(value["status"]["metered"]["state"], "guess-no");
        assert_eq!(value["status"]["wireless"]["tx_bitrate_mbps"], 130.0);
        assert_eq!(value["connect_success"]["suggest_open_portal"], false);
        assert_eq!(value["connect_error"]["reason"], "secret-required");
    }
}
