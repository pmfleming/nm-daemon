use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};

use crate::model::{
    AccessPoint, ConnectEnginePath, ConnectFailureReason, ConnectResult, ConnectivityStatus,
    Ip4Status, MeteredStatus, NetworkEntry, ProfilePrivacy, SavedWifiConnection, WifiSharePayload,
    WifiStatus, WirelessStatus, network_entries_with_profile_matches, security_flags_label,
    security_label,
};
use crate::protocol::{Method, Stream};

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
    let password_network = canonical_network(crate::model::NM_AP_SEC_KEY_MGMT_PSK, false, false);
    let enterprise_network =
        canonical_network(crate::model::NM_AP_SEC_KEY_MGMT_802_1X, false, false);
    json!({
        "protocol-registry": {
            "metadata": crate::protocol::contract_registry(),
            "markdown": crate::protocol::markdown_reference(),
        },
        "wifi-networks.saved": response_fixture(Method::WifiNetworks, json!([combined.network])),
        "wifi-networks.password-required": response_fixture(Method::WifiNetworks, json!([password_network])),
        "wifi-networks.enterprise-required": response_fixture(Method::WifiNetworks, json!([enterprise_network])),
        "wifi-status.active": response_fixture(Method::WifiStatus, json!(combined.status)),
        "wifi-status.inactive": response_fixture(Method::WifiStatus, json!(inactive_status())),
        "wifi-connect.success": response_fixture(Method::WifiConnectTarget, json!(combined.connect_success)),
        "wifi-connect.secret-required": response_fixture(Method::WifiConnectTarget, json!(combined.connect_error)),
        "wifi-scan.stream": {
            "events": scan_stream_events(),
        },
        "wifi-profile.share": {
            "payload": WifiSharePayload::shareable(
                &contract_profile(),
                "WPA",
                Some("correct horse battery staple"),
                false,
            ),
        },
    })
}

fn response_fixture(method: Method, value: Value) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(method.spec().response_key.to_string(), value);
    Value::Object(object)
}

fn shelllist_contract_fixture() -> ShelllistContractFixture {
    let access_point = canonical_access_point(crate::model::NM_AP_SEC_KEY_MGMT_PSK, true);
    let profile = contract_profile();
    let network = network_from_production(access_point.clone(), vec![profile.clone()]);
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
        connect_success: ConnectResult::connected(
            "Example",
            "Connected to Example via D-Bus",
            ConnectEnginePath::Dbus,
            Some(ConnectivityStatus::from_nm_code(4)),
        ),
        connect_error: ConnectResult::failed(
            "Example",
            ConnectFailureReason::SecretRequired,
            "password required for Example",
        ),
    }
}

fn canonical_access_point(rsn_flags: u32, active: bool) -> AccessPoint {
    AccessPoint {
        ssid: "Example".to_string(),
        ssid_bytes: b"Example".to_vec(),
        active,
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

fn canonical_network(rsn_flags: u32, active: bool, with_profile: bool) -> NetworkEntry {
    let access_point = canonical_access_point(rsn_flags, active);
    let profiles = with_profile.then(contract_profile).into_iter().collect();
    network_from_production(access_point, profiles)
}

fn network_from_production(
    access_point: AccessPoint,
    profiles: Vec<SavedWifiConnection>,
) -> NetworkEntry {
    let mut profile_matches = BTreeMap::new();
    if !profiles.is_empty() {
        profile_matches.insert(access_point.path.clone(), profiles);
    }
    network_entries_with_profile_matches(vec![access_point], &profile_matches)
        .pop()
        .expect("canonical access point produces one network")
}

fn inactive_status() -> WifiStatus {
    WifiStatus::inactive(
        Some("wlan0".to_string()),
        Some(ConnectivityStatus::from_nm_code(1)),
    )
}

fn scan_stream_events() -> Vec<Value> {
    let network = canonical_network(crate::model::NM_AP_SEC_KEY_MGMT_PSK, false, false);
    [
        ("status", json!({ "message": "Scanning Wi-Fi networks" })),
        (
            "snapshot",
            json!({ "scanning": true, "networks_found": 1, "networks": [network] }),
        ),
        (
            "complete",
            json!({ "timed_out": false, "networks_found": 1 }),
        ),
    ]
    .into_iter()
    .map(|(event, data)| {
        serde_json::from_str(&crate::daemon_event::event_json(
            Stream::WifiScan,
            Some("scan-contract"),
            event,
            data,
        ))
        .expect("canonical scan event JSON")
    })
    .collect()
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
fn serialized_boundary_snapshot() -> Value {
    let shell = serde_json::to_value(shelllist_contract_fixture()).expect("shell fixture JSON");
    let methods = method_contract_fixtures();
    json!({
        "saved_network": {
            "capabilities": shell["network"]["capabilities"],
            "auth": shell["network"]["auth"],
            "connect_prompt": shell["network"]["connect_prompt"],
            "share": shell["network"]["share"],
        },
        "password_network": {
            "capabilities": methods["wifi-networks.password-required"]["networks"][0]["capabilities"],
            "auth": methods["wifi-networks.password-required"]["networks"][0]["auth"],
            "connect_prompt": methods["wifi-networks.password-required"]["networks"][0]["connect_prompt"],
        },
        "enterprise_network": {
            "capabilities": methods["wifi-networks.enterprise-required"]["networks"][0]["capabilities"],
            "auth": methods["wifi-networks.enterprise-required"]["networks"][0]["auth"],
            "connect_prompt": methods["wifi-networks.enterprise-required"]["networks"][0]["connect_prompt"],
        },
        "status": {
            "connectivity": shell["status"]["connectivity"],
            "metered": shell["status"]["metered"],
            "wireless": shell["status"]["wireless"],
        },
        "connect_success": shell["connect_success"],
        "connect_error": shell["connect_error"],
        "scan_status_event": methods["wifi-scan.stream"]["events"][0],
        "profile_share": methods["wifi-profile.share"]["payload"],
    })
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        method_contract_fixtures, serialized_boundary_snapshot, shelllist_contract_fixture,
    };

    #[test]
    fn serialized_v1_boundary_matches_checked_in_snapshot() {
        let actual = format!(
            "{}\n",
            serde_json::to_string_pretty(&serialized_boundary_snapshot()).unwrap()
        );
        assert_eq!(actual, include_str!("../test_support/contract-v1.json"));
    }

    #[test]
    fn serialized_shelllist_contract_satisfies_boundary_schema() {
        let value = serde_json::to_value(shelllist_contract_fixture()).expect("fixture JSON");
        for pointer in [
            "/network/capabilities/can_connect",
            "/network/capabilities/needs_password",
            "/network/capabilities/needs_credentials",
            "/network/share/requires_profile_secret_check",
            "/network/portal_hint/auto_open_on_connect",
            "/connect_success/suggest_open_portal",
        ] {
            assert!(
                value.pointer(pointer).is_some_and(Value::is_boolean),
                "{pointer}"
            );
        }
        for pointer in [
            "/network/auth/kind",
            "/network/auth/note",
            "/network/connect_prompt/kind",
            "/status/connectivity/state",
            "/status/metered/state",
            "/connect_success/path",
            "/connect_error/reason",
        ] {
            assert!(
                value.pointer(pointer).is_some_and(Value::is_string),
                "{pointer}"
            );
        }
        assert!(
            value
                .pointer("/status/wireless/tx_bitrate_mbps")
                .is_some_and(Value::is_number)
        );
    }

    #[test]
    fn method_contract_fixtures_cover_frontend_api_shapes() {
        let value = method_contract_fixtures();

        assert_eq!(
            value["protocol-registry"]["metadata"]["methods"][0]["name"],
            "wifi.status"
        );
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
