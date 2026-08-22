use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};

use crate::forget::{ForgetProfile, ForgetResult, ForgetStatus};
use crate::model::{
    AccessPoint, ActiveConnectionSummary, ConnectEnginePath, ConnectFailureReason, ConnectPhase,
    ConnectResult, ConnectTargetIdentity, ConnectivityStatus, DeviceStatisticsSample,
    DhcpLeaseStatus, DisconnectResult, HotspotCapabilities, HotspotDevice, HotspotSecurity,
    HotspotShare, HotspotStartResult, HotspotStatus, HotspotStopResult, HotspotUnavailableReason,
    Ip4Status, Ip6Status, IpAddressEntry, IpRouteEntry, LinkStateStatus, MeteredStatus,
    NetworkConnectionSummary, NetworkDeactivateResult, NetworkDeviceSummary, NetworkEntry,
    NetworkInventory, NetworkSnapshotMetadata, NetworkSnapshotSource, NetworkStateSummary,
    ProfileActivationResult, ProfileEnterpriseSettings, ProfileIpSettings, ProfilePrivacy,
    RadioPowerResult, RadioStatus, SavedWifiConnection, SecretFlags, WifiBand,
    WifiBandSelectionResult, WifiBandStatus, WifiPowerResult, WifiProfileDetails,
    WifiProfileSecret, WifiSharePayload, WifiStatus, WirelessStatus, device_state_reason,
    network_entries_with_profile_matches, security_flags_label, security_label,
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
    print_fixture(&shelllist_contract_fixture(), "fixture")
}

pub(crate) fn print_method_contract_fixtures() -> Result<()> {
    print_fixture(&method_contract_fixtures(), "fixtures")
}

fn print_fixture(fixture: &impl Serialize, key: &str) -> Result<()> {
    crate::output::print_api_data(key, fixture, "serialize contract fixture response")
}

fn method_contract_fixtures() -> Value {
    let mut fixtures = serde_json::Map::new();
    for group in [
        registry_fixtures(),
        wifi_method_fixtures(),
        network_method_fixtures(),
        hotspot_method_fixtures(),
    ] {
        if let Value::Object(group) = group {
            fixtures.extend(group);
        }
    }
    Value::Object(fixtures)
}

fn registry_fixtures() -> Value {
    json!({
        "protocol-registry": {
            "metadata": crate::protocol::contract_registry(),
            "markdown": crate::protocol::markdown_reference(),
        },
    })
}

fn wifi_method_fixtures() -> Value {
    let combined = shelllist_contract_fixture();
    let password_network = canonical_network(crate::model::NM_AP_SEC_KEY_MGMT_PSK, false, false);
    let enterprise_network =
        canonical_network(crate::model::NM_AP_SEC_KEY_MGMT_802_1X, false, false);
    json!({
        "wifi-networks.saved": network_response_fixture(vec![combined.network]),
        "wifi-networks.password-required": network_response_fixture(vec![password_network]),
        "wifi-networks.enterprise-required": network_response_fixture(vec![enterprise_network]),
        "wifi-band.status": response_fixture(Method::WifiBandStatus, json!(contract_band_status())),
        "wifi-band.set": response_fixture(Method::WifiBandSet, json!({
            "status": "started",
            "request_id": "band-contract",
            "stream": Stream::WifiBand,
            "message": "Wi-Fi band selection started; listen for Event('wifi.band', event_json) signals",
        })),
        "wifi-band.stream": { "events": operation_stream_events(Stream::WifiBand) },
        "wifi-saved.profiles": response_fixture(Method::WifiSaved, json!([contract_profile()])),
        "wifi-status.active": response_fixture(Method::WifiStatus, json!(combined.status)),
        "wifi-status.inactive": response_fixture(Method::WifiStatus, json!(inactive_status())),
        "wifi-set-enabled.success": response_fixture(Method::WifiSetEnabled, json!(WifiPowerResult {
            enabled: true,
            message: "Wi-Fi turned on".to_string(),
        })),
        "radio-set-wwan-enabled.success": response_fixture(Method::RadioSetWwanEnabled, json!(RadioPowerResult {
            radios: contract_radio_status(),
            message: "Mobile data turned on".to_string(),
        })),
        "radio-set-airplane-mode.success": response_fixture(Method::RadioSetAirplaneMode, json!(RadioPowerResult {
            radios: RadioStatus { airplane_mode: true, wireless_enabled: false, wwan_enabled: false, ..contract_radio_status() },
            message: "Airplane mode enabled".to_string(),
        })),
        "wifi-connect.success": response_fixture(Method::WifiConnectTarget, json!(combined.connect_success)),
        "wifi-connect.secret-required": response_fixture(Method::WifiConnectTarget, json!(combined.connect_error)),
        "wifi-connect.stream": { "events": operation_stream_events(Stream::WifiConnect) },
        "wifi-scan.stream": { "events": scan_stream_events() },
        "wifi-disconnect.success": response_fixture(
            Method::WifiDisconnect,
            json!(DisconnectResult { status: "disconnected", message: "Wi-Fi disconnected".to_string() }),
        ),
        "wifi-profile.details": response_fixture(Method::WifiProfileOperation, json!(contract_profile_details())),
        "wifi-profile.update": response_fixture(Method::WifiProfileOperation, json!({
            "status": "ok",
            "message": "Saved Wi-Fi profile settings updated",
        })),
        "wifi-profile.update-conflict": json!({
            "protocol": crate::output::API_PROTOCOL,
            "version": crate::output::API_VERSION,
            "ok": false,
            "error": {
                "code": crate::error::ErrorCode::Conflict,
                "message": "the saved profile changed since it was read; reload it and retry",
                "details": {
                    "operation": "profile-operation",
                    "source": "validation",
                    "expected_version": "1f0a3c5e7b9d2468",
                    "current_version": "a7c1de904b2f3355",
                },
            },
            "data": {},
        }),
        "wifi-profile.reveal-secret": response_fixture(Method::WifiProfileOperation, json!(contract_profile_secret())),
        "wifi-profile.forget": response_fixture(Method::WifiProfileOperation, forget_result_fixture()),
        "wifi-profile.share": response_fixture(
            Method::WifiProfileOperation,
            json!(WifiSharePayload::shareable(
                &contract_profile(),
                "WPA",
                Some("correct horse battery staple"),
                false,
            )),
        ),
        "wifi-secret.capabilities": response_fixture(Method::WifiSecretCapabilities, secret_capabilities_fixture()),
        "wifi-secret.provide": response_fixture(Method::WifiSecretProvide, json!({
            "status": "accepted",
            "request_id": "secret-contract",
            "accepted": true,
            "save_requested": true,
            "persistence_status": "pending",
            "message": "Secret provided to pending NetworkManager request; the wifi.secret stream reports the persistence outcome",
        })),
        "wifi-secret.stream": { "events": operation_stream_events(Stream::WifiSecret) },
        "continuous.streams": { "events": continuous_stream_events() },
    })
}

fn network_method_fixtures() -> Value {
    json!({
        "network-connectivity.full": response_fixture(Method::NetworkConnectivity, json!(ConnectivityStatus::from_nm_code(4))),
        "network-inventory.snapshot": response_fixture(Method::NetworkInventory, json!(contract_inventory())),
        "network-devices.list": response_fixture(Method::NetworkDevices, json!(contract_devices())),
        "network-connections.list": response_fixture(Method::NetworkConnections, json!(contract_connections())),
        "network-status.connected": response_fixture(Method::NetworkState, json!(contract_network_state())),
        "network-activate-profile.started": response_fixture(Method::NetworkActivateProfile, json!(contract_activation_result())),
        "network-deactivate.success": response_fixture(Method::NetworkDeactivate, json!(contract_deactivate_result())),
        "network-statistics.watch": response_fixture(Method::NetworkStatisticsWatch, json!({
            "status": "started",
            "request_id": "stats-contract",
            "stream": Stream::NetworkStatistics,
            "device_path": "/org/freedesktop/NetworkManager/Devices/1",
            "device_iface": "wlan0",
            "interval_ms": 1_000,
            "message": "Device statistics watch started; listen for Event('network.statistics', event_json) signals",
        })),
        "network-statistics.stream": { "events": statistics_stream_events() },
    })
}

fn hotspot_method_fixtures() -> Value {
    json!({
        "hotspot.capabilities": response_fixture(Method::HotspotCapabilities, json!(contract_hotspot_capabilities())),
        "hotspot.capabilities-unsupported": response_fixture(Method::HotspotCapabilities, json!(HotspotCapabilities {
            supported: false,
            unsupported_reason: Some(HotspotUnavailableReason::ApModeUnsupported),
            message: "No Wi-Fi device advertises access-point mode".to_string(),
            recommended_device: None,
            devices: vec![HotspotDevice { ap_capable: false, ..contract_hotspot_device() }],
            supported_security: vec![HotspotSecurity::WpaPsk, HotspotSecurity::Sae],
            supported_bands: vec![WifiBand::Auto, WifiBand::Ghz2_4, WifiBand::Ghz5],
        })),
        "hotspot.status-active": response_fixture(Method::HotspotStatus, json!(contract_hotspot_status())),
        "hotspot.status-inactive": response_fixture(Method::HotspotStatus, json!(HotspotStatus {
            active: false,
            device_path: None,
            device_iface: None,
            ssid: None,
            ssid_hex: None,
            band: None,
            channel: None,
            security: None,
            hidden: false,
            profile_path: None,
            active_connection: None,
            state: None,
            state_name: None,
            share: None,
        })),
        "hotspot.start": response_fixture(Method::HotspotStart, json!({
            "status": "started",
            "request_id": "hotspot-contract",
            "stream": Stream::Hotspot,
            "message": "Hotspot start requested; listen for Event('hotspot', event_json) signals",
        })),
        "hotspot.stop": response_fixture(Method::HotspotStop, json!(HotspotStopResult {
            status: "stopped",
            message: "Hotspot laufan-hotspot stopped".to_string(),
            ssid: Some("laufan-hotspot".to_string()),
            device_iface: Some("wlan0".to_string()),
        })),
        "hotspot.stream": { "events": hotspot_stream_events() },
    })
}

fn response_fixture(method: Method, value: Value) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(method.spec().response_key.to_string(), value);
    Value::Object(object)
}

fn network_response_fixture(networks: Vec<NetworkEntry>) -> Value {
    json!({
        "networks": networks,
        "snapshot": contract_snapshot_metadata(),
    })
}

fn contract_snapshot_metadata() -> NetworkSnapshotMetadata {
    NetworkSnapshotMetadata {
        source: NetworkSnapshotSource::Cache,
        updated_at_ms: 1_762_000_000_000,
        age_ms: 2_500,
        stale: false,
        scanning: false,
        refresh_requested: true,
    }
}

fn shelllist_contract_fixture() -> ShelllistContractFixture {
    let access_point = canonical_access_point(crate::model::NM_AP_SEC_KEY_MGMT_PSK, true);
    let profile = contract_profile();
    let network = network_from_production(access_point.clone(), vec![profile.clone()]);
    ShelllistContractFixture {
        network: network.clone(),
        status: WifiStatus {
            enabled: true,
            radios: contract_radio_status(),
            active: true,
            device_iface: Some("wlan0".to_string()),
            device_path: Some("/org/freedesktop/NetworkManager/Devices/1".to_string()),
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
                addresses: vec![
                    IpAddressEntry {
                        address: "192.0.2.10".to_string(),
                        prefix: 24,
                    },
                    IpAddressEntry {
                        address: "192.0.2.11".to_string(),
                        prefix: 24,
                    },
                ],
                gateway: Some("192.0.2.1".to_string()),
                dns: vec!["192.0.2.1".to_string(), "1.1.1.1".to_string()],
                domains: vec!["example.test".to_string()],
                searches: vec!["example.test".to_string()],
                routes: vec![IpRouteEntry {
                    dest: "0.0.0.0".to_string(),
                    prefix: 0,
                    next_hop: Some("192.0.2.1".to_string()),
                    metric: Some(600),
                }],
                dhcp_lease: Some(DhcpLeaseStatus {
                    server_identifier: Some("192.0.2.1".to_string()),
                    domain_name: Some("example.test".to_string()),
                    lease_time_seconds: Some(86_400),
                    expires_at_ms: Some(1_762_086_400_000),
                }),
            }),
            ip6: Some(Ip6Status {
                address: Some("2001:db8::10".to_string()),
                prefix: Some(64),
                addresses: vec![IpAddressEntry {
                    address: "2001:db8::10".to_string(),
                    prefix: 64,
                }],
                gateway: Some("fe80::1".to_string()),
                dns: vec!["2001:db8::1".to_string()],
                domains: vec!["example.test".to_string()],
                searches: Vec::new(),
                routes: vec![IpRouteEntry {
                    dest: "::".to_string(),
                    prefix: 0,
                    next_hop: Some("fe80::1".to_string()),
                    metric: Some(1024),
                }],
                dhcp_lease: Some(DhcpLeaseStatus {
                    server_identifier: None,
                    domain_name: Some("example.test".to_string()),
                    lease_time_seconds: Some(3_600),
                    expires_at_ms: Some(1_762_003_600_000),
                }),
            }),
            wireless: Some(WirelessStatus {
                bitrate_mbps: Some(144),
                tx_bitrate_mbps: Some(130.0),
                rx_bitrate_mbps: Some(144.4),
                mac_address: Some("02:00:00:00:00:01".to_string()),
            }),
            metered: Some(MeteredStatus::from_nm_code(4)),
            active_since_ms: Some(1_762_000_000_000),
            link: Some(LinkStateStatus {
                device_state: 100,
                device_state_name: "activated",
                device_state_reason: device_state_reason(0),
                active_connection_state: Some(2),
                active_connection_state_name: Some("activated"),
                active_connection_state_flags: Some(92),
                primary: true,
                default4: true,
                default6: false,
            }),
        },
        connect_success: connected_fixture(),
        connect_error: connect_error_fixture(),
    }
}

fn contract_connect_identity() -> ConnectTargetIdentity {
    ConnectTargetIdentity {
        network_key: Some(
            "ssid-hex:4578616d706c65|security:personal|ifname:776c616e30".to_string(),
        ),
        ssid: "Example".to_string(),
        ssid_bytes: b"Example".to_vec(),
        ssid_hex: "4578616d706c65".to_string(),
        device_iface: Some("wlan0".to_string()),
        device_path: Some("/org/freedesktop/NetworkManager/Devices/1".to_string()),
        access_point_path: Some("/org/freedesktop/NetworkManager/AccessPoint/1".to_string()),
        bssid: Some("00:11:22:33:44:55".to_string()),
    }
}

fn connected_fixture() -> ConnectResult {
    ConnectResult::connected(
        "Example",
        "Connected to Example via D-Bus",
        ConnectEnginePath::Dbus,
        Some(ConnectivityStatus::from_nm_code(4)),
    )
}

fn connect_error_fixture() -> ConnectResult {
    ConnectResult::failed(
        "Example",
        ConnectFailureReason::SecretRequired,
        "password required for Example",
    )
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

fn contract_hotspot_device() -> HotspotDevice {
    HotspotDevice {
        path: "/org/freedesktop/NetworkManager/Devices/1".to_string(),
        interface: "wlan0".to_string(),
        ap_capable: true,
        in_use: false,
        state: 30,
        state_name: "disconnected",
        mode: "infrastructure",
        bands: vec![WifiBand::Ghz2_4, WifiBand::Ghz5],
    }
}

fn contract_hotspot_capabilities() -> HotspotCapabilities {
    HotspotCapabilities {
        supported: true,
        unsupported_reason: None,
        message: "A Wi-Fi hotspot can be started".to_string(),
        recommended_device: Some("/org/freedesktop/NetworkManager/Devices/1".to_string()),
        devices: vec![contract_hotspot_device()],
        supported_security: vec![HotspotSecurity::WpaPsk, HotspotSecurity::Sae],
        supported_bands: vec![WifiBand::Auto, WifiBand::Ghz2_4, WifiBand::Ghz5],
    }
}

fn contract_hotspot_status() -> HotspotStatus {
    HotspotStatus {
        active: true,
        device_path: Some("/org/freedesktop/NetworkManager/Devices/1".to_string()),
        device_iface: Some("wlan0".to_string()),
        ssid: Some("laufan-hotspot".to_string()),
        ssid_hex: Some(crate::model::ssid_hex(b"laufan-hotspot")),
        band: Some(WifiBand::Ghz5),
        channel: Some(36),
        security: Some(HotspotSecurity::WpaPsk),
        hidden: false,
        profile_path: Some("/org/freedesktop/NetworkManager/Settings/3".to_string()),
        active_connection: Some("/org/freedesktop/NetworkManager/ActiveConnection/3".to_string()),
        state: Some(2),
        state_name: Some("activated"),
        share: None,
    }
}

fn contract_hotspot_start_result() -> HotspotStartResult {
    let passphrase = "kq7mreb2xa4t";
    HotspotStartResult {
        status: "started",
        message: "Hotspot laufan-hotspot is running".to_string(),
        generated_passphrase: true,
        generated_ssid: true,
        passphrase: passphrase.to_string(),
        hotspot: HotspotStatus {
            share: Some(HotspotShare {
                ssid: "laufan-hotspot".to_string(),
                auth_type: HotspotSecurity::WpaPsk.qr_auth_type(),
                hidden: false,
                qr_payload: crate::model::wifi_qr_payload(
                    HotspotSecurity::WpaPsk.qr_auth_type(),
                    "laufan-hotspot",
                    Some(passphrase),
                    false,
                ),
            }),
            ..contract_hotspot_status()
        },
    }
}

fn hotspot_stream_events() -> Vec<Value> {
    stream_events(
        Stream::Hotspot,
        "hotspot-contract",
        vec![
            subscribed_event("hotspot-subscription"),
            (
                "started",
                json!({ "request_id": "hotspot-contract", "phase": "preparing" }),
            ),
            (
                "progress",
                json!({ "request_id": "hotspot-contract", "phase": "activating" }),
            ),
            (
                "succeeded",
                json!({
                    "request_id": "hotspot-contract",
                    "phase": "complete",
                    "result": contract_hotspot_start_result(),
                }),
            ),
            (
                "failed",
                json!({
                    "request_id": "hotspot-contract",
                    "phase": "failed",
                    "code": crate::error::ErrorCode::ValidationError,
                    "message": "No Wi-Fi device advertises access-point mode",
                    "details": {
                        "operation": "hotspot-operation",
                        "source": "validation",
                        "unsupported_reason": "ap-mode-unsupported",
                    },
                }),
            ),
            (
                "cancelled",
                json!({
                    "request_id": "hotspot-contract",
                    "phase": "cancelled",
                    "message": "Hotspot start was cancelled",
                }),
            ),
        ],
    )
}

fn statistics_stream_events() -> Vec<Value> {
    let device = json!({
        "request_id": "stats-contract",
        "device_path": "/org/freedesktop/NetworkManager/Devices/1",
        "device_iface": "wlan0",
    });
    let with = |extra: Value| {
        let mut event = device.clone();
        if let (Some(event), Some(extra)) = (event.as_object_mut(), extra.as_object()) {
            event.extend(extra.clone());
        }
        event
    };
    stream_events(
        Stream::NetworkStatistics,
        "stats-contract",
        vec![
            subscribed_event("statistics-subscription"),
            ("started", with(json!({ "interval_ms": 1_000 }))),
            (
                "sample",
                with(json!({
                    "statistics": DeviceStatisticsSample {
                        rx_bytes: 4_294_967_296,
                        tx_bytes: 1_073_741_824,
                        rx_bytes_per_second: Some(125_000.0),
                        tx_bytes_per_second: Some(64_000.0),
                        interval_ms: 1_000,
                        sampled_at_ms: 1_762_000_000_000,
                    },
                })),
            ),
            (
                "failed",
                with(json!({
                    "code": crate::error::ErrorCode::NetworkmanagerUnavailable,
                    "message": "read RxBytes for /org/freedesktop/NetworkManager/Devices/1",
                    "details": { "operation": "statistics", "source": "dbus" },
                })),
            ),
            (
                "cancelled",
                with(json!({ "message": "Device statistics watch stopped" })),
            ),
        ],
    )
}

fn contract_devices() -> Vec<NetworkDeviceSummary> {
    vec![
        NetworkDeviceSummary {
            path: "/org/freedesktop/NetworkManager/Devices/1".to_string(),
            interface: "wlan0".to_string(),
            ip_interface: Some("wlan0".to_string()),
            device_type: 2,
            type_name: "wifi",
            state: 100,
            state_name: "activated",
            state_reason: device_state_reason(0),
            managed: true,
            autoconnect: true,
            driver: Some("iwlwifi".to_string()),
            firmware_version: Some("77.a20a2p1".to_string()),
            hw_address: Some("02:00:00:00:00:01".to_string()),
            mtu: Some(1500),
            carrier: None,
            speed_mbps: None,
            active_connection: Some(
                "/org/freedesktop/NetworkManager/ActiveConnection/1".to_string(),
            ),
            available_connections: vec!["/org/freedesktop/NetworkManager/Settings/1".to_string()],
        },
        NetworkDeviceSummary {
            path: "/org/freedesktop/NetworkManager/Devices/2".to_string(),
            interface: "enp3s0".to_string(),
            ip_interface: Some("enp3s0".to_string()),
            device_type: 1,
            type_name: "ethernet",
            state: 20,
            state_name: "unavailable",
            state_reason: device_state_reason(40),
            managed: true,
            autoconnect: true,
            driver: Some("r8169".to_string()),
            firmware_version: None,
            hw_address: Some("02:00:00:00:00:02".to_string()),
            mtu: Some(1500),
            carrier: Some(false),
            speed_mbps: None,
            active_connection: None,
            available_connections: Vec::new(),
        },
    ]
}

fn contract_connections() -> Vec<NetworkConnectionSummary> {
    vec![
        NetworkConnectionSummary {
            path: "/org/freedesktop/NetworkManager/Settings/1".to_string(),
            id: "Example".to_string(),
            uuid: "6f4a1a0c-1f4b-4f2c-9a1e-0f9a4c2d5e11".to_string(),
            connection_type: "802-11-wireless".to_string(),
            type_name: "wifi",
            autoconnect: true,
            autoconnect_priority: 10,
            timestamp_ms: Some(1_762_000_000_000),
            interface_name: None,
            permissions: Vec::new(),
            available_devices: vec!["/org/freedesktop/NetworkManager/Devices/1".to_string()],
            active_connection: Some(
                "/org/freedesktop/NetworkManager/ActiveConnection/1".to_string(),
            ),
        },
        NetworkConnectionSummary {
            path: "/org/freedesktop/NetworkManager/Settings/2".to_string(),
            id: "Work VPN".to_string(),
            uuid: "0a1c9c6e-3d21-4a55-8c2b-1e5b9d6f7a22".to_string(),
            connection_type: "vpn".to_string(),
            type_name: "vpn",
            autoconnect: false,
            autoconnect_priority: 0,
            timestamp_ms: None,
            interface_name: None,
            permissions: vec!["user:laufan:".to_string()],
            available_devices: Vec::new(),
            active_connection: None,
        },
    ]
}

fn contract_active_connections() -> Vec<ActiveConnectionSummary> {
    vec![ActiveConnectionSummary {
        path: "/org/freedesktop/NetworkManager/ActiveConnection/1".to_string(),
        id: "Example".to_string(),
        uuid: "6f4a1a0c-1f4b-4f2c-9a1e-0f9a4c2d5e11".to_string(),
        connection_type: "802-11-wireless".to_string(),
        state: 2,
        state_name: "activated",
        state_flags: 92,
        vpn: false,
        default4: true,
        default6: false,
        profile_path: Some("/org/freedesktop/NetworkManager/Settings/1".to_string()),
        specific_object: Some("/org/freedesktop/NetworkManager/AccessPoint/1".to_string()),
        devices: vec!["/org/freedesktop/NetworkManager/Devices/1".to_string()],
    }]
}

fn contract_inventory() -> NetworkInventory {
    NetworkInventory {
        networking_enabled: true,
        primary_connection: Some("/org/freedesktop/NetworkManager/ActiveConnection/1".to_string()),
        activating_connection: None,
        devices: contract_devices(),
        connections: contract_connections(),
        active_connections: contract_active_connections(),
    }
}

fn contract_network_state() -> NetworkStateSummary {
    let primary = contract_active_connections().pop();
    NetworkStateSummary {
        state: 70,
        state_name: "connected-global",
        networking_enabled: true,
        radios: contract_radio_status(),
        connectivity: ConnectivityStatus::from_nm_code(4),
        connectivity_check_uri: Some("http://networkcheck.example/nm-check.txt".to_string()),
        connectivity_check_enabled: true,
        primary_connection_type: Some("802-11-wireless".to_string()),
        primary_connection: primary,
        activating_connection: None,
        default4: Some("/org/freedesktop/NetworkManager/ActiveConnection/1".to_string()),
        default6: None,
    }
}

fn contract_activation_result() -> ProfileActivationResult {
    ProfileActivationResult {
        status: "activating",
        profile_path: "/org/freedesktop/NetworkManager/Settings/2".to_string(),
        id: "Work VPN".to_string(),
        uuid: "0a1c9c6e-3d21-4a55-8c2b-1e5b9d6f7a22".to_string(),
        connection_type: "vpn".to_string(),
        type_name: "vpn",
        active_connection: Some("/org/freedesktop/NetworkManager/ActiveConnection/2".to_string()),
        device: Some("/org/freedesktop/NetworkManager/Devices/1".to_string()),
        state: 1,
        state_name: "activating",
        message: "Activating saved profile Work VPN".to_string(),
    }
}

fn contract_deactivate_result() -> NetworkDeactivateResult {
    NetworkDeactivateResult {
        status: "deactivated",
        path: "/org/freedesktop/NetworkManager/ActiveConnection/2".to_string(),
        id: "Work VPN".to_string(),
        uuid: "0a1c9c6e-3d21-4a55-8c2b-1e5b9d6f7a22".to_string(),
        connection_type: "vpn".to_string(),
        message: "Deactivated Work VPN".to_string(),
    }
}

fn contract_radio_status() -> RadioStatus {
    RadioStatus {
        wireless_enabled: true,
        wireless_hardware_enabled: true,
        wireless_available: true,
        wwan_enabled: true,
        wwan_hardware_enabled: true,
        wwan_available: true,
        airplane_mode: false,
    }
}

fn inactive_status() -> WifiStatus {
    WifiStatus::inactive(
        false,
        RadioStatus {
            wireless_enabled: false,
            ..contract_radio_status()
        },
        Some("wlan0".to_string()),
        Some(ConnectivityStatus::from_nm_code(1)),
    )
}

fn scan_stream_events() -> Vec<Value> {
    let network = canonical_network(crate::model::NM_AP_SEC_KEY_MGMT_PSK, false, false);
    stream_events(
        Stream::WifiScan,
        "scan-contract",
        vec![
            subscribed_event("subscription-contract"),
            ("status", json!({ "message": "Scanning Wi-Fi networks" })),
            (
                "warning",
                json!({ "code": "timeout", "message": "Scan timed out", "details": {} }),
            ),
            (
                "snapshot",
                json!({
                    "scanning": false,
                    "networks_found": 1,
                    "networks": [network],
                    "snapshot": NetworkSnapshotMetadata {
                        source: NetworkSnapshotSource::Scan,
                        updated_at_ms: 1_762_000_002_500,
                        age_ms: 0,
                        stale: false,
                        scanning: false,
                        refresh_requested: false,
                    },
                }),
            ),
            (
                "complete",
                json!({ "timed_out": false, "networks_found": 1 }),
            ),
            ("cancelled", json!({ "message": "Wi-Fi scan cancelled" })),
            (
                "failed",
                json!({ "code": "internal-error", "message": "Scan failed", "details": {} }),
            ),
        ],
    )
}

fn operation_stream_events(stream: Stream) -> Vec<Value> {
    let (request_id, events) = match stream {
        Stream::WifiConnect => (
            "connect-contract",
            vec![
                subscribed_event("subscription-contract"),
                (
                    "started",
                    json!({
                        "phase": ConnectPhase::Starting,
                        "target": contract_connect_identity(),
                        "message": "starting Wi-Fi connection",
                    }),
                ),
                (
                    "progress",
                    json!({
                        "phase": ConnectPhase::ActivatingSavedProfile,
                        "target": contract_connect_identity(),
                        "message": "activating saved NetworkManager profile",
                    }),
                ),
                (
                    "succeeded",
                    json!({
                        "phase": ConnectPhase::Connected,
                        "target": contract_connect_identity(),
                        "result": connected_fixture(),
                    }),
                ),
                (
                    "failed",
                    json!({
                        "phase": ConnectPhase::Failed,
                        "target": contract_connect_identity(),
                        "result": connect_error_fixture(),
                        "reason": "secret-required",
                        "code": "secret-required",
                        "message": "password required for Example",
                        "details": {},
                    }),
                ),
                (
                    "cancelled",
                    json!({
                        "phase": ConnectPhase::Cancelled,
                        "target": contract_connect_identity(),
                        "message": "connection attempt was cancelled",
                    }),
                ),
            ],
        ),
        Stream::WifiBand => (
            "band-contract",
            vec![
                subscribed_event("subscription-contract"),
                (
                    "started",
                    json!({
                        "phase": "preparing",
                        "path": contract_profile().path,
                        "requested_band": WifiBand::Ghz5,
                    }),
                ),
                (
                    "progress",
                    json!({
                        "phase": "applying",
                        "path": contract_profile().path,
                        "requested_band": WifiBand::Ghz5,
                    }),
                ),
                (
                    "succeeded",
                    json!({
                        "phase": "complete",
                        "path": contract_profile().path,
                        "requested_band": WifiBand::Ghz5,
                        "result": WifiBandSelectionResult {
                            status: "selected",
                            changed: true,
                            band: contract_band_status(),
                            message: "Wi-Fi band selection updated for Example".to_string(),
                        },
                    }),
                ),
                (
                    "failed",
                    json!({
                        "phase": "failed",
                        "path": contract_profile().path,
                        "requested_band": WifiBand::Ghz5,
                        "code": "activation-failed",
                        "message": "Wi-Fi band selection failed",
                        "details": {},
                    }),
                ),
                (
                    "cancelled",
                    json!({
                        "phase": "cancelled",
                        "path": contract_profile().path,
                        "requested_band": WifiBand::Ghz5,
                        "message": "Wi-Fi band selection was cancelled",
                    }),
                ),
            ],
        ),
        Stream::WifiSecret => (
            "secret-contract",
            vec![
                subscribed_event("subscription-contract"),
                (
                    "requested",
                    json!({
                        "connection_path": "/org/freedesktop/NetworkManager/Settings/1",
                        "setting_name": "802-1x",
                        "hints": ["password", "private-key-password"],
                        "secret_keys": ["password", "private-key-password"],
                        "primary_secret_key": "password",
                        "flags": 0,
                        "save_supported": true,
                        "timeout_ms": 120000,
                    }),
                ),
                ("cancelled", json!({})),
                ("persistence", json!({ "status": "stored" })),
                (
                    "persistence",
                    json!({ "status": "prompt_unsupported", "operation": "create", "prompt": "/org/freedesktop/secrets/prompt/1" }),
                ),
                (
                    "persistence",
                    json!({ "status": "failed", "error": "keyring unavailable" }),
                ),
            ],
        ),
        _ => return Vec::new(),
    };
    stream_events(stream, request_id, events)
}

fn subscribed_event(subscription_id: &str) -> (&'static str, Value) {
    ("subscribed", json!({ "subscription_id": subscription_id }))
}

fn continuous_stream_events() -> Vec<Value> {
    let mut events = stream_events(
        Stream::WifiStatus,
        "status-contract",
        vec![
            subscribed_event("status-subscription"),
            ("changed", json!({ "status": inactive_status() })),
        ],
    );
    events.extend(stream_events(
        Stream::NetworkConnectivity,
        "connectivity-contract",
        vec![
            subscribed_event("connectivity-subscription"),
            (
                "changed",
                json!({ "connectivity": ConnectivityStatus::from_nm_code(4) }),
            ),
        ],
    ));
    events.extend(stream_events(
        Stream::NetworkInventory,
        "inventory-contract",
        vec![
            subscribed_event("inventory-subscription"),
            ("changed", json!({ "inventory": contract_inventory() })),
        ],
    ));
    events.extend(stream_events(
        Stream::WifiNetworks,
        "networks-contract",
        vec![
            subscribed_event("networks-subscription"),
            (
                "changed",
                json!({
                    "subscription_id": "networks-subscription",
                    "initial": true,
                    "added": [canonical_network(crate::model::NM_AP_SEC_KEY_MGMT_PSK, false, false)],
                    "removed": [],
                    "changed": [],
                    "snapshot": NetworkSnapshotMetadata {
                        source: NetworkSnapshotSource::NetworkManager,
                        updated_at_ms: 1_762_000_000_000,
                        age_ms: 0,
                        stale: false,
                        scanning: false,
                        refresh_requested: false,
                    },
                }),
            ),
        ],
    ));
    events
}

fn stream_events(stream: Stream, request_id: &str, events: Vec<(&str, Value)>) -> Vec<Value> {
    events
        .into_iter()
        .map(|(event, data)| {
            crate::daemon_event::event_value(stream, Some(request_id), event, data)
        })
        .collect()
}

fn contract_band_status() -> WifiBandStatus {
    WifiBandStatus {
        path: "/org/freedesktop/NetworkManager/Settings/1".to_string(),
        id: "Example".to_string(),
        ssid: "Example".to_string(),
        device_iface: "wlan0".to_string(),
        current: WifiBand::Ghz5,
        selected: WifiBand::Ghz5,
        available: vec![WifiBand::Ghz2_4, WifiBand::Ghz5, WifiBand::Ghz6],
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

fn contract_profile_details() -> WifiProfileDetails {
    WifiProfileDetails {
        path: "/org/freedesktop/NetworkManager/Settings/1".to_string(),
        id: "Example".to_string(),
        uuid: "6f4a1a0c-1f4b-4f2c-9a1e-0f9a4c2d5e11".to_string(),
        ssid: "Example".to_string(),
        version: "1f0a3c5e7b9d2468".to_string(),
        autoconnect: true,
        autoconnect_priority: 10,
        metered: "auto".to_string(),
        hidden: false,
        mac_address_policy: "stable".to_string(),
        cloned_mac_address: None,
        mac_address: Some("02:00:00:00:00:01".to_string()),
        bssid: Some("00:11:22:33:44:55".to_string()),
        mtu: Some(1500),
        mode: "infrastructure".to_string(),
        band: WifiBand::Ghz5,
        channel: Some(36),
        send_hostname: false,
        permissions: vec!["user:laufan:".to_string()],
        firewall_zone: Some("home".to_string()),
        secondaries: vec!["0a1c9c6e-3d21-4a55-8c2b-1e5b9d6f7a22".to_string()],
        security_type: "WPA Enterprise".to_string(),
        enterprise: Some(ProfileEnterpriseSettings {
            eap: vec!["peap".to_string()],
            identity: Some("laufan".to_string()),
            anonymous_identity: Some("anonymous@example.test".to_string()),
            domain_suffix_match: Some("example.test".to_string()),
            ca_cert: Some("file:///etc/ssl/certs/example-ca.pem".to_string()),
            system_ca_certs: false,
            phase2_auth: Some("mschapv2".to_string()),
            password_flags: SecretFlags::from_code(1),
            private_key_password_flags: SecretFlags::from_code(0),
            ..Default::default()
        }),
        ipv4: ProfileIpSettings {
            method: "auto".to_string(),
            dns: vec!["1.1.1.1".to_string()],
            may_fail: true,
            dhcp_client_id: Some("mac".to_string()),
            dhcp_hostname: Some("laufan".to_string()),
            dad_timeout: Some(-1),
            ..Default::default()
        },
        ipv6: ProfileIpSettings {
            method: "auto".to_string(),
            may_fail: true,
            ip6_privacy: Some(2),
            ..Default::default()
        },
    }
}

fn contract_profile_secret() -> WifiProfileSecret {
    WifiProfileSecret {
        path: "/org/freedesktop/NetworkManager/Settings/1".to_string(),
        available: true,
        kind: "enterprise".to_string(),
        setting_name: Some("802-1x".to_string()),
        secret_keys: vec![
            "password".to_string(),
            "private-key-password".to_string(),
            "pin".to_string(),
        ],
        primary_secret_key: Some("password".to_string()),
        values: BTreeMap::from([
            ("password".to_string(), "enterprise-password".to_string()),
            (
                "private-key-password".to_string(),
                "private-key-secret".to_string(),
            ),
        ]),
        password: Some("enterprise-password".to_string()),
    }
}

fn forget_result_fixture() -> Value {
    json!(ForgetResult {
        operation: "forget",
        status: ForgetStatus::Forgotten,
        request_id: "forget-contract".to_string(),
        ssid: "Example".to_string(),
        message: "Disconnected and forgot 1 saved profile for Example".to_string(),
        was_active: true,
        disconnected: true,
        profiles_found: 1,
        deleted_profiles: vec![ForgetProfile {
            id: "Example".to_string(),
            path: "/org/freedesktop/NetworkManager/Settings/1".to_string(),
        }],
        failed_profiles: Vec::new(),
        cancelled_connect_requests: vec!["connect-contract".to_string()],
        pending_connect_requests: Vec::new(),
        warnings: Vec::new(),
        portal_session_reset: false,
        portal_note: "The hotspot may continue to recognize this device until its captive-portal session expires.",
    })
}

fn secret_capabilities_fixture() -> Value {
    json!({
        "registered": true,
        "agent_path": "/org/laufan/NmDaemon/SecretAgent",
        "keyring": {
            "available": true,
            "persistence_supported": true,
            "default_save": false,
            "prompt_handling": "unsupported",
            "prompt_policy": "dismiss_and_report",
        },
        "events": {
            "stream": Stream::WifiSecret,
            "implemented": true,
            "persistence_outcomes": true,
        },
        "message": "SecretAgent is registered when NetworkManager is available; save:true persists only when the user's Secret Service keyring can complete without a desktop prompt",
    })
}

#[cfg(test)]
fn serialized_boundary_snapshot() -> Value {
    let shell = serde_json::to_value(shelllist_contract_fixture()).expect("shell fixture JSON");
    let methods = method_contract_fixtures();
    json!({
        "network_snapshot": methods["wifi-networks.saved"]["snapshot"],
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
            "enabled": shell["status"]["enabled"],
            "radios": shell["status"]["radios"],
            "connectivity": shell["status"]["connectivity"],
            "metered": shell["status"]["metered"],
            "wireless": shell["status"]["wireless"],
        },
        "connect_success": shell["connect_success"],
        "connect_error": shell["connect_error"],
        "connect_stream": methods["wifi-connect.stream"],
        "scan_stream": methods["wifi-scan.stream"],
        "saved_profiles": methods["wifi-saved.profiles"],
        "band_status": methods["wifi-band.status"],
        "band_set": methods["wifi-band.set"],
        "band_stream": methods["wifi-band.stream"],
        "disconnect": methods["wifi-disconnect.success"],
        "set_enabled": methods["wifi-set-enabled.success"],
        "set_wwan_enabled": methods["radio-set-wwan-enabled.success"],
        "set_airplane_mode": methods["radio-set-airplane-mode.success"],
        "profile_details": methods["wifi-profile.details"],
        "profile_update": methods["wifi-profile.update"],
        "profile_secret": methods["wifi-profile.reveal-secret"],
        "profile_forget": methods["wifi-profile.forget"],
        "profile_share": methods["wifi-profile.share"],
        "secret_capabilities": methods["wifi-secret.capabilities"],
        "secret_provide": methods["wifi-secret.provide"],
        "secret_stream": methods["wifi-secret.stream"],
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
        if std::env::var_os("NM_DAEMON_UPDATE_CONTRACT_FIXTURE").is_some() {
            std::fs::write("test_support/contract-v1.json", &actual)
                .expect("update checked-in contract fixture");
            return;
        }
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
            "/status/enabled",
            "/status/radios/wireless_hardware_enabled",
            "/status/radios/wwan_enabled",
            "/status/radios/airplane_mode",
            "/connect_success/suggest_open_portal",
        ] {
            assert!(
                value.pointer(pointer).is_some_and(Value::is_boolean),
                "{pointer}"
            );
        }
        for pointer in [
            "/network/security_class",
            "/network/auth/kind",
            "/network/auth/note",
            "/network/connect_prompt/kind",
            "/status/connectivity/state",
            "/status/ip4/dhcp_lease/server_identifier",
            "/status/ip4/dhcp_lease/domain_name",
            "/status/metered/state",
            "/connect_success/path",
            "/connect_error/reason",
        ] {
            assert!(
                value.pointer(pointer).is_some_and(Value::is_string),
                "{pointer}"
            );
        }
        for pointer in [
            "/status/ip4/dhcp_lease/lease_time_seconds",
            "/status/ip4/dhcp_lease/expires_at_ms",
            "/status/wireless/tx_bitrate_mbps",
        ] {
            assert!(
                value.pointer(pointer).is_some_and(Value::is_number),
                "{pointer}"
            );
        }
    }

    #[test]
    fn method_contract_fixtures_cover_frontend_api_shapes() {
        let value = method_contract_fixtures();

        assert_eq!(
            value["protocol-registry"]["metadata"]["methods"][0]["name"],
            "wifi.status"
        );
        let covered_methods = std::collections::HashSet::from([
            crate::protocol::Method::WifiStatus,
            crate::protocol::Method::WifiSetEnabled,
            crate::protocol::Method::RadioSetWwanEnabled,
            crate::protocol::Method::RadioSetAirplaneMode,
            crate::protocol::Method::NetworkConnectivity,
            crate::protocol::Method::NetworkInventory,
            crate::protocol::Method::NetworkDevices,
            crate::protocol::Method::NetworkConnections,
            crate::protocol::Method::NetworkState,
            crate::protocol::Method::NetworkActivateProfile,
            crate::protocol::Method::NetworkDeactivate,
            crate::protocol::Method::NetworkStatisticsWatch,
            crate::protocol::Method::HotspotCapabilities,
            crate::protocol::Method::HotspotStatus,
            crate::protocol::Method::HotspotStart,
            crate::protocol::Method::HotspotStop,
            crate::protocol::Method::WifiNetworks,
            crate::protocol::Method::WifiBandStatus,
            crate::protocol::Method::WifiBandSet,
            crate::protocol::Method::WifiSaved,
            crate::protocol::Method::WifiScan,
            crate::protocol::Method::WifiConnectTarget,
            crate::protocol::Method::WifiDisconnect,
            crate::protocol::Method::WifiProfileOperation,
            crate::protocol::Method::WifiSecretCapabilities,
            crate::protocol::Method::WifiSecretProvide,
        ]);
        let registered_methods = crate::protocol::METHOD_REGISTRY
            .iter()
            .map(|spec| spec.method)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(covered_methods, registered_methods);
        assert!(value["wifi-networks.saved"]["networks"].is_array());
        assert_eq!(value["wifi-networks.saved"]["snapshot"]["source"], "cache");
        assert_eq!(
            value["wifi-networks.saved"]["snapshot"]["refresh_requested"],
            true
        );
        assert_eq!(
            value["wifi-networks.saved"]["networks"][0]["security_class"],
            "personal"
        );
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
        assert_eq!(value["wifi-status.inactive"]["status"]["enabled"], false);
        assert_eq!(value["wifi-set-enabled.success"]["result"]["enabled"], true);
        assert_eq!(value["wifi-band.status"]["band"]["selected"], "5");
        assert_eq!(
            value["wifi-band.set"]["result"]["request_id"],
            "band-contract"
        );
        assert_eq!(value["wifi-saved.profiles"]["profiles"][0]["id"], "Example");
        assert_eq!(
            value["wifi-connect.secret-required"]["result"]["reason"],
            "secret-required"
        );
        assert_eq!(value["wifi-scan.stream"]["events"][0]["protocol"], "nm-api");
        assert_eq!(
            value["network-connectivity.full"]["connectivity"]["state"],
            "full"
        );
        assert_eq!(
            value["network-devices.list"]["devices"][0]["type_name"],
            "wifi"
        );
        assert_eq!(
            value["network-connections.list"]["connections"][1]["type_name"],
            "vpn"
        );
        assert_eq!(
            value["network-status.connected"]["network"]["state_name"],
            "connected-global"
        );
        assert_eq!(
            value["network-inventory.snapshot"]["inventory"]["active_connections"][0]["default4"],
            true
        );
        assert_eq!(
            value["network-activate-profile.started"]["result"]["status"],
            "activating"
        );
        assert_eq!(
            value["network-deactivate.success"]["result"]["status"],
            "deactivated"
        );
        assert_eq!(
            value["continuous.streams"]["events"][4]["stream"],
            "network.inventory"
        );
        assert_eq!(
            value["continuous.streams"]["events"][6]["stream"],
            "wifi.networks"
        );
        assert_eq!(
            value["continuous.streams"]["events"][7]["snapshot"]["refresh_requested"],
            false
        );
        assert_eq!(
            value["wifi-disconnect.success"]["result"]["status"],
            "disconnected"
        );
        assert_eq!(
            value["wifi-profile.details"]["result"]["security_type"],
            "WPA Enterprise"
        );
        assert_eq!(
            value["wifi-profile.details"]["result"]["enterprise"]["eap"][0],
            "peap"
        );
        assert_eq!(
            value["wifi-profile.details"]["result"]["enterprise"]["password_flags"]["agent_owned"],
            true
        );
        assert_eq!(value["wifi-profile.details"]["result"]["band"], "5");
        assert!(
            value["wifi-profile.details"]["result"]["version"]
                .as_str()
                .is_some_and(|version| version.len() == 16)
        );
        assert_eq!(
            value["wifi-profile.update-conflict"]["error"]["code"],
            "conflict"
        );
        assert_eq!(
            value["wifi-profile.reveal-secret"]["result"]["primary_secret_key"],
            "password"
        );
        assert_eq!(
            value["wifi-profile.reveal-secret"]["result"]["values"]["private-key-password"],
            "private-key-secret"
        );
        assert_eq!(
            value["wifi-profile.forget"]["result"]["status"],
            "forgotten"
        );
        assert_eq!(value["wifi-profile.share"]["result"]["shareable"], true);
        assert_eq!(
            value["wifi-secret.capabilities"]["secret_agent"]["keyring"]["prompt_handling"],
            "unsupported"
        );
        assert_eq!(
            value["wifi-secret.provide"]["result"]["persistence_status"],
            "pending"
        );
        assert_eq!(
            value["network-statistics.watch"]["result"]["interval_ms"],
            1_000
        );
        assert_eq!(value["hotspot.capabilities"]["hotspot"]["supported"], true);
        assert_eq!(
            value["hotspot.capabilities-unsupported"]["hotspot"]["unsupported_reason"],
            "ap-mode-unsupported"
        );
        assert_eq!(value["hotspot.status-active"]["hotspot"]["active"], true);
        assert_eq!(value["hotspot.status-inactive"]["hotspot"]["active"], false);
        assert_eq!(value["hotspot.stop"]["result"]["status"], "stopped");
        assert!(
            value["hotspot.stream"]["events"][3]["result"]["hotspot"]["share"]["qr_payload"]
                .as_str()
                .is_some_and(|payload| payload.starts_with("WIFI:T:WPA;S:laufan-hotspot;"))
        );
        assert_eq!(
            value["network-statistics.stream"]["events"][2]["statistics"]["rx_bytes_per_second"],
            125_000.0
        );
        for fixture in [
            "wifi-connect.stream",
            "wifi-band.stream",
            "wifi-scan.stream",
            "wifi-secret.stream",
            "network-statistics.stream",
            "hotspot.stream",
        ] {
            let stream = match fixture {
                "wifi-connect.stream" => crate::protocol::Stream::WifiConnect,
                "wifi-band.stream" => crate::protocol::Stream::WifiBand,
                "wifi-scan.stream" => crate::protocol::Stream::WifiScan,
                "network-statistics.stream" => crate::protocol::Stream::NetworkStatistics,
                "hotspot.stream" => crate::protocol::Stream::Hotspot,
                _ => crate::protocol::Stream::WifiSecret,
            };
            let actual = value[fixture]["events"]
                .as_array()
                .expect("stream fixture events")
                .iter()
                .filter_map(|event| event["event"].as_str())
                .collect::<std::collections::HashSet<_>>();
            let expected = stream
                .spec()
                .events
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>();
            assert_eq!(actual, expected, "{fixture}");
        }
    }
}
