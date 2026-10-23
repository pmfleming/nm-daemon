//! Decode the actual response bodies, not parallel frontend-shaped Rust structs.
//! Some output DTOs borrow compile-time labels. Tests retain their small JSON
//! fixtures for the process lifetime; no deserialization is added to live paths.
use super::*;
use serde::Deserialize;
fn decode<T: Deserialize<'static>>(value: &Value) -> T {
    T::deserialize(&*Box::leak(Box::new(value.clone())))
        .unwrap_or_else(|e| panic!("{}: {e}", std::any::type_name::<T>()))
}
#[test]
fn frontend_contract_network_status_profiles_and_results_use_owned_types() {
    let f = method_contract_fixtures();
    let shell = serde_json::to_value(shelllist_contract_fixture()).unwrap();
    let typed: ShelllistContractFixture = decode(&shell);
    assert_eq!(
        serde_json::to_value(&typed.network.capabilities).unwrap()["can_connect"],
        true
    );
    assert_eq!(typed.connect_success.path, Some(ConnectEnginePath::Dbus));
    let failed = typed.connect_error;
    assert_eq!(failed.reason, Some(ConnectFailureReason::SecretRequired));
    assert_eq!(failed.status, "error");
    for name in [
        "wifi-networks.saved",
        "wifi-networks.password-required",
        "wifi-networks.enterprise-required",
    ] {
        let _: Vec<NetworkEntry> = decode(&f[name]["networks"]);
        let _: NetworkSnapshotMetadata = decode(&f[name]["snapshot"]);
    }
    for name in ["wifi-status.active", "wifi-status.inactive"] {
        let _: WifiStatus = decode(&f[name]["status"]);
    }
    let _: WifiProfileDetails = decode(&f["wifi-profile.details"]["result"]);
    let _: WifiBandStatus = decode(&f["wifi-band.status"]["band"]);
    let _: WifiPowerResult = decode(&f["wifi-set-enabled.success"]["result"]);
    for name in [
        "radio-set-wwan-enabled.success",
        "radio-set-airplane-mode.success",
    ] {
        let _: RadioPowerResult = decode(&f[name]["result"]);
    }
    let _: NetworkInventory = decode(&f["network-inventory.snapshot"]["inventory"]);
    let _: Vec<NetworkDeviceSummary> = decode(&f["network-devices.list"]["devices"]);
    let _: NetworkStateSummary = decode(&f["network-status.connected"]["network"]);
    let _: ProfileActivationResult = decode(&f["network-activate-profile.started"]["result"]);
    let _: NetworkDeactivateResult = decode(&f["network-deactivate.success"]["result"]);
    for name in ["hotspot.capabilities", "hotspot.capabilities-unsupported"] {
        let _: HotspotCapabilities = decode(&f[name]["hotspot"]);
    }
    let _: Vec<VpnProfileSummary> = decode(&f["vpn.list"]["vpns"]);
    let _: VpnStatus = decode(&f["vpn.status-connected"]["vpn"]);
    for path in [
        "/network/strength",
        "/network/security_class",
        "/network/share/requires_profile_secret_check",
    ] {
        let mut bad = shell["network"].clone();
        let relative = path.strip_prefix("/network").unwrap();
        *bad.pointer_mut(relative).unwrap() = json!({});
        assert!(serde_json::from_value::<NetworkEntry>(bad).is_err());
    }
    let mut bad = shell["status"].clone();
    bad["radios"]["wwan_enabled"] = json!("yes");
    assert!(WifiStatus::deserialize(&*Box::leak(Box::new(bad))).is_err());
}
#[test]
fn frontend_contract_semantic_witnesses_and_checked_snapshot() {
    assert_eq!(
        serialized_boundary_snapshot(),
        serde_json::from_str::<Value>(include_str!("../../test_support/contract-v1.json")).unwrap()
    );
    let f = method_contract_fixtures();
    for (pointer, expected) in [
        ("/wifi-networks.saved/snapshot/source", json!("cache")),
        (
            "/wifi-networks.saved/networks/0/security_class",
            json!("personal"),
        ),
        (
            "/wifi-networks.password-required/networks/0/capabilities/needs_password",
            json!(true),
        ),
        (
            "/wifi-networks.enterprise-required/networks/0/capabilities/needs_credentials",
            json!(true),
        ),
        (
            "/wifi-networks.enterprise-required/networks/0/connect_prompt/kind",
            json!("enterprise"),
        ),
        ("/wifi-status.active/status/active", json!(true)),
        ("/wifi-status.inactive/status/active", json!(false)),
        ("/wifi-set-enabled.success/result/enabled", json!(true)),
        ("/portal.prepare/portal/intent/reason", json!("manual")),
        (
            "/portal.claim/portal/intent/launch_id",
            json!("launch-contract"),
        ),
        ("/portal.complete/portal/outcome", json!("opened")),
        ("/wifi-band.status/band/selected", json!("5")),
        ("/wifi-band.set/result/stream", json!("wifi.band")),
        (
            "/radio-set-wwan-enabled.success/result/radios/wwan_enabled",
            json!(true),
        ),
        (
            "/radio-set-airplane-mode.success/result/radios/airplane_mode",
            json!(true),
        ),
        ("/wifi-connect.success/result/status", json!("connected")),
        ("/wifi-connect.success/result/path", json!("dbus")),
        (
            "/wifi-connect.secret-required/result/reason",
            json!("secret-required"),
        ),
        ("/wifi-scan.stream/events/0/protocol", json!("nm-api")),
        ("/wifi-scan.stream/events/0/stream", json!("wifi.scan")),
        ("/wifi-profile.share/result/shareable", json!(true)),
        (
            "/wifi-profile.update-conflict/error/code",
            json!("conflict"),
        ),
        ("/network-devices.list/devices/0/type_name", json!("wifi")),
        (
            "/network-status.connected/network/state_name",
            json!("connected-global"),
        ),
        (
            "/network-activate-profile.started/result/status",
            json!("activating"),
        ),
        (
            "/network-deactivate.success/result/status",
            json!("deactivated"),
        ),
        (
            "/network-statistics.watch/result/stream",
            json!("network.statistics"),
        ),
        ("/hotspot.capabilities/hotspot/supported", json!(true)),
        (
            "/hotspot.capabilities-unsupported/hotspot/unsupported_reason",
            json!("ap-mode-unsupported"),
        ),
        ("/vpn.list/vpns/0/plugin", json!("openconnect")),
        ("/vpn.list/vpns/1/plugin", json!("wireguard")),
        ("/wifi-qr.parse/qr/auth", json!("wpa")),
        ("/wifi-qr.parse/qr/has_password", json!(true)),
        ("/wifi-qr.parse-open/qr/auth", json!("open")),
        (
            "/wifi-secret.capabilities/secret_agent/keyring/available",
            json!(false),
        ),
        (
            "/wifi-secret.capabilities/secret_agent/keyring/persistence_supported",
            json!(false),
        ),
        (
            "/wifi-secret.capabilities/secret_agent/storage/provider",
            json!("networkmanager"),
        ),
    ] {
        assert_eq!(f.pointer(pointer), Some(&expected), "{pointer}");
    }
    assert!(f["wifi-qr.parse"]["qr"].get("password").is_none());
    assert!(!f["wifi-profile.details"]["result"]["version"].is_null());
    assert_eq!(
        f["wifi-band.stream"]["events"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["event"],
        "cancelled"
    );
    let events = |name: &str| f[name]["events"].as_array().unwrap();
    assert!(events("hotspot.stream").iter().any(|e| {
        e["event"] == "succeeded"
            && e["data"]["result"]["hotspot"]["share"]["qr_payload"]
                .as_str()
                .is_some_and(|s| s.starts_with("WIFI:"))
    }));
    assert!(
        events("vpn.stream")
            .iter()
            .any(|e| e["event"] == "failed" && e["error"]["details"]["reason"] == "no-secrets")
    );
    assert!(
        events("wifi-secret.stream")
            .iter()
            .any(|e| e["event"] == "requested" && e["data"]["save_required"] == true)
    );
    assert!(
        events("wifi-secret.stream")
            .iter()
            .any(|e| e["event"] == "persistence"
                && e["data"]["status"] == "stored"
                && e["data"]["storage_provider"] == "networkmanager")
    );
    assert!(
        events("network-health.stream")
            .iter()
            .any(|e| e["event"] == "device"
                && e["data"]["health"]["reason"]["category"] == "authentication")
    );
}
