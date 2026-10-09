use std::sync::{Arc, Mutex};

use anyhow::Result;
use zvariant::OwnedObjectPath;

use super::ForgetService;
use crate::nm::{ConnectionSettings, NM_PATH, Nm};
use crate::test_support::TestPeer;
use crate::variant::value_map;

fn path(value: &str) -> OwnedObjectPath {
    value.try_into().unwrap()
}

#[derive(Default)]
struct State {
    disconnected: Vec<String>,
    // Deactivation can be acknowledged before the device actually drops its link.
    hold_target: bool,
}

struct Manager(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Manager {
    fn get_devices(&self) -> Vec<OwnedObjectPath> {
        vec![
            path("/device/other"),
            path("/device/target"),
            path("/device/target2"),
        ]
    }

    fn deactivate_connection(&self, active: OwnedObjectPath) {
        self.0.lock().unwrap().disconnected.push(active.to_string());
    }
}

struct Device(Arc<Mutex<State>>, &'static str);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
impl Device {
    #[zbus(property)]
    fn device_type(&self) -> u32 {
        2
    }

    #[zbus(property)]
    fn interface(&self) -> &str {
        self.1
    }

    #[zbus(property(emits_changed_signal = "false"))]
    fn active_connection(&self) -> OwnedObjectPath {
        let active = format!("/active/{}", self.1);
        let state = self.0.lock().unwrap();
        if state.disconnected.contains(&active) && !state.hold_target {
            path("/")
        } else {
            path(&active)
        }
    }
}

struct Active(&'static str);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Connection.Active")]
impl Active {
    #[zbus(property)]
    fn connection(&self) -> OwnedObjectPath {
        path(&format!("/profile/{}", self.0))
    }
}

struct Profile(&'static str);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl Profile {
    fn get_settings(&self) -> ConnectionSettings {
        ConnectionSettings::from([(
            "802-11-wireless".into(),
            value_map([("ssid", self.0.as_bytes().to_vec().into())]).unwrap(),
        )])
    }
}

#[test]
fn forget_disconnect_and_confirmation_are_target_scoped_across_adapters() -> Result<()> {
    let peer = TestPeer::new(":1.0", ":1.1");
    let state = Arc::new(Mutex::new(State::default()));
    let server = peer.server.object_server();
    server.at(NM_PATH, Manager(state.clone()))?;
    for (device, ssid) in [
        ("other", "Other"),
        ("target", "Example"),
        ("target2", "Example"),
    ] {
        server.at(format!("/device/{device}"), Device(state.clone(), device))?;
        server.at(format!("/active/{device}"), Active(device))?;
        server.at(format!("/profile/{device}"), Profile(ssid))?;
    }
    let nm = Nm::with_connection_runner_destination_and_telemetry(
        peer.client.clone(),
        crate::command::default_runner(),
        ":1.0",
        Arc::new(crate::nl80211::UnavailableWirelessTelemetry),
    )?;
    let target = crate::model::example_connect_target(false);
    // No active AP is exported: activating links must also prevent profile deletion.
    assert!(nm.wifi_connection_active_for_ssid(target.ssid_bytes())?);
    state.lock().unwrap().hold_target = true;
    nm.disconnect_wifi_for_ssid(target.ssid_bytes())?;
    assert!(nm.wifi_connection_active_for_ssid(target.ssid_bytes())?);
    state.lock().unwrap().hold_target = false;
    assert!(!nm.wifi_connection_active_for_ssid(target.ssid_bytes())?);
    state.lock().unwrap().disconnected.clear();

    let mut warnings = Vec::new();
    assert!(ForgetService { nm: &nm }.disconnect_and_confirm(
        "forget-test",
        &target,
        &mut warnings
    )?);
    assert!(warnings.is_empty());
    assert_eq!(
        state.lock().unwrap().disconnected,
        ["/active/target", "/active/target2"]
    );
    assert!(nm.wifi_connection_active_for_ssid(b"Other")?);
    assert!(!nm.wifi_connection_active_for_ssid(target.ssid_bytes())?);
    Ok(())
}
