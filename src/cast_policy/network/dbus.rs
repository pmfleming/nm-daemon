//! Real D-Bus transport with scripted NM state; no host networking or firewall.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use zvariant::OwnedObjectPath;

use super::{enabled_interfaces, tests::settings};
use crate::nm::{ConnectionSettings, NM_PATH};
use crate::test_support::TestPeer;

const DEVICE: &str = "/org/freedesktop/NetworkManager/Devices/1";
const ACTIVE: &str = "/org/freedesktop/NetworkManager/ActiveConnection/1";
const PROFILE: &str = "/org/freedesktop/NetworkManager/Settings/1";

fn path(value: &str) -> OwnedObjectPath {
    value.try_into().unwrap()
}

#[derive(Default)]
struct State {
    saved: i32,
    applied: i32,
    state: u32,
    reads: u64,
    version_race: bool,
    active_race: bool,
    fail: bool,
}

struct Bus;
#[zbus::interface(name = "org.freedesktop.DBus")]
impl Bus {
    fn get_name_owner(&self, name: &str) -> &str {
        assert_eq!(name, crate::nm::NM_DEST);
        "org.freedesktop.DBus"
    }
}

struct Manager;
#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Manager {
    fn get_devices(&self) -> Vec<OwnedObjectPath> {
        vec![path(DEVICE)]
    }
}

struct Device(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
impl Device {
    #[zbus(property)]
    fn interface(&self) -> &str {
        "wlan0"
    }
    #[zbus(property)]
    fn state(&self) -> u32 {
        self.0.lock().unwrap().state
    }
    #[zbus(property)]
    fn active_connection(&self) -> OwnedObjectPath {
        let state = self.0.lock().unwrap();
        path(if state.active_race && state.reads > 0 {
            "/"
        } else {
            ACTIVE
        })
    }
    fn get_applied_connection(&self, flags: u32) -> (ConnectionSettings, u64) {
        assert_eq!(flags, 0);
        let mut state = self.0.lock().unwrap();
        state.reads += 1;
        (
            settings(state.applied),
            if state.version_race { state.reads } else { 7 },
        )
    }
}

struct Active;
#[zbus::interface(name = "org.freedesktop.NetworkManager.Connection.Active")]
impl Active {
    #[zbus(property)]
    fn connection(&self) -> OwnedObjectPath {
        path(PROFILE)
    }
}

struct Saved(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl Saved {
    fn get_settings(&self) -> zbus::fdo::Result<ConnectionSettings> {
        let state = self.0.lock().unwrap();
        if state.fail {
            return Err(zbus::fdo::Error::Failed("NM unavailable".into()));
        }
        Ok(settings(state.saved))
    }
}

#[test]
fn snapshots_use_fresh_saved_and_applied_policy_and_reject_races() -> Result<()> {
    crate::test_support::workflows::isolated(
        concat!(
            module_path!(),
            "::snapshots_use_fresh_saved_and_applied_policy_and_reject_races"
        ),
        run,
    )
}

fn run() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    // org.freedesktop.DBus is treated as a reserved unique name by zbus. This
    // peer serves both the name-owner lookup and the scripted NM objects.
    let peer = TestPeer::new("org.freedesktop.DBus", ":1.1");
    let state = Arc::new(Mutex::new(State::default()));
    peer.server
        .object_server()
        .at("/org/freedesktop/DBus", Bus)?;
    peer.server.object_server().at(NM_PATH, Manager)?;
    peer.server
        .object_server()
        .at(DEVICE, Device(state.clone()))?;
    peer.server.object_server().at(ACTIVE, Active)?;
    peer.server
        .object_server()
        .at(PROFILE, Saved(state.clone()))?;
    let wifi = BTreeSet::from(["wlan0".to_string()]);
    // Reuse the connection across policy changes to detect accidental property caching.
    for (saved, applied, device_state, version_race, active_race, fail, expected) in [
        (1, 1, 100, false, false, false, true),
        (0, 1, 100, false, false, false, false),
        (1, 0, 100, false, false, false, false),
        (2, 2, 100, false, false, false, true),
        (-1, 1, 100, false, false, false, false),
        (1, 1, 90, false, false, false, false),
        (1, 1, 110, false, false, false, false),
        (1, 1, 100, true, false, false, false),
        (1, 1, 100, false, true, false, false),
        (1, 1, 100, false, false, true, false),
    ] {
        *state.lock().unwrap() = State {
            saved,
            applied,
            state: device_state,
            reads: 0,
            version_race,
            active_race,
            fail,
        };
        let result = runtime.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(4),
                enabled_interfaces(peer.client.inner(), &wifi),
            )
            .await
        })?;
        if fail {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result?,
                if expected {
                    wifi.clone()
                } else {
                    BTreeSet::new()
                }
            );
        }
    }
    // A NM device not identified as a Linux Wi-Fi interface cannot be enabled.
    let result = runtime.block_on(enabled_interfaces(peer.client.inner(), &BTreeSet::new()))?;
    assert!(result.is_empty());
    peer.server
        .object_server()
        .remove::<Bus, _>("/org/freedesktop/DBus")?;
    assert!(
        runtime
            .block_on(enabled_interfaces(peer.client.inner(), &wifi))
            .is_err()
    );
    Ok(())
}
