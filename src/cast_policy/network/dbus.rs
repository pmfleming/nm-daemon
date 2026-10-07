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

#[derive(Debug, Default)]
struct State {
    saved: i32,
    applied: i32,
    state: u32,
    reads: u64,
    version_race: bool,
    active_race: bool,
    state_race: bool,
    zero_version: bool,
    fail: bool,
}

impl State {
    fn enabled() -> Self {
        Self {
            saved: 1,
            applied: 1,
            state: 100,
            ..Self::default()
        }
    }
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
        let state = self.0.lock().unwrap();
        if state.state_race && state.reads > 0 {
            110
        } else {
            state.state
        }
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
            if state.zero_version {
                0
            } else if state.version_race {
                state.reads
            } else {
                7
            },
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

struct Fixture {
    peer: TestPeer,
    state: Arc<Mutex<State>>,
    wifi: BTreeSet<String>,
}

impl Fixture {
    fn new() -> Result<Self> {
        // The isolated test harness owns the Tokio runtime. The reserved unique
        // name lets this peer serve both owner lookup and scripted NM objects.
        let peer = TestPeer::new("org.freedesktop.DBus", ":1.1");
        let state = Arc::new(Mutex::new(State::enabled()));
        let server = peer.server.object_server();
        server.at("/org/freedesktop/DBus", Bus)?;
        server.at(NM_PATH, Manager)?;
        server.at(DEVICE, Device(Arc::clone(&state)))?;
        server.at(ACTIVE, Active)?;
        server.at(PROFILE, Saved(Arc::clone(&state)))?;
        drop(server);
        Ok(Self {
            peer,
            state,
            wifi: BTreeSet::from(["wlan0".to_string()]),
        })
    }

    fn snapshot(&self, wifi: &BTreeSet<String>) -> Result<BTreeSet<String>> {
        tokio::runtime::Handle::current().block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(4),
                enabled_interfaces(self.peer.client.inner(), wifi),
            )
            .await?
        })
    }

    fn check(&self, state: State, enabled: bool) -> Result<()> {
        *self.state.lock().unwrap() = state;
        let actual = self.snapshot(&self.wifi)?;
        let empty = BTreeSet::new();
        assert_eq!(
            &actual,
            if enabled { &self.wifi } else { &empty },
            "{:?}",
            self.state.lock().unwrap()
        );
        Ok(())
    }
}

fn run() -> Result<()> {
    let fixture = Fixture::new()?;
    // Reusing the same connection detects accidental property caching.
    for (saved, applied, enabled) in [
        (1, 1, true),
        (0, 1, false),
        (1, 0, false),
        (2, 2, true),
        (-1, 1, false),
    ] {
        fixture.check(
            State {
                saved,
                applied,
                ..State::enabled()
            },
            enabled,
        )?;
    }
    for state in [
        State {
            state: 90,
            ..State::enabled()
        },
        State {
            state: 110,
            ..State::enabled()
        },
        State {
            version_race: true,
            ..State::enabled()
        },
        State {
            active_race: true,
            ..State::enabled()
        },
        State {
            state_race: true,
            ..State::enabled()
        },
        State {
            zero_version: true,
            ..State::enabled()
        },
    ] {
        fixture.check(state, false)?;
    }
    *fixture.state.lock().unwrap() = State {
        fail: true,
        ..State::enabled()
    };
    assert!(fixture.snapshot(&fixture.wifi).is_err());
    // Unknown Linux interfaces stay closed even if the saved-profile read fails.
    assert!(fixture.snapshot(&BTreeSet::new())?.is_empty());
    fixture
        .peer
        .server
        .object_server()
        .remove::<Bus, _>("/org/freedesktop/DBus")?;
    assert!(fixture.snapshot(&fixture.wifi).is_err());
    Ok(())
}
