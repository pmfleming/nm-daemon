use std::sync::{Arc, Mutex};

use zvariant::OwnedObjectPath;

use super::{casting_enabled_from_settings, mdns_policy};
use crate::command::SystemCommandRunner;
use crate::error::{ErrorOperation, ErrorReport};
use crate::nl80211::UnavailableWirelessTelemetry;
use crate::nm::{ConnectionSettings, NM_PATH, Nm, owned_value};
use crate::test_support::TestPeer;

const PROFILE: &str = "/org/freedesktop/NetworkManager/Settings/1";
const ACTIVE: &str = "/org/freedesktop/NetworkManager/ActiveConnection/1";
const DEVICE: &str = "/org/freedesktop/NetworkManager/Devices/1";

fn path(value: &str) -> OwnedObjectPath {
    value.try_into().unwrap()
}

fn settings(mdns: i32) -> ConnectionSettings {
    ConnectionSettings::from([
        (
            "connection".into(),
            [
                ("id".into(), owned_value("Example".to_string()).unwrap()),
                (
                    "type".into(),
                    owned_value("802-11-wireless".to_string()).unwrap(),
                ),
                ("mdns".into(), owned_value(mdns).unwrap()),
            ]
            .into(),
        ),
        (
            "802-11-wireless".into(),
            [("ssid".into(), owned_value(b"Example".to_vec()).unwrap())].into(),
        ),
        (
            "ipv4".into(),
            [("method".into(), owned_value("auto".to_string()).unwrap())].into(),
        ),
    ])
}

struct State {
    saved: ConnectionSettings,
    applied: ConnectionSettings,
    active: bool,
    reject: bool,
    switched: bool,
    reapplications: usize,
    firewall_reconciliations: usize,
    reject_firewall: bool,
}

struct Firewall(Arc<Mutex<State>>);
#[zbus::interface(name = "org.laufan.NmCastPolicy1")]
impl Firewall {
    fn reconcile(&self) -> zbus::fdo::Result<()> {
        let mut state = self.0.lock().unwrap();
        state.firewall_reconciliations += 1;
        if state.reject_firewall {
            return Err(zbus::fdo::Error::Failed("nft update failed".into()));
        }
        Ok(())
    }
}

struct Manager(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Manager {
    #[zbus(property)]
    fn active_connections(&self) -> Vec<OwnedObjectPath> {
        if self.0.lock().unwrap().active {
            vec![path(ACTIVE)]
        } else {
            vec![]
        }
    }
}

struct Active;
#[zbus::interface(name = "org.freedesktop.NetworkManager.Connection.Active")]
impl Active {
    #[zbus(property)]
    fn connection(&self) -> OwnedObjectPath {
        path(PROFILE)
    }
    #[zbus(property)]
    fn devices(&self) -> Vec<OwnedObjectPath> {
        vec![path(DEVICE)]
    }
}

struct Saved(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl Saved {
    fn get_settings(&self) -> ConnectionSettings {
        self.0.lock().unwrap().saved.clone()
    }
    fn update(&self, settings: ConnectionSettings) {
        self.0.lock().unwrap().saved = settings;
    }
}

struct Device(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
impl Device {
    #[zbus(property)]
    fn active_connection(&self) -> OwnedObjectPath {
        if self.0.lock().unwrap().switched {
            path("/")
        } else {
            path(ACTIVE)
        }
    }
    fn get_applied_connection(&self, flags: u32) -> (ConnectionSettings, u64) {
        assert_eq!(flags, 0);
        (self.0.lock().unwrap().applied.clone(), 7)
    }
    fn reapply(
        &self,
        settings: ConnectionSettings,
        version: u64,
        flags: u32,
    ) -> zbus::fdo::Result<()> {
        assert_eq!(version, 7, "never opt out of NM's version guard");
        assert_eq!(flags, 1, "preserve external IP configuration");
        let mut state = self.0.lock().unwrap();
        state.reapplications += 1;
        if state.reject {
            return Err(zbus::fdo::Error::Failed("concurrent Reapply".into()));
        }
        state.applied = settings;
        Ok(())
    }
}

#[test]
fn saved_policy_and_live_reapply_are_scoped_and_partial_failure_is_explicit() -> anyhow::Result<()>
{
    crate::test_support::workflows::isolated(
        concat!(
            module_path!(),
            "::saved_policy_and_live_reapply_are_scoped_and_partial_failure_is_explicit"
        ),
        || {
            run_policy_test();
            Ok(())
        },
    )
}

fn run_policy_test() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    for (initial, enabled, active, reject, switched, reject_firewall) in [
        (0, true, true, false, false, false),
        (0, false, true, false, false, false), // idempotent Off still enforces firewall
        (1, false, true, false, false, false),
        (2, false, true, false, false, false),
        (2, true, true, false, false, false), // resolve-only, not hostname advertising
        (0, true, false, false, false, false),
        (0, true, true, true, false, false),
        (0, true, true, false, true, false),
        (1, false, true, true, false, false), // firewall still closes if resolver fails
        (1, false, true, false, false, true),
        (0, true, true, false, false, true),
        (0, false, false, false, false, true), // inactive still needs installed enforcement
    ] {
        let peer = TestPeer::new(":1.0", ":1.1");
        let saved = settings(initial);
        let mut applied = saved.clone();
        applied
            .get_mut("ipv4")
            .unwrap()
            .insert("method".into(), owned_value("manual".to_string()).unwrap());
        let expected_ip = applied["ipv4"].clone();
        let state = Arc::new(Mutex::new(State {
            saved,
            applied,
            active,
            reject,
            switched,
            reapplications: 0,
            firewall_reconciliations: 0,
            reject_firewall,
        }));
        let server = peer.server.object_server();
        server.at(NM_PATH, Manager(state.clone())).unwrap();
        server.at(PROFILE, Saved(state.clone())).unwrap();
        server.at(ACTIVE, Active).unwrap();
        server.at(DEVICE, Device(state.clone())).unwrap();
        let missing_firewall = reject_firewall && enabled;
        if !missing_firewall {
            server
                .at(crate::cast_policy::PATH, Firewall(state.clone()))
                .unwrap();
        }
        let nm = Nm::with_connection_runner_destination_and_telemetry(
            peer.client.clone(),
            Arc::new(SystemCommandRunner),
            ":1.0",
            Arc::new(UnavailableWirelessTelemetry),
        )
        .unwrap();
        let result = if !enabled && initial == 2 {
            // Exercise the advanced editor route as well as the direct CLI toggle.
            let update = serde_json::from_value(serde_json::json!({
                "autoconnect": true, "metered": "auto", "hidden": false,
                "mac_address_policy": "stable", "send_hostname": false,
                "ipv4": { "method": "auto" }, "ipv6": { "method": "auto" },
                "advanced": { "casting_enabled": enabled }
            }))
            .unwrap();
            nm.update_wifi_profile_by_path(PROFILE, &update)
        } else {
            nm.set_connection_casting_by_path(PROFILE, enabled)
        };
        if reject || switched || reject_firewall {
            let report = ErrorReport::from_error(&result.unwrap_err(), ErrorOperation::Unknown);
            assert_eq!(report.details["profile_saved"], true);
            assert_eq!(report.details["live_applied"], false);
            assert!(report.message.contains("Profile saved"));
        } else {
            result.unwrap();
        }
        let state = state.lock().unwrap();
        assert_eq!(mdns_policy(&state.saved), Some(i32::from(enabled)));
        assert_eq!(
            mdns_policy(&state.applied),
            Some(if active && !reject && !switched {
                i32::from(enabled)
            } else {
                initial
            })
        );
        assert_eq!(
            state.applied["ipv4"], expected_ip,
            "do not apply pending saved IP changes"
        );
        assert_eq!(
            state.reapplications,
            usize::from(active && !switched && initial != i32::from(enabled))
        );
        assert_eq!(
            state.firewall_reconciliations,
            if missing_firewall { 0 } else { 2 },
            "enforce before and after resolver reapply, even on failure"
        );
    }
}

#[test]
fn only_explicit_supported_policies_report_discovery_enabled() {
    for (policy, enabled) in [(-1, false), (0, false), (1, true), (2, true), (3, false)] {
        assert_eq!(casting_enabled_from_settings(&settings(policy)), enabled);
    }
    assert!(!casting_enabled_from_settings(&ConnectionSettings::new()));
}
