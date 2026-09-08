use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use zvariant::OwnedObjectPath;

use crate::command::SystemCommandRunner;
use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
use crate::nl80211::UnavailableWirelessTelemetry;
use crate::nm::{ConnectionSettings, Nm, owned_value};
use crate::test_support::TestPeer;

const EXPIRED: &str = "/org/freedesktop/NetworkManager/Settings/1";
const LIVE: &str = "/org/freedesktop/NetworkManager/Settings/2";
fn path(value: &str) -> OwnedObjectPath {
    value.try_into().unwrap()
}

struct Settings(Arc<AtomicBool>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings")]
impl Settings {
    fn list_connections(&self) -> Vec<OwnedObjectPath> {
        if self.0.load(Ordering::Relaxed) {
            vec![path(LIVE)]
        } else {
            vec![path(EXPIRED), path(LIVE)]
        }
    }
}
struct Profile {
    removed: Arc<AtomicBool>,
    delete_on_read: bool,
    live: bool,
}
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl Profile {
    fn get_settings(&self) -> zbus::fdo::Result<ConnectionSettings> {
        if self.live {
            return Ok(ConnectionSettings::from([
                (
                    "connection".into(),
                    HashMap::from([
                        ("id".into(), owned_value("Persistent".to_string()).unwrap()),
                        (
                            "type".into(),
                            owned_value("802-11-wireless".to_string()).unwrap(),
                        ),
                    ]),
                ),
                (
                    "802-11-wireless".into(),
                    HashMap::from([("ssid".into(), owned_value(b"Persistent".to_vec()).unwrap())]),
                ),
            ]));
        }
        if self.delete_on_read {
            self.removed.store(true, Ordering::Relaxed);
            Err(zbus::fdo::Error::UnknownObject(
                "initrd profile removed after takeover".into(),
            ))
        } else {
            Err(zbus::fdo::Error::AccessDenied(
                "profile access denied".into(),
            ))
        }
    }
}

#[test]
fn disappearing_profiles_do_not_break_listing_but_existing_profile_errors_survive() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    for delete_on_read in [true, false] {
        let peer = TestPeer::new(":1.0", ":1.1");
        let removed = Arc::new(AtomicBool::new(false));
        peer.server
            .object_server()
            .at(crate::nm::SETTINGS_PATH, Settings(removed.clone()))
            .unwrap();
        peer.server
            .object_server()
            .at(
                EXPIRED,
                Profile {
                    removed: removed.clone(),
                    delete_on_read,
                    live: false,
                },
            )
            .unwrap();
        peer.server
            .object_server()
            .at(
                LIVE,
                Profile {
                    removed,
                    delete_on_read,
                    live: true,
                },
            )
            .unwrap();
        let nm = Nm::with_connection_runner_destination_and_telemetry(
            peer.client.clone(),
            Arc::new(SystemCommandRunner),
            ":1.0",
            Arc::new(UnavailableWirelessTelemetry),
        )
        .unwrap();
        let result = nm.saved_wifi_connections();
        if delete_on_read {
            let profiles = result.unwrap();
            assert_eq!(profiles.len(), 1);
            assert_eq!(profiles[0].path, LIVE);
            assert!(
                nm.wifi_profile_details_by_path(EXPIRED).is_err(),
                "explicit stale lookups remain errors"
            );
        } else {
            let report =
                ErrorReport::from_error(&result.unwrap_err(), ErrorOperation::ProfileOperation);
            assert_eq!(report.code, ErrorCode::AuthorizationRequired);
        }
    }
}
