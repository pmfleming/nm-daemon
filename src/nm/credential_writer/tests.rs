use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use zvariant::{OwnedObjectPath, OwnedValue};

use super::*;
use crate::network_credentials::{flags_key, set_system_owned, set_text};
use crate::test_support::{TestPeer, workflows::isolated};
use crate::variant::value_map;

#[path = "retention_tests.rs"]
mod retention_tests;

const PATH: &str = "/test/profile";
#[derive(Default)]
struct State {
    public: ConnectionSettings,
    secrets: ConnectionSettings,
    version: u64,
    nm_version: String,
    dirty: bool,
    filename: String,
    fail_read: bool,
    fail_write: bool,
    race_read: bool,
    reads: usize,
    writes: usize,
    written: Option<ConnectionSettings>,
    retention_flags: u32,
    active: bool,
    deleted: bool,
    update_flags: u32,
}
struct Manager(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Manager {
    #[zbus(property)]
    fn version(&self) -> String {
        self.0.lock().unwrap().nm_version.clone()
    }
}
struct Settings(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings")]
impl Settings {
    fn list_connections(&self) -> Vec<OwnedObjectPath> {
        if self.0.lock().unwrap().deleted {
            vec![]
        } else {
            vec![PATH.try_into().unwrap()]
        }
    }
}
struct Profile(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl Profile {
    fn get_settings(&self) -> ConnectionSettings {
        self.0.lock().unwrap().public.clone()
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn version_id(&self) -> u64 {
        self.0.lock().unwrap().version
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn unsaved(&self) -> bool {
        self.0.lock().unwrap().dirty
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn filename(&self) -> String {
        self.0.lock().unwrap().filename.clone()
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn flags(&self) -> u32 {
        self.0.lock().unwrap().retention_flags
    }
    fn get_secrets(&self, _section: &str) -> zbus::fdo::Result<ConnectionSettings> {
        let mut s = self.0.lock().unwrap();
        s.reads += 1;
        if s.fail_read {
            return Err(zbus::fdo::Error::AccessDenied(
                "do-not-log-synthetic-value".into(),
            ));
        }
        s.version += 1; // NM's own successful GetSecrets update.
        if s.race_read {
            s.version += 1; // A competing external edit must not be absorbed.
        }
        Ok(s.secrets.clone())
    }
    fn update2(
        &self,
        settings: ConnectionSettings,
        flags: u32,
        args: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<HashMap<String, OwnedValue>> {
        let mut s = self.0.lock().unwrap();
        s.writes += 1;
        assert!(
            flags == 1 || flags == 33 || flags == 114,
            "explicit persistence mode required"
        );
        assert_eq!(u64::try_from(&args["version-id"]).unwrap(), s.version);
        assert_ne!(s.version, 0);
        if s.fail_write {
            return Err(zbus::fdo::Error::Failed(
                "do-not-log-synthetic-value".into(),
            ));
        }
        s.update_flags = flags;
        if flags & 16 != 0 {
            assert!(
                settings.is_empty(),
                "retention must preserve NM's credential cache natively"
            );
            s.retention_flags = 5;
            s.dirty = true;
            s.filename = "/run/NetworkManager/system-connections/fixture.nmconnection".into();
            s.deleted = !s.active;
        } else {
            s.retention_flags = 0;
            s.dirty = false;
            s.filename = "/etc/NetworkManager/system-connections/fixture.nmconnection".into();
            s.public = crate::network_credentials::public_settings(&settings).unwrap();
        }
        s.written = Some(settings);
        s.version += 1;
        Ok(HashMap::new())
    }
}

struct Harness {
    nm: Nm,
    state: Arc<Mutex<State>>,
    _peer: TestPeer,
}
impl Harness {
    fn new() -> Result<Self> {
        let state = Arc::new(Mutex::new(State {
            public: ConnectionSettings::from([
                (
                    "connection".into(),
                    value_map([
                        ("uuid", "fixture-uuid".into()),
                        ("id", "fixture".into()),
                        ("type", "802-11-wireless".into()),
                    ])?,
                ),
                (
                    "802-11-wireless".into(),
                    HashMap::from([("ssid".into(), owned_value(b"fixture".to_vec())?)]),
                ),
                (
                    "802-1x".into(),
                    value_map([
                        ("password-flags", 0u32.into()),
                        ("private-key-password-flags", 0u32.into()),
                        ("domain-suffix-match", "example.invalid".into()),
                    ])?,
                ),
            ]),
            secrets: ConnectionSettings::from([(
                "802-1x".into(),
                value_map([
                    ("password", "old-password".into()),
                    ("private-key-password", "keep-private-key-password".into()),
                ])?,
            )]),
            version: 7,
            nm_version: "1.56.0".into(),
            filename: "/etc/NetworkManager/system-connections/fixture.nmconnection".into(),
            active: true,
            ..State::default()
        }));
        let peer = TestPeer::new(":1.0", ":1.1");
        peer.server
            .object_server()
            .at(crate::nm::NM_PATH, Manager(state.clone()))?;
        peer.server
            .object_server()
            .at(PATH, Profile(state.clone()))?;
        peer.server
            .object_server()
            .at(crate::nm::SETTINGS_PATH, Settings(state.clone()))?;
        let nm = Nm::with_connection_runner_destination_and_telemetry(
            peer.client.clone(),
            crate::command::default_runner(),
            ":1.0",
            Arc::new(crate::nl80211::UnavailableWirelessTelemetry),
        )?;
        Ok(Self {
            nm,
            state,
            _peer: peer,
        })
    }
    fn edit(&self) -> Result<ProfileEdit> {
        let mut edit = self
            .nm
            .begin_credential_edit(&OwnedObjectPath::try_from(PATH)?)?;
        set_text(&mut edit.settings, "802-1x", "password", "replacement")?;
        Ok(edit)
    }
}

#[test]
fn preserving_writer_rejects_races_staged_edits_unknown_schemas_and_unreadable_secrets()
-> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::preserving_writer_rejects_races_staged_edits_unknown_schemas_and_unreadable_secrets"
        ),
        || {
            for failure in [
                "none",
                "read",
                "write",
                "race",
                "stale",
                "dirty",
                "temporary",
                "zero-version",
                "uuid",
                "unknown-secret",
                "ownership-only",
                "not-saved",
                "unvalidated-version",
            ] {
                let h = Harness::new()?;
                {
                    let mut s = h.state.lock().unwrap();
                    match failure {
                        "dirty" => s.dirty = true,
                        "temporary" => {
                            s.filename = "/run/NetworkManager/system-connections/temporary".into()
                        }
                        "zero-version" => s.version = 0,
                        "ownership-only" | "not-saved" => {
                            s.public
                                .get_mut("802-1x")
                                .context("fixture enterprise")?
                                .insert(
                                    "password-flags".into(),
                                    owned_value(if failure == "not-saved" { 2u32 } else { 1u32 })?,
                                );
                        }
                        _ => {}
                    }
                }
                let result = h.edit().and_then(|mut edit| {
                    {
                        let mut s = h.state.lock().unwrap();
                        s.fail_read = failure == "read";
                        s.fail_write = failure == "write";
                        s.race_read = failure == "race";
                        match failure {
                            "unvalidated-version" => s.nm_version = "1.60.0".into(),
                            "stale" => s.version += 1,
                            "uuid" => {
                                edit.settings
                                    .get_mut("connection")
                                    .context("fixture connection")?
                                    .insert("uuid".into(), owned_value("wrong-uuid")?);
                            }
                            "unknown-secret" => {
                                s.secrets.insert(
                                    "future-setting".into(),
                                    value_map([("new-secret", "keep-this-too".into())])?,
                                );
                            }
                            "ownership-only" | "not-saved" => {
                                let section = edit
                                    .settings
                                    .get_mut("802-1x")
                                    .context("fixture enterprise")?;
                                section.insert("password-flags".into(), owned_value(0u32)?);
                                if failure == "ownership-only" {
                                    section.remove("password");
                                }
                            }
                            _ => {}
                        }
                    }
                    h.nm.commit_credential_edit(edit, true)
                });
                let s = h.state.lock().unwrap();
                if failure == "none" {
                    result?;
                    let saved = s.written.as_ref().unwrap();
                    assert!(text(saved, "802-1x", "password").as_deref() == Some("replacement"));
                    assert!(
                        text(saved, "802-1x", "private-key-password").as_deref()
                            == Some("keep-private-key-password")
                    );
                    assert_eq!(
                        setting::<&str>(&saved["802-1x"], "domain-suffix-match"),
                        Some("example.invalid")
                    );
                    assert_eq!(s.writes, 1);
                } else {
                    let error = result.expect_err(failure);
                    assert!(!format!("{error:#}").contains("do-not-log-synthetic-value"));
                    assert!(s.written.is_none(), "{failure}");
                    assert_eq!(s.writes, usize::from(failure == "write"), "{failure}");
                }
            }
            Ok(())
        },
    )
}

#[test]
fn policy_preserves_not_required_and_blocks_ambiguous_shared_wep_conversion() -> Result<()> {
    for (section, key, policy) in [
        ("802-1x", "password", 4u32),
        ("802-11-wireless-security", "wep-key0", 1u32),
    ] {
        let original = ConnectionSettings::from([(
            section.into(),
            value_map([(flags_key(key).as_str(), policy.into())])?,
        )]);
        let mut edited = original.clone();
        set_text(&mut edited, section, key, "synthetic")?;
        edited
            .get_mut(section)
            .unwrap()
            .insert(flags_key(key), owned_value(0u32)?);
        assert!(validate_policy_changes(&original, &edited).is_err());
    }
    let mut settings = ConnectionSettings::from([(
        "802-1x".into(),
        value_map([("password-flags", 5u32.into())])?,
    )]);
    set_system_owned(&mut settings, "802-1x", "password")?;
    assert_eq!(flags(&settings, "802-1x", "password")?, 4);
    Ok(())
}
