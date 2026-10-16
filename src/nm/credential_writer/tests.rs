use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use zvariant::{OwnedObjectPath, OwnedValue};

use super::*;
use crate::test_support::{TestPeer, workflows::isolated};
use crate::variant::value_map;

const PATH: &str = "/test/profile";
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
}
struct Manager(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Manager {
    #[zbus(property)]
    fn version(&self) -> String {
        self.0.lock().unwrap().nm_version.clone()
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
        assert!(flags == 1 || flags == 33, "explicit TO_DISK required");
        assert_eq!(u64::try_from(&args["version-id"]).unwrap(), s.version);
        assert_ne!(s.version, 0);
        if s.fail_write {
            return Err(zbus::fdo::Error::Failed(
                "do-not-log-synthetic-value".into(),
            ));
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
            dirty: false,
            filename: "/etc/NetworkManager/system-connections/fixture.nmconnection".into(),
            fail_read: false,
            fail_write: false,
            race_read: false,
            reads: 0,
            writes: 0,
            written: None,
        }));
        let peer = TestPeer::new(":1.0", ":1.1");
        peer.server
            .object_server()
            .at(crate::nm::NM_PATH, Manager(state.clone()))?;
        peer.server
            .object_server()
            .at(PATH, Profile(state.clone()))?;
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
        edit.settings
            .get_mut("802-1x")
            .unwrap()
            .insert("password".into(), owned_value("replacement")?);
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
                if matches!(failure, "dirty" | "temporary" | "zero-version") {
                    let mut s = h.state.lock().unwrap();
                    s.dirty = failure == "dirty";
                    if failure == "temporary" {
                        s.filename = "/run/NetworkManager/system-connections/temporary".into();
                    }
                    if failure == "zero-version" {
                        s.version = 0;
                    }
                    drop(s);
                    assert!(h.edit().is_err(), "{failure}");
                    assert_eq!(h.state.lock().unwrap().writes, 0);
                    continue;
                }
                if matches!(failure, "ownership-only" | "not-saved") {
                    h.state
                        .lock()
                        .unwrap()
                        .public
                        .get_mut("802-1x")
                        .unwrap()
                        .insert(
                            "password-flags".into(),
                            owned_value(if failure == "not-saved" { 2u32 } else { 1u32 })?,
                        );
                }
                let mut edit = h.edit()?;
                {
                    let mut s = h.state.lock().unwrap();
                    s.fail_read = failure == "read";
                    s.fail_write = failure == "write";
                    s.race_read = failure == "race";
                    if failure == "unvalidated-version" {
                        s.nm_version = "1.60.0".into();
                    }
                    if failure == "stale" {
                        s.version += 1;
                    }
                    if failure == "uuid" {
                        edit.settings
                            .get_mut("connection")
                            .unwrap()
                            .insert("uuid".into(), owned_value("wrong-uuid")?);
                    }
                    if failure == "unknown-secret" {
                        s.secrets.insert(
                            "future-setting".into(),
                            value_map([("new-secret", "keep-this-too".into())])?,
                        );
                    }
                    if matches!(failure, "ownership-only" | "not-saved") {
                        edit.settings
                            .get_mut("802-1x")
                            .unwrap()
                            .insert("password-flags".into(), owned_value(0u32)?);
                        if failure == "ownership-only" {
                            edit.settings.get_mut("802-1x").unwrap().remove("password");
                        }
                    }
                }
                let result = h.nm.commit_credential_edit(edit, true);
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
                    let error = result.err().expect(failure);
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
            HashMap::from([(
                crate::network_credentials::flags_key(key),
                owned_value(policy)?,
            )]),
        )]);
        let mut edited = original.clone();
        crate::network_credentials::set_text(&mut edited, section, key, "synthetic".into())?;
        edited.get_mut(section).unwrap().insert(
            crate::network_credentials::flags_key(key),
            owned_value(0u32)?,
        );
        assert!(validate_policy_changes(&original, &edited).is_err());
    }
    let mut settings = ConnectionSettings::from([(
        "802-1x".into(),
        value_map([("password-flags", 5u32.into())])?,
    )]);
    crate::network_credentials::set_system_owned(&mut settings, "802-1x", "password")?;
    assert_eq!(flags(&settings, "802-1x", "password")?, 4);
    Ok(())
}
