use super::{SECRET, discard_on};
use crate::test_support::{bus::TestBus, workflows::isolated};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use zvariant::OwnedObjectPath;

const ITEM: &str = "/org/freedesktop/secrets/collection/test/1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Success,
    ForeignApplication,
    Locked,
    WrongUuid,
    Prompt,
    IdentityChanged,
    MetadataChanged,
    ModifiedChanged,
    LockChanged,
    StillPresent,
}
struct State {
    mode: Mode,
    reads: AtomicUsize,
    deletes: AtomicUsize,
    secret_reads: AtomicUsize,
}
fn identity() -> HashMap<String, String> {
    [
        ("application", "nm-daemon"),
        ("uuid", "fixture-uuid"),
        ("setting", "802-11-wireless-security"),
        ("key", "psk"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect()
}
struct Service(Arc<State>);
#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        assert_eq!(
            attributes,
            identity(),
            "search must be exact, never provider-wide"
        );
        let items = if self.0.deletes.load(Ordering::SeqCst) > 0
            && !matches!(self.0.mode, Mode::Prompt | Mode::StillPresent)
        {
            vec![]
        } else {
            vec![ITEM.try_into().unwrap()]
        };
        if self.0.mode == Mode::Locked {
            (vec![], items)
        } else {
            (items, vec![])
        }
    }
}
struct Item(Arc<State>);
#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        let read = self.0.reads.fetch_add(1, Ordering::SeqCst);
        let mut attributes = identity();
        match self.0.mode {
            Mode::ForeignApplication => {
                attributes.insert("application".into(), "foreign".into());
            }
            Mode::WrongUuid => {
                attributes.insert("uuid".into(), "different".into());
            }
            Mode::IdentityChanged if read > 0 => {
                attributes.insert("uuid".into(), "different".into());
            }
            Mode::MetadataChanged if read > 0 => {
                attributes.insert("extra".into(), "changed".into());
            }
            _ => {}
        }
        attributes
    }
    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.mode == Mode::Locked
            || (self.0.mode == Mode::LockChanged && self.0.reads.load(Ordering::SeqCst) > 1)
    }
    #[zbus(property)]
    fn modified(&self) -> u64 {
        if self.0.mode == Mode::ModifiedChanged && self.0.reads.load(Ordering::SeqCst) > 1 {
            2
        } else {
            1
        }
    }
    fn delete(&self) -> OwnedObjectPath {
        self.0.deletes.fetch_add(1, Ordering::SeqCst);
        if self.0.mode == Mode::Prompt {
            "/prompt"
        } else {
            "/"
        }
        .try_into()
        .unwrap()
    }
    fn get_secret(&self, _session: OwnedObjectPath) -> String {
        self.0.secret_reads.fetch_add(1, Ordering::SeqCst);
        "must-not-read".into()
    }
}

#[test]
fn disposal_is_exact_scoped_and_never_treats_a_prompt_as_deletion() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::disposal_is_exact_scoped_and_never_treats_a_prompt_as_deletion"
        ),
        || {
            for mode in [
                Mode::Success,
                Mode::ForeignApplication,
                Mode::Locked,
                Mode::WrongUuid,
                Mode::Prompt,
                Mode::IdentityChanged,
                Mode::MetadataChanged,
                Mode::ModifiedChanged,
                Mode::LockChanged,
                Mode::StillPresent,
            ] {
                let bus = TestBus::new()?;
                let server = bus.connect()?;
                let state = Arc::new(State {
                    mode,
                    reads: AtomicUsize::new(0),
                    deletes: AtomicUsize::new(0),
                    secret_reads: AtomicUsize::new(0),
                });
                server
                    .object_server()
                    .at("/org/freedesktop/secrets", Service(state.clone()))?;
                server.object_server().at(ITEM, Item(state.clone()))?;
                server.request_name(SECRET)?;
                let client = bus.connect()?;
                for identity in [
                    ("", "802-11-wireless-security", "psk"),
                    ("fixture-uuid", "", "psk"),
                    ("fixture-uuid", "802-11-wireless-security", ""),
                ] {
                    assert!(discard_on(&client, ITEM, identity.0, identity.1, identity.2).is_err());
                }
                assert_eq!(
                    state.reads.load(Ordering::SeqCst),
                    0,
                    "empty identity fails before metadata reads"
                );
                let result = discard_on(
                    &client,
                    ITEM,
                    "fixture-uuid",
                    "802-11-wireless-security",
                    "psk",
                );
                assert_eq!(result.is_ok(), mode == Mode::Success, "{mode:?}");
                assert_eq!(
                    state.deletes.load(Ordering::SeqCst),
                    usize::from(matches!(
                        mode,
                        Mode::Success | Mode::Prompt | Mode::StillPresent
                    )),
                    "{mode:?}"
                );
                assert_eq!(state.secret_reads.load(Ordering::SeqCst), 0, "{mode:?}");
            }
            Ok(())
        },
    )
}
