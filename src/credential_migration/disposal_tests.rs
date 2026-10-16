use super::*;
use crate::test_support::{bus::TestBus, workflows::isolated};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const ITEM: &str = "/org/freedesktop/secrets/collection/test/1";
struct State {
    mode: usize,
    reads: AtomicUsize,
    deletes: AtomicUsize,
}
struct Service(Arc<State>);
#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    fn search_items(
        &self,
        _attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let items = if self.0.deletes.load(Ordering::SeqCst) > 0 && self.0.mode != 4 {
            vec![]
        } else {
            vec![ITEM.try_into().unwrap()]
        };
        if self.0.mode == 2 {
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
        HashMap::from([
            (
                "application".into(),
                if self.0.mode == 1 {
                    "another-application"
                } else {
                    "nm-daemon"
                }
                .into(),
            ),
            (
                "uuid".into(),
                if self.0.mode == 3 || (self.0.mode == 5 && read > 0) {
                    "different"
                } else {
                    "fixture-uuid"
                }
                .into(),
            ),
            ("setting".into(), "802-11-wireless-security".into()),
            ("key".into(), "psk".into()),
        ])
    }
    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.mode == 2
    }
    #[zbus(property)]
    fn modified(&self) -> u64 {
        1
    }
    fn delete(&self) -> OwnedObjectPath {
        self.0.deletes.fetch_add(1, Ordering::SeqCst);
        if self.0.mode == 4 { "/prompt" } else { "/" }
            .try_into()
            .unwrap()
    }
    fn get_secret(&self, _session: OwnedObjectPath) -> String {
        panic!("disposal must never read a password")
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
            for mode in 0..6 {
                let bus = TestBus::new()?;
                let server = bus.connect()?;
                let state = Arc::new(State {
                    mode,
                    reads: AtomicUsize::new(0),
                    deletes: AtomicUsize::new(0),
                });
                server
                    .object_server()
                    .at("/org/freedesktop/secrets", Service(state.clone()))?;
                server.object_server().at(ITEM, Item(state.clone()))?;
                server.request_name(SECRET)?;
                let result = discard_on(
                    &bus.connect()?,
                    ITEM,
                    "fixture-uuid",
                    "802-11-wireless-security",
                    "psk",
                );
                assert_eq!(result.is_ok(), mode == 0, "mode {mode}");
                assert_eq!(
                    state.deletes.load(Ordering::SeqCst),
                    usize::from(mode == 0 || mode == 4)
                );
            }
            Ok(())
        },
    )
}
