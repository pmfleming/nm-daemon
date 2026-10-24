use super::{Profile, SECRET, legacy_inventory_on};
use crate::test_support::{bus::TestBus, workflows::isolated};
use anyhow::Result;
use std::collections::{BTreeMap, HashMap};
use zvariant::OwnedObjectPath;

const FIRST: &str = "/items/a";
const SECOND: &str = "/items/b";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Success,
    QueryFailed,
    NewItem,
    Duplicate,
    OwnerLost,
}
struct Service {
    mode: Mode,
    connection: zbus::Connection,
}
#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        assert_eq!(
            attributes.get("application").map(String::as_str),
            Some("nm-daemon")
        );
        let path = |path: &str| OwnedObjectPath::try_from(path).unwrap();
        match attributes.get("uuid").map(String::as_str) {
            None if self.mode == Mode::Duplicate => Ok((vec![path(FIRST), path(FIRST)], vec![])),
            None => Ok((vec![path(FIRST)], vec![path(SECOND)])),
            Some("first") => Ok((vec![path(FIRST)], vec![])),
            Some("second") => {
                match self.mode {
                    Mode::QueryFailed => {
                        return Err(zbus::fdo::Error::Failed("metadata unavailable".into()));
                    }
                    Mode::NewItem => return Ok((vec![path("/items/new")], vec![])),
                    Mode::OwnerLost => {
                        self.connection.release_name(SECRET).await?;
                    }
                    _ => {}
                }
                Ok((vec![], vec![path(SECOND)]))
            }
            _ => panic!("unexpected UUID filter"),
        }
    }
}
struct Item(bool);
#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        if self.0 {
            HashMap::from([("uuid".into(), "first".into())])
        } else {
            HashMap::new()
        }
    }
}
fn profile(uuid: &str) -> Profile {
    Profile {
        uuid: uuid.into(),
        name: uuid.into(),
        kind: "wifi".into(),
        path: "/profile".into(),
        filename: String::new(),
        unsaved: false,
        version: 1,
        permissions: vec![],
        autoconnect: false,
        secret_flags: BTreeMap::new(),
        legacy_items: vec!["previous".into()],
    }
}

#[test]
fn inventory_publishes_only_complete_owner_fenced_associations() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::inventory_publishes_only_complete_owner_fenced_associations"
        ),
        || {
            for mode in [
                Mode::Success,
                Mode::QueryFailed,
                Mode::NewItem,
                Mode::Duplicate,
                Mode::OwnerLost,
            ] {
                let bus = TestBus::new()?;
                let server = bus.connect()?;
                server.object_server().at(
                    "/org/freedesktop/secrets",
                    Service {
                        mode,
                        connection: server.inner().clone(),
                    },
                )?;
                server.object_server().at(FIRST, Item(true))?;
                server.object_server().at(SECOND, Item(false))?;
                server.request_name(SECRET)?;
                let mut profiles = [profile("first"), profile("second")];
                let result = legacy_inventory_on(&bus.connect()?, &mut profiles);
                if mode != Mode::Success {
                    assert!(result.is_err(), "{mode:?}");
                    assert!(
                        profiles
                            .iter()
                            .all(|profile| profile.legacy_items == ["previous"]),
                        "{mode:?}: partial links escaped"
                    );
                    continue;
                }
                let legacy = result?;
                assert!(legacy.available && legacy.error.is_none());
                assert_eq!(profiles[0].legacy_items, [FIRST]);
                assert_eq!(profiles[1].legacy_items, [SECOND]);
                assert_eq!(
                    legacy
                        .items
                        .iter()
                        .map(|item| item.path.as_str())
                        .collect::<Vec<_>>(),
                    [FIRST, SECOND]
                );
                assert_eq!(legacy.items[0].matched_profiles, ["first"]);
                assert_eq!(legacy.items[1].matched_profiles, ["second"]);
                assert!(!legacy.items[0].locked && legacy.items[0].attributes_visible);
                assert!(legacy.items[1].locked && !legacy.items[1].attributes_visible);
                assert!(
                    legacy.items[1].uuid.is_none(),
                    "hidden attributes must not prevent UUID-query matching"
                );
            }
            Ok(())
        },
    )
}
