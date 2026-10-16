//! Explicit legacy credential inventory and opt-in exact-item disposal.
//! Never run at daemon startup. Never read secret values or unlock a vault.
use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result};
use serde::Serialize;
use zbus::blocking::{Connection, Proxy};
use zvariant::{OwnedObjectPath, OwnedValue};

use crate::nm::ConnectionSettings;
use crate::variant::{setting, setting_strings, value_string_map};

const NM: &str = "org.freedesktop.NetworkManager";
const PROFILE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const SECRET: &str = "org.freedesktop.secrets";

#[cfg(test)]
mod disposal_tests;

#[derive(Serialize)]
struct Inventory {
    schema: u32,
    read_only: bool,
    secret_values_read: bool,
    networkmanager_version: String,
    profiles: Vec<Profile>,
    legacy: Legacy,
}

#[derive(Serialize)]
struct Profile {
    uuid: String,
    name: String,
    kind: String,
    path: String,
    filename: String,
    unsaved: bool,
    version: u64,
    permissions: Vec<String>,
    autoconnect: bool,
    secret_flags: BTreeMap<String, u32>,
    legacy_items: Vec<String>,
}

#[derive(Default, Serialize)]
struct Legacy {
    available: bool,
    error: Option<String>,
    items: Vec<LegacyItem>,
}

#[derive(Serialize)]
struct LegacyItem {
    path: String,
    locked: bool,
    // Locked providers may hide attributes; UUID queries still find matches.
    attributes_visible: bool,
    uuid: Option<String>,
    setting: Option<String>,
    key: Option<String>,
    legacy_path_only: bool,
    matched_profiles: Vec<String>,
}

pub fn run() -> Result<()> {
    let inventory = inventory()?;
    println!("{}", serde_json::to_string_pretty(&inventory)?);
    Ok(())
}

/// Destructive opt-in: the caller explicitly accepts losing this credential.
/// This is not migration and does not claim an NM replacement exists.
pub fn discard_legacy(item: &str, uuid: &str, setting: &str, key: &str) -> Result<()> {
    let connection = zbus::blocking::connection::Builder::session()?
        .method_timeout(std::time::Duration::from_secs(5))
        .build()?;
    discard_on(&connection, item, uuid, setting, key)?;
    println!("Deleted one verified nm-daemon credential; no password was read or copied.");
    Ok(())
}

fn discard_on(
    connection: &Connection,
    path: &str,
    uuid: &str,
    setting: &str,
    key: &str,
) -> Result<()> {
    anyhow::ensure!(
        !uuid.is_empty() && !setting.is_empty() && !key.is_empty(),
        "exact item identity is required"
    );
    let bus = zbus::blocking::fdo::DBusProxy::new(connection)?;
    let owner = bus.get_name_owner(SECRET.try_into()?)?.to_string();
    let service = Proxy::new(
        connection,
        owner.as_str(),
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )?;
    let expected = HashMap::from([
        ("application", "nm-daemon"),
        ("uuid", uuid),
        ("setting", setting),
        ("key", key),
    ]);
    let search = || -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        service
            .call("SearchItems", &(expected.clone(),))
            .map_err(|_| anyhow::anyhow!("legacy metadata search failed"))
    };
    let (unlocked, locked) = search()?;
    anyhow::ensure!(
        unlocked.iter().any(|p| p.as_str() == path) && !locked.iter().any(|p| p.as_str() == path),
        "exact item is absent or locked; no deletion attempted"
    );
    let item = zbus::blocking::proxy::Builder::<Proxy>::new(connection)
        .destination(owner.as_str())?
        .path(path)?
        .interface("org.freedesktop.Secret.Item")?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()?;
    let check = || -> Result<HashMap<String, String>> {
        let attributes: HashMap<String, String> = item.get_property("Attributes")?;
        anyhow::ensure!(
            expected
                .iter()
                .all(|(k, v)| attributes.get(*k).map(String::as_str) == Some(*v)),
            "item ownership/identity mismatch; no deletion attempted"
        );
        anyhow::ensure!(
            !item.get_property::<bool>("Locked")?,
            "item is locked; no deletion attempted"
        );
        Ok(attributes)
    };
    let attributes = check()?;
    let modified: u64 = item.get_property("Modified")?;
    anyhow::ensure!(
        check()? == attributes
            && item.get_property::<u64>("Modified")? == modified
            && bus.get_name_owner(SECRET.try_into()?)?.as_str() == owner,
        "item/provider changed; no deletion attempted"
    );
    let prompt: OwnedObjectPath = item.call("Delete", &()).map_err(|_| {
        anyhow::anyhow!("item deletion not acknowledged; re-inventory before retrying")
    })?;
    anyhow::ensure!(
        prompt.as_str() == "/",
        "deletion requires a provider prompt; completion unconfirmed, no prompt presented or dismissed"
    );
    let (unlocked, locked) = search()?;
    anyhow::ensure!(
        !unlocked.iter().chain(&locked).any(|p| p.as_str() == path)
            && bus.get_name_owner(SECRET.try_into()?)?.as_str() == owner,
        "deletion outcome unconfirmed; re-inventory before retrying"
    );
    Ok(())
}

fn inventory() -> Result<Inventory> {
    let connection = Connection::system().context("connect to NetworkManager bus")?;
    let bus = zbus::blocking::fdo::DBusProxy::new(&connection)?;
    let owner = bus.get_name_owner(NM.try_into()?)?.to_string();
    let root = Proxy::new(
        &connection,
        owner.as_str(),
        "/org/freedesktop/NetworkManager",
        NM,
    )?;
    let version = root.get_property("Version")?;
    let settings = Proxy::new(
        &connection,
        owner.as_str(),
        "/org/freedesktop/NetworkManager/Settings",
        "org.freedesktop.NetworkManager.Settings",
    )?;
    let paths: Vec<OwnedObjectPath> = settings.call("ListConnections", &())?;
    let mut profiles = Vec::new();
    for path in paths {
        let profile = Proxy::new(&connection, owner.as_str(), path.as_str(), PROFILE)?;
        let settings: ConnectionSettings = profile.call("GetSettings", &())?;
        let metadata = settings
            .get("connection")
            .context("profile has no identity")?;
        let text = |key| {
            setting::<&str>(metadata, key)
                .unwrap_or_default()
                .to_string()
        };
        profiles.push(Profile {
            uuid: text("uuid"),
            name: text("id"),
            kind: text("type"),
            path: path.to_string(),
            filename: profile.get_property("Filename")?,
            unsaved: profile.get_property("Unsaved")?,
            version: profile.get_property("VersionId")?,
            permissions: setting_strings(metadata, "permissions"),
            autoconnect: setting(metadata, "autoconnect").unwrap_or(true),
            secret_flags: flag_inventory(&settings)?,
            legacy_items: Vec::new(),
        });
    }
    profiles.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    let legacy = legacy_inventory(&mut profiles).unwrap_or_else(|_| Legacy {
        error: Some(
            "Legacy metadata unavailable; inventory is incomplete (no unlock attempted)".into(),
        ),
        ..Default::default()
    });
    anyhow::ensure!(
        bus.get_name_owner(NM.try_into()?)?.as_str() == owner,
        "NetworkManager changed during inventory; retry"
    );
    Ok(Inventory {
        schema: 1,
        read_only: true,
        secret_values_read: false,
        networkmanager_version: version,
        profiles,
        legacy,
    })
}

fn legacy_inventory(profiles: &mut [Profile]) -> Result<Legacy> {
    let connection = Connection::session()?;
    let bus = zbus::blocking::fdo::DBusProxy::new(&connection)?;
    // Do not activate an absent provider during inventory.
    let owner = bus.get_name_owner(SECRET.try_into()?)?.to_string();
    let service = Proxy::new(
        &connection,
        owner.as_str(),
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )?;
    let search = |uuid: Option<&str>| -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let mut attributes = HashMap::from([("application", "nm-daemon")]);
        if let Some(uuid) = uuid {
            attributes.insert("uuid", uuid);
        }
        Ok(service.call("SearchItems", &(attributes,))?)
    };
    let (unlocked, locked) = search(None)?;
    let mut items = Vec::new();
    for (path, locked) in unlocked
        .into_iter()
        .map(|p| (p, false))
        .chain(locked.into_iter().map(|p| (p, true)))
    {
        let item = Proxy::new(
            &connection,
            owner.as_str(),
            path.as_str(),
            "org.freedesktop.Secret.Item",
        )?;
        let attributes: HashMap<String, String> = item.get_property("Attributes")?;
        items.push(LegacyItem {
            path: path.to_string(),
            locked,
            attributes_visible: !attributes.is_empty(),
            uuid: attributes.get("uuid").cloned(),
            setting: attributes.get("setting").cloned(),
            key: attributes.get("key").cloned(),
            legacy_path_only: attributes.contains_key("connection_path")
                && !attributes.contains_key("uuid"),
            matched_profiles: Vec::new(),
        });
    }
    for profile in profiles {
        let (unlocked, locked) = search(Some(&profile.uuid))?;
        for path in unlocked.into_iter().chain(locked) {
            profile.legacy_items.push(path.to_string());
            if let Some(item) = items.iter_mut().find(|i| i.path == path.as_str()) {
                item.matched_profiles.push(profile.uuid.clone());
            }
        }
        profile.legacy_items.sort();
    }
    items.sort_by(|a, b| a.path.cmp(&b.path));
    anyhow::ensure!(
        bus.get_name_owner(SECRET.try_into()?)?.as_str() == owner,
        "provider replaced"
    );
    Ok(Legacy {
        available: true,
        error: None,
        items,
    })
}

fn flag_inventory(settings: &ConnectionSettings) -> Result<BTreeMap<String, u32>> {
    let mut flags = BTreeMap::new();
    for (name, section) in settings {
        // GetSettings contains no secrets. Still serialize only flag values,
        // never arbitrary settings, VPN data, peer dictionaries or attributes.
        for (key, value) in section {
            if key.ends_with("-flags")
                && let Ok(value) = u32::try_from(value)
            {
                flags.insert(format!("{name}.{key}"), value);
            }
        }
        if name == "vpn"
            && let Some(data) = section.get("data").and_then(value_string_map)
        {
            for (key, value) in data {
                if key.ends_with("-flags")
                    && let Ok(value) = value.parse()
                {
                    flags.insert(format!("vpn.data.{key}"), value);
                }
            }
        }
        if name == "wireguard"
            && let Some(peers) = section.get("peers")
        {
            let peers: Vec<HashMap<String, OwnedValue>> = peers.try_clone()?.try_into()?;
            for (index, peer) in peers.iter().enumerate() {
                if let Some(value) = setting::<u32>(peer, "preshared-key-flags") {
                    flags.insert(
                        format!("wireguard.peers[{index}].preshared-key-flags"),
                        value,
                    );
                }
            }
        }
    }
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variant::{owned_value, value_map};

    #[test]
    fn inventory_only_serializes_flag_values_not_passwords_or_plugin_data() -> Result<()> {
        let settings = ConnectionSettings::from([
            (
                "802-11-wireless-security".into(),
                value_map([("psk", "do-not-print".into()), ("psk-flags", 0u32.into())])?,
            ),
            (
                "vpn".into(),
                HashMap::from([(
                    "data".into(),
                    owned_value(HashMap::from([
                        ("password-flags".to_string(), "1".to_string()),
                        ("cookie".into(), "do-not-print".into()),
                    ]))?,
                )]),
            ),
        ]);
        let encoded = serde_json::to_string(&flag_inventory(&settings)?)?;
        assert!(!encoded.contains("do-not-print"));
        assert!(!encoded.contains("cookie"));
        assert!(encoded.contains("vpn.data.password-flags"));
        Ok(())
    }
}
