use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use zbus::{Connection, Proxy, proxy::CacheProperties};
use zvariant::OwnedObjectPath;

use crate::nm::{
    ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, NM_DEST, NM_DEVICE_STATE_ACTIVATED,
    NM_IFACE, NM_PATH, SETTINGS_CONNECTION_IFACE,
};

pub(super) fn wifi_interfaces() -> Result<BTreeSet<String>> {
    let mut interfaces = BTreeSet::new();
    // Do not depend on NM already running to install the initial default-off
    // policy. This also closes discovery on unmanaged Linux wireless interfaces.
    for entry in std::fs::read_dir("/sys/class/net").context("enumerate network interfaces")? {
        let entry = entry?;
        if entry.path().join("phy80211").exists() || entry.path().join("wireless").exists() {
            let interface = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("Wi-Fi interface name is not valid UTF-8"))?;
            super::firewall::validate_interface(&interface)?;
            interfaces.insert(interface);
        }
    }
    ensure!(interfaces.len() <= 64, "too many Wi-Fi interfaces");
    Ok(interfaces)
}

async fn proxy<'a>(
    conn: &'a Connection,
    destination: &'a str,
    path: &'a str,
    interface: &'a str,
) -> Result<Proxy<'a>> {
    // A policy snapshot must not use zbus's asynchronously updated property cache.
    Ok(zbus::proxy::Builder::new(conn)
        .destination(destination)?
        .path(path)?
        .interface(interface)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?)
}

pub(super) async fn enabled_interfaces(
    conn: &Connection,
    wifi: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    // Never D-Bus-activate an intentionally stopped NM, or mix objects from
    // different NM processes during a restart. Pin the entire snapshot to its
    // current unique bus owner; GetNameOwner itself does not activate services.
    let owner = zbus::fdo::DBusProxy::builder(conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await?
        .get_name_owner(NM_DEST.try_into()?)
        .await?;
    let manager = proxy(conn, owner.as_str(), NM_PATH, NM_IFACE).await?;
    let devices: Vec<OwnedObjectPath> = manager.call("GetDevices", &()).await?;
    let mut enabled = BTreeSet::new();
    for path in devices {
        let device = proxy(conn, owner.as_str(), path.as_str(), DEVICE_IFACE).await?;
        let interface: String = device.get_property("Interface").await?;
        if wifi.contains(&interface) && device_enabled(conn, &device).await? {
            enabled.insert(interface);
        }
    }
    Ok(enabled)
}

async fn device_enabled(conn: &Connection, device: &Proxy<'_>) -> Result<bool> {
    if device.get_property::<u32>("State").await? != NM_DEVICE_STATE_ACTIVATED {
        return Ok(false);
    }
    let active_path: OwnedObjectPath = device.get_property("ActiveConnection").await?;
    if active_path.as_str() == "/" {
        return Ok(false);
    }
    let (applied, version): (ConnectionSettings, u64) =
        device.call("GetAppliedConnection", &(0_u32,)).await?;
    let active = proxy(
        conn,
        device.destination().as_str(),
        active_path.as_str(),
        ACTIVE_CONNECTION_IFACE,
    )
    .await?;
    let profile: OwnedObjectPath = active.get_property("Connection").await?;
    let saved: ConnectionSettings = proxy(
        conn,
        device.destination().as_str(),
        profile.as_str(),
        SETTINGS_CONNECTION_IFACE,
    )
    .await?
    .call("GetSettings", &())
    .await?;
    // Saved-off must close the firewall even if resolver reapply failed. Saved-on
    // must not open it while the old applied policy is off or activation is pending.
    let (_, current_version): (ConnectionSettings, u64) =
        device.call("GetAppliedConnection", &(0_u32,)).await?;
    let current_active: OwnedObjectPath = device.get_property("ActiveConnection").await?;
    let state: u32 = device.get_property("State").await?;
    Ok(policy_enabled(
        &saved,
        &applied,
        state,
        version,
        current_version,
        active_path == current_active,
    ))
}

fn mdns_enabled(settings: &ConnectionSettings) -> bool {
    settings
        .get("connection")
        .and_then(|connection| connection.get("mdns"))
        .and_then(|value| i32::try_from(value).ok())
        .is_some_and(|value| matches!(value, 1 | 2))
}

fn policy_enabled(
    saved: &ConnectionSettings,
    applied: &ConnectionSettings,
    state: u32,
    version: u64,
    current_version: u64,
    same_active: bool,
) -> bool {
    state == NM_DEVICE_STATE_ACTIVATED
        && version != 0
        && version == current_version
        && same_active
        && mdns_enabled(saved)
        && mdns_enabled(applied)
}

#[cfg(test)]
mod dbus;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::owned_value;

    pub(super) fn settings(mdns: i32) -> ConnectionSettings {
        ConnectionSettings::from([(
            "connection".into(),
            [("mdns".into(), owned_value(mdns).unwrap())].into(),
        )])
    }

    #[test]
    fn only_consistent_active_explicit_on_policies_open_the_firewall() {
        for saved in [-1, 0, 1, 2, 3] {
            for applied in [-1, 0, 1, 2, 3] {
                let expected = matches!(saved, 1 | 2) && matches!(applied, 1 | 2);
                assert_eq!(
                    policy_enabled(&settings(saved), &settings(applied), 100, 7, 7, true),
                    expected
                );
            }
        }
        for (state, version, current, same_active) in [
            (90, 7, 7, true),  // pre-up: closed even on an enabled network
            (110, 7, 7, true), // pre-down: close before switching networks
            (100, 0, 0, true),
            (100, 7, 8, true),
            (100, 7, 7, false),
        ] {
            assert!(!policy_enabled(
                &settings(1),
                &settings(1),
                state,
                version,
                current,
                same_active
            ));
        }
        assert!(!mdns_enabled(&ConnectionSettings::new()));
    }
}
