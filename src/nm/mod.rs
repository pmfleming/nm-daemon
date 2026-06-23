use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use zbus::blocking::{Connection, Proxy};
use zvariant::{OwnedObjectPath, OwnedValue};

mod activate;
mod devices;
mod scan;
mod settings;

pub(crate) const NM_DEST: &str = "org.freedesktop.NetworkManager";
pub(crate) const WIFI_IFACE: &str = "org.freedesktop.NetworkManager.Device.Wireless";
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(250);

pub(super) const NM_PATH: &str = "/org/freedesktop/NetworkManager";
pub(super) const NM_IFACE: &str = "org.freedesktop.NetworkManager";
pub(super) const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
pub(super) const SETTINGS_IFACE: &str = "org.freedesktop.NetworkManager.Settings";
pub(super) const SETTINGS_CONNECTION_IFACE: &str =
    "org.freedesktop.NetworkManager.Settings.Connection";
pub(super) const DEVICE_IFACE: &str = "org.freedesktop.NetworkManager.Device";
pub(super) const ACTIVE_CONNECTION_IFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";
pub(super) const AP_IFACE: &str = "org.freedesktop.NetworkManager.AccessPoint";
pub(super) const NM_DEVICE_TYPE_WIFI: u32 = 2;
pub(super) const NM_DEVICE_STATE_DISCONNECTED: u32 = 30;
pub(super) const NM_DEVICE_STATE_ACTIVATED: u32 = 100;
pub(super) const NM_DEVICE_STATE_DEACTIVATING: u32 = 110;
pub(super) const NM_ACTIVE_CONNECTION_STATE_ACTIVATED: u32 = 2;

pub(super) type ConnectionSettings = HashMap<String, HashMap<String, OwnedValue>>;

#[derive(Debug, Clone)]
pub(crate) struct WifiActivationStatus {
    pub(crate) iface: String,
    pub(crate) device_state: u32,
    pub(crate) device_state_reason: (u32, u32),
    pub(crate) active_connection_state: Option<u32>,
}

impl WifiActivationStatus {
    pub(crate) fn activated(&self) -> bool {
        self.device_state == NM_DEVICE_STATE_ACTIVATED
            && self.active_connection_state == Some(NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
    }

    pub(crate) fn terminal_failure_after_progress(&self) -> bool {
        self.device_state <= NM_DEVICE_STATE_DISCONNECTED
            || self.device_state >= NM_DEVICE_STATE_DEACTIVATING
    }
}

pub(crate) struct Nm {
    conn: Connection,
}

impl Nm {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            conn: Connection::system().context("connect to system D-Bus")?,
        })
    }

    pub(crate) fn connection(&self) -> Connection {
        self.conn.clone()
    }

    pub(super) fn proxy<'a>(&'a self, path: &'a str, iface: &'a str) -> Result<Proxy<'a>> {
        Proxy::new(&self.conn, NM_DEST, path, iface).context("create D-Bus proxy")
    }

    pub(super) fn proxy_path<'a>(
        &'a self,
        path: &'a OwnedObjectPath,
        iface: &'a str,
    ) -> Result<Proxy<'a>> {
        self.proxy(path.as_str(), iface)
    }
}
