use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use zbus::blocking::{Connection, Proxy};
use zvariant::{OwnedObjectPath, OwnedValue};

use crate::command::{CommandRunner, default_runner};
use crate::error::{ErrorOperation, ensure_domain};
use crate::nl80211::{KernelWirelessTelemetry, WirelessTelemetry};

mod activate;
mod connectivity;
mod devices;
mod events;
mod scan;
mod settings;
mod status;
mod wifi_settings;

pub(crate) const NM_DEST: &str = "org.freedesktop.NetworkManager";
pub(crate) const WIFI_IFACE: &str = "org.freedesktop.NetworkManager.Device.Wireless";

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
pub(super) const NM_ACTIVE_CONNECTION_STATE_ACTIVATED: u32 = 2;

pub(crate) type ConnectionSettings = HashMap<String, HashMap<String, OwnedValue>>;
pub(super) use crate::variant::owned_value;

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
        // NetworkManager commonly moves a Wi-Fi device through low states while
        // replacing an existing active connection. The caller applies a grace
        // period before treating this as terminal.
        self.device_state <= NM_DEVICE_STATE_DISCONNECTED
    }
}

pub(crate) struct Nm {
    conn: Connection,
    destination: String,
    commands: Arc<dyn CommandRunner>,
    events: Arc<events::NetworkEvents>,
    wireless_telemetry: Arc<dyn WirelessTelemetry>,
}

impl Nm {
    pub(crate) fn new() -> Result<Self> {
        Self::with_command_runner(default_runner())
    }

    pub(crate) fn with_command_runner(commands: Arc<dyn CommandRunner>) -> Result<Self> {
        let conn = Connection::system()
            .map_err(|error| ensure_domain(ErrorOperation::ConnectSystemBus, error.into()))?;
        Ok(Self::with_connection_and_runner(conn, commands))
    }

    pub(crate) fn with_connection_and_runner(
        conn: Connection,
        commands: Arc<dyn CommandRunner>,
    ) -> Self {
        Self::with_connection_runner_and_destination(conn, commands, NM_DEST)
    }

    pub(crate) fn with_connection_runner_and_destination(
        conn: Connection,
        commands: Arc<dyn CommandRunner>,
        destination: impl Into<String>,
    ) -> Self {
        Self::with_connection_runner_destination_and_telemetry(
            conn,
            commands,
            destination,
            Arc::new(KernelWirelessTelemetry),
        )
    }

    pub(crate) fn with_connection_runner_destination_and_telemetry(
        conn: Connection,
        commands: Arc<dyn CommandRunner>,
        destination: impl Into<String>,
        wireless_telemetry: Arc<dyn WirelessTelemetry>,
    ) -> Self {
        Self {
            events: events::NetworkEvents::start(conn.clone()),
            conn,
            destination: destination.into(),
            commands,
            wireless_telemetry,
        }
    }

    pub(crate) fn connection(&self) -> Connection {
        self.conn.clone()
    }

    pub(crate) fn command_runner(&self) -> &dyn CommandRunner {
        self.commands.as_ref()
    }

    pub(crate) fn wireless_telemetry(&self) -> &dyn WirelessTelemetry {
        self.wireless_telemetry.as_ref()
    }

    pub(crate) fn event_generation(&self) -> u64 {
        self.events.generation()
    }

    pub(crate) fn wait_for_event(&self, observed: u64, timeout: Duration) -> u64 {
        self.events.wait_for_change(observed, timeout)
    }

    pub(crate) fn subscribe_events(&self, listener: Arc<dyn Fn() + Send + Sync>) {
        self.events.subscribe(listener);
    }

    pub(crate) fn wake_waiters(&self) {
        self.events.notify();
    }

    pub(super) fn proxy<'a>(&'a self, path: &'a str, iface: &'a str) -> Result<Proxy<'a>> {
        Proxy::new(&self.conn, self.destination.as_str(), path, iface)
            .map_err(|error| ensure_domain(ErrorOperation::CreateDbusProxy, error.into()))
    }

    pub(super) fn proxy_path<'a>(
        &'a self,
        path: &'a OwnedObjectPath,
        iface: &'a str,
    ) -> Result<Proxy<'a>> {
        self.proxy(path.as_str(), iface)
    }
}
