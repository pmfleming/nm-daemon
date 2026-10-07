use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::Result;
use zbus::blocking::{Connection, Proxy};
use zvariant::{OwnedObjectPath, OwnedValue};

use crate::command::{CommandRunner, default_runner};
use crate::error::{ErrorOperation, ensure_domain};
use crate::nl80211::{KernelWirelessTelemetry, WirelessTelemetry};

mod activate;
mod band;
mod connectivity;
mod devices;
mod events;
mod health;
mod hotspot;
mod inventory;
mod ip_settings;
mod ip_status;
mod profile_policy;
mod scan;
mod scan_schedule;
mod settings;
mod statistics;
mod status;
mod vpn;
mod wifi_settings;

pub(crate) use events::{HealthSignal, HealthSubject};
pub(crate) use health::{HealthSeverity, HealthTransitionKind, NetworkHealthEvent};
pub(crate) use hotspot::HotspotRequest;
pub(crate) use inventory::{ActiveConnectionSelector, ProfileSelector};
pub(crate) use statistics::{StatisticsDevice, statistics_rates};
pub(crate) use vpn::VpnSelector;

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
pub(super) const NM_DEVICE_TYPE_MODEM: u32 = 8;
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
    pub(crate) active_connection_path: Option<OwnedObjectPath>,
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

#[derive(Debug, Default)]
pub(super) struct RadioRestoreState {
    pub(super) airplane_mode: bool,
    pub(super) wireless_enabled: bool,
    pub(super) wwan_enabled: bool,
}

pub(crate) struct Nm {
    conn: Connection,
    destination: String,
    service_name: String,
    scope: Mutex<Option<Arc<Nm>>>,
    // Store async handles so dropping an owner scope on an async control path
    // cannot invoke the blocking proxy destructor's nested runtime.
    root_proxy: zbus::Proxy<'static>,
    settings_proxy: zbus::Proxy<'static>,
    commands: Arc<dyn CommandRunner>,
    events: Arc<events::NetworkEvents>,
    wireless_telemetry: Arc<dyn WirelessTelemetry>,
    radio_restore: Mutex<RadioRestoreState>,
    profile_transaction: Mutex<()>,
    statistics: statistics::StatisticsRefresh,
    scan_schedule: scan_schedule::ScanScheduler,
}

impl Nm {
    pub(crate) fn new() -> Result<Self> {
        Self::with_command_runner(default_runner())
    }

    pub(crate) fn with_command_runner(commands: Arc<dyn CommandRunner>) -> Result<Self> {
        let conn = Connection::system()
            .map_err(|error| ensure_domain(ErrorOperation::ConnectSystemBus, error.into()))?;
        Self::with_connection_runner_destination_and_telemetry(
            conn,
            commands,
            NM_DEST,
            Arc::new(KernelWirelessTelemetry),
        )
    }

    pub(crate) fn with_connection_runner_destination_and_telemetry(
        conn: Connection,
        commands: Arc<dyn CommandRunner>,
        destination: impl Into<String>,
        wireless_telemetry: Arc<dyn WirelessTelemetry>,
    ) -> Result<Self> {
        let destination = destination.into();
        let events = events::NetworkEvents::start(conn.clone(), destination.clone());
        Self::from_parts(
            conn,
            commands,
            destination.clone(),
            destination,
            wireless_telemetry,
            events,
        )
    }

    fn from_parts(
        conn: Connection,
        commands: Arc<dyn CommandRunner>,
        destination: String,
        service_name: String,
        wireless_telemetry: Arc<dyn WirelessTelemetry>,
        events: Arc<events::NetworkEvents>,
    ) -> Result<Self> {
        let root_proxy = uncached_proxy(&conn, &destination, NM_PATH, NM_IFACE)?.into_inner();
        let settings_proxy =
            uncached_proxy(&conn, &destination, SETTINGS_PATH, SETTINGS_IFACE)?.into_inner();
        Ok(Self {
            events,
            conn,
            destination,
            service_name,
            scope: Mutex::new(None),
            root_proxy,
            settings_proxy,
            commands,
            wireless_telemetry,
            radio_restore: Mutex::new(RadioRestoreState::default()),
            profile_transaction: Mutex::new(()),
            statistics: statistics::StatisticsRefresh::default(),
            scan_schedule: scan_schedule::ScanScheduler::default(),
        })
    }

    /// Resolve without activating NM. An operation retains this unique owner
    /// through retries, cancellation and rollback, including time spent queued.
    pub(crate) fn scoped(&self) -> Result<Arc<Self>> {
        let owner = self.current_owner()?;
        let mut scope = recover_lock(&self.scope);
        if let Some(nm) = scope.as_ref().filter(|nm| nm.destination == owner) {
            return Ok(Arc::clone(nm));
        }
        let nm = Arc::new(Self::from_parts(
            self.conn.clone(),
            Arc::clone(&self.commands),
            owner,
            self.service_name.clone(),
            Arc::clone(&self.wireless_telemetry),
            Arc::clone(&self.events),
        )?);
        *scope = Some(Arc::clone(&nm));
        Ok(nm)
    }

    pub(crate) fn current_owner(&self) -> Result<String> {
        // An explicitly supplied unique peer cannot be replaced. This also
        // supports point-to-point test transports without a bus daemon.
        if self.service_name.starts_with(':') {
            return Ok(self.service_name.clone());
        }
        let bus = zbus::blocking::fdo::DBusProxy::new(&self.conn)?;
        Ok(bus
            .get_name_owner(self.service_name.as_str().try_into()?)?
            .to_string())
    }

    pub(crate) fn destination(&self) -> &str {
        &self.destination
    }

    pub(crate) fn ensure_current_owner(&self) -> Result<()> {
        if self.destination.starts_with(':') && self.current_owner()? != self.destination {
            return Err(crate::error::DomainError::cancelled(
                "NetworkManager changed during the operation",
            )
            .into());
        }
        Ok(())
    }

    pub(crate) fn cached_scope(&self) -> Option<Arc<Self>> {
        recover_lock(&self.scope).as_ref().map(Arc::clone)
    }

    pub(crate) fn invalidate_owner_state(&self, owner: Option<&str>) {
        self.events.clear_health();
        let mut scope = recover_lock(&self.scope);
        if scope
            .as_ref()
            .is_some_and(|nm| Some(nm.destination()) != owner)
        {
            scope.take();
        }
        drop(scope);
        self.wake_waiters();
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

    pub(super) fn begin_profile_transaction(&self) -> MutexGuard<'_, ()> {
        recover_lock(&self.profile_transaction)
    }

    pub(super) fn radio_restore_state(&self) -> MutexGuard<'_, RadioRestoreState> {
        recover_lock(&self.radio_restore)
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

    pub(crate) fn subscribe_health(&self, listener: Arc<dyn Fn(HealthSignal) + Send + Sync>) {
        self.events.subscribe_health(listener);
    }

    pub(crate) fn latest_health_signal(
        &self,
        subject: HealthSubject,
        path: &str,
    ) -> Option<HealthSignal> {
        self.events
            .latest_health(subject, path)
            .filter(|signal| signal.owner == self.destination)
    }

    pub(crate) fn latest_detailed_health_signal(
        &self,
        subject: HealthSubject,
        path: &str,
    ) -> Option<HealthSignal> {
        self.events
            .latest_detailed_health(subject, path)
            .filter(|signal| signal.owner == self.destination)
    }

    pub(crate) fn wake_waiters(&self) {
        self.events.notify();
        self.scan_schedule.notify_waiters();
    }

    pub(super) fn root_proxy(&self) -> Proxy<'static> {
        self.root_proxy.clone().into()
    }

    pub(super) fn settings_proxy(&self) -> Proxy<'static> {
        self.settings_proxy.clone().into()
    }

    pub(super) fn proxy<'a>(&'a self, path: &'a str, iface: &'a str) -> Result<Proxy<'a>> {
        self.ensure_current_owner()?;
        uncached_proxy(&self.conn, &self.destination, path, iface)
    }

    pub(super) fn owned_proxy(&self, path: &str, iface: &str) -> Result<Proxy<'static>> {
        self.ensure_current_owner()?;
        uncached_proxy(&self.conn, &self.destination, path, iface)
    }

    pub(super) fn proxy_path<'a>(
        &'a self,
        path: &'a OwnedObjectPath,
        iface: &'a str,
    ) -> Result<Proxy<'a>> {
        self.proxy(path.as_str(), iface)
    }
}

fn uncached_proxy(
    conn: &Connection,
    destination: &str,
    path: &str,
    interface: &str,
) -> Result<Proxy<'static>> {
    zbus::blocking::proxy::Builder::new(conn)
        .destination(destination.to_owned())?
        .path(path.to_owned())?
        .interface(interface.to_owned())?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .map_err(|error| ensure_domain(ErrorOperation::CreateDbusProxy, error.into()))
}

fn recover_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
