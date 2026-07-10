use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::time::Duration;

use anyhow::{Context, Result};
use zbus::blocking::{Connection, Proxy};
use zvariant::{DynamicType, OwnedObjectPath, OwnedValue, Value};

mod activate;
mod connectivity;
mod devices;
mod scan;
mod settings;
mod status;
mod wifi_settings;

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
pub(super) const NM_ACTIVE_CONNECTION_STATE_ACTIVATED: u32 = 2;

pub(crate) type ConnectionSettings = HashMap<String, HashMap<String, OwnedValue>>;

pub(super) fn owned_value<T>(value: T) -> Result<OwnedValue>
where
    T: Into<Value<'static>> + DynamicType,
{
    OwnedValue::try_from(Value::new(value)).context("create D-Bus variant value")
}

pub(crate) fn split_nmcli_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ':' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }

    fields.push(current);
    fields
}

pub(crate) fn split_nmcli_key_value(line: &str) -> Option<(String, String)> {
    let mut parts = split_nmcli_fields(line).into_iter();
    Some((parts.next()?, parts.next().unwrap_or_default()))
}

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

    pub(crate) fn spawn_activation_signal_watcher(&self, device_path: String, wake: Sender<()>) {
        spawn_property_watcher::<u32>(
            self.connection(),
            device_path.clone(),
            DEVICE_IFACE,
            "State",
            wake.clone(),
        );
        spawn_property_watcher::<OwnedObjectPath>(
            self.connection(),
            device_path.clone(),
            DEVICE_IFACE,
            "ActiveConnection",
            wake.clone(),
        );
        spawn_property_watcher::<OwnedObjectPath>(
            self.connection(),
            device_path,
            WIFI_IFACE,
            "ActiveAccessPoint",
            wake,
        );
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

fn spawn_property_watcher<T>(
    conn: Connection,
    path: String,
    iface: &'static str,
    property: &'static str,
    wake: Sender<()>,
) where
    T: TryFrom<OwnedValue> + Unpin + Send + 'static,
{
    std::thread::spawn(move || {
        let path_for_log = path.clone();
        let proxy = match Proxy::new_owned(conn, NM_DEST, path, iface) {
            Ok(proxy) => proxy,
            Err(err) => {
                tracing::debug!(path = %path_for_log, iface, property, error = %format_args!("{err:#}"), "could not create signal watcher proxy");
                return;
            }
        };
        let mut changes = proxy.receive_property_changed::<T>(property);
        while changes.next().is_some() {
            let _ = wake.send(());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::split_nmcli_fields;

    #[test]
    fn split_nmcli_fields_unescapes_colons() {
        assert_eq!(
            split_nmcli_fields("a:b\\:c:d"),
            vec!["a".to_string(), "b:c".to_string(), "d".to_string()]
        );
    }
}
