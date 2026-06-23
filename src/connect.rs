use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::cache;
use crate::nm::Nm;

const NMCLI_CONNECT_TIMEOUT_SECS: &str = "30";
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(30);
const ACTIVATION_POLL_INTERVAL: Duration = Duration::from_millis(500);

pub(crate) fn connect_ssid_with_password(
    nm: &Nm,
    ssid: &str,
    password: Option<&str>,
) -> Result<()> {
    cache::write_status("connecting", format!("Connecting to {ssid}…"))?;
    match activate_saved_or_visible(nm, ssid, password) {
        Ok(message) => {
            cache::write_status("connected", message)?;
            refresh_cached_networks(nm)?;
            Ok(())
        }
        Err(err) => {
            cache::write_status("error", format!("Connection failed for {ssid}: {err:#}"))?;
            Err(err)
        }
    }
}

fn activate_saved_or_visible(nm: &Nm, ssid: &str, password: Option<&str>) -> Result<String> {
    match nm.activate_saved_wifi_connection(ssid) {
        Ok(true) => {
            wait_for_active_ssid(nm, ssid)?;
            Ok(format!("Connected to saved network {ssid} via D-Bus"))
        }
        Ok(false) => match nm.add_and_activate_wifi_connection(ssid, password) {
            Ok(true) => {
                wait_for_active_ssid(nm, ssid)?;
                Ok(format!("Connected to Wi-Fi network {ssid} via D-Bus"))
            }
            Ok(false) => activate_with_nmcli_fallback(ssid, password),
            Err(dbus_err) => match activate_with_nmcli_fallback(ssid, password) {
                Ok(message) => Ok(format!(
                    "{message} (D-Bus add/activate failed: {dbus_err:#})"
                )),
                Err(fallback_err) => bail!(
                    "D-Bus add/activate failed: {dbus_err:#}; nmcli fallback failed: {fallback_err:#}"
                ),
            },
        },
        Err(dbus_err) => match activate_with_nmcli_fallback(ssid, password) {
            Ok(message) => Ok(format!("{message} (D-Bus activation failed: {dbus_err:#})")),
            Err(fallback_err) => bail!(
                "D-Bus saved profile activation failed: {dbus_err:#}; nmcli fallback failed: {fallback_err:#}"
            ),
        },
    }
}

fn activate_with_nmcli_fallback(ssid: &str, password: Option<&str>) -> Result<String> {
    match nmcli(["connection", "up", "id", ssid]) {
        Ok(_) => Ok(format!(
            "Connected to saved network {ssid} via nmcli fallback"
        )),
        Err(saved_err) => {
            let connect_result = if let Some(password) = password {
                nmcli(["device", "wifi", "connect", ssid, "password", password])
            } else {
                nmcli(["device", "wifi", "connect", ssid])
            };
            match connect_result {
                Ok(_) => Ok(format!("Connected to {ssid} via nmcli fallback")),
                Err(connect_err) => bail!(
                    "saved profile activation failed: {saved_err:#}; wifi connect failed: {connect_err:#}"
                ),
            }
        }
    }
}

fn wait_for_active_ssid(nm: &Nm, ssid: &str) -> Result<()> {
    let deadline = Instant::now() + ACTIVATION_TIMEOUT;
    let mut saw_progress = false;
    let mut last_status = None;
    while Instant::now() < deadline {
        if nm.active_ssid()?.as_deref() == Some(ssid) {
            return Ok(());
        }
        if let Some(status) = nm.wifi_activation_status(ssid)? {
            saw_progress |= status.device_state > 30;
            if status.activated() {
                return Ok(());
            }
            if saw_progress && status.terminal_failure_after_progress() {
                bail!(
                    "connection activation failed on {}: device state {}, reason {:?}, active connection state {:?}",
                    status.iface,
                    status.device_state,
                    status.device_state_reason,
                    status.active_connection_state
                );
            }
            last_status = Some(status);
        }
        sleep(ACTIVATION_POLL_INTERVAL);
    }
    if let Some(status) = last_status {
        bail!(
            "timed out waiting for {ssid} to become active on {}: device state {}, reason {:?}, active connection state {:?}",
            status.iface,
            status.device_state,
            status.device_state_reason,
            status.active_connection_state
        );
    }
    bail!("timed out waiting for {ssid} to become active")
}

fn nmcli<const N: usize>(args: [&str; N]) -> Result<String> {
    let output = Command::new("nmcli")
        .arg("--wait")
        .arg(NMCLI_CONNECT_TIMEOUT_SECS)
        .args(args)
        .output()
        .context("run nmcli")?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        return Ok(stdout);
    }

    let message = if stderr.is_empty() { stdout } else { stderr };
    bail!("nmcli exited with {}: {message}", output.status)
}

fn refresh_cached_networks(nm: &Nm) -> Result<()> {
    let networks = nm.list_access_points()?;
    cache::write_snapshot(false, &networks)?;
    cache::write_complete(false, networks.len())
}
