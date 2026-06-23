use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use zvariant::OwnedObjectPath;

use crate::cache;
use crate::model::{WepKeyType, WifiConnectTarget};
use crate::nm::Nm;

const NMCLI_CONNECT_TIMEOUT_SECS: &str = "30";
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(30);
const ACTIVATION_POLL_INTERVAL: Duration = Duration::from_millis(500);

pub(crate) fn connect_target_with_password(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<()> {
    cache::write_status("connecting", format!("Connecting to {}…", target.ssid))?;
    match activate_saved_or_visible(nm, target, password, wep_key_type) {
        Ok(message) => {
            cache::write_status("connected", message)?;
            refresh_cached_networks(nm)?;
            Ok(())
        }
        Err(err) => {
            cache::write_status(
                "error",
                format!("Connection failed for {}: {err:#}", target.ssid),
            )?;
            Err(err)
        }
    }
}

fn activate_saved_or_visible(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<String> {
    match nm.activate_saved_wifi_connection_for(target) {
        Ok(true) => {
            wait_for_active_target(nm, target)?;
            Ok(format!(
                "Connected to saved network {} via D-Bus",
                target.ssid
            ))
        }
        Ok(false) => {
            match nm.add_and_activate_wifi_connection_for(target, password, wep_key_type) {
                Ok(Some(created_connection)) => {
                    wait_for_new_connection(nm, target, &created_connection)?;
                    Ok(format!(
                        "Connected to Wi-Fi network {} via D-Bus",
                        target.ssid
                    ))
                }
                Ok(None) => activate_with_nmcli_fallback(target, password, wep_key_type),
                Err(dbus_err) => match activate_with_nmcli_fallback(target, password, wep_key_type)
                {
                    Ok(message) => Ok(format!(
                        "{message} (D-Bus add/activate failed: {dbus_err:#})"
                    )),
                    Err(fallback_err) => bail!(
                        "D-Bus add/activate failed: {dbus_err:#}; nmcli fallback failed: {fallback_err:#}"
                    ),
                },
            }
        }
        Err(dbus_err) => match activate_with_nmcli_fallback(target, password, wep_key_type) {
            Ok(message) => Ok(format!("{message} (D-Bus activation failed: {dbus_err:#})")),
            Err(fallback_err) => bail!(
                "D-Bus saved profile activation failed: {dbus_err:#}; nmcli fallback failed: {fallback_err:#}"
            ),
        },
    }
}

fn wait_for_new_connection(
    nm: &Nm,
    target: &WifiConnectTarget,
    created_connection: &OwnedObjectPath,
) -> Result<()> {
    if let Err(err) = wait_for_active_target(nm, target) {
        if let Err(delete_err) = nm.delete_connection(created_connection) {
            eprintln!(
                "warning: failed to delete failed connection {created_connection}: {delete_err:#}"
            );
        }
        return Err(err);
    }
    Ok(())
}

fn activate_with_nmcli_fallback(
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<String> {
    let ssid = target.ssid.as_str();
    match nmcli(&["connection", "up", "id", ssid]) {
        Ok(_) => Ok(format!(
            "Connected to saved network {ssid} via nmcli fallback"
        )),
        Err(saved_err) => {
            let mut args = vec!["device", "wifi", "connect", ssid];
            if let Some(password) = password {
                args.extend(["password", password]);
            }
            if let Some(wep_key_type) = wep_key_type {
                args.extend(["wep-key-type", wep_key_type.nmcli_value()]);
            }
            if let Some(bssid) = target.bssid.as_deref() {
                args.extend(["bssid", bssid]);
            }
            if target.hidden {
                args.extend(["hidden", "yes"]);
            }
            match nmcli(&args) {
                Ok(_) => Ok(format!("Connected to {ssid} via nmcli fallback")),
                Err(connect_err) => bail!(
                    "saved profile activation failed: {saved_err:#}; wifi connect failed: {connect_err:#}"
                ),
            }
        }
    }
}

fn wait_for_active_target(nm: &Nm, target: &WifiConnectTarget) -> Result<()> {
    let deadline = Instant::now() + ACTIVATION_TIMEOUT;
    let mut saw_progress = false;
    let mut last_status = None;
    while Instant::now() < deadline {
        if nm.active_ssid()?.as_deref() == Some(target.ssid.as_str()) {
            return Ok(());
        }
        if let Some(status) = nm.wifi_activation_status_for(target)? {
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
            "timed out waiting for {} to become active on {}: device state {}, reason {:?}, active connection state {:?}",
            target.ssid,
            status.iface,
            status.device_state,
            status.device_state_reason,
            status.active_connection_state
        );
    }
    bail!("timed out waiting for {} to become active", target.ssid)
}

fn nmcli(args: &[&str]) -> Result<String> {
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
