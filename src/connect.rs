use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::cache;
use crate::nm::Nm;

const NMCLI_CONNECT_TIMEOUT_SECS: &str = "30";

pub(crate) fn connect_ssid(nm: &Nm, ssid: &str) -> Result<()> {
    cache::write_status("connecting", format!("Connecting to {ssid}…"))?;
    match activate_saved_or_visible(ssid) {
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

fn activate_saved_or_visible(ssid: &str) -> Result<String> {
    match nmcli(["connection", "up", "id", ssid]) {
        Ok(_) => Ok(format!("Connected to saved network {ssid}")),
        Err(saved_err) => match nmcli(["device", "wifi", "connect", ssid]) {
            Ok(_) => Ok(format!("Connected to {ssid}")),
            Err(connect_err) => bail!(
                "saved profile activation failed: {saved_err:#}; wifi connect failed: {connect_err:#}"
            ),
        },
    }
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
