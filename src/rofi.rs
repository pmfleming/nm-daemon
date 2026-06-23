use std::env;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::cache::{self, CachedSnapshot};
use crate::model::AccessPoint;
use crate::nm::Nm;

const ACTION_RESCAN: &str = "rescan";
const ACTION_STATUS: &str = "status";
const ACTION_SSID_PREFIX: &str = "ssid:";

pub(crate) fn run(nm: &Nm, timeout: u64, retries: u32) -> Result<()> {
    handle_action(nm, timeout, retries)?;
    emit_menu(nm)
}

fn handle_action(nm: &Nm, timeout: u64, retries: u32) -> Result<()> {
    match selected_action().as_deref() {
        Some(ACTION_RESCAN) => request_background_scan(timeout, retries),
        Some(ACTION_STATUS) | None => Ok(()),
        Some(action) => handle_network_action(nm, action),
    }
}

fn selected_action() -> Option<String> {
    env::var("ROFI_INFO").ok().filter(|value| !value.is_empty())
}

fn request_background_scan(timeout: u64, retries: u32) -> Result<()> {
    start_background_scan(timeout, retries)?;
    cache::write_status("status", "scan requested in background")
}

fn handle_network_action(nm: &Nm, action: &str) -> Result<()> {
    let Some(ssid) = action.strip_prefix(ACTION_SSID_PREFIX) else {
        return Ok(());
    };
    if let Err(err) = crate::connect::connect_ssid(nm, ssid) {
        eprintln!("warning: {err:#}");
    }
    Ok(())
}

fn start_background_scan(timeout: u64, retries: u32) -> Result<()> {
    let timeout = timeout.to_string();
    let retries = retries.to_string();
    Command::new(env::current_exe().context("find current executable")?)
        .args([
            "scan",
            "--stream",
            "--cache",
            "--timeout",
            &timeout,
            "--retries",
            &retries,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start background cached scan")?;
    Ok(())
}

fn emit_menu(nm: &Nm) -> Result<()> {
    print_rofi_header();
    print_row(" Rescan", ACTION_RESCAN);
    print_status_row()?;

    for ap in menu_networks(nm)? {
        print_network_row(&ap);
    }
    Ok(())
}

fn menu_networks(nm: &Nm) -> Result<Vec<AccessPoint>> {
    if let Some(snapshot) = cache::read_snapshot()? {
        return Ok(snapshot.into_networks());
    }
    nm.list_access_points()
}

fn print_status_row() -> Result<()> {
    if let Some(status) = cache::read_status()? {
        print_row(clean_label(status.message()), "status");
    } else if let Some(snapshot) = cache::read_snapshot()? {
        print_snapshot_status(&snapshot);
    } else {
        print_row("No cached scan yet", "status");
    }
    Ok(())
}

fn print_snapshot_status(snapshot: &CachedSnapshot) {
    let state = if snapshot.scanning() {
        "Scanning"
    } else {
        "Cached"
    };
    print_row(
        format!("{state}: {} networks", snapshot.networks_found()),
        "status",
    );
}

fn print_network_row(ap: &AccessPoint) {
    let active = if ap.active { "●" } else { " " };
    let lock = if ap.security == "--" { " " } else { "" };
    let label = format!(
        "{active} {lock} {:>3}%  {}",
        ap.strength,
        clean_label(&ap.ssid)
    );
    print_row(label, format!("ssid:{}", ap.ssid));
}

fn print_rofi_header() {
    println!("\0prompt\x1fWi-Fi");
    println!("\0no-custom\x1ftrue");
}

fn print_row(label: impl AsRef<str>, info: impl AsRef<str>) {
    println!("{}\0info\x1f{}", label.as_ref(), info.as_ref());
}

fn clean_label(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\t' | '\n' | '\r' | '\0' => ' ',
            _ => ch,
        })
        .collect()
}
