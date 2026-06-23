use std::env;
use std::fmt::Write as _;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::cache::{self, CachedSnapshot};
use crate::model::{AccessPoint, WifiConnectTarget};
use crate::nm::Nm;

const ACTION_RESCAN: &str = "rescan";
const ACTION_STATUS: &str = "status";
const ACTION_SSID_PREFIX: &str = "ssid:";
const ACTION_SSID_HEX_PREFIX: &str = "ssid-hex:";
const ACTION_AP_HEX_PREFIX: &str = "ap-hex:";
const ROFI_CUSTOM_RESCAN_OR_REFRESH: &str = "10";
const ROFI_CUSTOM_AUTO_REFRESH: &str = "11";
const STALE_SESSION_GRACE_SECS: u64 = 2;

pub(crate) fn run(nm: &Nm, timeout: u64, retries: u32) -> Result<()> {
    handle_action(nm, timeout, retries)?;
    emit_menu(nm, timeout)
}

fn handle_action(nm: &Nm, timeout: u64, retries: u32) -> Result<()> {
    match rofi_return_code().as_deref() {
        Some(ROFI_CUSTOM_RESCAN_OR_REFRESH) => return handle_rescan_hotkey(timeout, retries),
        Some(ROFI_CUSTOM_AUTO_REFRESH) => return Ok(()),
        _ => {}
    }

    match selected_action().as_deref() {
        Some(ACTION_RESCAN) => request_background_scan(timeout, retries),
        Some(ACTION_STATUS) | None => Ok(()),
        Some(action) => handle_network_action(nm, action),
    }
}

fn rofi_return_code() -> Option<String> {
    env::var("ROFI_RETV").ok()
}

fn handle_rescan_hotkey(timeout: u64, retries: u32) -> Result<()> {
    if active_session(timeout)?.is_some() {
        return Ok(());
    }
    request_background_scan(timeout, retries)
}

fn selected_action() -> Option<String> {
    env::var("ROFI_INFO").ok().filter(|value| !value.is_empty())
}

fn request_background_scan(timeout: u64, retries: u32) -> Result<()> {
    cache::reset_progressive_reveal()?;
    cache::write_empty_scanning_snapshot()?;
    cache::write_status("scanning", "Scanning… 0 networks found")?;
    start_background_scan(timeout, retries)
}

fn handle_network_action(nm: &Nm, action: &str) -> Result<()> {
    let Some(target) = decode_network_action(action) else {
        return Ok(());
    };
    let password = if nm.needs_wifi_password_for(&target)? {
        let Some(password) = prompt_wifi_password(&target.ssid)? else {
            cache::write_status(
                "canceled",
                format!("Connection canceled for {}", target.ssid),
            )?;
            return Ok(());
        };
        Some(password)
    } else {
        None
    };
    if let Err(err) =
        crate::connect::connect_target_with_password(nm, &target, password.as_deref(), None)
    {
        eprintln!("warning: {err:#}");
    }
    Ok(())
}

fn prompt_wifi_password(ssid: &str) -> Result<Option<String>> {
    let output = Command::new("rofi")
        .args([
            "-dmenu",
            "-password",
            "-p",
            &format!("Password for {}", clean_label(ssid)),
        ])
        .stdin(Stdio::null())
        .output()
        .context("prompt for Wi-Fi password with rofi")?;
    if !output.status.success() {
        return Ok(None);
    }
    let password = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\r', '\n'])
        .to_string();
    Ok((!password.is_empty()).then_some(password))
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

fn emit_menu(nm: &Nm, timeout: u64) -> Result<()> {
    print_rofi_header();
    let session = active_session(timeout)?;
    let latest = if session.is_none() {
        cache::read_snapshot()?
    } else {
        None
    };
    let snapshot = session.as_ref().or(latest.as_ref());
    let progressive = session.is_some();
    let networks = menu_networks(nm, snapshot, progressive)?;

    print_rescan_row(progressive, networks.len());
    if !progressive {
        print_status_row(snapshot)?;
    }
    for ap in networks {
        print_network_row(&ap);
    }
    Ok(())
}

fn active_session(timeout: u64) -> Result<Option<CachedSnapshot>> {
    let max_age_ms = u128::from(timeout.saturating_add(STALE_SESSION_GRACE_SECS)) * 1_000;
    Ok(cache::read_session_snapshot()?.filter(|snapshot| {
        snapshot.scanning()
            && cache::now_ms().saturating_sub(snapshot.updated_at_ms()) <= max_age_ms
    }))
}

fn print_rescan_row(progressive: bool, visible_count: usize) {
    if progressive {
        print_disabled_row(scan_progress_label(visible_count), ACTION_STATUS);
    } else {
        print_row(" Rescan", ACTION_RESCAN);
    }
}

fn scan_progress_label(visible_count: usize) -> String {
    format!(" Scanning… {visible_count} networks found")
}

fn menu_networks(
    nm: &Nm,
    snapshot: Option<&CachedSnapshot>,
    progressive: bool,
) -> Result<Vec<AccessPoint>> {
    let Some(snapshot) = snapshot else {
        return nm.list_access_points();
    };
    if !progressive {
        return Ok(snapshot.networks().to_vec());
    }
    let visible_count = cache::visible_network_count(
        snapshot.scanning(),
        snapshot.updated_at_ms(),
        snapshot.networks_found(),
    )?;
    Ok(snapshot.networks()[..visible_count].to_vec())
}

fn print_status_row(snapshot: Option<&CachedSnapshot>) -> Result<()> {
    if let Some(status) = cache::read_status()? {
        print_row(clean_label(status.message()), ACTION_STATUS);
    } else if let Some(snapshot) = snapshot {
        print_row(
            format!("Cached: {} networks", snapshot.networks_found()),
            ACTION_STATUS,
        );
    } else {
        print_row("No cached scan yet", ACTION_STATUS);
    }
    Ok(())
}

fn print_network_row(ap: &AccessPoint) {
    let active = if ap.active { "●" } else { " " };
    let lock = if ap.security == "--" { " " } else { "" };
    let label = format!(
        "{active} {lock} {:>3}%  {}",
        ap.strength,
        clean_label(&ap.ssid)
    );
    print_row(label, encode_ap_action(ap));
}

fn print_rofi_header() {
    println!("\0prompt\x1fWi-Fi");
    println!("\0no-custom\x1ftrue");
    println!("\0use-hot-keys\x1ftrue");
    println!("\0keep-selection\x1ftrue");
    println!("\0keep-filter\x1ftrue");
}

fn print_row(label: impl AsRef<str>, info: impl AsRef<str>) {
    println!(
        "{}\0info\x1f{}",
        clean_label(label.as_ref()),
        clean_label(info.as_ref())
    );
}

fn print_disabled_row(label: impl AsRef<str>, info: impl AsRef<str>) {
    println!(
        "{}\0info\x1f{}\x1fnonselectable\x1ftrue",
        clean_label(label.as_ref()),
        clean_label(info.as_ref())
    );
}

fn encode_ap_action(ap: &AccessPoint) -> String {
    encode_hex_action(
        ACTION_AP_HEX_PREFIX,
        &serde_json::to_vec(&WifiConnectTarget {
            ssid: ap.ssid.clone(),
            ap_path: (!ap.path.is_empty()).then(|| ap.path.clone()),
            bssid: (!ap.bssid.is_empty()).then(|| ap.bssid.clone()),
            hidden: false,
        })
        .unwrap_or_else(|_| ap.ssid.as_bytes().to_vec()),
    )
}

#[cfg(test)]
fn encode_ssid_action(ssid: &str) -> String {
    encode_hex_action(ACTION_SSID_HEX_PREFIX, ssid.as_bytes())
}

fn encode_hex_action(prefix: &str, bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(prefix.len() + bytes.len() * 2);
    encoded.push_str(prefix);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_network_action(action: &str) -> Option<WifiConnectTarget> {
    if let Some(encoded) = action.strip_prefix(ACTION_AP_HEX_PREFIX) {
        return decode_hex(encoded).and_then(|bytes| serde_json::from_slice(&bytes).ok());
    }
    decode_ssid_action(action).map(WifiConnectTarget::visible)
}

fn decode_ssid_action(action: &str) -> Option<String> {
    if let Some(encoded) = action.strip_prefix(ACTION_SSID_HEX_PREFIX) {
        return decode_hex(encoded).and_then(|bytes| String::from_utf8(bytes).ok());
    }
    action.strip_prefix(ACTION_SSID_PREFIX).map(str::to_string)
}

fn decode_hex(encoded: &str) -> Option<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        return None;
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let hex = std::str::from_utf8(chunk).ok()?;
            u8::from_str_radix(hex, 16).ok()
        })
        .collect()
}

fn clean_label(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\t' | '\n' | '\r' | '\0' | '\x1f' => ' ',
            _ => ch,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ACTION_AP_HEX_PREFIX, ACTION_SSID_HEX_PREFIX, ACTION_SSID_PREFIX, clean_label,
        decode_network_action, decode_ssid_action, encode_ap_action, encode_ssid_action,
    };
    use crate::model::AccessPoint;

    #[test]
    fn ssid_action_encoding_round_trips_protocol_characters() {
        let ssid = "Cafe\t\n\r\0\x1f☕";
        let action = encode_ssid_action(ssid);

        assert!(action.starts_with(ACTION_SSID_HEX_PREFIX));
        assert_eq!(decode_ssid_action(&action).as_deref(), Some(ssid));
    }

    #[test]
    fn ap_action_encoding_carries_selected_ap_identity() {
        let ap = AccessPoint {
            ssid: "Cafe".to_string(),
            active: false,
            security: "WPA2/3".to_string(),
            strength: 80,
            frequency: 5180,
            bssid: "00:11:22:33:44:55".to_string(),
            last_seen: 0,
            path: "/org/freedesktop/NetworkManager/AccessPoint/1".to_string(),
            device_path: "/org/freedesktop/NetworkManager/Devices/1".to_string(),
            flags: 0,
            wpa_flags: 0,
            rsn_flags: 0,
        };
        let action = encode_ap_action(&ap);
        let target = decode_network_action(&action).expect("target");

        assert!(action.starts_with(ACTION_AP_HEX_PREFIX));
        assert_eq!(target.ssid, ap.ssid);
        assert_eq!(target.ap_path.as_deref(), Some(ap.path.as_str()));
        assert_eq!(target.bssid.as_deref(), Some(ap.bssid.as_str()));
    }

    #[test]
    fn legacy_ssid_actions_remain_supported() {
        assert_eq!(
            decode_ssid_action(&format!("{ACTION_SSID_PREFIX}Example")).as_deref(),
            Some("Example")
        );
    }

    #[test]
    fn clean_label_removes_rofi_protocol_separators() {
        assert_eq!(clean_label("a\tb\nc\rd\0e\x1ff"), "a b c d e f");
    }
}
