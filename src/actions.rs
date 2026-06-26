use std::io::{self, BufRead};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::cli::ProfileCommand;
use crate::connect;
use crate::model::{
    ConnectResult, ScanRequestOptions, ScanStreamOptions, WepKeyType, WifiConnectTarget,
    validate_ssid_bytes,
};
use crate::nm::Nm;
use crate::output::{
    print_access_points, print_connect_result, print_connectivity, print_disconnect_result,
    print_saved_wifi_connections, print_saved_wifi_connections_json, print_wifi_status,
};

pub(crate) struct ConnectSsidOptions {
    pub(crate) ssid: String,
    pub(crate) password: Option<String>,
    pub(crate) password_stdin: bool,
    pub(crate) bssid: Option<String>,
    pub(crate) hidden: bool,
    pub(crate) wep_key_type: Option<WepKeyType>,
    pub(crate) json: bool,
}

pub(crate) fn connect_ssid(nm: &Nm, options: ConnectSsidOptions) -> Result<()> {
    let target = WifiConnectTarget {
        ssid_bytes: options.ssid.as_bytes().to_vec(),
        ssid: options.ssid,
        ap_path: None,
        bssid: options.bssid,
        ifname: None,
        device_path: None,
        connection_name: None,
        private: false,
        hidden: options.hidden,
        security: None,
        enterprise: None,
    };
    let password = resolve_password(options.password, options.password_stdin)?;
    print_connect_attempt(
        nm,
        &target,
        password.as_deref(),
        options.wep_key_type,
        options.json,
    )
}

pub(crate) fn connect_target(
    nm: &Nm,
    target_json: String,
    password: Option<String>,
    password_stdin: bool,
    wep_key_type: Option<WepKeyType>,
    json: bool,
) -> Result<()> {
    let target = parse_connect_target(&target_json)?;
    let password = resolve_password(password, password_stdin)?;
    print_connect_attempt(nm, &target, password.as_deref(), wep_key_type, json)
}

fn print_connect_attempt(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    json: bool,
) -> Result<()> {
    match connect::connect_target_with_password(nm, target, password, wep_key_type) {
        Ok(result) => print_connect_result(&result, json),
        Err(err) if json => {
            let result = connect_error(target, &err);
            print_connect_result(&result, true)?;
            Err(anyhow!("Wi-Fi connection failed: {}", result.message))
        }
        Err(err) => Err(err),
    }
}

fn connect_error(target: &WifiConnectTarget, err: &anyhow::Error) -> ConnectResult {
    let message = format!("{err:#}");
    ConnectResult {
        status: "error",
        reason: Some(connect::connect_failure_reason(err)),
        ssid: target.ssid.clone(),
        message,
        connectivity: None,
        suggest_open_portal: false,
    }
}

fn resolve_password(password: Option<String>, password_stdin: bool) -> Result<Option<String>> {
    if !password_stdin {
        return Ok(password);
    }

    let mut value = String::new();
    io::stdin()
        .lock()
        .read_line(&mut value)
        .context("read Wi-Fi password from stdin")?;
    while matches!(value.chars().last(), Some('\n' | '\r')) {
        value.pop();
    }
    Ok(Some(value))
}

pub(crate) struct ScanCommandOptions {
    pub(crate) timeout: u64,
    pub(crate) stream: bool,
    pub(crate) strict: bool,
    pub(crate) retries: u32,
    pub(crate) cache: bool,
    pub(crate) ifname: Option<String>,
    pub(crate) ssids: Vec<String>,
}

pub(crate) fn run_scan(nm: &Nm, options: ScanCommandOptions) -> Result<()> {
    tracing::info!(
        options.timeout,
        options.stream,
        options.strict,
        options.retries,
        options.cache,
        ifname = ?options.ifname,
        ssid_count = options.ssids.len(),
        "running Wi-Fi scan"
    );
    let timeout = Duration::from_secs(options.timeout);
    let ssid_bytes = scan_ssid_bytes(options.ssids)?;
    if options.stream {
        return nm.scan_stream(ScanStreamOptions {
            timeout,
            retries: options.retries,
            cache: options.cache,
            ifname: options.ifname,
            ssid_bytes,
        });
    }

    if let Err(err) = nm.scan_with_options(ScanRequestOptions {
        timeout,
        ifname: options.ifname,
        ssid_bytes,
    }) {
        tracing::warn!(error = %format_args!("{err:#}"), "scan failed");
        if options.strict {
            return Err(err);
        }
        eprintln!("warning: scan failed: {err:#}; showing cached NetworkManager results");
    }
    let networks = nm.list_all_access_points()?;
    if options.cache {
        crate::cache::write_snapshot(false, &networks)?;
        crate::cache::write_complete(false, networks.len())?;
    }
    print_access_points(&networks);
    Ok(())
}

fn scan_ssid_bytes(ssids: Vec<String>) -> Result<Vec<Vec<u8>>> {
    ssids
        .into_iter()
        .map(|ssid| {
            let bytes = ssid.into_bytes();
            validate_ssid_bytes(&bytes)?;
            Ok(bytes)
        })
        .collect()
}

pub(crate) fn print_saved_profiles(nm: &Nm, json: bool) -> Result<()> {
    tracing::info!(json, "listing saved Wi-Fi profiles");
    let profiles = nm.saved_wifi_connections()?;
    if json {
        print_saved_wifi_connections_json(&profiles)
    } else {
        print_saved_wifi_connections(&profiles);
        Ok(())
    }
}

pub(crate) fn run_profile_command(nm: &Nm, command: ProfileCommand) -> Result<()> {
    match command {
        ProfileCommand::Delete { path } => {
            tracing::info!(path, "deleting saved Wi-Fi profile");
            nm.delete_connection_by_path(&path)?;
        }
        ProfileCommand::Autoconnect { path, enabled } => {
            tracing::info!(path, enabled, "setting saved Wi-Fi profile autoconnect");
            nm.set_connection_autoconnect_by_path(&path, enabled)?;
        }
        ProfileCommand::MacRandomization { path, randomized } => {
            tracing::info!(path, randomized, "setting saved Wi-Fi profile MAC privacy");
            nm.set_connection_mac_randomization_by_path(&path, randomized)?;
        }
        ProfileCommand::SendHostname { path, enabled } => {
            tracing::info!(
                path,
                enabled,
                "setting saved Wi-Fi profile DHCP hostname privacy"
            );
            nm.set_connection_send_hostname_by_path(&path, enabled)?;
        }
    }
    Ok(())
}

pub(crate) fn print_status(nm: &Nm, json: bool) -> Result<()> {
    print_wifi_status(&nm.wifi_status()?, json)
}

pub(crate) fn disconnect(nm: &Nm, json: bool) -> Result<()> {
    print_disconnect_result(&nm.disconnect_wifi()?, json)
}

pub(crate) fn print_connectivity_state(nm: &Nm, json: bool) -> Result<()> {
    print_connectivity(&nm.connectivity_check()?, json)
}

pub(crate) fn print_active_ssid(nm: &Nm) -> Result<()> {
    if let Some(ssid) = nm.active_ssid()? {
        println!("{ssid}");
    }
    Ok(())
}

fn parse_connect_target(target_json: &str) -> Result<WifiConnectTarget> {
    serde_json::from_str(target_json).context("parse Wi-Fi connect target JSON")
}
