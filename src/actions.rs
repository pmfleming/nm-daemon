use std::io::{self, BufRead, Read};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::cli::{ConnectOptions, ConnectTargetOptions, ProfileCommand, ScanOptions};
use crate::connect;
use crate::model::{
    ConnectResult, ScanRequestOptions, ScanStreamOptions, WepKeyType, WifiConnectTarget,
    WifiStatus, validate_ssid_bytes,
};
use crate::nm::Nm;
use crate::output::{
    print_access_points_json, print_api_message, print_connect_result, print_connectivity,
    print_disconnect_result, print_saved_wifi_connections_json, print_wifi_share_payload,
    print_wifi_status,
};
use serde::Deserialize;

pub(crate) fn connect_ssid(nm: &Nm, options: ConnectOptions) -> Result<()> {
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
        key_mgmt: options.key_mgmt,
        enterprise: None,
        profile: Default::default(),
    };
    let password = resolve_password(options.password_stdin)?;
    print_connect_attempt(nm, &target, password.as_deref(), options.wep_key_type)
}

pub(crate) fn connect_target(nm: &Nm, options: ConnectTargetOptions) -> Result<()> {
    let request = connect_target_request(options)?;
    print_connect_attempt(
        nm,
        &request.target,
        request.password.as_deref(),
        request.wep_key_type,
    )
}

fn print_connect_attempt(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<()> {
    match connect::connect_target_with_password(nm, target, password, wep_key_type) {
        Ok(result) => print_connect_result(&result),
        Err(err) => {
            let result = connect_error(target, &err);
            print_connect_result(&result)?;
            tracing::debug!(message = %result.message, "connect error response emitted");
            Err(crate::output::reported_error())
        }
    }
}

fn connect_error(target: &WifiConnectTarget, err: &anyhow::Error) -> ConnectResult {
    let message = format!("{err:#}");
    ConnectResult {
        status: "error",
        reason: Some(connect::connect_failure_reason(err)),
        path: None,
        ssid: target.ssid.clone(),
        message,
        connectivity: None,
        suggest_open_portal: false,
    }
}

fn resolve_password(password_stdin: bool) -> Result<Option<String>> {
    if !password_stdin {
        return Ok(None);
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

pub(crate) fn run_scan(nm: &Nm, options: ScanOptions) -> Result<()> {
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
    print_access_points_json(&networks)
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

pub(crate) fn print_saved_profiles(nm: &Nm) -> Result<()> {
    tracing::info!("listing saved Wi-Fi profiles");
    let profiles = nm.saved_wifi_connections()?;
    print_saved_wifi_connections_json(&profiles)
}

pub(crate) fn run_profile_command(nm: &Nm, command: ProfileCommand) -> Result<()> {
    match command {
        ProfileCommand::Delete { path } => {
            tracing::info!(path, "deleting saved Wi-Fi profile");
            nm.delete_connection_by_path(&path)?;
            print_api_message("Saved Wi-Fi profile deleted")?;
        }
        ProfileCommand::Autoconnect { path, enabled } => {
            tracing::info!(path, enabled, "setting saved Wi-Fi profile autoconnect");
            nm.set_connection_autoconnect_by_path(&path, enabled)?;
            print_api_message("Saved Wi-Fi profile autoconnect updated")?;
        }
        ProfileCommand::MacRandomization { path, randomized } => {
            tracing::info!(path, randomized, "setting saved Wi-Fi profile MAC privacy");
            nm.set_connection_mac_randomization_by_path(&path, randomized)?;
            print_api_message("Saved Wi-Fi profile MAC privacy updated")?;
        }
        ProfileCommand::Share { path } => {
            tracing::info!(path, "building saved Wi-Fi profile share payload");
            let payload = nm.wifi_share_payload_by_path(&path)?;
            print_wifi_share_payload(&payload)?;
        }
        ProfileCommand::SendHostname { path, enabled } => {
            tracing::info!(
                path,
                enabled,
                "setting saved Wi-Fi profile DHCP hostname privacy"
            );
            nm.set_connection_send_hostname_by_path(&path, enabled)?;
            print_api_message("Saved Wi-Fi profile DHCP hostname privacy updated")?;
        }
    }
    Ok(())
}

pub(crate) fn print_status(nm: &Nm) -> Result<()> {
    let status = nm.wifi_status()?;
    cache_status_best_effort(&status);
    print_wifi_status(&status)
}

pub(crate) fn disconnect(nm: &Nm) -> Result<()> {
    let result = nm.disconnect_wifi()?;
    clear_active_cache_best_effort();
    print_disconnect_result(&result)
}

pub(crate) fn print_connectivity_state(nm: &Nm) -> Result<()> {
    print_connectivity(&nm.connectivity_check()?)
}

fn cache_status_best_effort(status: &WifiStatus) {
    if let Err(err) = crate::cache::cache_connected_network_status(status) {
        tracing::warn!(error = %format_args!("{err:#}"), "failed to cache active Wi-Fi status");
    }
}

fn clear_active_cache_best_effort() {
    if let Err(err) = crate::cache::clear_active_connection_cache() {
        tracing::warn!(error = %format_args!("{err:#}"), "failed to clear active Wi-Fi cache");
    }
}

#[derive(Deserialize)]
struct ConnectTargetStdinRequest {
    target: WifiConnectTarget,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    wep_key_type: Option<WepKeyType>,
}

struct ConnectTargetRequest {
    target: WifiConnectTarget,
    password: Option<String>,
    wep_key_type: Option<WepKeyType>,
}

fn connect_target_request(options: ConnectTargetOptions) -> Result<ConnectTargetRequest> {
    let mut request_json = String::new();
    io::stdin()
        .read_to_string(&mut request_json)
        .context("read Wi-Fi connect target request JSON from stdin")?;
    let request_json = request_json.trim();
    if request_json.is_empty() {
        bail!("connect-target requires a target JSON argument or request JSON on stdin");
    }

    match serde_json::from_str::<ConnectTargetStdinRequest>(request_json) {
        Ok(request) => Ok(ConnectTargetRequest {
            target: request.target,
            password: request.password,
            wep_key_type: request.wep_key_type.or(options.wep_key_type),
        }),
        Err(request_err) => match serde_json::from_str::<WifiConnectTarget>(request_json) {
            Ok(target) => Ok(ConnectTargetRequest {
                target,
                password: None,
                wep_key_type: options.wep_key_type,
            }),
            Err(target_err) => Err(target_err).context(format!(
                "parse Wi-Fi connect target request JSON: {request_err}"
            )),
        },
    }
}
