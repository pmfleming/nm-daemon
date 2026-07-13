use std::io::{self, BufRead, Read};
use std::time::Duration;

use anyhow::Result;

use crate::application::{
    Application, ConnectOutcome, ConnectRequest, NetworksRequest, ProfileOperation,
    ProfileOperationResult, ScanRequest, validated_ssids,
};
use crate::background_scan::InlineBackgroundScan;
use crate::cli::{ConnectOptions, ConnectTargetOptions, ProfileCommand, ScanOptions};
use crate::error::{DomainError, ErrorCode, ErrorOperation, ErrorSource};
use crate::model::{ScanStreamOptions, Ssid, WepKeyType, WifiConnectTarget};
use crate::nm::Nm;
use crate::output::{
    print_access_points_json, print_api_message, print_connect_failure, print_connect_result,
    print_connectivity, print_disconnect_result, print_saved_wifi_connections_json,
    print_wifi_share_payload, print_wifi_status,
};
use serde::Deserialize;

pub(crate) fn connect_ssid(nm: &Nm, options: ConnectOptions) -> Result<()> {
    let target = WifiConnectTarget {
        ssid: Ssid::from_display(options.ssid).map_err(|error| {
            DomainError::validation(ErrorOperation::Connect, &error)
                .with_detail("field", "ssid")
                .with_cause(error)
        })?,
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
    let request = ConnectRequest {
        target,
        password: resolve_password(options.password_stdin)?,
        wep_key_type: options.wep_key_type,
    };
    print_connect_attempt(nm, request)
}

pub(crate) fn connect_target(nm: &Nm, options: ConnectTargetOptions) -> Result<()> {
    let request = connect_target_request(options)?;
    print_connect_attempt(nm, request)
}

fn print_connect_attempt(nm: &Nm, request: ConnectRequest) -> Result<()> {
    match Application::new(nm).connect(&request, None, |_| Ok(()))? {
        ConnectOutcome::Succeeded(result) => print_connect_result(&result),
        ConnectOutcome::Failed { result, error } => {
            print_connect_failure(&result, &error)?;
            tracing::debug!(message = %result.message, "connect error response emitted");
            Err(crate::output::reported_error())
        }
        ConnectOutcome::Cancelled { message } => Err(DomainError::cancelled(message).into()),
    }
}

fn resolve_password(password_stdin: bool) -> Result<Option<String>> {
    if !password_stdin {
        return Ok(None);
    }

    let mut value = String::new();
    io::stdin().lock().read_line(&mut value).map_err(|error| {
        DomainError::new(
            ErrorCode::InternalError,
            ErrorOperation::Connect,
            ErrorSource::Io,
            format!("read Wi-Fi password from stdin: {error}"),
        )
        .with_detail("field", "password")
        .with_cause(error.into())
    })?;
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
        options.quiet,
        ifname = ?options.ifname,
        ssid_count = options.ssids.len(),
        "running Wi-Fi scan"
    );
    if options.stream && options.quiet {
        return Err(DomainError::validation(
            ErrorOperation::Scan,
            "--quiet cannot be used with --stream",
        )
        .with_detail("field", "quiet")
        .into());
    }
    let timeout = Duration::from_secs(options.timeout);
    if options.stream {
        return nm.scan_stream(ScanStreamOptions {
            timeout,
            retries: options.retries,
            cache: options.cache,
            ifname: options.ifname,
            ssid_bytes: validated_ssids(options.ssids).map_err(|error| {
                DomainError::validation(ErrorOperation::Scan, &error)
                    .with_detail("field", "ssid")
                    .with_cause(error)
            })?,
        });
    }

    let result = Application::new(nm).scan(
        ScanRequest {
            timeout,
            strict: options.strict,
            cache: options.cache,
            ifname: options.ifname,
            ssids: options.ssids,
        },
        |_| Ok(()),
    )?;
    if let Some(warning) = result.warning.as_ref() {
        tracing::warn!(error = %warning.message, code = ?warning.code, "scan failed");
        eprintln!(
            "warning: scan failed: {}; showing cached NetworkManager results",
            warning.message
        );
    }
    if options.quiet {
        return Ok(());
    }
    print_access_points_json(&result.access_points)
}

pub(crate) fn print_saved_profiles(nm: &Nm) -> Result<()> {
    tracing::info!("listing saved Wi-Fi profiles");
    let profiles = Application::new(nm).saved_profiles()?;
    print_saved_wifi_connections_json(&profiles)
}

pub(crate) fn run_profile_command(nm: &Nm, command: ProfileCommand) -> Result<()> {
    let operation = match command {
        ProfileCommand::Delete { path } => {
            tracing::info!(path = %path, "deleting saved Wi-Fi profile");
            ProfileOperation::Delete { path }
        }
        ProfileCommand::Autoconnect { path, enabled } => {
            tracing::info!(path = %path, enabled, "setting saved Wi-Fi profile autoconnect");
            ProfileOperation::SetAutoconnect { path, enabled }
        }
        ProfileCommand::MacRandomization { path, randomized } => {
            tracing::info!(path = %path, randomized, "setting saved Wi-Fi profile MAC privacy");
            ProfileOperation::SetMacRandomization { path, randomized }
        }
        ProfileCommand::Share { path } => {
            tracing::info!(path = %path, "building saved Wi-Fi profile share payload");
            ProfileOperation::Share { path }
        }
        ProfileCommand::SendHostname { path, enabled } => {
            tracing::info!(
                path = %path,
                enabled,
                "setting saved Wi-Fi profile DHCP hostname privacy"
            );
            ProfileOperation::SetSendHostname { path, enabled }
        }
    };
    match Application::new(nm).profile_operation(operation)? {
        ProfileOperationResult::Updated { message } => print_api_message(message),
        ProfileOperationResult::Share(payload) => print_wifi_share_payload(&payload),
    }
}

pub(crate) fn print_status(nm: &Nm) -> Result<()> {
    let status = Application::new(nm).status()?;
    print_wifi_status(&status)
}

pub(crate) fn disconnect(nm: &Nm) -> Result<()> {
    let result = Application::new(nm).disconnect()?;
    print_disconnect_result(&result)
}

pub(crate) fn print_connectivity_state(nm: &Nm) -> Result<()> {
    print_connectivity(&Application::new(nm).connectivity()?)
}

pub(crate) fn print_networks(
    nm: &Nm,
    cached: bool,
    refresh_cache: bool,
    refresh_timeout: u64,
    _verbose: u8,
    _log_file: &Option<std::path::PathBuf>,
) -> Result<()> {
    let background_scans = InlineBackgroundScan::new(nm);
    let result = Application::new(nm)
        .with_background_scans(&background_scans)
        .networks(NetworksRequest::new(
            cached,
            refresh_cache,
            Duration::from_secs(refresh_timeout),
        ))?;
    if let Some(warning) = result.warning.as_ref() {
        eprintln!(
            "warning: scan failed: {}; showing cached NetworkManager results",
            warning.message
        );
    }
    crate::output::print_network_entries_json(&result.networks)
}

#[derive(Deserialize)]
struct ConnectTargetStdinRequest {
    target: WifiConnectTarget,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    wep_key_type: Option<WepKeyType>,
}

fn connect_target_request(options: ConnectTargetOptions) -> Result<ConnectRequest> {
    let mut request_json = String::new();
    io::stdin()
        .read_to_string(&mut request_json)
        .map_err(|error| {
            DomainError::new(
                ErrorCode::InternalError,
                ErrorOperation::ParseRequest,
                ErrorSource::Io,
                format!("read Wi-Fi connect target request JSON from stdin: {error}"),
            )
            .with_detail("transport", "stdin")
            .with_cause(error.into())
        })?;
    let request_json = request_json.trim();
    if request_json.is_empty() {
        return Err(DomainError::validation(
            ErrorOperation::ParseRequest,
            "connect-target requires request JSON on stdin",
        )
        .with_detail("transport", "stdin")
        .into());
    }

    match serde_json::from_str::<ConnectTargetStdinRequest>(request_json) {
        Ok(request) => Ok(ConnectRequest {
            target: request.target,
            password: request.password,
            wep_key_type: request.wep_key_type.or(options.wep_key_type),
        }),
        Err(request_err) => match serde_json::from_str::<WifiConnectTarget>(request_json) {
            Ok(target) => Ok(ConnectRequest {
                target,
                password: None,
                wep_key_type: options.wep_key_type,
            }),
            Err(target_err) => Err(DomainError::validation(
                ErrorOperation::ParseRequest,
                "invalid Wi-Fi connect target request JSON",
            )
            .with_detail("transport", "stdin")
            .with_detail("request_error", request_err.to_string())
            .with_detail("target_error", target_err.to_string())
            .with_cause(target_err.into())
            .into()),
        },
    }
}
