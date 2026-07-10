use std::fmt;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use zvariant::OwnedObjectPath;

use crate::cache;
use crate::connect_cancel::{
    check_cancelled, check_cancelled_and_abort, nmcli, wait_for_activation_signal,
};
use crate::deadline::Deadline;
use crate::model::{
    ConnectEnginePath, ConnectFailureReason, ConnectResult, ScanRequestOptions, WepKeyType,
    WifiConnectTarget, WifiStatus,
};
use crate::nm::Nm;

const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(90);
const ACTIVATION_POLL_INTERVAL: Duration = Duration::from_millis(500);
const ACTIVATION_FAILURE_GRACE: Duration = Duration::from_secs(3);
const POST_CONNECT_STATUS_WAIT: Duration = Duration::from_secs(1);
const NOT_FOUND_RESCAN_TIMEOUT: Duration = Duration::from_secs(8);

const NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE: u32 = 5;
const NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED: u32 = 6;
const NM_DEVICE_STATE_REASON_NO_SECRETS: u32 = 7;
const NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT: u32 = 8;
const NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED: u32 = 9;
const NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED: u32 = 10;
const NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT: u32 = 11;
const WPA_WRONG_KEY_RETRY_DELAY: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct ConnectAttemptError {
    reason: ConnectFailureReason,
    message: String,
}

#[derive(Debug)]
struct ActivationOutcome {
    message: String,
    path: ConnectEnginePath,
}

impl ActivationOutcome {
    fn new(message: impl Into<String>, path: ConnectEnginePath) -> Self {
        Self {
            message: message.into(),
            path,
        }
    }
}

impl fmt::Display for ConnectAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConnectAttemptError {}

pub(crate) fn connect_failure_reason(err: &anyhow::Error) -> ConnectFailureReason {
    err.chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<ConnectAttemptError>()
                .map(|error| error.reason)
        })
        .or_else(|| failure_reason_from_text(&format!("{err:#}")))
        .unwrap_or(ConnectFailureReason::Unknown)
}

fn connect_failure(reason: ConnectFailureReason, message: impl Into<String>) -> anyhow::Error {
    ConnectAttemptError {
        reason,
        message: message.into(),
    }
    .into()
}

fn connect_failure_from_error(reason: ConnectFailureReason, err: anyhow::Error) -> anyhow::Error {
    connect_failure(reason, format!("{err:#}"))
}

pub(crate) fn connect_target_with_password(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<ConnectResult> {
    connect_target_with_password_inner(nm, target, password, wep_key_type, None)
}

pub(crate) fn connect_target_with_password_cancellable(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: &AtomicBool,
) -> Result<ConnectResult> {
    connect_target_with_password_inner(nm, target, password, wep_key_type, Some(cancellation))
}

fn connect_target_with_password_inner(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&AtomicBool>,
) -> Result<ConnectResult> {
    check_cancelled(cancellation)?;
    target
        .validate()
        .map_err(|err| connect_failure_from_error(ConnectFailureReason::ValidationError, err))?;
    tracing::info!(
        ssid = %target.ssid,
        ssid_len = target.ssid_bytes().len(),
        ap_path = ?target.ap_path,
        bssid = ?target.bssid,
        ifname = ?target.ifname,
        device_path = ?target.device_path,
        hidden = target.hidden,
        has_password = password.is_some(),
        wep_key_type = ?wep_key_type,
        "starting Wi-Fi connection attempt"
    );
    write_cache_status_best_effort("connecting", format!("Connecting to {}…", target.ssid));
    let started_at = Instant::now();
    match activate_saved_or_visible(nm, target, password, wep_key_type, cancellation) {
        Ok(outcome) => {
            tracing::info!(ssid = %target.ssid, message = %outcome.message, path = ?outcome.path, "Wi-Fi connection succeeded");
            write_cache_status_best_effort("connected", &outcome.message);
            refresh_cached_networks_background();
            check_cancelled(cancellation)?;
            let active_status = cache_active_status_best_effort(nm, cancellation);
            let connectivity = active_status
                .as_ref()
                .and_then(|status| status.connectivity.clone())
                .or_else(|| nm.connectivity_check().ok());
            let suggest_open_portal = connectivity
                .as_ref()
                .is_some_and(|status| status.captive_portal);
            let result = ConnectResult {
                status: "connected",
                reason: None,
                path: Some(outcome.path),
                ssid: target.ssid.clone(),
                message: outcome.message,
                connectivity,
                suggest_open_portal,
            };
            append_connect_history_best_effort(target, &result, started_at);
            Ok(result)
        }
        Err(err) => {
            tracing::error!(ssid = %target.ssid, error = %format_args!("{err:#}"), "Wi-Fi connection failed");
            write_cache_status_best_effort(
                "error",
                format!("Connection failed for {}: {err:#}", target.ssid),
            );
            let result = ConnectResult {
                status: "error",
                reason: Some(connect_failure_reason(&err)),
                path: None,
                ssid: target.ssid.clone(),
                message: format!("{err:#}"),
                connectivity: None,
                suggest_open_portal: false,
            };
            append_connect_history_best_effort(target, &result, started_at);
            Err(err)
        }
    }
}

fn activate_saved_or_visible(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&AtomicBool>,
) -> Result<ActivationOutcome> {
    check_cancelled(cancellation)?;
    match nm.active_ssid_matches(target) {
        Ok(true) => {
            tracing::info!(ssid = %target.ssid, "target Wi-Fi network is already active; skipping reactivation");
            return Ok(ActivationOutcome::new(
                format!("Already connected to {}", target.ssid),
                ConnectEnginePath::AlreadyActive,
            ));
        }
        Ok(false) => {}
        Err(err) => {
            tracing::debug!(ssid = %target.ssid, error = %format_args!("{err:#}"), "could not check active Wi-Fi target before activation");
        }
    }

    match nm.activate_saved_wifi_connection_for(target, password, wep_key_type) {
        Ok(true) => activate_saved_profile(nm, target, cancellation),
        Ok(false) => add_activate_or_nmcli(nm, target, password, wep_key_type, cancellation),
        Err(dbus_err) if should_return_secret_agent_error(password, &dbus_err) => Err(
            connect_failure_from_error(ConnectFailureReason::PasswordUnavailable, dbus_err),
        ),
        Err(dbus_err) => nmcli_after_dbus_failure(
            target,
            password,
            wep_key_type,
            cancellation,
            &dbus_err,
            "D-Bus activation failed",
            "D-Bus saved profile activation failed",
        ),
    }
}

fn activate_saved_profile(
    nm: &Nm,
    target: &WifiConnectTarget,
    cancellation: Option<&AtomicBool>,
) -> Result<ActivationOutcome> {
    tracing::info!(ssid = %target.ssid, "requested activation of saved Wi-Fi profile over D-Bus");
    wait_for_active_target(nm, target, cancellation)?;
    Ok(ActivationOutcome::new(
        format!("Connected to saved network {} via D-Bus", target.ssid),
        ConnectEnginePath::Dbus,
    ))
}

fn add_activate_or_nmcli(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&AtomicBool>,
) -> Result<ActivationOutcome> {
    check_cancelled(cancellation)?;
    tracing::info!(ssid = %target.ssid, "no saved D-Bus profile activation target; trying add-and-activate path");
    match nm.add_and_activate_wifi_connection_for(target, password, wep_key_type) {
        Ok(Some(created_connection)) => {
            activate_created_connection(nm, target, &created_connection, cancellation)
        }
        Ok(None) => {
            if let Some(outcome) =
                retry_dbus_after_targeted_rescan(nm, target, password, wep_key_type, cancellation)?
            {
                return Ok(outcome);
            }
            tracing::info!(ssid = %target.ssid, "D-Bus add-and-activate not applicable; trying nmcli fallback");
            activate_with_nmcli_fallback(target, password, wep_key_type, cancellation)
        }
        Err(dbus_err) if should_return_secret_agent_error(password, &dbus_err) => Err(
            connect_failure_from_error(ConnectFailureReason::PasswordUnavailable, dbus_err),
        ),
        Err(dbus_err) => nmcli_after_dbus_failure(
            target,
            password,
            wep_key_type,
            cancellation,
            &dbus_err,
            "D-Bus add/activate failed",
            "D-Bus add/activate failed",
        ),
    }
}

fn retry_dbus_after_targeted_rescan(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&AtomicBool>,
) -> Result<Option<ActivationOutcome>> {
    check_cancelled(cancellation)?;
    if target.hidden {
        return Ok(None);
    }
    match nm.target_access_point_visible(target) {
        Ok(true) => return Ok(None),
        Ok(false) => {}
        Err(err) => {
            tracing::debug!(ssid = %target.ssid, error = %format_args!("{err:#}"), "could not verify target AP visibility before rescan");
        }
    }

    tracing::info!(ssid = %target.ssid, bssid = ?target.bssid, ifname = ?target.ifname, "target AP is not visible; rescanning once before nmcli fallback");
    if let Err(err) = nm.scan_with_options(ScanRequestOptions {
        timeout: NOT_FOUND_RESCAN_TIMEOUT,
        ifname: target.ifname.clone(),
        ssid_bytes: vec![target.ssid_bytes().into_owned()],
    }) {
        tracing::warn!(ssid = %target.ssid, error = %format_args!("{err:#}"), "targeted rescan before connect fallback failed");
        return Ok(None);
    }

    check_cancelled(cancellation)?;
    match nm.activate_saved_wifi_connection_for(target, password, wep_key_type) {
        Ok(true) => return activate_saved_profile(nm, target, cancellation).map(Some),
        Ok(false) => {}
        Err(dbus_err) if should_return_secret_agent_error(password, &dbus_err) => {
            return Err(connect_failure_from_error(
                ConnectFailureReason::PasswordUnavailable,
                dbus_err,
            ));
        }
        Err(dbus_err) => {
            return nmcli_after_dbus_failure(
                target,
                password,
                wep_key_type,
                cancellation,
                &dbus_err,
                "D-Bus activation after rescan failed",
                "D-Bus saved profile activation after rescan failed",
            )
            .map(Some);
        }
    }

    check_cancelled(cancellation)?;
    match nm.add_and_activate_wifi_connection_for(target, password, wep_key_type) {
        Ok(Some(created_connection)) => {
            activate_created_connection(nm, target, &created_connection, cancellation).map(Some)
        }
        Ok(None) => Ok(None),
        Err(dbus_err) if should_return_secret_agent_error(password, &dbus_err) => Err(
            connect_failure_from_error(ConnectFailureReason::PasswordUnavailable, dbus_err),
        ),
        Err(dbus_err) => nmcli_after_dbus_failure(
            target,
            password,
            wep_key_type,
            cancellation,
            &dbus_err,
            "D-Bus add/activate after rescan failed",
            "D-Bus add/activate after rescan failed",
        )
        .map(Some),
    }
}

fn activate_created_connection(
    nm: &Nm,
    target: &WifiConnectTarget,
    created_connection: &OwnedObjectPath,
    cancellation: Option<&AtomicBool>,
) -> Result<ActivationOutcome> {
    tracing::info!(ssid = %target.ssid, connection = %created_connection, "created and requested activation of Wi-Fi profile over D-Bus");
    wait_for_new_connection(nm, target, created_connection, cancellation)?;
    Ok(ActivationOutcome::new(
        format!("Connected to Wi-Fi network {} via D-Bus", target.ssid),
        ConnectEnginePath::Dbus,
    ))
}

fn should_return_secret_agent_error(password: Option<&str>, err: &anyhow::Error) -> bool {
    password.is_none()
        && dbus_failure_reason(err).is_some_and(|reason| {
            matches!(
                reason,
                ConnectFailureReason::PasswordUnavailable | ConnectFailureReason::SecretRequired
            )
        })
}

fn nmcli_after_dbus_failure(
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&AtomicBool>,
    dbus_err: &anyhow::Error,
    success_note: &str,
    failure_subject: &str,
) -> Result<ActivationOutcome> {
    tracing::warn!(ssid = %target.ssid, error = %format_args!("{dbus_err:#}"), failure = failure_subject, "D-Bus activation path failed; trying nmcli fallback");
    activate_with_nmcli_fallback(target, password, wep_key_type, cancellation)
        .map(|mut outcome| {
            outcome.message = format!("{} ({success_note}: {dbus_err:#})", outcome.message);
            outcome
        })
        .map_err(|fallback_err| {
            combined_connect_failure(
                dbus_err,
                &fallback_err,
                format!("{failure_subject}: {dbus_err:#}; nmcli fallback failed: {fallback_err:#}"),
            )
        })
}

fn wait_for_new_connection(
    nm: &Nm,
    target: &WifiConnectTarget,
    created_connection: &OwnedObjectPath,
    cancellation: Option<&AtomicBool>,
) -> Result<()> {
    if let Err(err) = wait_for_active_target(nm, target, cancellation) {
        tracing::warn!(ssid = %target.ssid, connection = %created_connection, error = %format_args!("{err:#}"), "newly-created connection failed to activate; deleting it");
        if let Err(delete_err) = nm.delete_connection(created_connection) {
            tracing::warn!(connection = %created_connection, error = %format_args!("{delete_err:#}"), "failed to delete failed newly-created connection");
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
    cancellation: Option<&AtomicBool>,
) -> Result<ActivationOutcome> {
    check_cancelled(cancellation)?;
    match try_nmcli_saved_activation(target, password, cancellation) {
        Ok(()) => Ok(ActivationOutcome::new(
            format!(
                "Connected to saved network {} via nmcli fallback",
                target.ssid
            ),
            ConnectEnginePath::NmcliFallback,
        )),
        Err(saved_err) => {
            nmcli_wifi_connect(target, password, wep_key_type, cancellation, &saved_err)
        }
    }
}

fn try_nmcli_saved_activation(
    target: &WifiConnectTarget,
    password: Option<&str>,
    cancellation: Option<&AtomicBool>,
) -> Result<()> {
    check_cancelled(cancellation)?;
    if target.has_specific_ap() {
        tracing::info!(ssid = %target.ssid, ap_path = ?target.ap_path, bssid = ?target.bssid, "skipping generic nmcli saved-profile activation for specific AP target");
        anyhow::bail!("skipped generic saved-profile activation for specific AP target");
    }
    if password.is_some() {
        tracing::info!(ssid = %target.ssid, "skipping nmcli saved-profile activation because caller supplied a password");
        anyhow::bail!("skipped saved-profile activation because caller supplied a password");
    }

    tracing::info!(ssid = %target.ssid, "trying nmcli saved-profile activation fallback");
    nmcli(
        &["connection", "up", "id", target.ssid.as_str()],
        cancellation,
    )
    .map(|_| ())
}

fn nmcli_wifi_connect(
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&AtomicBool>,
    saved_err: &anyhow::Error,
) -> Result<ActivationOutcome> {
    check_cancelled(cancellation)?;
    if selected_ap_requires_unrepresentable_bssid(target) {
        tracing::warn!(ssid = %target.ssid, ap_path = ?target.ap_path, "not running generic nmcli Wi-Fi connect because selected AP cannot be represented without BSSID");
        return Err(connect_failure(
            ConnectFailureReason::UnsupportedAuth,
            format!(
                "saved profile activation failed: {saved_err:#}; nmcli fallback cannot preserve selected AP path without a BSSID"
            ),
        ));
    }
    if password.is_some() {
        tracing::warn!(ssid = %target.ssid, "not running nmcli Wi-Fi connect fallback because it would expose the secret in process arguments");
        return Err(connect_failure(
            ConnectFailureReason::ActivationFailed,
            format!(
                "saved profile activation failed: {saved_err:#}; nmcli password fallback is disabled because secrets must not be passed through argv"
            ),
        ));
    }

    let args = nmcli_wifi_connect_args(target, password, wep_key_type);
    nmcli(&args, cancellation)
        .map(|_| {
            ActivationOutcome::new(
                format!("Connected to {} via nmcli fallback", target.ssid),
                ConnectEnginePath::NmcliFallback,
            )
        })
        .map_err(|connect_err| {
            connect_failure(
                fallback_failure_reason(target, password, &connect_err),
                format!(
                    "saved profile activation failed: {saved_err:#}; wifi connect failed: {connect_err:#}"
                ),
            )
        })
}

fn selected_ap_requires_unrepresentable_bssid(target: &WifiConnectTarget) -> bool {
    target.has_specific_ap() && target.bssid.as_deref().is_none_or(str::is_empty)
}

fn nmcli_wifi_connect_args<'a>(
    target: &'a WifiConnectTarget,
    password: Option<&'a str>,
    wep_key_type: Option<WepKeyType>,
) -> Vec<&'a str> {
    let mut args = vec!["device", "wifi", "connect", target.ssid.as_str()];
    if let Some(password) = password {
        args.extend(["password", password]);
    }
    if let Some(wep_key_type) = wep_key_type {
        args.extend(["wep-key-type", wep_key_type.nmcli_value()]);
    }
    if let Some(bssid) = target.bssid.as_deref() {
        args.extend(["bssid", bssid]);
    }
    if let Some(ifname) = target.ifname.as_deref() {
        args.extend(["ifname", ifname]);
    }
    if target.hidden {
        args.extend(["hidden", "yes"]);
    }
    if let Some(name) = target.connection_name.as_deref() {
        args.extend(["name", name]);
    }
    if target.private {
        args.extend(["private", "yes"]);
    }
    args
}

fn combined_connect_failure(
    dbus_err: &anyhow::Error,
    fallback_err: &anyhow::Error,
    message: String,
) -> anyhow::Error {
    let fallback_reason = connect_failure_reason(fallback_err);
    let dbus_reason = dbus_failure_reason(dbus_err);
    let reason = if fallback_reason == ConnectFailureReason::Unknown
        || (fallback_reason == ConnectFailureReason::ActivationFailed
            && dbus_reason.is_some_and(secret_or_password_failure))
    {
        dbus_reason.unwrap_or(ConnectFailureReason::Unknown)
    } else {
        fallback_reason
    };
    connect_failure(reason, message)
}

fn dbus_failure_reason(err: &anyhow::Error) -> Option<ConnectFailureReason> {
    failure_reason_from_text(&format!("{err:#}")).or_else(|| {
        err.chain().find_map(|cause| {
            let zbus_error = cause.downcast_ref::<zbus::Error>()?;
            match zbus_error {
                zbus::Error::MethodError(name, _, _)
                    if dbus_error_name_is_authorization(name.as_str()) =>
                {
                    Some(ConnectFailureReason::AuthorizationRequired)
                }
                zbus::Error::Unsupported => Some(ConnectFailureReason::UnsupportedAuth),
                _ => None,
            }
        })
    })
}

fn dbus_error_name_is_authorization(name: &str) -> bool {
    matches!(
        name,
        "org.freedesktop.NetworkManager.Settings.PermissionDenied"
            | "org.freedesktop.NetworkManager.PermissionDenied"
            | "org.freedesktop.DBus.Error.AccessDenied"
            | "org.freedesktop.PolicyKit1.Error.Failed"
    )
}

fn secret_or_password_failure(reason: ConnectFailureReason) -> bool {
    matches!(
        reason,
        ConnectFailureReason::WrongPassword
            | ConnectFailureReason::PasswordUnavailable
            | ConnectFailureReason::SecretRequired
    )
}

fn failure_reason_from_text(message: &str) -> Option<ConnectFailureReason> {
    let lower = message.to_lowercase();
    if lower.contains("wrong_key")
        || lower.contains("wrong key")
        || lower.contains("wrong password")
        || lower.contains("invalid password")
        || lower.contains("4-way handshake")
        || lower.contains("four-way handshake")
        || lower.contains("pre-shared key may be incorrect")
    {
        Some(ConnectFailureReason::WrongPassword)
    } else if lower.contains("no secrets")
        || lower.contains("secrets were required, but not provided")
        || lower.contains("no agents were available")
        || lower.contains("no secret agent")
        || lower.contains("requires a secret agent")
    {
        Some(ConnectFailureReason::PasswordUnavailable)
    } else if (lower.contains("dhcp") && (lower.contains("failed") || lower.contains("timeout")))
        || lower.contains("ip configuration could not be reserved")
        || lower.contains("ip configuration")
            && (lower.contains("failed") || lower.contains("timeout"))
    {
        Some(ConnectFailureReason::DhcpFailed)
    } else if lower.contains("cancelled") || lower.contains("canceled") {
        Some(ConnectFailureReason::ActivationFailed)
    } else if lower.contains("timed out") || lower.contains("timeout") {
        Some(ConnectFailureReason::Timeout)
    } else {
        None
    }
}

fn fallback_failure_reason(
    target: &WifiConnectTarget,
    password: Option<&str>,
    err: &anyhow::Error,
) -> ConnectFailureReason {
    if let Some(reason) = failure_reason_from_text(&format!("{err:#}")) {
        reason
    } else if nmcli_error_says_not_found(err) {
        ConnectFailureReason::NotFound
    } else if unsupported_security_label(target.security.as_deref()) {
        ConnectFailureReason::UnsupportedAuth
    } else if password.is_none() && target_appears_to_need_secret(target) {
        ConnectFailureReason::SecretRequired
    } else {
        ConnectFailureReason::Unknown
    }
}

fn nmcli_error_says_not_found(err: &anyhow::Error) -> bool {
    let message = format!("{err:#}").to_lowercase();
    message.contains("no network with ssid") || message.contains("no access point with bssid")
}

fn target_appears_to_need_secret(target: &WifiConnectTarget) -> bool {
    matches!(
        target.security.as_deref(),
        Some("WPA") | Some("WPA2/3") | Some("WEP")
    ) || (target.hidden && target.security.as_deref().is_none())
}

fn unsupported_security_label(security: Option<&str>) -> bool {
    security.is_some_and(|security| !matches!(security, "--" | "OWE" | "WPA" | "WPA2/3" | "WEP"))
}

fn wait_for_active_target(
    nm: &Nm,
    target: &WifiConnectTarget,
    cancellation: Option<&AtomicBool>,
) -> Result<()> {
    tracing::info!(ssid = %target.ssid, "waiting for target Wi-Fi network to become active");
    let activation_device = nm.wifi_activation_device_for_target(target)?;
    let signal_rx = activation_device.as_ref().map(|device| {
        let (tx, rx) = mpsc::channel();
        nm.spawn_activation_signal_watcher(device.path.to_string(), tx);
        rx
    });
    if let Some(device) = activation_device.as_ref() {
        tracing::debug!(ssid = %target.ssid, iface = %device.iface, device = %device.path, "cached activation device for signal-assisted wait loop");
    }
    let deadline = Deadline::from_now(ACTIVATION_TIMEOUT);
    let mut saw_progress = false;
    let mut possible_failure_since = None;
    let mut last_status = None;
    while !deadline.expired() {
        check_cancelled_and_abort(nm, cancellation)?;
        let target_matches = active_target_matches(nm, activation_device.as_ref(), target)?;
        if let Some(status) = activation_status(nm, activation_device.as_ref(), target)? {
            saw_progress |= status.device_state > 30;
            if target_matches && status.activated() {
                tracing::info!(ssid = %target.ssid, iface = %status.iface, "target Wi-Fi network is fully activated");
                return Ok(());
            }
            if target_matches {
                tracing::debug!(
                    ssid = %target.ssid,
                    iface = %status.iface,
                    device_state = status.device_state,
                    active_connection_state = ?status.active_connection_state,
                    "target access point is selected; waiting for NetworkManager activation to finish"
                );
            } else if status.activated() {
                tracing::debug!(
                    ssid = %target.ssid,
                    iface = %status.iface,
                    "device reports activation complete, waiting for active AP identity to match target"
                );
            }
            if saw_progress && status.terminal_failure_after_progress() {
                let failure_since = possible_failure_since.get_or_insert_with(Instant::now);
                if failure_since.elapsed() >= ACTIVATION_FAILURE_GRACE {
                    let reason = activation_failure_reason(target, &status);
                    return Err(connect_failure(
                        reason,
                        activation_failure_message(target, &status, reason),
                    ));
                }
            } else {
                possible_failure_since = None;
            }
            tracing::debug!(
                ssid = %target.ssid,
                iface = %status.iface,
                device_state = status.device_state,
                device_state_reason = ?status.device_state_reason,
                active_connection_state = ?status.active_connection_state,
                "activation status poll"
            );
            last_status = Some(status);
        } else if target_matches {
            tracing::info!(ssid = %target.ssid, "target Wi-Fi network is active; activation status unavailable");
            return Ok(());
        }
        wait_for_activation_signal(signal_rx.as_ref(), deadline, cancellation)?;
    }
    if let Some(status) = last_status {
        let reason = timeout_failure_reason(target, &status);
        return Err(connect_failure(
            reason,
            activation_timeout_message(target, &status, reason),
        ));
    }
    Err(connect_failure(
        ConnectFailureReason::Timeout,
        format!("timed out waiting for {} to become active", target.ssid),
    ))
}

fn activation_failure_reason(
    target: &WifiConnectTarget,
    status: &crate::nm::WifiActivationStatus,
) -> ConnectFailureReason {
    match status.device_state_reason.1 {
        NM_DEVICE_STATE_REASON_NO_SECRETS => ConnectFailureReason::PasswordUnavailable,
        NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE | NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED => {
            ConnectFailureReason::DhcpFailed
        }
        NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT => ConnectFailureReason::Timeout,
        NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT
        | NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED
        | NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED
            if target_appears_to_need_secret(target) =>
        {
            ConnectFailureReason::WrongPassword
        }
        _ => ConnectFailureReason::ActivationFailed,
    }
}

fn timeout_failure_reason(
    target: &WifiConnectTarget,
    status: &crate::nm::WifiActivationStatus,
) -> ConnectFailureReason {
    match activation_failure_reason(target, status) {
        ConnectFailureReason::ActivationFailed => ConnectFailureReason::Timeout,
        reason => reason,
    }
}

fn activation_failure_message(
    target: &WifiConnectTarget,
    status: &crate::nm::WifiActivationStatus,
    reason: ConnectFailureReason,
) -> String {
    match reason {
        ConnectFailureReason::WrongPassword => format!(
            "wrong password for {}{}; wpa_supplicant may ignore this AP for about {} seconds before retrying is useful",
            target.ssid,
            target_radio_details(target),
            WPA_WRONG_KEY_RETRY_DELAY.as_secs()
        ),
        ConnectFailureReason::PasswordUnavailable => format!(
            "saved password unavailable for {}{}; NetworkManager requested secrets but no usable secret was provided",
            target.ssid,
            target_radio_details(target)
        ),
        ConnectFailureReason::DhcpFailed => format!(
            "connected to Wi-Fi network {}{} but DHCP/IP configuration failed on {}",
            target.ssid,
            target_radio_details(target),
            status.iface
        ),
        _ => format!(
            "connection activation failed for {}{} on {}: device state {}, reason {:?}, active connection state {:?}",
            target.ssid,
            target_radio_details(target),
            status.iface,
            status.device_state,
            status.device_state_reason,
            status.active_connection_state
        ),
    }
}

fn activation_timeout_message(
    target: &WifiConnectTarget,
    status: &crate::nm::WifiActivationStatus,
    reason: ConnectFailureReason,
) -> String {
    match reason {
        ConnectFailureReason::DhcpFailed => format!(
            "connected to Wi-Fi network {}{} but timed out waiting for DHCP/IP configuration on {}",
            target.ssid,
            target_radio_details(target),
            status.iface
        ),
        _ => format!(
            "timed out waiting for {}{} to become active on {}; the AP may be unreachable or signal may be weak: device state {}, reason {:?}, active connection state {:?}",
            target.ssid,
            target_radio_details(target),
            status.iface,
            status.device_state,
            status.device_state_reason,
            status.active_connection_state
        ),
    }
}

fn target_radio_details(target: &WifiConnectTarget) -> String {
    target
        .bssid
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|bssid| format!(" (BSSID {bssid})"))
        .unwrap_or_default()
}

fn active_target_matches(
    nm: &Nm,
    activation_device: Option<&crate::model::WifiDevice>,
    target: &WifiConnectTarget,
) -> Result<bool> {
    if let Some(device) = activation_device {
        nm.active_ssid_matches_on_device(device, target)
    } else {
        nm.active_ssid_matches(target)
    }
}

fn activation_status(
    nm: &Nm,
    activation_device: Option<&crate::model::WifiDevice>,
    target: &WifiConnectTarget,
) -> Result<Option<crate::nm::WifiActivationStatus>> {
    if let Some(device) = activation_device {
        nm.wifi_activation_status_for_device(device).map(Some)
    } else {
        nm.wifi_activation_status_for(target)
    }
}

fn write_cache_status_best_effort(state: impl Into<String>, message: impl Into<String>) {
    if let Err(err) = cache::write_status(state, message) {
        tracing::warn!(error = %format_args!("{err:#}"), "failed to write Wi-Fi cache status");
    }
}

fn append_connect_history_best_effort(
    target: &WifiConnectTarget,
    result: &ConnectResult,
    started_at: Instant,
) {
    let record = cache::ConnectAttemptRecord::new(
        target,
        result.status,
        result.reason,
        result.path,
        &result.message,
        started_at.elapsed().as_millis(),
    );
    if let Err(err) = cache::append_connect_attempt(&record) {
        tracing::warn!(error = %format_args!("{err:#}"), "failed to append persistent connect history");
    }
}

fn cache_active_status_best_effort(
    nm: &Nm,
    cancellation: Option<&AtomicBool>,
) -> Option<WifiStatus> {
    match read_active_status_after_connect(nm, cancellation) {
        Ok(status) => {
            if let Err(err) = cache::cache_connected_network_status(&status) {
                tracing::warn!(error = %format_args!("{err:#}"), "failed to cache active Wi-Fi details after connect");
            }
            Some(status)
        }
        Err(err) => {
            tracing::warn!(error = %format_args!("{err:#}"), "failed to read active Wi-Fi details after connect");
            None
        }
    }
}

fn read_active_status_after_connect(
    nm: &Nm,
    cancellation: Option<&AtomicBool>,
) -> Result<WifiStatus> {
    let deadline = Deadline::from_now(POST_CONNECT_STATUS_WAIT);
    loop {
        check_cancelled(cancellation)?;
        let status = nm.wifi_status()?;
        if status_has_network_details(&status) || deadline.expired() {
            return Ok(status);
        }
        deadline.sleep(ACTIVATION_POLL_INTERVAL);
    }
}

fn status_has_network_details(status: &WifiStatus) -> bool {
    status.ip4.as_ref().is_some_and(|ip4| {
        ip4.address
            .as_deref()
            .is_some_and(|address| !address.is_empty())
    })
}

fn refresh_cached_networks_background() {
    thread::spawn(|| {
        if let Err(err) = refresh_cached_networks() {
            tracing::warn!(error = %format_args!("{err:#}"), "failed to refresh Wi-Fi cache after connect");
        }
    });
}

fn refresh_cached_networks() -> Result<()> {
    let nm = Nm::new()?;
    let networks = nm.list_access_points()?;
    cache::write_snapshot(false, &networks)?;
    cache::write_complete(false, networks.len())
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectFailureReason, connect_failure, connect_failure_reason, failure_reason_from_text,
        fallback_failure_reason,
    };
    use crate::model::example_connect_target;

    #[test]
    fn typed_connect_errors_provide_machine_readable_reasons() {
        let err = connect_failure(ConnectFailureReason::ValidationError, "bad target");

        assert_eq!(
            connect_failure_reason(&err),
            ConnectFailureReason::ValidationError
        );
    }

    #[test]
    fn fallback_reason_uses_target_metadata_not_error_text() {
        let mut target = example_connect_target(false);
        target.security = Some("WPA2/3".to_string());
        let generic_err = connect_failure(ConnectFailureReason::Unknown, "generic failure");
        assert_eq!(
            fallback_failure_reason(&target, None, &generic_err),
            ConnectFailureReason::SecretRequired
        );

        target.security = Some("802.1X".to_string());
        assert_eq!(
            fallback_failure_reason(&target, Some("secret"), &generic_err),
            ConnectFailureReason::UnsupportedAuth
        );

        let not_found_err = connect_failure(
            ConnectFailureReason::Unknown,
            "nmcli exited with exit status: 10: Error: No network with SSID 'Cafe' found.",
        );
        assert_eq!(
            fallback_failure_reason(&target, Some("secret"), &not_found_err),
            ConnectFailureReason::NotFound
        );
    }

    #[test]
    fn wrong_key_and_secret_agent_errors_are_mapped_for_ui_prompting() {
        assert_eq!(
            failure_reason_from_text("CTRL-EVENT-SSID-TEMP-DISABLED reason=WRONG_KEY"),
            Some(ConnectFailureReason::WrongPassword)
        );
        assert_eq!(
            failure_reason_from_text("4-way handshake failed: pre-shared key may be incorrect"),
            Some(ConnectFailureReason::WrongPassword)
        );
        assert_eq!(
            failure_reason_from_text(
                "Secrets were required, but not provided; no agents were available"
            ),
            Some(ConnectFailureReason::PasswordUnavailable)
        );
        assert_eq!(
            failure_reason_from_text("saved Wi-Fi profile requires a secret agent"),
            Some(ConnectFailureReason::PasswordUnavailable)
        );
        assert_eq!(
            failure_reason_from_text("DHCP request failed"),
            Some(ConnectFailureReason::DhcpFailed)
        );
        assert_eq!(
            failure_reason_from_text("IP configuration could not be reserved"),
            Some(ConnectFailureReason::DhcpFailed)
        );
    }
}
