use std::fmt;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use crate::cache;
use crate::model::{ConnectFailureReason, ConnectResult, WepKeyType, WifiConnectTarget};
use crate::nm::Nm;

const NMCLI_CONNECT_TIMEOUT_SECS: &str = "90";
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(90);
const ACTIVATION_POLL_INTERVAL: Duration = Duration::from_millis(500);
const ACTIVATION_FAILURE_GRACE: Duration = Duration::from_secs(3);

#[derive(Debug)]
struct ConnectAttemptError {
    reason: ConnectFailureReason,
    message: String,
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
    match activate_saved_or_visible(nm, target, password, wep_key_type) {
        Ok(message) => {
            tracing::info!(ssid = %target.ssid, message = %message, "Wi-Fi connection succeeded");
            write_cache_status_best_effort("connected", &message);
            refresh_cached_networks_best_effort(nm);
            let connectivity = nm.connectivity_check().ok();
            let suggest_open_portal = connectivity
                .as_ref()
                .is_some_and(|status| status.captive_portal);
            Ok(ConnectResult {
                status: "connected",
                reason: None,
                ssid: target.ssid.clone(),
                message,
                connectivity,
                suggest_open_portal,
            })
        }
        Err(err) => {
            tracing::error!(ssid = %target.ssid, error = %format_args!("{err:#}"), "Wi-Fi connection failed");
            write_cache_status_best_effort(
                "error",
                format!("Connection failed for {}: {err:#}", target.ssid),
            );
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
    match nm.activate_saved_wifi_connection_for(target, password, wep_key_type) {
        Ok(true) => {
            tracing::info!(ssid = %target.ssid, "requested activation of saved Wi-Fi profile over D-Bus");
            wait_for_active_target(nm, target)?;
            Ok(format!(
                "Connected to saved network {} via D-Bus",
                target.ssid
            ))
        }
        Ok(false) => {
            tracing::info!(ssid = %target.ssid, "no saved D-Bus profile activation target; trying add-and-activate path");
            match nm.add_and_activate_wifi_connection_for(target, password, wep_key_type) {
                Ok(Some(created_connection)) => {
                    tracing::info!(ssid = %target.ssid, connection = %created_connection, "created and requested activation of Wi-Fi profile over D-Bus");
                    wait_for_new_connection(nm, target, &created_connection)?;
                    Ok(format!(
                        "Connected to Wi-Fi network {} via D-Bus",
                        target.ssid
                    ))
                }
                Ok(None) => {
                    tracing::info!(ssid = %target.ssid, "D-Bus add-and-activate not applicable; trying nmcli fallback");
                    activate_with_nmcli_fallback(target, password, wep_key_type)
                }
                Err(dbus_err) => {
                    tracing::warn!(ssid = %target.ssid, error = %format_args!("{dbus_err:#}"), "D-Bus add-and-activate failed; trying nmcli fallback");
                    match activate_with_nmcli_fallback(target, password, wep_key_type) {
                        Ok(message) => Ok(format!(
                            "{message} (D-Bus add/activate failed: {dbus_err:#})"
                        )),
                        Err(fallback_err) => Err(combined_connect_failure(
                            &dbus_err,
                            &fallback_err,
                            format!(
                                "D-Bus add/activate failed: {dbus_err:#}; nmcli fallback failed: {fallback_err:#}"
                            ),
                        )),
                    }
                }
            }
        }
        Err(dbus_err) => {
            tracing::warn!(ssid = %target.ssid, error = %format_args!("{dbus_err:#}"), "D-Bus saved profile activation failed; trying nmcli fallback");
            match activate_with_nmcli_fallback(target, password, wep_key_type) {
                Ok(message) => Ok(format!("{message} (D-Bus activation failed: {dbus_err:#})")),
                Err(fallback_err) => Err(combined_connect_failure(
                    &dbus_err,
                    &fallback_err,
                    format!(
                        "D-Bus saved profile activation failed: {dbus_err:#}; nmcli fallback failed: {fallback_err:#}"
                    ),
                )),
            }
        }
    }
}

fn wait_for_new_connection(
    nm: &Nm,
    target: &WifiConnectTarget,
    created_connection: &OwnedObjectPath,
) -> Result<()> {
    if let Err(err) = wait_for_active_target(nm, target) {
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
) -> Result<String> {
    let ssid = target.ssid.as_str();
    let saved_activation = if target.has_specific_ap() {
        tracing::info!(ssid = %target.ssid, ap_path = ?target.ap_path, bssid = ?target.bssid, "skipping generic nmcli saved-profile activation for specific AP target");
        Err(anyhow::anyhow!(
            "skipped generic saved-profile activation for specific AP target"
        ))
    } else if password.is_some() {
        tracing::info!(ssid = %target.ssid, "skipping nmcli saved-profile activation because caller supplied a password");
        Err(anyhow::anyhow!(
            "skipped saved-profile activation because caller supplied a password"
        ))
    } else {
        tracing::info!(ssid = %target.ssid, "trying nmcli saved-profile activation fallback");
        nmcli(&["connection", "up", "id", ssid])
    };

    match saved_activation {
        Ok(_) => Ok(format!(
            "Connected to saved network {ssid} via nmcli fallback"
        )),
        Err(saved_err) => {
            if target.has_specific_ap() && target.bssid.as_deref().is_none_or(str::is_empty) {
                tracing::warn!(ssid = %target.ssid, ap_path = ?target.ap_path, "not running generic nmcli Wi-Fi connect because selected AP cannot be represented without BSSID");
                return Err(connect_failure(
                    ConnectFailureReason::UnsupportedAuth,
                    format!(
                        "saved profile activation failed: {saved_err:#}; nmcli fallback cannot preserve selected AP path without a BSSID"
                    ),
                ));
            }
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
            match nmcli(&args) {
                Ok(_) => Ok(format!("Connected to {ssid} via nmcli fallback")),
                Err(connect_err) => Err(connect_failure(
                    fallback_failure_reason(target, password),
                    format!(
                        "saved profile activation failed: {saved_err:#}; wifi connect failed: {connect_err:#}"
                    ),
                )),
            }
        }
    }
}

fn combined_connect_failure(
    dbus_err: &anyhow::Error,
    fallback_err: &anyhow::Error,
    message: String,
) -> anyhow::Error {
    let fallback_reason = connect_failure_reason(fallback_err);
    let reason = if fallback_reason == ConnectFailureReason::Unknown {
        dbus_failure_reason(dbus_err).unwrap_or(ConnectFailureReason::Unknown)
    } else {
        fallback_reason
    };
    connect_failure(reason, message)
}

fn dbus_failure_reason(err: &anyhow::Error) -> Option<ConnectFailureReason> {
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

fn fallback_failure_reason(
    target: &WifiConnectTarget,
    password: Option<&str>,
) -> ConnectFailureReason {
    if unsupported_security_label(target.security.as_deref()) {
        ConnectFailureReason::UnsupportedAuth
    } else if password.is_none() && target_appears_to_need_secret(target) {
        ConnectFailureReason::SecretRequired
    } else {
        ConnectFailureReason::Unknown
    }
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

fn wait_for_active_target(nm: &Nm, target: &WifiConnectTarget) -> Result<()> {
    tracing::info!(ssid = %target.ssid, "waiting for target Wi-Fi network to become active");
    let activation_device = nm.wifi_activation_device_for_target(target)?;
    if let Some(device) = activation_device.as_ref() {
        tracing::debug!(ssid = %target.ssid, iface = %device.iface, device = %device.path, "cached activation device for wait loop");
    }
    let deadline = Instant::now() + ACTIVATION_TIMEOUT;
    let mut saw_progress = false;
    let mut possible_failure_since = None;
    let mut last_status = None;
    while Instant::now() < deadline {
        if active_target_matches(nm, activation_device.as_ref(), target)? {
            tracing::info!(ssid = %target.ssid, "target Wi-Fi network is active");
            return Ok(());
        }
        if let Some(status) = activation_status(nm, activation_device.as_ref(), target)? {
            saw_progress |= status.device_state > 30;
            if status.activated() {
                tracing::debug!(
                    ssid = %target.ssid,
                    iface = %status.iface,
                    "device reports activation complete, waiting for active AP identity to match target"
                );
            }
            if saw_progress && status.terminal_failure_after_progress() {
                let failure_since = possible_failure_since.get_or_insert_with(Instant::now);
                if failure_since.elapsed() >= ACTIVATION_FAILURE_GRACE {
                    return Err(connect_failure(
                        ConnectFailureReason::ActivationFailed,
                        format!(
                            "connection activation failed on {}: device state {}, reason {:?}, active connection state {:?}",
                            status.iface,
                            status.device_state,
                            status.device_state_reason,
                            status.active_connection_state
                        ),
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
        }
        sleep(ACTIVATION_POLL_INTERVAL);
    }
    if let Some(status) = last_status {
        return Err(connect_failure(
            ConnectFailureReason::Timeout,
            format!(
                "timed out waiting for {} to become active on {}: device state {}, reason {:?}, active connection state {:?}",
                target.ssid,
                status.iface,
                status.device_state,
                status.device_state_reason,
                status.active_connection_state
            ),
        ));
    }
    Err(connect_failure(
        ConnectFailureReason::Timeout,
        format!("timed out waiting for {} to become active", target.ssid),
    ))
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

fn nmcli(args: &[&str]) -> Result<String> {
    tracing::info!(args = ?redact_nmcli_args(args), "running nmcli fallback command");
    let output = Command::new("nmcli")
        .arg("--wait")
        .arg(NMCLI_CONNECT_TIMEOUT_SECS)
        .args(args)
        .output()
        .context("run nmcli")?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        tracing::debug!(status = %output.status, stdout = %stdout, "nmcli command succeeded");
        return Ok(stdout);
    }

    let message = if stderr.is_empty() { stdout } else { stderr };
    tracing::warn!(status = %output.status, message = %message, "nmcli command failed");
    Err(anyhow::anyhow!(
        "nmcli exited with {}: {message}",
        output.status
    ))
}

fn redact_nmcli_args(args: &[&str]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            redacted.push("<redacted>".to_string());
            redact_next = false;
        } else {
            redacted.push((*arg).to_string());
            redact_next = *arg == "password";
        }
    }
    redacted
}

fn write_cache_status_best_effort(state: impl Into<String>, message: impl Into<String>) {
    if let Err(err) = cache::write_status(state, message) {
        tracing::warn!(error = %format_args!("{err:#}"), "failed to write Wi-Fi cache status");
    }
}

fn refresh_cached_networks_best_effort(nm: &Nm) {
    if let Err(err) = refresh_cached_networks(nm) {
        tracing::warn!(error = %format_args!("{err:#}"), "failed to refresh Wi-Fi cache after connect");
    }
}

fn refresh_cached_networks(nm: &Nm) -> Result<()> {
    let networks = nm.list_access_points()?;
    cache::write_snapshot(false, &networks)?;
    cache::write_complete(false, networks.len())
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectFailureReason, connect_failure, connect_failure_reason, fallback_failure_reason,
    };
    use crate::model::WifiConnectTarget;

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
        let mut target = test_target();
        target.security = Some("WPA2/3".to_string());
        assert_eq!(
            fallback_failure_reason(&target, None),
            ConnectFailureReason::SecretRequired
        );

        target.security = Some("802.1X".to_string());
        assert_eq!(
            fallback_failure_reason(&target, Some("secret")),
            ConnectFailureReason::UnsupportedAuth
        );
    }

    fn test_target() -> WifiConnectTarget {
        WifiConnectTarget {
            ssid: "Example".to_string(),
            ssid_bytes: b"Example".to_vec(),
            ap_path: None,
            bssid: None,
            ifname: None,
            device_path: None,
            connection_name: None,
            private: false,
            hidden: false,
            security: None,
            enterprise: None,
        }
    }
}
