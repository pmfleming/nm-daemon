use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::connect_cancel::check_cancelled_and_abort;
use crate::connect_error::{connect_failure, target_appears_to_need_secret};
use crate::deadline::Deadline;
use crate::model::{ConnectFailureReason, WifiConnectTarget};
use crate::nm::Nm;

const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(90);
const ACTIVATION_FAILURE_GRACE: Duration = Duration::from_secs(3);

const NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE: u32 = 5;
const NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED: u32 = 6;
const NM_DEVICE_STATE_REASON_NO_SECRETS: u32 = 7;
const NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT: u32 = 8;
const NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED: u32 = 9;
const NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED: u32 = 10;
const NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT: u32 = 11;
const WPA_WRONG_KEY_RETRY_DELAY: Duration = Duration::from_secs(10);

pub(crate) fn wait_for_active_target(
    nm: &Nm,
    target: &WifiConnectTarget,
    cancellation: Option<&AtomicBool>,
) -> Result<()> {
    tracing::info!(ssid = %target.ssid, "waiting for target Wi-Fi network to become active");
    let activation_device = nm.wifi_activation_device_for_target(target)?;
    if let Some(device) = activation_device.as_ref() {
        tracing::debug!(ssid = %target.ssid, iface = %device.iface, device = %device.path, "cached activation device for signal-assisted wait loop");
    }
    let deadline = Deadline::from_now(ACTIVATION_TIMEOUT);
    let mut wait = ActivationWait::default();
    let mut event_generation = nm.event_generation();
    while !deadline.expired() {
        check_cancelled_and_abort(nm, cancellation)?;
        let ssid_matches = active_ssid_matches(nm, activation_device.as_ref(), target)?;
        let status = activation_status(nm, activation_device.as_ref(), target)?;
        if wait.observe(target, status, ssid_matches)? {
            return Ok(());
        }
        check_cancelled_and_abort(nm, cancellation)?;
        event_generation = nm.wait_for_event(event_generation, deadline.wait(Duration::MAX));
    }
    Err(wait.timeout_error(target))
}

#[derive(Default)]
struct ActivationWait {
    saw_progress: bool,
    possible_failure_since: Option<Instant>,
    last_status: Option<crate::nm::WifiActivationStatus>,
}

impl ActivationWait {
    fn observe(
        &mut self,
        target: &WifiConnectTarget,
        status: Option<crate::nm::WifiActivationStatus>,
        ssid_matches: bool,
    ) -> Result<bool> {
        let Some(status) = status else {
            if ssid_matches {
                tracing::info!(ssid = %target.ssid, requested_bssid = ?target.bssid, "target SSID is active; activation status unavailable");
            }
            return Ok(ssid_matches);
        };

        self.saw_progress |= status.device_state > 30;
        if ssid_matches && status.activated() {
            tracing::info!(ssid = %target.ssid, iface = %status.iface, requested_bssid = ?target.bssid, "target SSID is fully activated");
            return Ok(true);
        }
        log_activation_progress(target, &status, ssid_matches);
        self.check_terminal_failure(target, &status)?;
        log_activation_status(target, &status);
        self.last_status = Some(status);
        Ok(false)
    }

    fn check_terminal_failure(
        &mut self,
        target: &WifiConnectTarget,
        status: &crate::nm::WifiActivationStatus,
    ) -> Result<()> {
        if !(self.saw_progress && status.terminal_failure_after_progress()) {
            self.possible_failure_since = None;
            return Ok(());
        }
        let failure_since = self.possible_failure_since.get_or_insert_with(Instant::now);
        if failure_since.elapsed() < ACTIVATION_FAILURE_GRACE {
            return Ok(());
        }
        let reason = activation_failure_reason(target, status);
        Err(connect_failure(
            reason,
            activation_failure_message(target, status, reason),
        ))
    }

    fn timeout_error(self, target: &WifiConnectTarget) -> anyhow::Error {
        let Some(status) = self.last_status else {
            return connect_failure(
                ConnectFailureReason::Timeout,
                format!("timed out waiting for {} to become active", target.ssid),
            );
        };
        let reason = timeout_failure_reason(target, &status);
        connect_failure(reason, activation_timeout_message(target, &status, reason))
    }
}

fn log_activation_status(target: &WifiConnectTarget, status: &crate::nm::WifiActivationStatus) {
    tracing::debug!(
        ssid = %target.ssid,
        iface = %status.iface,
        device_state = status.device_state,
        device_state_reason = ?status.device_state_reason,
        active_connection_state = ?status.active_connection_state,
        "activation status update"
    );
}

fn log_activation_progress(
    target: &WifiConnectTarget,
    status: &crate::nm::WifiActivationStatus,
    ssid_matches: bool,
) {
    if ssid_matches {
        tracing::debug!(
            ssid = %target.ssid,
            iface = %status.iface,
            device_state = status.device_state,
            active_connection_state = ?status.active_connection_state,
            "target SSID is selected; waiting for NetworkManager activation to finish"
        );
    } else if status.activated() {
        tracing::debug!(
            ssid = %target.ssid,
            iface = %status.iface,
            "device reports activation complete, waiting for active SSID identity to match target"
        );
    }
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

fn active_ssid_matches(
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
