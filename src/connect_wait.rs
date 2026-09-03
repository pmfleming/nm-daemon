use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use anyhow::Result;
use zvariant::OwnedObjectPath;

use crate::connect_cancel::check_cancelled_and_abort;
use crate::connect_error::{connect_failure, target_appears_to_need_secret};
use crate::deadline::Deadline;
use crate::error::DomainError;
use crate::generated::{ACTIVATION_FAILURE_GRACE, ACTIVATION_TIMEOUT, WPA_WRONG_KEY_RETRY_DELAY};
use crate::model::{ConnectFailureReason, WifiConnectTarget};
use crate::nm::Nm;

const NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE: u32 = 5;
const NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED: u32 = 6;
const NM_DEVICE_STATE_REASON_NO_SECRETS: u32 = 7;
const NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT: u32 = 8;
const NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED: u32 = 9;
const NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED: u32 = 10;
const NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT: u32 = 11;
const NM_DEVICE_STATE_REASON_DHCP_START_FAILED: u32 = 15;
const NM_DEVICE_STATE_REASON_DHCP_ERROR: u32 = 16;
const NM_DEVICE_STATE_REASON_DHCP_FAILED: u32 = 17;
const NM_DEVICE_STATE_REASON_SSID_NOT_FOUND: u32 = 53;
pub(crate) fn wait_for_active_target(
    nm: &Nm,
    target: &WifiConnectTarget,
    cancellation: Option<&AtomicBool>,
) -> Result<()> {
    wait_for_active_target_path(nm, target, None, cancellation)
}

pub(crate) fn wait_for_active_target_path(
    nm: &Nm,
    target: &WifiConnectTarget,
    requested_active_path: Option<&OwnedObjectPath>,
    cancellation: Option<&AtomicBool>,
) -> Result<()> {
    tracing::info!(
        ssid = %target.ssid,
        active_path = ?requested_active_path,
        "waiting for target Wi-Fi network to become active"
    );
    let activation_device = nm
        .wifi_activation_device_for_target(target)?
        .inspect(|device| {
            tracing::debug!(ssid = %target.ssid, iface = %device.iface, device = %device.path, "cached activation device for signal-assisted wait loop");
        });
    let deadline = Deadline::from_now(ACTIVATION_TIMEOUT)?;
    let mut wait = ActivationWait::default();
    let mut event_generation = nm.event_generation();
    while !deadline.expired() {
        check_cancelled_and_abort(nm, target, cancellation)?;
        let requested_active_state =
            requested_active_path.and_then(|path| nm.active_connection_state(path));
        let (ssid_matches, status) =
            activation_observation(nm, activation_device.as_ref(), target)?;
        if wait.observe(
            target,
            status,
            ssid_matches,
            requested_active_path,
            requested_active_state,
        )? {
            return Ok(());
        }
        // Cancellation wakes NetworkEvents, so a cancel racing this wait is
        // observed at the top of the next iteration without a second poll.
        event_generation = nm.wait_for_event(event_generation, wait.next_wake(deadline));
    }
    Err(wait.timeout_error(target))
}

#[derive(Debug)]
struct PendingFailure {
    since: Instant,
    status: crate::nm::WifiActivationStatus,
}

#[derive(Default)]
struct ActivationWait {
    saw_progress: bool,
    pending_failure: Option<PendingFailure>,
    last_status: Option<crate::nm::WifiActivationStatus>,
}

impl ActivationWait {
    fn observe(
        &mut self,
        target: &WifiConnectTarget,
        status: Option<crate::nm::WifiActivationStatus>,
        ssid_matches: bool,
        requested_active_path: Option<&OwnedObjectPath>,
        requested_active_state: Option<u32>,
    ) -> Result<bool> {
        let Some(status) = status else {
            if ssid_matches {
                tracing::info!(ssid = %target.ssid, requested_bssid = ?target.bssid, "target SSID is active; activation status unavailable");
            }
            return Ok(ssid_matches);
        };

        self.saw_progress |= status.device_state > 30 || requested_active_path.is_some();
        if ssid_matches && status.activated() {
            tracing::info!(ssid = %target.ssid, iface = %status.iface, requested_bssid = ?target.bssid, "target SSID is fully activated");
            return Ok(true);
        }
        log_activation_progress(target, &status, ssid_matches);
        self.check_terminal_failure(
            target,
            &status,
            requested_active_path,
            requested_active_state,
        )?;
        log_activation_status(target, &status);
        self.last_status = Some(status);
        Ok(false)
    }

    fn check_terminal_failure(
        &mut self,
        target: &WifiConnectTarget,
        status: &crate::nm::WifiActivationStatus,
        requested_active_path: Option<&OwnedObjectPath>,
        requested_active_state: Option<u32>,
    ) -> Result<()> {
        let requested_activation_stopped =
            requested_activation_stopped(requested_active_path, requested_active_state);
        if !(self.saw_progress
            && (status.terminal_failure_after_progress() || requested_activation_stopped))
        {
            self.pending_failure = None;
            return Ok(());
        }
        latch_pending_failure(&mut self.pending_failure, status);
        let pending = self.pending_failure.as_ref().expect("pending failure");
        if pending.since.elapsed() < ACTIVATION_FAILURE_GRACE {
            return Ok(());
        }
        let reason = activation_failure_reason(target, &pending.status);
        Err(activation_error(
            target,
            &pending.status,
            reason,
            activation_failure_message(target, &pending.status, reason),
        ))
    }

    fn next_wake(&self, deadline: Deadline) -> Duration {
        let grace_wait = self
            .pending_failure
            .as_ref()
            .map(|pending| ACTIVATION_FAILURE_GRACE.saturating_sub(pending.since.elapsed()))
            .unwrap_or(Duration::MAX);
        deadline.wait(grace_wait)
    }

    fn timeout_error(self, target: &WifiConnectTarget) -> anyhow::Error {
        let Some(status) = self.last_status else {
            return connect_failure(
                ConnectFailureReason::Timeout,
                format!("timed out waiting for {} to become active", target.ssid),
            );
        };
        let reason = timeout_failure_reason(target, &status);
        activation_error(
            target,
            &status,
            reason,
            activation_timeout_message(target, &status, reason),
        )
    }
}

fn latch_pending_failure(
    pending: &mut Option<PendingFailure>,
    status: &crate::nm::WifiActivationStatus,
) {
    match pending {
        Some(pending)
            if pending.status.device_state_reason.1 == 0 && status.device_state_reason.1 != 0 =>
        {
            // Keep the original grace deadline, but do not let a later
            // generic disconnected/none snapshot erase the useful reason.
            pending.status = status.clone();
        }
        Some(_) => {}
        None => {
            *pending = Some(PendingFailure {
                since: Instant::now(),
                status: status.clone(),
            });
        }
    }
}

fn log_activation_status(target: &WifiConnectTarget, status: &crate::nm::WifiActivationStatus) {
    tracing::debug!(
        ssid = %target.ssid,
        iface = %status.iface,
        device_state = status.device_state,
        device_state_reason = ?status.device_state_reason,
        active_connection_path = ?status.active_connection_path,
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

fn requested_activation_stopped(
    requested_active_path: Option<&OwnedObjectPath>,
    requested_active_state: Option<u32>,
) -> bool {
    requested_active_path.is_some() && requested_active_state.is_none_or(|state| state >= 3)
}

fn activation_failure_reason(
    target: &WifiConnectTarget,
    status: &crate::nm::WifiActivationStatus,
) -> ConnectFailureReason {
    match status.device_state_reason.1 {
        NM_DEVICE_STATE_REASON_NO_SECRETS => ConnectFailureReason::PasswordUnavailable,
        NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE
        | NM_DEVICE_STATE_REASON_IP_CONFIG_EXPIRED
        | NM_DEVICE_STATE_REASON_DHCP_START_FAILED
        | NM_DEVICE_STATE_REASON_DHCP_ERROR
        | NM_DEVICE_STATE_REASON_DHCP_FAILED => ConnectFailureReason::DhcpFailed,
        NM_DEVICE_STATE_REASON_SSID_NOT_FOUND => ConnectFailureReason::NotFound,
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

fn activation_error(
    target: &WifiConnectTarget,
    status: &crate::nm::WifiActivationStatus,
    reason: ConnectFailureReason,
    message: String,
) -> anyhow::Error {
    let typed_reason = crate::model::device_state_reason(status.device_state_reason.1);
    let mut error = DomainError::connect(reason, message)
        .with_detail("ssid", target.ssid.to_string())
        .with_detail("device_iface", status.iface.clone())
        .with_detail("device_state", status.device_state)
        .with_detail("reason", typed_reason.name)
        .with_detail("reason_category", serde_json::json!(typed_reason.category))
        .with_detail("reason_code", typed_reason.code);
    if let Some(state) = status.active_connection_state {
        error = error.with_detail("active_connection_state", state);
    }
    if let Some(bssid) = target.bssid.as_ref() {
        error = error.with_detail("bssid", bssid.as_str());
    }
    error.into()
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
        .as_ref()
        .map(crate::model::Bssid::as_str)
        .filter(|value| !value.is_empty())
        .map(|bssid| format!(" (BSSID {bssid})"))
        .unwrap_or_default()
}

fn activation_observation(
    nm: &Nm,
    activation_device: Option<&crate::model::WifiDevice>,
    target: &WifiConnectTarget,
) -> Result<(bool, Option<crate::nm::WifiActivationStatus>)> {
    match activation_device {
        Some(device) => Ok((
            nm.active_ssid_matches_on_device(device, target)?,
            Some(nm.wifi_activation_status_for_device(device)?),
        )),
        None => Ok((
            nm.active_ssid_matches(target)?,
            nm.wifi_activation_status_for(target)?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        ActivationWait, PendingFailure, latch_pending_failure, requested_activation_stopped,
    };
    use crate::deadline::Deadline;
    use crate::generated::ACTIVATION_FAILURE_GRACE;
    use zvariant::OwnedObjectPath;

    #[test]
    fn requested_activation_disappearance_or_deactivation_is_terminal() {
        let path = OwnedObjectPath::try_from("/active/1").unwrap();
        assert!(requested_activation_stopped(Some(&path), None));
        assert!(!requested_activation_stopped(Some(&path), Some(1)));
        assert!(!requested_activation_stopped(Some(&path), Some(2)));
        assert!(requested_activation_stopped(Some(&path), Some(3)));
        assert!(requested_activation_stopped(Some(&path), Some(4)));
        assert!(!requested_activation_stopped(None, None));
    }

    #[test]
    fn informative_activation_failure_survives_later_generic_snapshots() {
        let status = |reason| crate::nm::WifiActivationStatus {
            iface: "wlan0".to_string(),
            device_state: 30,
            device_state_reason: (30, reason),
            active_connection_path: None,
            active_connection_state: None,
        };
        let since = Instant::now();
        let mut pending = Some(PendingFailure {
            since,
            status: status(super::NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE),
        });

        latch_pending_failure(&mut pending, &status(0));
        let pending = pending.unwrap();
        assert_eq!(
            pending.status.device_state_reason.1,
            super::NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE
        );
        assert_eq!(pending.since, since);
    }

    #[test]
    fn terminal_failure_grace_sets_the_next_wake_instead_of_waiting_to_timeout() {
        let wait = ActivationWait {
            saw_progress: true,
            pending_failure: Some(super::PendingFailure {
                since: Instant::now() - ACTIVATION_FAILURE_GRACE,
                status: crate::nm::WifiActivationStatus {
                    iface: "wlan0".to_string(),
                    device_state: 30,
                    device_state_reason: (30, 0),
                    active_connection_path: None,
                    active_connection_state: None,
                },
            }),
            last_status: None,
        };
        assert_eq!(
            wait.next_wake(Deadline::from_now(Duration::from_secs(90)).unwrap()),
            Duration::ZERO
        );
    }
}
