use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use anyhow::Result;
use zvariant::OwnedObjectPath;

use crate::cache;
use crate::connect_cancel::check_cancelled;
use crate::connect_error::{
    connect_failure, connect_failure_from_error, should_return_secret_agent_error,
};
use crate::connect_wait::wait_for_active_target;
use crate::deadline::Deadline;
use crate::error::{ErrorOperation, best_effort, ensure_domain};
use crate::model::{
    ConnectEnginePath, ConnectFailureReason, ConnectResult, ScanRequestOptions, WepKeyType,
    WifiConnectTarget, WifiStatus,
};
use crate::nm::Nm;

const POST_CONNECT_STATUS_WAIT: Duration = Duration::from_secs(1);
const NOT_FOUND_RESCAN_TIMEOUT: Duration = Duration::from_secs(8);

pub(crate) use crate::connect_error::connect_failure_reason;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Explicit phases of one connection attempt. A successful rescan loops back through
/// `SavedProfile` and `CreateProfile` once before proceeding to fallback.
enum ConnectionState {
    AlreadyActive,
    SavedProfile,
    CreateProfile,
    Rescan,
    Verify(VerificationKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationKind {
    SavedProfile,
    CreatedProfile,
}

enum StateTransition {
    Next(ConnectionState),
    Connected(ActivationOutcome),
}

#[derive(Debug, Clone, Copy)]
enum DbusAttempt {
    SavedProfile,
    CreateProfile,
    SavedProfileAfterRescan,
    CreateProfileAfterRescan,
}

impl DbusAttempt {
    fn failure_subject(self) -> &'static str {
        match self {
            Self::SavedProfile => "D-Bus saved profile activation failed",
            Self::CreateProfile => "D-Bus add/activate failed",
            Self::SavedProfileAfterRescan => "D-Bus saved profile activation after rescan failed",
            Self::CreateProfileAfterRescan => "D-Bus add/activate after rescan failed",
        }
    }
}

struct ConnectionMachine<'a> {
    nm: &'a Nm,
    target: &'a WifiConnectTarget,
    password: Option<&'a str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&'a AtomicBool>,
    rescanned: bool,
    created_connection: Option<OwnedObjectPath>,
}

impl<'a> ConnectionMachine<'a> {
    fn new(
        nm: &'a Nm,
        target: &'a WifiConnectTarget,
        password: Option<&'a str>,
        wep_key_type: Option<WepKeyType>,
        cancellation: Option<&'a AtomicBool>,
    ) -> Self {
        Self {
            nm,
            target,
            password,
            wep_key_type,
            cancellation,
            rescanned: false,
            created_connection: None,
        }
    }

    fn run(mut self) -> Result<ConnectResult> {
        check_cancelled(self.cancellation)?;
        self.target.validate().map_err(|err| {
            connect_failure_from_error(ConnectFailureReason::ValidationError, err)
        })?;
        self.log_start();
        best_effort("failed to write Wi-Fi cache status", || {
            cache::write_status("connecting", format!("Connecting to {}…", self.target.ssid))
        });
        let started_at = Instant::now();

        match self.run_states() {
            Ok(outcome) => self.finish_success(outcome, started_at),
            Err(err) => {
                self.cleanup_created_connection();
                self.finish_failure(err, started_at)
            }
        }
    }

    fn run_states(&mut self) -> Result<ActivationOutcome> {
        let mut state = ConnectionState::AlreadyActive;
        loop {
            check_cancelled(self.cancellation)?;
            match self.step(state)? {
                StateTransition::Next(next) => {
                    tracing::debug!(from = ?state, to = ?next, ssid = %self.target.ssid, "Wi-Fi connection state transition");
                    state = next;
                }
                StateTransition::Connected(outcome) => return Ok(outcome),
            }
        }
    }

    fn step(&mut self, state: ConnectionState) -> Result<StateTransition> {
        match state {
            ConnectionState::AlreadyActive => self.check_already_active(),
            ConnectionState::SavedProfile => self.activate_saved_profile(),
            ConnectionState::CreateProfile => self.create_profile(),
            ConnectionState::Rescan => self.rescan(),
            ConnectionState::Verify(kind) => self.verify(kind),
        }
    }

    fn check_already_active(&self) -> Result<StateTransition> {
        match self.nm.active_target_matches(self.target) {
            Ok(true) => {
                tracing::info!(ssid = %self.target.ssid, "target Wi-Fi network is already active; skipping reactivation");
                Ok(StateTransition::Connected(ActivationOutcome::new(
                    format!("Already connected to {}", self.target.ssid),
                    ConnectEnginePath::AlreadyActive,
                )))
            }
            Ok(false) => Ok(StateTransition::Next(ConnectionState::SavedProfile)),
            Err(err) => {
                tracing::debug!(ssid = %self.target.ssid, error = %crate::error::err_chain(&err), "could not check active Wi-Fi target before activation");
                Ok(StateTransition::Next(ConnectionState::SavedProfile))
            }
        }
    }

    fn activate_saved_profile(&mut self) -> Result<StateTransition> {
        let attempt = if self.rescanned {
            DbusAttempt::SavedProfileAfterRescan
        } else {
            DbusAttempt::SavedProfile
        };
        match self.nm.activate_saved_wifi_connection_for(
            self.target,
            self.password,
            self.wep_key_type,
        ) {
            Ok(true) => {
                tracing::info!(ssid = %self.target.ssid, "requested activation of saved Wi-Fi profile over D-Bus");
                Ok(StateTransition::Next(ConnectionState::Verify(
                    VerificationKind::SavedProfile,
                )))
            }
            Ok(false) => Ok(StateTransition::Next(ConnectionState::CreateProfile)),
            Err(err) => self.finish_dbus_failure(attempt, err),
        }
    }

    fn create_profile(&mut self) -> Result<StateTransition> {
        tracing::info!(ssid = %self.target.ssid, "no saved D-Bus profile activation target; trying add-and-activate path");
        let attempt = if self.rescanned {
            DbusAttempt::CreateProfileAfterRescan
        } else {
            DbusAttempt::CreateProfile
        };
        match self.nm.add_and_activate_wifi_connection_for(
            self.target,
            self.password,
            self.wep_key_type,
        ) {
            Ok(Some(created_connection)) => {
                tracing::info!(ssid = %self.target.ssid, connection = %created_connection, "created and requested activation of Wi-Fi profile over D-Bus");
                self.created_connection = Some(created_connection);
                Ok(StateTransition::Next(ConnectionState::Verify(
                    VerificationKind::CreatedProfile,
                )))
            }
            Ok(None) if self.should_rescan() => Ok(StateTransition::Next(ConnectionState::Rescan)),
            Ok(None) => Err(self.unavailable_activation_error()),
            Err(err) => self.finish_dbus_failure(attempt, err),
        }
    }

    fn should_rescan(&self) -> bool {
        if self.rescanned || self.target.hidden {
            return false;
        }
        match self.nm.target_access_point_visible(self.target) {
            Ok(visible) => !visible,
            Err(err) => {
                tracing::debug!(ssid = %self.target.ssid, error = %crate::error::err_chain(&err), "could not verify target AP visibility before rescan");
                true
            }
        }
    }

    fn rescan(&mut self) -> Result<StateTransition> {
        self.rescanned = true;
        tracing::info!(ssid = %self.target.ssid, bssid = ?self.target.bssid, ifname = ?self.target.ifname, "target AP is not visible; rescanning once before the final D-Bus activation attempt");
        let result = self.nm.scan_with_options(
            ScanRequestOptions {
                timeout: NOT_FOUND_RESCAN_TIMEOUT,
                ifname: self.target.ifname.clone(),
                ssid_bytes: vec![self.target.ssid_bytes().to_vec()],
            },
            self.cancellation,
        );
        result?;
        Ok(StateTransition::Next(ConnectionState::SavedProfile))
    }

    fn finish_dbus_failure(
        &self,
        attempt: DbusAttempt,
        error: anyhow::Error,
    ) -> Result<StateTransition> {
        tracing::warn!(
            ssid = %self.target.ssid,
            error = %crate::error::err_chain(&error),
            failure = attempt.failure_subject(),
            "D-Bus activation path failed"
        );
        if should_return_secret_agent_error(self.password, &error) {
            return Err(connect_failure_from_error(
                ConnectFailureReason::PasswordUnavailable,
                error,
            ));
        }
        Err(error)
    }

    fn unavailable_activation_error(&self) -> anyhow::Error {
        let reason = if self.target.hidden {
            ConnectFailureReason::NotFound
        } else {
            match self.nm.target_access_point_visible(self.target) {
                Ok(true) => ConnectFailureReason::UnsupportedAuth,
                Ok(false) | Err(_) => ConnectFailureReason::NotFound,
            }
        };
        connect_failure(
            reason,
            format!(
                "no supported D-Bus activation path is available for {}",
                self.target.ssid
            ),
        )
    }

    fn verify(&mut self, kind: VerificationKind) -> Result<StateTransition> {
        let outcome = match kind {
            VerificationKind::SavedProfile => {
                wait_for_active_target(self.nm, self.target, self.cancellation)?;
                ActivationOutcome::new(
                    format!("Connected to saved network {} via D-Bus", self.target.ssid),
                    ConnectEnginePath::Dbus,
                )
            }
            VerificationKind::CreatedProfile => {
                wait_for_active_target(self.nm, self.target, self.cancellation)?;
                self.created_connection = None;
                ActivationOutcome::new(
                    format!("Connected to Wi-Fi network {} via D-Bus", self.target.ssid),
                    ConnectEnginePath::Dbus,
                )
            }
        };
        Ok(StateTransition::Connected(outcome))
    }

    fn cleanup_created_connection(&mut self) {
        let Some(created_connection) = self.created_connection.take() else {
            return;
        };
        tracing::warn!(ssid = %self.target.ssid, connection = %created_connection, "newly-created connection failed to activate; deleting it");
        if let Err(err) = self.nm.delete_connection(&created_connection) {
            tracing::warn!(connection = %created_connection, error = %crate::error::err_chain(&err), "failed to delete failed newly-created connection");
            eprintln!("warning: failed to delete failed connection {created_connection}: {err:#}");
        }
    }

    fn finish_success(
        self,
        outcome: ActivationOutcome,
        started_at: Instant,
    ) -> Result<ConnectResult> {
        tracing::info!(ssid = %self.target.ssid, message = %outcome.message, path = ?outcome.path, "Wi-Fi connection succeeded");
        best_effort("failed to write Wi-Fi cache status", || {
            cache::write_status("connected", &outcome.message)
        });
        best_effort("failed to refresh Wi-Fi cache after connect", || {
            refresh_cached_networks(self.nm)
        });
        check_cancelled(self.cancellation)?;
        let active_status = cache_active_status(self.nm, self.cancellation);
        let connectivity = active_status
            .as_ref()
            .and_then(|status| status.connectivity.clone())
            .or_else(|| self.nm.connectivity_check().ok());
        let result = ConnectResult::connected(
            self.target.ssid.to_string(),
            outcome.message,
            outcome.path,
            connectivity,
        );
        if let Some(status) = &result.connectivity {
            tracing::info!(
                ssid = %self.target.ssid,
                connectivity_code = status.code,
                connectivity_state = status.state,
                captive_portal = status.captive_portal,
                suggest_open_portal = result.suggest_open_portal,
                "classified connectivity after successful Wi-Fi activation"
            );
        } else {
            tracing::warn!(
                ssid = %self.target.ssid,
                suggest_open_portal = result.suggest_open_portal,
                "successful Wi-Fi activation had no connectivity result"
            );
        }
        record_connect_attempt(self.target, &result, started_at);
        Ok(result)
    }

    fn finish_failure(self, error: anyhow::Error, started_at: Instant) -> Result<ConnectResult> {
        let error = ensure_domain(ErrorOperation::Connect, error);
        tracing::error!(ssid = %self.target.ssid, error = %crate::error::err_chain(&error), "Wi-Fi connection failed");
        best_effort("failed to write Wi-Fi cache status", || {
            cache::write_status(
                "error",
                format!("Connection failed for {}: {error:#}", self.target.ssid),
            )
        });
        let result = ConnectResult::failed(
            self.target.ssid.to_string(),
            connect_failure_reason(&error),
            format!("{error:#}"),
        );
        record_connect_attempt(self.target, &result, started_at);
        Err(error)
    }

    fn log_start(&self) {
        tracing::info!(
            ssid = %self.target.ssid,
            ssid_len = self.target.ssid_bytes().len(),
            ap_path = ?self.target.ap_path,
            bssid = ?self.target.bssid,
            ifname = ?self.target.ifname,
            device_path = ?self.target.device_path,
            hidden = self.target.hidden,
            has_password = self.password.is_some(),
            wep_key_type = ?self.wep_key_type,
            "starting Wi-Fi connection attempt"
        );
    }
}

pub(crate) fn connect_target_with_password(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&AtomicBool>,
) -> Result<ConnectResult> {
    ConnectionMachine::new(nm, target, password, wep_key_type, cancellation).run()
}

fn record_connect_attempt(target: &WifiConnectTarget, result: &ConnectResult, started_at: Instant) {
    let record = cache::ConnectAttemptRecord::new(
        target,
        result.status,
        result.reason,
        result.path,
        &result.message,
        started_at.elapsed().as_millis(),
    );
    best_effort("failed to append persistent connect history", || {
        cache::append_connect_attempt(&record)
    });
}

fn cache_active_status(nm: &Nm, cancellation: Option<&AtomicBool>) -> Option<WifiStatus> {
    let status = best_effort("failed to read active Wi-Fi details after connect", || {
        read_active_status_after_connect(nm, cancellation)
    })?;
    best_effort("failed to cache active Wi-Fi details after connect", || {
        cache::cache_connected_network_status(&status)
    });
    Some(status)
}

fn read_active_status_after_connect(
    nm: &Nm,
    cancellation: Option<&AtomicBool>,
) -> Result<WifiStatus> {
    let deadline = Deadline::from_now(POST_CONNECT_STATUS_WAIT);
    let mut event_generation = nm.event_generation();
    loop {
        check_cancelled(cancellation)?;
        let status = nm.wifi_status()?;
        if status_has_network_details(&status) || deadline.expired() {
            return Ok(status);
        }
        event_generation = nm.wait_for_event(event_generation, deadline.wait(Duration::MAX));
    }
}

fn status_has_network_details(status: &WifiStatus) -> bool {
    status.ip4.as_ref().is_some_and(|ip4| {
        ip4.address
            .as_deref()
            .is_some_and(|address| !address.is_empty())
    })
}

fn refresh_cached_networks(nm: &Nm) -> Result<()> {
    let networks = nm.list_access_points()?;
    cache::write_snapshot(false, &networks)?;
    cache::write_complete(false, networks.len())
}
