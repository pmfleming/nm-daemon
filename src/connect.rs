use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use anyhow::Result;
use zvariant::OwnedObjectPath;

use crate::cache;
use crate::command::CommandRunner;
use crate::command::nmcli::Nmcli;
use crate::connect_cancel::check_cancelled;
use crate::connect_error::{
    combined_connect_failure, connect_failure, connect_failure_from_error,
    connect_failure_from_error_with_message, fallback_failure_reason,
    should_return_secret_agent_error, terminal_before_fallback,
};
use crate::connect_wait::wait_for_active_target;
use crate::deadline::Deadline;
use crate::error::{ErrorOperation, ensure_domain};
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
    Fallback,
    Verify(VerificationKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationKind {
    SavedProfile,
    CreatedProfile,
    Fallback,
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
    fn success_note(self) -> &'static str {
        match self {
            Self::SavedProfile => "D-Bus activation failed",
            Self::CreateProfile => "D-Bus add/activate failed",
            Self::SavedProfileAfterRescan => "D-Bus activation after rescan failed",
            Self::CreateProfileAfterRescan => "D-Bus add/activate after rescan failed",
        }
    }

    fn failure_subject(self) -> &'static str {
        match self {
            Self::SavedProfile => "D-Bus saved profile activation failed",
            Self::CreateProfile => "D-Bus add/activate failed",
            Self::SavedProfileAfterRescan => "D-Bus saved profile activation after rescan failed",
            Self::CreateProfileAfterRescan => "D-Bus add/activate after rescan failed",
        }
    }
}

struct DbusFallbackCause {
    attempt: DbusAttempt,
    error: anyhow::Error,
}

struct ConnectionMachine<'a> {
    nm: &'a Nm,
    target: &'a WifiConnectTarget,
    password: Option<&'a str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&'a AtomicBool>,
    rescanned: bool,
    created_connection: Option<OwnedObjectPath>,
    pending_outcome: Option<ActivationOutcome>,
    fallback_cause: Option<DbusFallbackCause>,
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
            pending_outcome: None,
            fallback_cause: None,
        }
    }

    fn run(mut self) -> Result<ConnectResult> {
        check_cancelled(self.cancellation)?;
        self.target.validate().map_err(|err| {
            connect_failure_from_error(ConnectFailureReason::ValidationError, err)
        })?;
        self.log_start();
        write_cache_status_best_effort(
            "connecting",
            format!("Connecting to {}…", self.target.ssid),
        );
        let started_at = Instant::now();

        match self.run_states() {
            Ok(outcome) => self.finish_success(outcome, started_at),
            Err(err) => {
                self.cleanup_created_connection_best_effort();
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
            ConnectionState::Fallback => self.activate_fallback(),
            ConnectionState::Verify(kind) => self.verify(kind),
        }
    }

    fn check_already_active(&self) -> Result<StateTransition> {
        match self.nm.active_ssid_matches(self.target) {
            Ok(true) => {
                tracing::info!(ssid = %self.target.ssid, "target Wi-Fi network is already active; skipping reactivation");
                Ok(StateTransition::Connected(ActivationOutcome::new(
                    format!("Already connected to {}", self.target.ssid),
                    ConnectEnginePath::AlreadyActive,
                )))
            }
            Ok(false) => Ok(StateTransition::Next(ConnectionState::SavedProfile)),
            Err(err) => {
                tracing::debug!(ssid = %self.target.ssid, error = %format_args!("{err:#}"), "could not check active Wi-Fi target before activation");
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
            Err(err) => self.transition_after_dbus_failure(attempt, err),
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
            Ok(None) => Ok(StateTransition::Next(ConnectionState::Fallback)),
            Err(err) => self.transition_after_dbus_failure(attempt, err),
        }
    }

    fn should_rescan(&self) -> bool {
        if self.rescanned || self.target.hidden {
            return false;
        }
        match self.nm.target_access_point_visible(self.target) {
            Ok(visible) => !visible,
            Err(err) => {
                tracing::debug!(ssid = %self.target.ssid, error = %format_args!("{err:#}"), "could not verify target AP visibility before rescan");
                true
            }
        }
    }

    fn rescan(&mut self) -> Result<StateTransition> {
        self.rescanned = true;
        tracing::info!(ssid = %self.target.ssid, bssid = ?self.target.bssid, ifname = ?self.target.ifname, "target AP is not visible; rescanning once before nmcli fallback");
        let result = self.nm.scan_with_options(ScanRequestOptions {
            timeout: NOT_FOUND_RESCAN_TIMEOUT,
            ifname: self.target.ifname.clone(),
            ssid_bytes: vec![self.target.ssid_bytes().to_vec()],
        });
        match result {
            Ok(()) => Ok(StateTransition::Next(ConnectionState::SavedProfile)),
            Err(err) => {
                tracing::warn!(ssid = %self.target.ssid, error = %format_args!("{err:#}"), "targeted rescan before connect fallback failed");
                Ok(StateTransition::Next(ConnectionState::Fallback))
            }
        }
    }

    fn transition_after_dbus_failure(
        &mut self,
        attempt: DbusAttempt,
        error: anyhow::Error,
    ) -> Result<StateTransition> {
        if should_return_secret_agent_error(self.password, &error) {
            return Err(connect_failure_from_error(
                ConnectFailureReason::PasswordUnavailable,
                error,
            ));
        }
        if terminal_before_fallback(&error) {
            return Err(error);
        }
        tracing::warn!(
            ssid = %self.target.ssid,
            error = %format_args!("{error:#}"),
            failure = attempt.failure_subject(),
            "D-Bus activation path failed; trying nmcli fallback"
        );
        self.fallback_cause = Some(DbusFallbackCause { attempt, error });
        Ok(StateTransition::Next(ConnectionState::Fallback))
    }

    fn activate_fallback(&mut self) -> Result<StateTransition> {
        tracing::info!(ssid = %self.target.ssid, "trying nmcli connection fallback");
        let fallback = activate_with_nmcli_fallback(
            self.nm.command_runner(),
            self.target,
            self.password,
            self.wep_key_type,
            self.cancellation,
        );
        let outcome = match (fallback, self.fallback_cause.take()) {
            (Ok(mut outcome), Some(cause)) => {
                outcome.message = format!(
                    "{} ({}: {:#})",
                    outcome.message,
                    cause.attempt.success_note(),
                    cause.error
                );
                outcome
            }
            (Ok(outcome), None) => outcome,
            (Err(fallback_err), Some(cause)) => {
                return Err(combined_connect_failure(
                    &cause.error,
                    &fallback_err,
                    format!(
                        "{}: {:#}; nmcli fallback failed: {fallback_err:#}",
                        cause.attempt.failure_subject(),
                        cause.error
                    ),
                ));
            }
            (Err(fallback_err), None) => return Err(fallback_err),
        };
        self.pending_outcome = Some(outcome);
        Ok(StateTransition::Next(ConnectionState::Verify(
            VerificationKind::Fallback,
        )))
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
            // `nmcli --wait` performs fallback activation verification itself.
            VerificationKind::Fallback => self.pending_outcome.take().ok_or_else(|| {
                anyhow::anyhow!("fallback verification has no activation outcome")
            })?,
        };
        Ok(StateTransition::Connected(outcome))
    }

    fn cleanup_created_connection_best_effort(&mut self) {
        let Some(created_connection) = self.created_connection.take() else {
            return;
        };
        tracing::warn!(ssid = %self.target.ssid, connection = %created_connection, "newly-created connection failed to activate; deleting it");
        if let Err(err) = self.nm.delete_connection(&created_connection) {
            tracing::warn!(connection = %created_connection, error = %format_args!("{err:#}"), "failed to delete failed newly-created connection");
            eprintln!("warning: failed to delete failed connection {created_connection}: {err:#}");
        }
    }

    fn finish_success(
        self,
        outcome: ActivationOutcome,
        started_at: Instant,
    ) -> Result<ConnectResult> {
        tracing::info!(ssid = %self.target.ssid, message = %outcome.message, path = ?outcome.path, "Wi-Fi connection succeeded");
        write_cache_status_best_effort("connected", &outcome.message);
        refresh_cached_networks_best_effort(self.nm);
        check_cancelled(self.cancellation)?;
        let active_status = cache_active_status_best_effort(self.nm, self.cancellation);
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
        append_connect_history_best_effort(self.target, &result, started_at);
        Ok(result)
    }

    fn finish_failure(self, error: anyhow::Error, started_at: Instant) -> Result<ConnectResult> {
        let error = ensure_domain(ErrorOperation::Connect, error);
        tracing::error!(ssid = %self.target.ssid, error = %format_args!("{error:#}"), "Wi-Fi connection failed");
        write_cache_status_best_effort(
            "error",
            format!("Connection failed for {}: {error:#}", self.target.ssid),
        );
        let result = ConnectResult::failed(
            self.target.ssid.to_string(),
            connect_failure_reason(&error),
            format!("{error:#}"),
        );
        append_connect_history_best_effort(self.target, &result, started_at);
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
) -> Result<ConnectResult> {
    ConnectionMachine::new(nm, target, password, wep_key_type, None).run()
}

pub(crate) fn connect_target_with_password_cancellable(
    nm: &Nm,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: &AtomicBool,
) -> Result<ConnectResult> {
    ConnectionMachine::new(nm, target, password, wep_key_type, Some(cancellation)).run()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WifiFallbackEligibility {
    Eligible,
    SelectedApNeedsBssid,
    PasswordWouldUseArgv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FallbackPolicy {
    try_saved_profile: bool,
    wifi_connect: WifiFallbackEligibility,
}

impl FallbackPolicy {
    fn for_request(target: &WifiConnectTarget, password: Option<&str>) -> Self {
        let try_saved_profile = !target.has_specific_ap() && password.is_none();
        let wifi_connect = if selected_ap_requires_unrepresentable_bssid(target) {
            WifiFallbackEligibility::SelectedApNeedsBssid
        } else if password.is_some() {
            WifiFallbackEligibility::PasswordWouldUseArgv
        } else {
            WifiFallbackEligibility::Eligible
        };
        Self {
            try_saved_profile,
            wifi_connect,
        }
    }
}

fn activate_with_nmcli_fallback(
    commands: &dyn CommandRunner,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&AtomicBool>,
) -> Result<ActivationOutcome> {
    check_cancelled(cancellation)?;
    let policy = FallbackPolicy::for_request(target, password);
    let saved_err = if policy.try_saved_profile {
        tracing::info!(ssid = %target.ssid, "trying nmcli saved-profile activation fallback");
        match Nmcli::new(commands).connect(
            &["connection", "up", "id", target.ssid.as_str()],
            cancellation,
        ) {
            Ok(_) => {
                return Ok(ActivationOutcome::new(
                    format!(
                        "Connected to saved network {} via nmcli fallback",
                        target.ssid
                    ),
                    ConnectEnginePath::NmcliFallback,
                ));
            }
            Err(err) => err,
        }
    } else if target.has_specific_ap() {
        tracing::info!(ssid = %target.ssid, ap_path = ?target.ap_path, bssid = ?target.bssid, "skipping generic nmcli saved-profile activation for specific AP target");
        anyhow::anyhow!("skipped generic saved-profile activation for specific AP target")
    } else {
        tracing::info!(ssid = %target.ssid, "skipping nmcli saved-profile activation because caller supplied a password");
        anyhow::anyhow!("skipped saved-profile activation because caller supplied a password")
    };

    match policy.wifi_connect {
        WifiFallbackEligibility::Eligible => nmcli_wifi_connect(
            commands,
            target,
            password,
            wep_key_type,
            cancellation,
            &saved_err,
        ),
        WifiFallbackEligibility::SelectedApNeedsBssid => {
            tracing::warn!(ssid = %target.ssid, ap_path = ?target.ap_path, "not running generic nmcli Wi-Fi connect because selected AP cannot be represented without BSSID");
            Err(connect_failure(
                ConnectFailureReason::UnsupportedAuth,
                format!(
                    "saved profile activation failed: {saved_err:#}; nmcli fallback cannot preserve selected AP path without a BSSID"
                ),
            ))
        }
        WifiFallbackEligibility::PasswordWouldUseArgv => {
            tracing::warn!(ssid = %target.ssid, "not running nmcli Wi-Fi connect fallback because it would expose the secret in process arguments");
            Err(connect_failure(
                ConnectFailureReason::ActivationFailed,
                format!(
                    "saved profile activation failed: {saved_err:#}; nmcli password fallback is disabled because secrets must not be passed through argv"
                ),
            ))
        }
    }
}

fn nmcli_wifi_connect(
    commands: &dyn CommandRunner,
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
    cancellation: Option<&AtomicBool>,
    saved_err: &anyhow::Error,
) -> Result<ActivationOutcome> {
    check_cancelled(cancellation)?;
    let args = nmcli_wifi_connect_args(target, password, wep_key_type);
    Nmcli::new(commands)
        .connect(&args, cancellation)
        .map(|_| {
            ActivationOutcome::new(
                format!("Connected to {} via nmcli fallback", target.ssid),
                ConnectEnginePath::NmcliFallback,
            )
        })
        .map_err(|connect_err| {
            let reason = fallback_failure_reason(target, password, &connect_err);
            connect_failure_from_error_with_message(
                reason,
                format!(
                    "saved profile activation failed: {saved_err:#}; wifi connect failed: {connect_err:#}"
                ),
                connect_err,
            )
        })
}

fn selected_ap_requires_unrepresentable_bssid(target: &WifiConnectTarget) -> bool {
    target.ap_path.is_some() && target.bssid.is_none()
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
        ConnectEnginePath, FallbackPolicy, WifiFallbackEligibility, activate_with_nmcli_fallback,
    };
    use crate::command::tests::FakeRunner;
    use crate::model::example_connect_target;

    #[test]
    fn fallback_policy_centralizes_target_and_secret_constraints() {
        let target = example_connect_target(false);
        assert_eq!(
            FallbackPolicy::for_request(&target, None),
            FallbackPolicy {
                try_saved_profile: true,
                wifi_connect: WifiFallbackEligibility::Eligible,
            }
        );

        let mut selected_ap = example_connect_target(false);
        selected_ap.ap_path = Some(
            crate::model::NmObjectPath::parse(
                "/org/freedesktop/NetworkManager/AccessPoint/1".to_string(),
            )
            .unwrap(),
        );
        assert_eq!(
            FallbackPolicy::for_request(&selected_ap, None),
            FallbackPolicy {
                try_saved_profile: false,
                wifi_connect: WifiFallbackEligibility::SelectedApNeedsBssid,
            }
        );

        assert_eq!(
            FallbackPolicy::for_request(&target, Some("secret")),
            FallbackPolicy {
                try_saved_profile: false,
                wifi_connect: WifiFallbackEligibility::PasswordWouldUseArgv,
            }
        );
    }

    #[test]
    fn command_fallback_orchestration_tries_saved_profile_then_wifi_connect() {
        let runner = FakeRunner::nmcli_failure_then_success(10, "saved profile not found");
        let target = example_connect_target(false);

        let outcome = activate_with_nmcli_fallback(&runner, &target, None, None, None).unwrap();

        assert_eq!(outcome.path, ConnectEnginePath::NmcliFallback);
        let requests = runner.all_redacted_args();
        assert_eq!(
            requests[0],
            ["--wait", "90", "connection", "up", "id", "Example"]
        );
        assert_eq!(
            requests[1],
            ["--wait", "90", "device", "wifi", "connect", "Example"]
        );
    }
}
