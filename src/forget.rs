use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

use crate::cache;
use crate::daemon_runtime::DaemonRuntime;
use crate::deadline::Deadline;
use crate::error::{ErrorOperation, best_effort};
use crate::model::{SavedWifiConnection, WifiConnectTarget, WifiStatus};
use crate::nm::Nm;

const CANCELLATION_TIMEOUT: Duration = Duration::from_secs(10);
const DEACTIVATION_TIMEOUT: Duration = Duration::from_secs(10);
const PORTAL_NOTE: &str =
    "The hotspot may continue to recognize this device until its captive-portal session expires.";

pub(crate) fn execute(
    runtime: &Arc<DaemonRuntime>,
    request_id: String,
    target: Box<WifiConnectTarget>,
) -> Result<ForgetResult> {
    target.validate()?;
    let request_id = normalized_request_id(request_id);
    tracing::info!(
        %request_id,
        ssid = %target.ssid,
        ap_path = ?target.ap_path,
        bssid = ?target.bssid,
        "accepted disconnect-and-forget request"
    );

    let cancelled = runtime.cancel_connects_for_ssid(&request_id, target.ssid_bytes());
    let pending = runtime.wait_for_tasks(&cancelled, CANCELLATION_TIMEOUT);
    tracing::info!(
        %request_id,
        ssid = %target.ssid,
        cancelled_connect_requests = ?cancelled,
        pending_connect_requests = ?pending,
        "completed pre-forget connection cancellation phase"
    );

    if !pending.is_empty() {
        let result = ForgetResult::cancellation_pending(
            request_id,
            target.ssid.to_string(),
            cancelled,
            pending,
        );
        tracing::warn!(
            request_id = %result.request_id,
            ssid = %result.ssid,
            pending_connect_requests = ?result.pending_connect_requests,
            "forget blocked while connection cancellation remains pending"
        );
        audit(&result);
        return Ok(result);
    }

    let log_request_id = request_id.clone();
    let log_ssid = target.ssid.to_string();
    let result = runtime.call(ErrorOperation::ProfileOperation, move |nm| {
        ForgetService::new(nm).run(request_id, &target, cancelled)
    });
    match result {
        Ok(result) => {
            audit(&result);
            Ok(result)
        }
        Err(error) => {
            tracing::error!(
                request_id = %log_request_id,
                ssid = %log_ssid,
                error = %crate::error::err_chain(&error),
                "disconnect-and-forget workflow failed"
            );
            Err(error)
        }
    }
}

struct ForgetService<'a> {
    nm: &'a Nm,
}

impl<'a> ForgetService<'a> {
    fn new(nm: &'a Nm) -> Self {
        Self { nm }
    }

    fn run(
        &self,
        request_id: String,
        target: &WifiConnectTarget,
        cancelled_connect_requests: Vec<String>,
    ) -> Result<ForgetResult> {
        let profiles = self.profiles_for(target)?;
        let initial_status = self.nm.wifi_status()?;
        let was_active = status_matches_target(&initial_status, target);
        self.log_start(
            &request_id,
            target,
            &profiles,
            was_active,
            &cancelled_connect_requests,
        );

        let mut warnings = Vec::new();
        self.disable_autoconnect(&request_id, &profiles, &mut warnings);
        let disconnected = if was_active {
            self.disconnect_and_confirm(&request_id, target, &mut warnings)?
        } else {
            false
        };
        if was_active && !disconnected {
            return Ok(ForgetResult::disconnect_pending(
                request_id,
                target.ssid.to_string(),
                profiles.len(),
                cancelled_connect_requests,
                warnings,
            ));
        }

        let (deleted_profiles, failed_profiles) = self.delete_profiles(&request_id, profiles);
        self.refresh_caches(&request_id, disconnected);
        let result = ForgetResult::completed(ForgetCompletion {
            request_id,
            ssid: target.ssid.to_string(),
            was_active,
            disconnected,
            cancelled_connect_requests,
            deleted_profiles,
            failed_profiles,
            warnings,
        });
        result.log_completion();
        Ok(result)
    }

    fn profiles_for(&self, target: &WifiConnectTarget) -> Result<Vec<SavedWifiConnection>> {
        Ok(self
            .nm
            .saved_wifi_connections()?
            .into_iter()
            .filter(|profile| profile.ssid_bytes == target.ssid_bytes())
            .collect())
    }

    fn log_start(
        &self,
        request_id: &str,
        target: &WifiConnectTarget,
        profiles: &[SavedWifiConnection],
        was_active: bool,
        cancelled_connect_requests: &[String],
    ) {
        let profile_ids = profiles
            .iter()
            .map(|profile| profile.id.as_str())
            .collect::<Vec<_>>();
        let profile_paths = profiles
            .iter()
            .map(|profile| profile.path.as_str())
            .collect::<Vec<_>>();
        tracing::info!(
            %request_id,
            ssid = %target.ssid,
            ssid_len = target.ssid_bytes().len(),
            was_active,
            profiles = profiles.len(),
            profile_ids = ?profile_ids,
            profile_paths = ?profile_paths,
            cancelled_connect_requests = ?cancelled_connect_requests,
            "starting disconnect-and-forget workflow"
        );
    }

    fn disable_autoconnect(
        &self,
        request_id: &str,
        profiles: &[SavedWifiConnection],
        warnings: &mut Vec<String>,
    ) {
        for profile in profiles.iter().filter(|profile| profile.autoconnect) {
            tracing::info!(%request_id, profile_id = %profile.id, profile_path = %profile.path, "disabling autoconnect before forget");
            if let Err(error) = self
                .nm
                .set_connection_autoconnect_by_path(&profile.path, false)
            {
                let message = format!(
                    "Could not disable autoconnect for '{}': {}",
                    profile.id,
                    crate::error::err_chain(&error)
                );
                tracing::warn!(%request_id, profile_id = %profile.id, profile_path = %profile.path, error = %crate::error::err_chain(&error), "failed to disable autoconnect before forget");
                warnings.push(message);
            }
        }
    }

    fn disconnect_and_confirm(
        &self,
        request_id: &str,
        target: &WifiConnectTarget,
        warnings: &mut Vec<String>,
    ) -> Result<bool> {
        tracing::info!(%request_id, ssid = %target.ssid, "disconnecting active network before forget");
        let result = self.nm.disconnect_wifi()?;
        tracing::info!(%request_id, ssid = %target.ssid, status = result.status, message = %result.message, "NetworkManager accepted disconnect before forget");
        let deadline = Deadline::from_now(DEACTIVATION_TIMEOUT);
        let mut generation = self.nm.event_generation();
        while !deadline.expired() {
            if !status_matches_target(&self.nm.wifi_status()?, target) {
                tracing::info!(%request_id, ssid = %target.ssid, "confirmed target network is disconnected before profile deletion");
                return Ok(true);
            }
            generation = self
                .nm
                .wait_for_event(generation, deadline.wait(Duration::from_millis(500)));
        }
        warnings.push(
            "NetworkManager did not confirm disconnection within 10 seconds; no profiles were deleted."
                .to_string(),
        );
        Ok(false)
    }

    fn delete_profiles(
        &self,
        request_id: &str,
        profiles: Vec<SavedWifiConnection>,
    ) -> (Vec<ForgetProfile>, Vec<ForgetProfileFailure>) {
        let mut deleted = Vec::new();
        let mut failed = Vec::new();
        for profile in profiles {
            tracing::info!(%request_id, profile_id = %profile.id, profile_path = %profile.path, "deleting saved profile during forget");
            match self.nm.delete_connection_by_path(&profile.path) {
                Ok(()) => {
                    tracing::info!(%request_id, profile_id = %profile.id, profile_path = %profile.path, "deleted saved profile during forget");
                    deleted.push(ForgetProfile::from(&profile));
                }
                Err(error) => {
                    let message = crate::error::err_chain(&error).to_string();
                    tracing::warn!(%request_id, profile_id = %profile.id, profile_path = %profile.path, error = %message, "failed to delete saved profile during forget");
                    failed.push(ForgetProfileFailure {
                        id: profile.id,
                        path: profile.path,
                        message,
                    });
                }
            }
        }
        (deleted, failed)
    }

    fn refresh_caches(&self, request_id: &str, disconnected: bool) {
        if disconnected {
            best_effort("failed to clear active Wi-Fi cache after forget", || {
                cache::clear_active_connection_cache()
            });
        }
        best_effort("failed to refresh Wi-Fi status cache after forget", || {
            cache::cache_connected_network_status(&self.nm.wifi_status()?)
        });
        tracing::info!(%request_id, "refreshed Wi-Fi cache state after forget");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ForgetStatus {
    Forgotten,
    Partial,
    Failed,
    NotSaved,
    DisconnectPending,
    CancellationPending,
}

#[derive(Debug, Serialize)]
pub(crate) struct ForgetResult {
    pub(crate) operation: &'static str,
    pub(crate) status: ForgetStatus,
    pub(crate) request_id: String,
    pub(crate) ssid: String,
    pub(crate) message: String,
    pub(crate) was_active: bool,
    pub(crate) disconnected: bool,
    pub(crate) profiles_found: usize,
    pub(crate) deleted_profiles: Vec<ForgetProfile>,
    pub(crate) failed_profiles: Vec<ForgetProfileFailure>,
    pub(crate) cancelled_connect_requests: Vec<String>,
    pub(crate) pending_connect_requests: Vec<String>,
    pub(crate) warnings: Vec<String>,
    pub(crate) portal_session_reset: bool,
    pub(crate) portal_note: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ForgetProfile {
    pub(crate) id: String,
    pub(crate) path: String,
}

impl From<&SavedWifiConnection> for ForgetProfile {
    fn from(profile: &SavedWifiConnection) -> Self {
        Self {
            id: profile.id.clone(),
            path: profile.path.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ForgetProfileFailure {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) message: String,
}

struct ForgetCompletion {
    request_id: String,
    ssid: String,
    was_active: bool,
    disconnected: bool,
    cancelled_connect_requests: Vec<String>,
    deleted_profiles: Vec<ForgetProfile>,
    failed_profiles: Vec<ForgetProfileFailure>,
    warnings: Vec<String>,
}

impl ForgetResult {
    fn completed(completion: ForgetCompletion) -> Self {
        let profiles_found = completion.deleted_profiles.len() + completion.failed_profiles.len();
        let status = match (profiles_found, completion.failed_profiles.len()) {
            (0, _) => ForgetStatus::NotSaved,
            (_, 0) => ForgetStatus::Forgotten,
            (found, failed) if found == failed => ForgetStatus::Failed,
            _ => ForgetStatus::Partial,
        };
        let message = completion_message(&completion);
        Self {
            operation: "forget",
            status,
            request_id: completion.request_id,
            ssid: completion.ssid,
            message,
            was_active: completion.was_active,
            disconnected: completion.disconnected,
            profiles_found,
            deleted_profiles: completion.deleted_profiles,
            failed_profiles: completion.failed_profiles,
            cancelled_connect_requests: completion.cancelled_connect_requests,
            pending_connect_requests: Vec::new(),
            warnings: completion.warnings,
            portal_session_reset: false,
            portal_note: PORTAL_NOTE,
        }
    }

    fn cancellation_pending(
        request_id: String,
        ssid: String,
        cancelled_connect_requests: Vec<String>,
        pending_connect_requests: Vec<String>,
    ) -> Self {
        Self {
            operation: "forget",
            status: ForgetStatus::CancellationPending,
            request_id,
            ssid,
            message: "Connection cancellation is still pending; try Forget again when the connection action finishes".to_string(),
            was_active: false,
            disconnected: false,
            profiles_found: 0,
            deleted_profiles: Vec::new(),
            failed_profiles: Vec::new(),
            cancelled_connect_requests,
            pending_connect_requests,
            warnings: Vec::new(),
            portal_session_reset: false,
            portal_note: PORTAL_NOTE,
        }
    }

    fn disconnect_pending(
        request_id: String,
        ssid: String,
        profiles_found: usize,
        cancelled_connect_requests: Vec<String>,
        warnings: Vec<String>,
    ) -> Self {
        Self {
            operation: "forget",
            status: ForgetStatus::DisconnectPending,
            request_id,
            message: format!(
                "Could not confirm disconnection from {ssid}; no saved profiles were deleted"
            ),
            ssid,
            was_active: true,
            disconnected: false,
            profiles_found,
            deleted_profiles: Vec::new(),
            failed_profiles: Vec::new(),
            cancelled_connect_requests,
            pending_connect_requests: Vec::new(),
            warnings,
            portal_session_reset: false,
            portal_note: PORTAL_NOTE,
        }
    }

    fn log_completion(&self) {
        tracing::info!(
            request_id = %self.request_id,
            ssid = %self.ssid,
            status = ?self.status,
            was_active = self.was_active,
            disconnected = self.disconnected,
            profiles_found = self.profiles_found,
            profiles_deleted = self.deleted_profiles.len(),
            profiles_failed = self.failed_profiles.len(),
            warnings = ?self.warnings,
            portal_session_reset = self.portal_session_reset,
            "disconnect-and-forget workflow completed"
        );
    }
}

fn completion_message(completion: &ForgetCompletion) -> String {
    let deleted = completion.deleted_profiles.len();
    let failed = completion.failed_profiles.len();
    if deleted == 0 && failed == 0 {
        return if completion.disconnected {
            format!(
                "Disconnected from {}; no saved profile remained",
                completion.ssid
            )
        } else {
            format!("{} has no saved profiles to forget", completion.ssid)
        };
    }
    let action = if completion.was_active && completion.disconnected {
        "Disconnected and forgot"
    } else {
        "Forgot"
    };
    match failed {
        0 if deleted == 1 => format!("{action} {}", completion.ssid),
        0 => format!("{action} {deleted} saved profiles for {}", completion.ssid),
        failed => format!(
            "Forgot {deleted} of {} saved profiles for {}; {failed} failed",
            deleted + failed,
            completion.ssid
        ),
    }
}

fn status_matches_target(status: &WifiStatus, target: &WifiConnectTarget) -> bool {
    status.active
        && status.access_point.as_ref().is_some_and(|access_point| {
            if access_point.ssid_bytes.is_empty() {
                access_point.ssid == target.ssid.as_str()
            } else {
                access_point.ssid_bytes == target.ssid_bytes()
            }
        })
}

fn normalized_request_id(request_id: String) -> String {
    if request_id.trim().is_empty() {
        crate::daemon_event::next_request_id("forget")
    } else {
        request_id
    }
}

#[derive(Serialize)]
struct ForgetAuditRecord<'a> {
    version: u32,
    timestamp_ms: u128,
    result: &'a ForgetResult,
}

fn audit(result: &ForgetResult) {
    let record = ForgetAuditRecord {
        version: 1,
        timestamp_ms: cache::now_ms(),
        result,
    };
    best_effort("failed to append persistent forget audit record", || {
        cache::append_profile_operation_audit(&record)
    });
}
