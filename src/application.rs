use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::cache;
use crate::connect;
use crate::error::{
    DomainError, ErrorOperation, ErrorReport, best_effort, ensure_domain, operation_result,
};
use crate::model::{
    AccessPoint, ConnectResult, ConnectivityStatus, DisconnectResult, InterfaceName, NetworkEntry,
    NmObjectPath, SavedWifiConnection, ScanRequestOptions, WepKeyType, WifiConnectTarget,
    WifiProfileDetails, WifiProfileSecret, WifiProfileUpdate, WifiSharePayload, WifiStatus,
    validate_ssid_bytes,
};
use crate::nm::Nm;
use anyhow::Result;

/// Canonical, transport-neutral entry point for user-facing NetworkManager operations.
///
/// CLI commands and D-Bus handlers should only translate requests/results at their boundary;
/// validation, cache policy, enrichment, and NetworkManager orchestration live here.
pub(crate) struct Application<'a> {
    nm: &'a Nm,
    background_scans: Option<&'a dyn BackgroundScanScheduler>,
}

impl<'a> Application<'a> {
    pub(crate) fn new(nm: &'a Nm) -> Self {
        Self {
            nm,
            background_scans: None,
        }
    }

    pub(crate) fn with_background_scans(
        mut self,
        scheduler: &'a dyn BackgroundScanScheduler,
    ) -> Self {
        self.background_scans = Some(scheduler);
        self
    }

    pub(crate) fn status(&self) -> Result<WifiStatus> {
        let status = operation_result(ErrorOperation::Status, self.nm.wifi_status())?;
        best_effort("failed to cache active Wi-Fi status", || {
            cache::cache_connected_network_status(&status)
        });
        Ok(status)
    }

    pub(crate) fn connectivity(&self) -> Result<ConnectivityStatus> {
        operation_result(ErrorOperation::Connectivity, self.nm.connectivity_check())
    }

    pub(crate) fn networks(&self, request: NetworksRequest) -> Result<NetworksResult> {
        operation_result(
            ErrorOperation::Networks,
            (|| {
                let (access_points, warning) = self.load_networks(&request)?;
                let networks = self.enrich_access_points(access_points)?;
                Ok(NetworksResult { networks, warning })
            })(),
        )
    }

    pub(crate) fn network_snapshot(
        &self,
        access_points: Vec<AccessPoint>,
    ) -> Result<NetworksResult> {
        operation_result(
            ErrorOperation::Networks,
            (|| {
                Ok(NetworksResult {
                    networks: self.enrich_access_points(access_points)?,
                    warning: None,
                })
            })(),
        )
    }

    pub(crate) fn scan(
        &self,
        request: ScanRequest,
        cancellation: Option<&AtomicBool>,
        emit: impl FnMut(&ScanEvent) -> Result<()>,
    ) -> Result<ScanResult> {
        self.scan_prepared(request.prepare()?, cancellation, emit)
    }

    pub(crate) fn scan_prepared(
        &self,
        request: PreparedScanRequest,
        cancellation: Option<&AtomicBool>,
        emit: impl FnMut(&ScanEvent) -> Result<()>,
    ) -> Result<ScanResult> {
        operation_result(
            ErrorOperation::Scan,
            self.scan_prepared_inner(request, cancellation, emit),
        )
    }

    fn scan_prepared_inner(
        &self,
        request: PreparedScanRequest,
        cancellation: Option<&AtomicBool>,
        mut emit: impl FnMut(&ScanEvent) -> Result<()>,
    ) -> Result<ScanResult> {
        check_scan_cancelled(cancellation)?;
        emit_scan_started(&mut emit)?;
        let options = ScanRequestOptions {
            timeout: request.timeout,
            ifname: request.ifname,
            ssid_bytes: request.ssid_bytes,
        };
        let warning = self.scan_warning(options, request.strict, cancellation, &mut emit)?;
        check_scan_cancelled(cancellation)?;
        let access_points = self.finish_scan(request.cache, &mut emit)?;
        Ok(ScanResult {
            access_points,
            warning,
        })
    }

    fn scan_warning(
        &self,
        options: ScanRequestOptions,
        strict: bool,
        cancellation: Option<&AtomicBool>,
        emit: &mut impl FnMut(&ScanEvent) -> Result<()>,
    ) -> Result<Option<ErrorReport>> {
        let warning = match self.nm.scan_with_options(options, cancellation) {
            Ok(()) => None,
            Err(err) if is_cancelled(cancellation) => return Err(err),
            Err(err) => {
                let err = ensure_domain(ErrorOperation::Scan, err);
                let error = ErrorReport::from_error(&err, ErrorOperation::Scan);
                emit(&ScanEvent::Warning {
                    error: error.clone(),
                })?;
                if strict {
                    return Err(err);
                }
                Some(error)
            }
        };
        Ok(warning)
    }

    fn finish_scan(
        &self,
        cache_result: bool,
        emit: &mut impl FnMut(&ScanEvent) -> Result<()>,
    ) -> Result<Vec<AccessPoint>> {
        let access_points = self.nm.list_all_access_points()?;
        let networks_found = access_points.len();
        cache_scan_snapshot(cache_result, &access_points)?;
        emit(&ScanEvent::Snapshot {
            networks_found,
            access_points: access_points.clone(),
        })?;
        cache_scan_complete(cache_result, networks_found)?;
        emit(&ScanEvent::Complete {
            timed_out: false,
            networks_found,
        })?;
        Ok(access_points)
    }

    pub(crate) fn connect(
        &self,
        request: &ConnectRequest,
        cancellation: Option<&AtomicBool>,
        emit: impl FnMut(&ConnectEvent) -> Result<()>,
    ) -> Result<ConnectOutcome> {
        operation_result(
            ErrorOperation::Connect,
            self.connect_inner(request, cancellation, emit),
        )
    }

    fn connect_inner(
        &self,
        request: &ConnectRequest,
        cancellation: Option<&AtomicBool>,
        mut emit: impl FnMut(&ConnectEvent) -> Result<()>,
    ) -> Result<ConnectOutcome> {
        if let Some(outcome) = start_connect(cancellation, &mut emit)? {
            return Ok(outcome);
        }
        let result = connect::connect_target_with_password(
            self.nm,
            &request.target,
            request.password.as_deref(),
            request.wep_key_type,
            cancellation,
        );

        if let Some(outcome) = finish_connect_cancellation(cancellation, &mut emit)? {
            return Ok(outcome);
        }
        let outcome = connect_outcome(&request.target, result);
        emit(&ConnectEvent::Finished(outcome.clone()))?;
        Ok(outcome)
    }

    pub(crate) fn saved_profiles(&self) -> Result<Vec<SavedWifiConnection>> {
        operation_result(
            ErrorOperation::ProfileOperation,
            self.nm.saved_wifi_connections(),
        )
    }

    pub(crate) fn profile_operation(
        &self,
        operation: ProfileOperation,
    ) -> Result<ProfileOperationResult> {
        operation_result(
            ErrorOperation::ProfileOperation,
            self.profile_operation_inner(operation),
        )
    }

    fn profile_operation_inner(
        &self,
        operation: ProfileOperation,
    ) -> Result<ProfileOperationResult> {
        match operation {
            ProfileOperation::Details { path } => self.profile_details(path.as_str()),
            ProfileOperation::Update { path, settings } => {
                self.update_profile(path.as_str(), settings.as_ref())
            }
            ProfileOperation::RevealSecret { path } => self.reveal_profile_secret(path.as_str()),
            ProfileOperation::Delete { path } => self.delete_profile(path.as_str()),
            ProfileOperation::SetAutoconnect { path, enabled } => {
                self.set_profile_autoconnect(path.as_str(), enabled)
            }
            ProfileOperation::SetMacRandomization { path, randomized } => {
                self.set_profile_mac_randomization(path.as_str(), randomized)
            }
            ProfileOperation::Share { path } => self.share_profile(path.as_str()),
            ProfileOperation::SetSendHostname { path, enabled } => {
                self.set_profile_send_hostname(path.as_str(), enabled)
            }
        }
    }

    fn profile_details(&self, path: &str) -> Result<ProfileOperationResult> {
        Ok(ProfileOperationResult::Details(Box::new(
            self.nm.wifi_profile_details_by_path(path)?,
        )))
    }

    fn update_profile(
        &self,
        path: &str,
        settings: &WifiProfileUpdate,
    ) -> Result<ProfileOperationResult> {
        self.nm.update_wifi_profile_by_path(path, settings)?;
        Ok(profile_updated("Saved Wi-Fi profile settings updated"))
    }

    fn reveal_profile_secret(&self, path: &str) -> Result<ProfileOperationResult> {
        Ok(ProfileOperationResult::Secret(
            self.nm.wifi_profile_secret_by_path(path)?,
        ))
    }

    fn delete_profile(&self, path: &str) -> Result<ProfileOperationResult> {
        tracing::info!(
            profile_path = path,
            "deleting saved Wi-Fi profile by explicit path"
        );
        self.nm.delete_connection_by_path(path)?;
        tracing::info!(
            profile_path = path,
            "saved Wi-Fi profile deleted by explicit path"
        );
        Ok(profile_updated("Saved Wi-Fi profile deleted"))
    }

    fn set_profile_autoconnect(&self, path: &str, enabled: bool) -> Result<ProfileOperationResult> {
        self.nm.set_connection_autoconnect_by_path(path, enabled)?;
        Ok(profile_updated("Saved Wi-Fi profile autoconnect updated"))
    }

    fn set_profile_mac_randomization(
        &self,
        path: &str,
        randomized: bool,
    ) -> Result<ProfileOperationResult> {
        self.nm
            .set_connection_mac_randomization_by_path(path, randomized)?;
        Ok(profile_updated("Saved Wi-Fi profile MAC privacy updated"))
    }

    fn share_profile(&self, path: &str) -> Result<ProfileOperationResult> {
        Ok(ProfileOperationResult::Share(
            self.nm.wifi_share_payload_by_path(path)?,
        ))
    }

    fn set_profile_send_hostname(
        &self,
        path: &str,
        enabled: bool,
    ) -> Result<ProfileOperationResult> {
        self.nm
            .set_connection_send_hostname_by_path(path, enabled)?;
        Ok(profile_updated(
            "Saved Wi-Fi profile DHCP hostname privacy updated",
        ))
    }

    pub(crate) fn disconnect(&self) -> Result<DisconnectResult> {
        let result = operation_result(ErrorOperation::Disconnect, self.nm.disconnect_wifi())?;
        best_effort("failed to clear active Wi-Fi cache", || {
            cache::clear_active_connection_cache()
        });
        Ok(result)
    }

    fn load_networks(
        &self,
        request: &NetworksRequest,
    ) -> Result<(Vec<AccessPoint>, Option<ErrorReport>)> {
        if let Some(cached) = self.cached_networks(request)? {
            return Ok(cached);
        }
        let networks = self.nm.list_all_access_points()?;
        self.schedule_requested_refresh(request);
        Ok((networks, None))
    }

    fn cached_networks(
        &self,
        request: &NetworksRequest,
    ) -> Result<Option<(Vec<AccessPoint>, Option<ErrorReport>)>> {
        if !request.cached {
            return Ok(None);
        }
        if let Some(networks) = self.read_cached_networks(request)? {
            return Ok(Some((networks, None)));
        }
        request
            .refresh_cache
            .then(|| self.scan_and_cache(request.refresh_timeout))
            .transpose()
    }

    fn read_cached_networks(&self, request: &NetworksRequest) -> Result<Option<Vec<AccessPoint>>> {
        match cache::read_snapshot()? {
            cache::CacheRead::Available(snapshot) => {
                self.schedule_requested_refresh(request);
                Ok(Some(snapshot.into_networks()))
            }
            cache::CacheRead::Missing => {
                tracing::debug!("Wi-Fi scan cache is missing");
                Ok(None)
            }
            state => {
                log_unavailable_cache(&state);
                Ok(None)
            }
        }
    }

    fn schedule_requested_refresh(&self, request: &NetworksRequest) {
        if request.refresh_cache {
            self.schedule_cache_refresh(request.refresh_timeout);
        }
    }

    fn scan_and_cache(&self, timeout: Duration) -> Result<(Vec<AccessPoint>, Option<ErrorReport>)> {
        let warning = self
            .nm
            .scan_with_options(
                ScanRequestOptions {
                    timeout,
                    ifname: None,
                    ssid_bytes: Vec::new(),
                },
                None,
            )
            .err()
            .map(|err| {
                let err = ensure_domain(ErrorOperation::Scan, err);
                let report = ErrorReport::from_error(&err, ErrorOperation::Scan);
                tracing::warn!(error = %report.message, code = ?report.code, "cache refresh scan failed before list");
                report
            });
        let networks = self.nm.list_all_access_points()?;
        cache::write_snapshot(false, &networks)?;
        cache::write_complete(false, networks.len())?;
        Ok((networks, warning))
    }

    fn enrich_access_points(&self, access_points: Vec<AccessPoint>) -> Result<Vec<NetworkEntry>> {
        let mut networks = self.nm.network_entries_for_access_points(access_points)?;
        match cache::attach_connection_details(&mut networks)? {
            cache::CacheRead::Available(_) => {}
            cache::CacheRead::Missing => {
                tracing::debug!("known-connections cache is missing");
            }
            state => tracing::warn!(
                message = %state.unavailable_message("known-connections cache").unwrap_or_default(),
                "connection details are unavailable"
            ),
        }
        Ok(networks)
    }

    fn schedule_cache_refresh(&self, timeout: Duration) {
        if let Some(scheduler) = self.background_scans {
            scheduler.schedule_scan(timeout);
        } else {
            tracing::warn!("background cache refresh requested without a configured scheduler");
        }
    }
}

pub(crate) trait BackgroundScanScheduler {
    fn schedule_scan(&self, timeout: Duration);
}

#[derive(Debug, Clone)]
pub(crate) struct NetworksRequest {
    pub(crate) cached: bool,
    pub(crate) refresh_cache: bool,
    pub(crate) refresh_timeout: Duration,
}

impl NetworksRequest {
    pub(crate) fn new(cached: bool, refresh_cache: bool, refresh_timeout: Duration) -> Self {
        Self {
            cached,
            refresh_cache,
            refresh_timeout,
        }
    }
}

#[derive(Debug)]
pub(crate) struct NetworksResult {
    pub(crate) networks: Vec<NetworkEntry>,
    pub(crate) warning: Option<ErrorReport>,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanRequest {
    pub(crate) timeout: Duration,
    pub(crate) strict: bool,
    pub(crate) cache: bool,
    pub(crate) ifname: Option<InterfaceName>,
    pub(crate) ssids: Vec<String>,
}

impl ScanRequest {
    pub(crate) fn prepare(self) -> Result<PreparedScanRequest> {
        Ok(PreparedScanRequest {
            timeout: self.timeout,
            strict: self.strict,
            cache: self.cache,
            ifname: self.ifname,
            ssid_bytes: validated_ssids(self.ssids).map_err(|error| {
                DomainError::validation(ErrorOperation::Scan, &error).with_cause(error)
            })?,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedScanRequest {
    timeout: Duration,
    strict: bool,
    cache: bool,
    ifname: Option<InterfaceName>,
    ssid_bytes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub(crate) enum ScanEvent {
    Status {
        message: String,
    },
    Warning {
        error: ErrorReport,
    },
    Snapshot {
        networks_found: usize,
        access_points: Vec<AccessPoint>,
    },
    Complete {
        timed_out: bool,
        networks_found: usize,
    },
}

#[derive(Debug)]
pub(crate) struct ScanResult {
    pub(crate) access_points: Vec<AccessPoint>,
    pub(crate) warning: Option<ErrorReport>,
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectRequest {
    pub(crate) target: WifiConnectTarget,
    pub(crate) password: Option<String>,
    pub(crate) wep_key_type: Option<WepKeyType>,
}

impl ConnectRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        self.target.validate().map_err(|error| {
            DomainError::validation(ErrorOperation::Connect, &error)
                .with_cause(error)
                .into()
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ConnectEvent {
    Started { message: String },
    Progress { message: String },
    Finished(ConnectOutcome),
    Cancelled { message: String },
}

#[derive(Debug, Clone)]
pub(crate) enum ConnectOutcome {
    Succeeded(ConnectResult),
    Failed {
        result: ConnectResult,
        error: ErrorReport,
    },
    Cancelled {
        message: String,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum ProfileOperation {
    Details {
        path: NmObjectPath,
    },
    Update {
        path: NmObjectPath,
        settings: Box<WifiProfileUpdate>,
    },
    RevealSecret {
        path: NmObjectPath,
    },
    Delete {
        path: NmObjectPath,
    },
    SetAutoconnect {
        path: NmObjectPath,
        enabled: bool,
    },
    SetMacRandomization {
        path: NmObjectPath,
        randomized: bool,
    },
    Share {
        path: NmObjectPath,
    },
    SetSendHostname {
        path: NmObjectPath,
        enabled: bool,
    },
}

#[derive(Debug)]
pub(crate) enum ProfileOperationResult {
    Updated { message: &'static str },
    Details(Box<WifiProfileDetails>),
    Secret(WifiProfileSecret),
    Share(WifiSharePayload),
}

pub(crate) fn validated_ssids(ssids: Vec<String>) -> Result<Vec<Vec<u8>>> {
    ssids
        .into_iter()
        .map(|ssid| {
            let bytes = ssid.into_bytes();
            validate_ssid_bytes(&bytes)?;
            Ok(bytes)
        })
        .collect()
}

fn connect_error(target: &WifiConnectTarget, error: &ErrorReport) -> ConnectResult {
    ConnectResult::failed(
        target.ssid.to_string(),
        error
            .code
            .connect_reason()
            .unwrap_or(crate::model::ConnectFailureReason::Unknown),
        error.message.clone(),
    )
}

fn check_scan_cancelled(cancellation: Option<&AtomicBool>) -> Result<()> {
    if is_cancelled(cancellation) {
        return Err(scan_cancelled_error());
    }
    Ok(())
}

fn emit_scan_started(emit: &mut impl FnMut(&ScanEvent) -> Result<()>) -> Result<()> {
    emit(&ScanEvent::Status {
        message: "starting Wi-Fi scan".to_string(),
    })
}

fn cache_scan_snapshot(cache_result: bool, access_points: &[AccessPoint]) -> Result<()> {
    if cache_result {
        cache::write_live_scan_snapshot(false, access_points)?;
    }
    Ok(())
}

fn cache_scan_complete(cache_result: bool, networks_found: usize) -> Result<()> {
    if cache_result {
        cache::write_complete(false, networks_found)?;
    }
    Ok(())
}

fn start_connect(
    cancellation: Option<&AtomicBool>,
    emit: &mut impl FnMut(&ConnectEvent) -> Result<()>,
) -> Result<Option<ConnectOutcome>> {
    emit(&ConnectEvent::Started {
        message: "starting Wi-Fi connection".to_string(),
    })?;
    if is_cancelled(cancellation) {
        return cancelled_connect(emit, "cancelled before connection attempt started").map(Some);
    }
    emit(&ConnectEvent::Progress {
        message: "activating NetworkManager connection".to_string(),
    })?;
    Ok(None)
}

fn finish_connect_cancellation(
    cancellation: Option<&AtomicBool>,
    emit: &mut impl FnMut(&ConnectEvent) -> Result<()>,
) -> Result<Option<ConnectOutcome>> {
    if is_cancelled(cancellation) {
        return cancelled_connect(emit, "connection attempt was cancelled").map(Some);
    }
    Ok(None)
}

fn connect_outcome(target: &WifiConnectTarget, result: Result<ConnectResult>) -> ConnectOutcome {
    match result {
        Ok(result) => ConnectOutcome::Succeeded(result),
        Err(err) => failed_connect_outcome(target, &err),
    }
}

fn failed_connect_outcome(target: &WifiConnectTarget, err: &anyhow::Error) -> ConnectOutcome {
    let error = ErrorReport::from_error(err, ErrorOperation::Connect);
    ConnectOutcome::Failed {
        result: connect_error(target, &error),
        error,
    }
}

fn log_unavailable_cache<T>(state: &cache::CacheRead<T>) {
    tracing::warn!(
        message = %state.unavailable_message("Wi-Fi scan cache").unwrap_or_default(),
        "Wi-Fi scan cache is unavailable"
    );
}

fn profile_updated(message: &'static str) -> ProfileOperationResult {
    ProfileOperationResult::Updated { message }
}

fn is_cancelled(cancellation: Option<&AtomicBool>) -> bool {
    cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed))
}

fn scan_cancelled_error() -> anyhow::Error {
    DomainError::new(
        crate::error::ErrorCode::Cancelled,
        ErrorOperation::Scan,
        crate::error::ErrorSource::Cancellation,
        "Wi-Fi scan cancelled",
    )
    .into()
}

fn cancelled_connect(
    emit: &mut impl FnMut(&ConnectEvent) -> Result<()>,
    message: &str,
) -> Result<ConnectOutcome> {
    let outcome = ConnectOutcome::Cancelled {
        message: message.to_string(),
    };
    emit(&ConnectEvent::Cancelled {
        message: message.to_string(),
    })?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::ScanRequest;

    #[test]
    fn scan_ssids_are_validated_once_at_the_application_boundary() {
        let request = |ssids| ScanRequest {
            timeout: Duration::from_secs(1),
            strict: false,
            cache: false,
            ifname: None,
            ssids,
        };
        assert_eq!(
            request(vec!["one".to_string(), "two".to_string()])
                .prepare()
                .unwrap()
                .ssid_bytes,
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        assert!(request(vec![String::new()]).prepare().is_err());
        assert!(request(vec!["x".repeat(33)]).prepare().is_err());
    }
}
