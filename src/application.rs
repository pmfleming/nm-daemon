use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;

use crate::cache;
use crate::connect;
use crate::error::{DomainError, ErrorOperation, ErrorReport, ensure_domain, operation_result};
use crate::model::{
    AccessPoint, ConnectResult, ConnectivityStatus, DisconnectResult, InterfaceName, NetworkEntry,
    NmObjectPath, SavedWifiConnection, ScanRequestOptions, WepKeyType, WifiConnectTarget,
    WifiSharePayload, WifiStatus, validate_ssid_bytes,
};
use crate::nm::Nm;

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
        cache_status_best_effort(&status);
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
        emit: impl FnMut(&ScanEvent) -> Result<()>,
    ) -> Result<ScanResult> {
        self.scan_prepared(request.prepare()?, emit)
    }

    pub(crate) fn scan_prepared(
        &self,
        request: PreparedScanRequest,
        emit: impl FnMut(&ScanEvent) -> Result<()>,
    ) -> Result<ScanResult> {
        self.scan_prepared_cancellable(request, None, emit)
    }

    pub(crate) fn scan_prepared_cancellable(
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
        if is_cancelled(cancellation) {
            return Err(scan_cancelled_error());
        }
        emit(&ScanEvent::Status {
            message: "starting Wi-Fi scan".to_string(),
        })?;

        let warning = match self.nm.scan_with_options_cancellable(
            ScanRequestOptions {
                timeout: request.timeout,
                ifname: request.ifname,
                ssid_bytes: request.ssid_bytes,
            },
            cancellation,
        ) {
            Ok(()) => None,
            Err(err) if is_cancelled(cancellation) => return Err(err),
            Err(err) => {
                let err = ensure_domain(ErrorOperation::Scan, err);
                let error = ErrorReport::from_error(&err, ErrorOperation::Scan);
                emit(&ScanEvent::Warning {
                    error: error.clone(),
                })?;
                if request.strict {
                    return Err(err);
                }
                Some(error)
            }
        };

        if is_cancelled(cancellation) {
            return Err(scan_cancelled_error());
        }

        let access_points = self.nm.list_all_access_points()?;
        let networks_found = access_points.len();
        if request.cache {
            cache::write_live_scan_snapshot(false, &access_points)?;
        }
        emit(&ScanEvent::Snapshot {
            networks_found,
            access_points: access_points.clone(),
        })?;
        if request.cache {
            cache::write_complete(false, networks_found)?;
        }
        emit(&ScanEvent::Complete {
            timed_out: false,
            networks_found,
        })?;

        Ok(ScanResult {
            access_points,
            warning,
        })
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
        emit(&ConnectEvent::Started {
            message: "starting Wi-Fi connection".to_string(),
        })?;
        if is_cancelled(cancellation) {
            return cancelled_connect(&mut emit, "cancelled before connection attempt started");
        }

        emit(&ConnectEvent::Progress {
            message: "activating NetworkManager connection".to_string(),
        })?;
        let result = match cancellation {
            Some(cancellation) => connect::connect_target_with_password_cancellable(
                self.nm,
                &request.target,
                request.password.as_deref(),
                request.wep_key_type,
                cancellation,
            ),
            None => connect::connect_target_with_password(
                self.nm,
                &request.target,
                request.password.as_deref(),
                request.wep_key_type,
            ),
        };

        if is_cancelled(cancellation) {
            return cancelled_connect(&mut emit, "connection attempt was cancelled");
        }

        let outcome = match result {
            Ok(result) => ConnectOutcome::Succeeded(result),
            Err(err) => {
                let error = ErrorReport::from_error(&err, ErrorOperation::Connect);
                ConnectOutcome::Failed {
                    result: connect_error(&request.target, &error),
                    error,
                }
            }
        };
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
        let result = match operation {
            ProfileOperation::Delete { path } => {
                self.nm.delete_connection_by_path(path.as_str())?;
                Ok(ProfileOperationResult::Updated {
                    message: "Saved Wi-Fi profile deleted",
                })
            }
            ProfileOperation::SetAutoconnect { path, enabled } => {
                self.nm
                    .set_connection_autoconnect_by_path(path.as_str(), enabled)?;
                Ok(ProfileOperationResult::Updated {
                    message: "Saved Wi-Fi profile autoconnect updated",
                })
            }
            ProfileOperation::SetMacRandomization { path, randomized } => {
                self.nm
                    .set_connection_mac_randomization_by_path(path.as_str(), randomized)?;
                Ok(ProfileOperationResult::Updated {
                    message: "Saved Wi-Fi profile MAC privacy updated",
                })
            }
            ProfileOperation::Share { path } => Ok(ProfileOperationResult::Share(
                self.nm.wifi_share_payload_by_path(path.as_str())?,
            )),
            ProfileOperation::SetSendHostname { path, enabled } => {
                self.nm
                    .set_connection_send_hostname_by_path(path.as_str(), enabled)?;
                Ok(ProfileOperationResult::Updated {
                    message: "Saved Wi-Fi profile DHCP hostname privacy updated",
                })
            }
        };
        operation_result(ErrorOperation::ProfileOperation, result)
    }

    pub(crate) fn disconnect(&self) -> Result<DisconnectResult> {
        let result = operation_result(ErrorOperation::Disconnect, self.nm.disconnect_wifi())?;
        clear_active_cache_best_effort();
        Ok(result)
    }

    fn load_networks(
        &self,
        request: &NetworksRequest,
    ) -> Result<(Vec<AccessPoint>, Option<ErrorReport>)> {
        if request.cached {
            match cache::read_snapshot()? {
                cache::CacheRead::Available(snapshot) => {
                    let networks = snapshot.into_networks();
                    if request.refresh_cache {
                        self.schedule_cache_refresh(request.refresh_timeout);
                    }
                    return Ok((networks, None));
                }
                cache::CacheRead::Missing => {
                    tracing::debug!("Wi-Fi scan cache is missing");
                }
                state => {
                    tracing::warn!(
                        message = %state.unavailable_message("Wi-Fi scan cache").unwrap_or_default(),
                        "Wi-Fi scan cache is unavailable"
                    );
                }
            }

            if request.refresh_cache {
                return self.scan_and_cache(request.refresh_timeout);
            }
        }

        let networks = self.nm.list_all_access_points()?;
        if request.refresh_cache {
            self.schedule_cache_refresh(request.refresh_timeout);
        }
        Ok((networks, None))
    }

    fn scan_and_cache(&self, timeout: Duration) -> Result<(Vec<AccessPoint>, Option<ErrorReport>)> {
        let warning = self.nm.scan(timeout).err().map(|err| {
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

fn cache_status_best_effort(status: &WifiStatus) {
    if let Err(err) = cache::cache_connected_network_status(status) {
        tracing::warn!(error = %format_args!("{err:#}"), "failed to cache active Wi-Fi status");
    }
}

fn clear_active_cache_best_effort() {
    if let Err(err) = cache::clear_active_connection_cache() {
        tracing::warn!(error = %format_args!("{err:#}"), "failed to clear active Wi-Fi cache");
    }
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
