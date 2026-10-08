use std::borrow::Cow;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use crate::cache;
use crate::connect;
use crate::error::{
    DomainError, ErrorOperation, ErrorReport, best_effort, cancellation_requested, ensure_domain,
    operation_result,
};
use crate::generated::REQUEST_TIMEOUT_MAX;
use crate::model::{
    AccessPoint, ConnectAttemptSummary, ConnectCandidateInfo, ConnectFailureReason, ConnectPhase,
    ConnectResult, ConnectTargetIdentity, ConnectivityStatus, DisconnectResult,
    HotspotCapabilities, HotspotStartResult, HotspotStatus, HotspotStopResult, InterfaceName,
    NetworkConnectionSummary, NetworkDeactivateResult, NetworkDeviceSummary, NetworkEntry,
    NetworkInventory, NetworkSnapshotMetadata, NetworkSnapshotSource, NetworkStateSummary,
    NmObjectPath, ProfileActivationResult, RadioPowerResult, SavedWifiConnection,
    ScanRequestOptions, VpnActivationResult, VpnDisconnectResult, VpnProfileSummary, VpnStatus,
    WepKeyType, WifiBand, WifiBandSelectionResult, WifiBandStatus, WifiConnectTarget,
    WifiPowerResult, WifiProfileDetails, WifiProfileSecret, WifiProfileUpdate, WifiSharePayload,
    WifiStatus, connect_target_for_network, connect_target_for_network_access_point,
    connect_target_for_network_key, validate_ssid_bytes,
};
use crate::nm::{ActiveConnectionSelector, HotspotRequest, Nm, ProfileSelector, VpnSelector};
use anyhow::Result;

/// Transport-neutral operations layer; boundaries only translate requests and results.
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
        let status = self.status_snapshot()?;
        self.persist_status(&status);
        Ok(status)
    }

    pub(crate) fn status_snapshot(&self) -> Result<WifiStatus> {
        operation_result(ErrorOperation::Status, self.nm.wifi_status())
    }

    pub(crate) fn persist_status(&self, status: &WifiStatus) {
        best_effort("failed to cache active Wi-Fi status", || {
            cache::cache_connected_network_status(status)
        });
    }

    pub(crate) fn connectivity(&self) -> Result<ConnectivityStatus> {
        operation_result(ErrorOperation::Connectivity, self.nm.connectivity_check())
    }

    pub(crate) fn discover_services(
        &self,
        query: &crate::discovery::ServiceQuery,
    ) -> Result<crate::discovery::DiscoverySnapshot> {
        operation_result(
            ErrorOperation::Discovery,
            // Discovery runs on a daemon blocking worker with the Tokio timer
            // driver active; keep the D-Bus requests cancellable at the deadline.
            futures::executor::block_on(crate::discovery::resolve_services(
                self.nm.connection().inner().clone(),
                query,
            )),
        )
    }

    pub(crate) fn hotspot_capabilities(&self) -> Result<HotspotCapabilities> {
        operation_result(
            ErrorOperation::HotspotOperation,
            self.nm.hotspot_capabilities(),
        )
    }

    pub(crate) fn hotspot_status(&self) -> Result<HotspotStatus> {
        operation_result(ErrorOperation::HotspotOperation, self.nm.hotspot_status())
    }

    pub(crate) fn start_hotspot(
        &self,
        request: &HotspotRequest,
        cancellation: Option<&AtomicBool>,
    ) -> Result<HotspotStartResult> {
        operation_result(
            ErrorOperation::HotspotOperation,
            self.nm.start_hotspot(request, cancellation),
        )
    }

    pub(crate) fn stop_hotspot(&self) -> Result<HotspotStopResult> {
        operation_result(ErrorOperation::HotspotOperation, self.nm.stop_hotspot())
    }

    pub(crate) fn vpn_profiles(&self) -> Result<Vec<VpnProfileSummary>> {
        operation_result(ErrorOperation::VpnOperation, self.nm.vpn_profiles())
    }

    pub(crate) fn vpn_status(&self) -> Result<VpnStatus> {
        operation_result(ErrorOperation::VpnOperation, self.nm.vpn_status())
    }

    pub(crate) fn connect_vpn(
        &self,
        selector: &VpnSelector,
        timeout: Duration,
        cancellation: Option<&AtomicBool>,
    ) -> Result<VpnActivationResult> {
        operation_result(
            ErrorOperation::VpnOperation,
            self.nm.activate_vpn(selector, timeout, cancellation),
        )
    }

    pub(crate) fn disconnect_vpn(&self, selector: &VpnSelector) -> Result<VpnDisconnectResult> {
        operation_result(
            ErrorOperation::VpnOperation,
            self.nm.deactivate_vpn(selector),
        )
    }

    pub(crate) fn network_inventory(&self) -> Result<NetworkInventory> {
        operation_result(ErrorOperation::Inventory, self.nm.network_inventory())
    }

    pub(crate) fn network_devices(&self) -> Result<Vec<NetworkDeviceSummary>> {
        operation_result(ErrorOperation::Inventory, self.nm.network_devices())
    }

    pub(crate) fn network_connections(&self) -> Result<Vec<NetworkConnectionSummary>> {
        operation_result(ErrorOperation::Inventory, self.nm.network_connections())
    }

    pub(crate) fn network_state(&self) -> Result<NetworkStateSummary> {
        operation_result(ErrorOperation::Inventory, self.nm.network_state())
    }

    pub(crate) fn activate_network_profile(
        &self,
        selector: &ProfileSelector,
    ) -> Result<ProfileActivationResult> {
        operation_result(
            ErrorOperation::Connect,
            self.nm.activate_network_profile(selector),
        )
    }

    pub(crate) fn deactivate_network_connection(
        &self,
        selector: &ActiveConnectionSelector,
    ) -> Result<NetworkDeactivateResult> {
        operation_result(
            ErrorOperation::Disconnect,
            self.nm.deactivate_network_connection(selector),
        )
    }

    pub(crate) fn band_status(&self, path: &str) -> Result<WifiBandStatus> {
        operation_result(
            ErrorOperation::BandOperation,
            self.nm.wifi_band_status(path),
        )
    }

    pub(crate) fn select_band(
        &self,
        path: &str,
        band: WifiBand,
        cancellation: Option<&AtomicBool>,
    ) -> Result<WifiBandSelectionResult> {
        operation_result(
            ErrorOperation::BandOperation,
            self.nm.select_wifi_band(path, band, cancellation),
        )
    }

    pub(crate) fn set_wifi_enabled(&self, enabled: bool) -> Result<WifiPowerResult> {
        operation_result(
            ErrorOperation::Status,
            self.nm.set_wireless_enabled(enabled),
        )
    }

    pub(crate) fn set_wwan_enabled(&self, enabled: bool) -> Result<RadioPowerResult> {
        operation_result(ErrorOperation::Status, self.nm.set_wwan_enabled(enabled))
    }

    pub(crate) fn set_airplane_mode(&self, enabled: bool) -> Result<RadioPowerResult> {
        operation_result(ErrorOperation::Status, self.nm.set_airplane_mode(enabled))
    }

    pub(crate) fn networks(&self, request: NetworksRequest) -> Result<NetworksResult> {
        operation_result(
            ErrorOperation::Networks,
            (|| {
                request.validate()?;
                let loaded = self.load_networks(&request)?;
                let networks = self.enrich_access_points(loaded.access_points)?;
                Ok(NetworksResult {
                    networks,
                    warning: loaded.warning,
                    snapshot: loaded.snapshot,
                })
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
                    snapshot: NetworkSnapshotMetadata::live(NetworkSnapshotSource::Scan),
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
            Err(err) if cancellation_requested(cancellation) => return Err(err),
            Err(err) => {
                let err = ensure_domain(ErrorOperation::Scan, err);
                let error = ErrorReport::from_error(&err, ErrorOperation::Scan);
                emit(&ScanEvent::Warning { error: &error })?;
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
            access_points: &access_points,
        })?;
        cache_scan_complete(cache_result, networks_found)?;
        emit(&ScanEvent::Complete { networks_found })?;
        Ok(access_points)
    }

    pub(crate) fn connect_request_for_key(
        &self,
        key: &str,
        password: Option<String>,
        wep_key_type: Option<WepKeyType>,
        enterprise_identity: Option<String>,
    ) -> Result<ConnectRequest> {
        operation_result(
            ErrorOperation::Connect,
            (|| {
                let networks = self
                    .nm
                    .network_entries_for_access_points(self.nm.list_all_access_points()?)?;
                let network = networks.iter().find(|network| network.key == key);
                let (target, candidate, mut alternatives) =
                    resolve_connect_candidates(network, key, enterprise_identity)?;
                if let Some(network) = network {
                    constrain_alternatives_to_saved_profile(self.nm, network, &mut alternatives);
                }
                let request = ConnectRequest {
                    target,
                    network_key: Some(key.to_string()),
                    password,
                    wep_key_type,
                    candidate,
                    alternatives,
                };
                request.validate()?;
                Ok(request)
            })(),
        )
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
        if let Some(outcome) = start_connect(request, cancellation, &mut emit)? {
            return Ok(outcome);
        }
        let target_identity =
            ConnectTargetIdentity::from_target(&request.target, request.network_key.as_deref());
        // A network-key request represents a roaming-compatible AP group. Try
        // at most one alternate candidate; explicit legacy BSSID/AP requests
        // remain strict and therefore contain no alternatives.
        let primary = request.primary_candidate();
        let mut alternative = request.alternatives.first();
        let total = 1 + usize::from(alternative.is_some());
        let mut attempts = Vec::with_capacity(total);
        let mut candidate = primary.as_ref();
        let mut attempt = 1;
        let outcome = loop {
            let candidate_info = candidate.info(attempt, total);
            emit_trying_candidate(&target_identity, &candidate_info, &mut emit)?;
            let started_at = Instant::now();
            let result = self.run_connect_candidate(
                request,
                candidate,
                total == 1,
                cancellation,
                (&target_identity, &candidate_info),
                &mut emit,
            );

            if let Some(outcome) = finish_connect_cancellation(request, cancellation, &mut emit)? {
                return Ok(outcome);
            }
            let error = match result {
                Ok(result) => {
                    break self.successful_connect_outcome(
                        result,
                        candidate_info,
                        attempt,
                        total,
                        started_at,
                        attempts,
                    );
                }
                Err(error) => error,
            };
            let reason = record_failed_attempt(&mut attempts, &candidate_info, started_at, &error);
            if retryable_candidate_failure(reason)
                && let Some(next) = alternative.take()
            {
                emit_retry(
                    &target_identity,
                    &candidate_info,
                    next.info(2, total),
                    reason,
                    &mut emit,
                )?;
                candidate = next;
                attempt += 1;
                continue;
            }
            break final_failed_connect_outcome(request, error, attempts, total > 1);
        };
        emit_finished_connect(request, &outcome, &mut emit)?;
        Ok(outcome)
    }

    fn run_connect_candidate(
        &self,
        request: &ConnectRequest,
        candidate: &ConnectCandidate,
        publish_failure: bool,
        cancellation: Option<&AtomicBool>,
        progress_context: (&ConnectTargetIdentity, &ConnectCandidateInfo),
        emit: &mut impl FnMut(&ConnectEvent) -> Result<()>,
    ) -> Result<ConnectResult> {
        let (target, candidate_info) = progress_context;
        let mut progress = |phase| {
            emit(&ConnectEvent::Progress {
                phase,
                target: target.clone(),
                message: connect_phase_message(phase).to_string(),
                candidate: Some(candidate_info.clone()),
                previous_reason: None,
            })
        };
        connect::connect_target(
            self.nm,
            &candidate.target,
            request.password.as_deref(),
            request.wep_key_type,
            cancellation,
            &mut progress,
            publish_failure,
        )
    }

    fn successful_connect_outcome(
        &self,
        mut result: ConnectResult,
        candidate: ConnectCandidateInfo,
        attempt: usize,
        total: usize,
        started_at: Instant,
        mut attempts: Vec<ConnectAttemptSummary>,
    ) -> ConnectOutcome {
        let actual = active_candidate_info(self.nm, attempt, total).unwrap_or(candidate);
        attempts.push(connect_attempt_summary(
            &actual,
            "connected",
            None,
            started_at,
            result.message.clone(),
        ));
        result.fallback_used = attempt > 1;
        result.attempts = attempts;
        if result.fallback_used {
            result.message = recovery_message(&result.ssid, &result.attempts);
            best_effort("failed to cache recovered Wi-Fi status", || {
                cache::write_status("connected", &result.message)
            });
        }
        ConnectOutcome::Succeeded(result)
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
        let message = match operation {
            ProfileOperation::Details { path } => {
                return self
                    .nm
                    .wifi_profile_details_by_path(path.as_str())
                    .map(|details| ProfileOperationResult::Details(Box::new(details)));
            }
            ProfileOperation::RevealSecret { path } => {
                return self
                    .nm
                    .wifi_profile_secret_by_path(path.as_str())
                    .map(ProfileOperationResult::Secret);
            }
            ProfileOperation::Share { path } => {
                return self
                    .nm
                    .wifi_share_payload_by_path(path.as_str())
                    .map(ProfileOperationResult::Share);
            }
            ProfileOperation::Update { path, settings } => {
                self.nm
                    .update_wifi_profile_by_path(path.as_str(), &settings)?;
                "Saved Wi-Fi profile settings updated"
            }
            ProfileOperation::Delete { path } => {
                tracing::info!(
                    profile_path = path.as_str(),
                    "deleting saved Wi-Fi profile by explicit path"
                );
                self.nm.delete_connection_by_path(path.as_str())?;
                tracing::info!(
                    profile_path = path.as_str(),
                    "saved Wi-Fi profile deleted by explicit path"
                );
                "Saved Wi-Fi profile deleted"
            }
            ProfileOperation::SetAutoconnect { path, enabled } => {
                self.nm
                    .set_connection_autoconnect_by_path(path.as_str(), enabled)?;
                "Saved Wi-Fi profile autoconnect updated"
            }
            ProfileOperation::SetCasting { path, enabled } => {
                self.nm
                    .set_connection_casting_by_path(path.as_str(), enabled)?;
                "Saved Wi-Fi profile Cast discovery updated"
            }
            ProfileOperation::SetMacRandomization { path, randomized } => {
                self.nm
                    .set_connection_mac_randomization_by_path(path.as_str(), randomized)?;
                "Saved Wi-Fi profile MAC privacy updated"
            }
            ProfileOperation::SetSendHostname { path, enabled } => {
                self.nm
                    .set_connection_send_hostname_by_path(path.as_str(), enabled)?;
                "Saved Wi-Fi profile DHCP hostname privacy updated"
            }
        };
        Ok(ProfileOperationResult::Updated { message })
    }

    pub(crate) fn disconnect(&self) -> Result<DisconnectResult> {
        let result = operation_result(ErrorOperation::Disconnect, self.nm.disconnect_wifi())?;
        best_effort("failed to clear active Wi-Fi cache", || {
            cache::clear_active_connection_cache()
        });
        Ok(result)
    }

    pub(crate) fn disconnect_wifi_for_ssid(&self, ssid: &[u8]) -> Result<DisconnectResult> {
        let result = operation_result(
            ErrorOperation::Disconnect,
            self.nm.disconnect_wifi_for_ssid(ssid),
        )?;
        self.clear_disconnected_cache(&result);
        Ok(result)
    }

    fn clear_disconnected_cache(&self, result: &DisconnectResult) {
        if result.status == "disconnected" {
            best_effort("failed to clear active Wi-Fi cache", || {
                cache::clear_active_connection_cache()
            });
        }
    }

    fn load_networks(&self, request: &NetworksRequest) -> Result<LoadedNetworks> {
        if let Some(cached) = self.cached_networks(request)? {
            return Ok(cached);
        }
        let networks = self.nm.list_all_access_points()?;
        let refresh_requested = self.schedule_requested_refresh(request, true);
        let mut snapshot = NetworkSnapshotMetadata::live(NetworkSnapshotSource::NetworkManager);
        snapshot.refresh_requested = refresh_requested;
        Ok(LoadedNetworks {
            access_points: networks,
            warning: None,
            snapshot,
        })
    }

    fn cached_networks(&self, request: &NetworksRequest) -> Result<Option<LoadedNetworks>> {
        if !request.cached {
            return Ok(None);
        }
        self.read_cached_networks(request)
    }

    fn read_cached_networks(&self, request: &NetworksRequest) -> Result<Option<LoadedNetworks>> {
        match cache::read_snapshot()? {
            cache::CacheRead::Available(snapshot) => {
                let mut metadata = snapshot.metadata(false);
                metadata.refresh_requested =
                    self.schedule_requested_refresh(request, metadata.stale);
                Ok(Some(LoadedNetworks {
                    access_points: snapshot.into_networks(),
                    warning: None,
                    snapshot: metadata,
                }))
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

    fn schedule_requested_refresh(&self, request: &NetworksRequest, refresh_needed: bool) -> bool {
        if !request.refresh_cache {
            return false;
        }
        if !refresh_needed {
            tracing::debug!(
                "skipped background Wi-Fi refresh because the cached snapshot is fresh"
            );
            return false;
        }
        self.schedule_cache_refresh(request.refresh_timeout);
        true
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

    fn validate(&self) -> Result<()> {
        validate_request_timeout(
            self.refresh_timeout,
            ErrorOperation::Networks,
            "refresh_timeout",
        )
    }
}

#[derive(Debug)]
struct LoadedNetworks {
    access_points: Vec<AccessPoint>,
    warning: Option<ErrorReport>,
    snapshot: NetworkSnapshotMetadata,
}

#[derive(Debug)]
pub(crate) struct NetworksResult {
    pub(crate) networks: Vec<NetworkEntry>,
    pub(crate) warning: Option<ErrorReport>,
    pub(crate) snapshot: NetworkSnapshotMetadata,
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
        validate_request_timeout(self.timeout, ErrorOperation::Scan, "timeout")?;
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

/// Synchronous notifications borrow data retained by the scan result.
#[derive(Debug)]
pub(crate) enum ScanEvent<'a> {
    Status {
        message: &'a str,
    },
    Warning {
        error: &'a ErrorReport,
    },
    Snapshot {
        networks_found: usize,
        access_points: &'a [AccessPoint],
    },
    Complete {
        networks_found: usize,
    },
}

#[derive(Debug)]
pub(crate) struct ScanResult {
    pub(crate) access_points: Vec<AccessPoint>,
    pub(crate) warning: Option<ErrorReport>,
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectCandidate {
    pub(crate) target: WifiConnectTarget,
    pub(crate) band: Option<String>,
    pub(crate) channel: Option<u32>,
    pub(crate) strength: Option<u8>,
}

impl ConnectCandidate {
    fn from_access_point(target: WifiConnectTarget, access_point: &AccessPoint) -> Self {
        Self {
            target,
            band: (!access_point.band.is_empty()).then(|| access_point.band.clone()),
            channel: (access_point.channel != 0).then_some(access_point.channel),
            strength: Some(access_point.strength),
        }
    }

    fn from_target(target: WifiConnectTarget) -> Self {
        Self {
            target,
            band: None,
            channel: None,
            strength: None,
        }
    }

    fn info(&self, attempt: usize, total: usize) -> ConnectCandidateInfo {
        ConnectCandidateInfo {
            attempt,
            total,
            bssid: self
                .target
                .bssid
                .as_ref()
                .map(|value| value.as_str().to_string()),
            band: self.band.clone(),
            channel: self.channel,
            strength: self.strength,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectRequest {
    pub(crate) target: WifiConnectTarget,
    pub(crate) network_key: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) wep_key_type: Option<WepKeyType>,
    pub(crate) candidate: Option<ConnectCandidate>,
    pub(crate) alternatives: Vec<ConnectCandidate>,
}

impl ConnectRequest {
    pub(crate) fn single(
        target: WifiConnectTarget,
        password: Option<String>,
        wep_key_type: Option<WepKeyType>,
    ) -> Self {
        Self {
            target,
            network_key: None,
            password,
            wep_key_type,
            candidate: None,
            alternatives: Vec::new(),
        }
    }

    fn primary_candidate(&self) -> Cow<'_, ConnectCandidate> {
        self.candidate.as_ref().map_or_else(
            || Cow::Owned(ConnectCandidate::from_target(self.target.clone())),
            Cow::Borrowed,
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.target.validate().map_err(|error| {
            DomainError::validation(ErrorOperation::Connect, &error)
                .with_cause(error)
                .into()
        })
    }
}

#[derive(Debug)]
pub(crate) enum ConnectEvent<'a> {
    Started {
        phase: ConnectPhase,
        target: ConnectTargetIdentity,
        message: String,
    },
    Progress {
        phase: ConnectPhase,
        target: ConnectTargetIdentity,
        message: String,
        candidate: Option<ConnectCandidateInfo>,
        previous_reason: Option<ConnectFailureReason>,
    },
    Finished {
        phase: ConnectPhase,
        target: ConnectTargetIdentity,
        outcome: &'a ConnectOutcome,
    },
    Cancelled {
        phase: ConnectPhase,
        target: ConnectTargetIdentity,
        message: String,
    },
}

#[derive(Debug)]
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
    SetCasting {
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

fn validate_request_timeout(
    timeout: Duration,
    operation: ErrorOperation,
    field: &'static str,
) -> Result<()> {
    if timeout.is_zero() || timeout > REQUEST_TIMEOUT_MAX {
        return Err(DomainError::validation(
            operation,
            format!(
                "{field} must be between 1 ms and {} ms",
                REQUEST_TIMEOUT_MAX.as_millis()
            ),
        )
        .with_detail("field", field)
        .with_detail("max_ms", REQUEST_TIMEOUT_MAX.as_millis() as u64)
        .into());
    }
    Ok(())
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
    if cancellation_requested(cancellation) {
        return Err(scan_cancelled_error());
    }
    Ok(())
}

fn emit_scan_started(emit: &mut impl FnMut(&ScanEvent) -> Result<()>) -> Result<()> {
    emit(&ScanEvent::Status {
        message: "starting Wi-Fi scan",
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
        cache::write_complete(networks_found)?;
    }
    Ok(())
}

fn start_connect(
    request: &ConnectRequest,
    cancellation: Option<&AtomicBool>,
    emit: &mut impl FnMut(&ConnectEvent) -> Result<()>,
) -> Result<Option<ConnectOutcome>> {
    let target =
        ConnectTargetIdentity::from_target(&request.target, request.network_key.as_deref());
    emit(&ConnectEvent::Started {
        phase: ConnectPhase::Starting,
        target,
        message: "starting Wi-Fi connection".to_string(),
    })?;
    if cancellation_requested(cancellation) {
        return cancelled_connect(request, emit, "cancelled before connection attempt started")
            .map(Some);
    }
    Ok(None)
}

fn connect_phase_message(phase: ConnectPhase) -> &'static str {
    match phase {
        ConnectPhase::Starting => "starting Wi-Fi connection",
        ConnectPhase::TryingAccessPoint => "trying Wi-Fi access point",
        ConnectPhase::CheckingActive => "checking current Wi-Fi connection",
        ConnectPhase::ActivatingSavedProfile => "activating saved NetworkManager profile",
        ConnectPhase::CreatingProfile => "creating NetworkManager Wi-Fi profile",
        ConnectPhase::Rescanning => "rescanning for selected Wi-Fi network",
        ConnectPhase::Verifying => "verifying Wi-Fi activation",
        ConnectPhase::RetryingAlternative => "retrying an alternate Wi-Fi access point",
        ConnectPhase::Connected => "Wi-Fi connection succeeded",
        ConnectPhase::Failed => "Wi-Fi connection failed",
        ConnectPhase::Cancelled => "Wi-Fi connection cancelled",
    }
}

fn emit_trying_candidate(
    target: &ConnectTargetIdentity,
    candidate: &ConnectCandidateInfo,
    emit: &mut impl FnMut(&ConnectEvent) -> Result<()>,
) -> Result<()> {
    emit(&ConnectEvent::Progress {
        phase: ConnectPhase::TryingAccessPoint,
        target: target.clone(),
        message: candidate_message("trying", candidate),
        candidate: Some(candidate.clone()),
        previous_reason: None,
    })
}

fn candidate_message(action: &str, candidate: &ConnectCandidateInfo) -> String {
    match (&candidate.band, candidate.channel) {
        (Some(band), Some(channel)) => format!(
            "{action} {band} access point on channel {channel} (attempt {}/{})",
            candidate.attempt, candidate.total
        ),
        (Some(band), None) => format!(
            "{action} {band} access point (attempt {}/{})",
            candidate.attempt, candidate.total
        ),
        _ => format!(
            "{action} Wi-Fi access point (attempt {}/{})",
            candidate.attempt, candidate.total
        ),
    }
}

fn retry_message(
    previous: &ConnectCandidateInfo,
    next: &ConnectCandidateInfo,
    reason: ConnectFailureReason,
) -> String {
    let previous_band = previous.band.as_deref().unwrap_or("selected");
    let next_band = next.band.as_deref().unwrap_or("alternate");
    let failure = match reason {
        ConnectFailureReason::DhcpFailed => "connected but did not receive an IP address",
        ConnectFailureReason::NotFound => "became unavailable",
        ConnectFailureReason::Timeout => "timed out",
        _ => "failed",
    };
    format!("{previous_band} access point {failure}; trying {next_band}")
}

fn emit_retry(
    target: &ConnectTargetIdentity,
    previous: &ConnectCandidateInfo,
    next: ConnectCandidateInfo,
    reason: ConnectFailureReason,
    emit: &mut impl FnMut(&ConnectEvent) -> Result<()>,
) -> Result<()> {
    emit(&ConnectEvent::Progress {
        phase: ConnectPhase::RetryingAlternative,
        target: target.clone(),
        message: retry_message(previous, &next, reason),
        candidate: Some(next),
        previous_reason: Some(reason),
    })
}

fn retryable_candidate_failure(reason: ConnectFailureReason) -> bool {
    matches!(
        reason,
        ConnectFailureReason::DhcpFailed
            | ConnectFailureReason::NotFound
            | ConnectFailureReason::Timeout
            | ConnectFailureReason::ActivationFailed
    )
}

fn connect_attempt_summary(
    candidate: &ConnectCandidateInfo,
    status: &'static str,
    reason: Option<ConnectFailureReason>,
    started_at: Instant,
    message: String,
) -> ConnectAttemptSummary {
    ConnectAttemptSummary {
        attempt: candidate.attempt,
        status,
        reason,
        bssid: candidate.bssid.clone(),
        band: candidate.band.clone(),
        channel: candidate.channel,
        duration_ms: started_at.elapsed().as_millis(),
        message,
    }
}

fn record_failed_attempt(
    attempts: &mut Vec<ConnectAttemptSummary>,
    candidate: &ConnectCandidateInfo,
    started_at: Instant,
    error: &anyhow::Error,
) -> ConnectFailureReason {
    let report = ErrorReport::from_error(error, ErrorOperation::Connect);
    let reason = report
        .code
        .connect_reason()
        .unwrap_or(ConnectFailureReason::Unknown);
    attempts.push(connect_attempt_summary(
        candidate,
        "failed",
        Some(reason),
        started_at,
        report.message,
    ));
    reason
}

fn final_failed_connect_outcome(
    request: &ConnectRequest,
    error: anyhow::Error,
    attempts: Vec<ConnectAttemptSummary>,
    publish_failure: bool,
) -> ConnectOutcome {
    if publish_failure {
        connect::publish_final_connect_failure(&request.target, &error);
    }
    let mut outcome = failed_connect_outcome(&request.target, &error);
    if let ConnectOutcome::Failed { result, .. } = &mut outcome {
        result.fallback_used = attempts.len() > 1;
        result.attempts = attempts;
    }
    outcome
}

fn active_candidate_info(nm: &Nm, attempt: usize, total: usize) -> Option<ConnectCandidateInfo> {
    let access_point = nm.wifi_status().ok()?.access_point?;
    Some(ConnectCandidateInfo {
        attempt,
        total,
        bssid: (!access_point.bssid.is_empty()).then_some(access_point.bssid),
        band: (!access_point.band.is_empty()).then_some(access_point.band),
        channel: (access_point.channel != 0).then_some(access_point.channel),
        strength: Some(access_point.strength),
    })
}

fn recovery_message(ssid: &str, attempts: &[ConnectAttemptSummary]) -> String {
    let failed_band = attempts
        .iter()
        .find(|attempt| attempt.status == "failed")
        .and_then(|attempt| attempt.band.as_deref())
        .unwrap_or("first access point");
    let connected_band = attempts
        .last()
        .and_then(|attempt| attempt.band.as_deref())
        .unwrap_or("alternate access point");
    format!("Connected to {ssid} on {connected_band} after {failed_band} failed")
}

fn emit_finished_connect(
    request: &ConnectRequest,
    outcome: &ConnectOutcome,
    emit: &mut impl FnMut(&ConnectEvent) -> Result<()>,
) -> Result<()> {
    let phase = match outcome {
        ConnectOutcome::Succeeded(_) => ConnectPhase::Connected,
        ConnectOutcome::Failed { .. } => ConnectPhase::Failed,
        ConnectOutcome::Cancelled { .. } => ConnectPhase::Cancelled,
    };
    emit(&ConnectEvent::Finished {
        phase,
        target: ConnectTargetIdentity::from_target(&request.target, request.network_key.as_deref()),
        outcome,
    })
}

fn finish_connect_cancellation(
    request: &ConnectRequest,
    cancellation: Option<&AtomicBool>,
    emit: &mut impl FnMut(&ConnectEvent) -> Result<()>,
) -> Result<Option<ConnectOutcome>> {
    if cancellation_requested(cancellation) {
        return cancelled_connect(request, emit, "connection attempt was cancelled").map(Some);
    }
    Ok(None)
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

fn resolve_connect_candidates(
    network: Option<&NetworkEntry>,
    key: &str,
    enterprise_identity: Option<String>,
) -> Result<(
    WifiConnectTarget,
    Option<ConnectCandidate>,
    Vec<ConnectCandidate>,
)> {
    let Some(network) = network else {
        if !key.contains('|') {
            // Protocol-v1 SSID-only keys retain their generic fallback. It has
            // no trustworthy AP group from which to build alternate candidates.
            return Ok((
                connect_target_for_network_key(key, enterprise_identity)?,
                None,
                Vec::new(),
            ));
        }
        return Err(DomainError::validation(
            ErrorOperation::Connect,
            "selected Wi-Fi network is no longer available; refresh the network list",
        )
        .with_detail("network_key", key)
        .into());
    };

    let target = connect_target_for_network(network, enterprise_identity.clone())?;
    let candidate = Some(ConnectCandidate::from_access_point(
        target.clone(),
        &network.access_point,
    ));
    let alternatives = ranked_alternatives(&network.access_point, &network.access_points)
        .into_iter()
        .map(|access_point| {
            let target = connect_target_for_network_access_point(
                network,
                access_point,
                enterprise_identity.clone(),
            )?;
            Ok(ConnectCandidate::from_access_point(target, access_point))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((target, candidate, alternatives))
}

/// Selection order is independent of execution: another band first, then
/// strongest signal, then BSSID. Execution still tries at most one alternate.
fn ranked_alternatives<'a>(
    primary: &AccessPoint,
    access_points: &'a [AccessPoint],
) -> Vec<&'a AccessPoint> {
    let mut alternatives = access_points
        .iter()
        .filter(|ap| ap.path != primary.path || !ap.bssid.eq_ignore_ascii_case(&primary.bssid))
        .collect::<Vec<_>>();
    alternatives.sort_by_key(|ap| {
        (
            ap.band == primary.band,
            std::cmp::Reverse(ap.strength),
            &ap.bssid,
        )
    });
    alternatives
}

fn constrain_alternatives_to_saved_profile(
    nm: &Nm,
    network: &NetworkEntry,
    alternatives: &mut Vec<ConnectCandidate>,
) {
    let Some(profile) = network.primary_profile.as_ref() else {
        return;
    };
    let details = match nm.wifi_profile_details_by_path(&profile.path) {
        Ok(details) => details,
        Err(error) => {
            tracing::warn!(
                profile_path = %profile.path,
                error = %crate::error::err_chain(&error),
                "could not inspect saved Wi-Fi profile restrictions; disabling AP fallback"
            );
            alternatives.clear();
            return;
        }
    };
    alternatives.retain(|candidate| candidate_matches_profile_restrictions(candidate, &details));
}

fn candidate_matches_profile_restrictions(
    candidate: &ConnectCandidate,
    profile: &WifiProfileDetails,
) -> bool {
    profile.bssid.as_deref().is_none_or(|bssid| {
        candidate
            .target
            .bssid
            .as_ref()
            .is_some_and(|candidate| candidate.as_str().eq_ignore_ascii_case(bssid))
    }) && (profile.band == WifiBand::Auto
        || candidate
            .band
            .as_deref()
            .and_then(WifiBand::from_frequency_label)
            == Some(profile.band))
        && profile
            .channel
            .is_none_or(|channel| candidate.channel == Some(channel))
}

fn scan_cancelled_error() -> anyhow::Error {
    DomainError::cancelled_operation(ErrorOperation::Scan, "Wi-Fi scan cancelled").into()
}

fn cancelled_connect(
    request: &ConnectRequest,
    emit: &mut impl FnMut(&ConnectEvent) -> Result<()>,
    message: &str,
) -> Result<ConnectOutcome> {
    let outcome = ConnectOutcome::Cancelled {
        message: message.to_string(),
    };
    emit(&ConnectEvent::Cancelled {
        phase: ConnectPhase::Cancelled,
        target: ConnectTargetIdentity::from_target(&request.target, request.network_key.as_deref()),
        message: message.to_string(),
    })?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ScanRequest, recovery_message, retry_message, retryable_candidate_failure};
    use crate::model::{ConnectAttemptSummary, ConnectCandidateInfo, ConnectFailureReason};

    #[test]
    fn selection_orders_alternatives_without_relaxing_explicit_targets() {
        use crate::model::AccessPoint;
        let primary = AccessPoint {
            path: "/ap/1".into(),
            bssid: "AA".into(),
            band: "5 GHz".into(),
            ..Default::default()
        };
        let ap = |path: &str, bssid: &str, band: &str, strength| AccessPoint {
            path: path.into(),
            bssid: bssid.into(),
            band: band.into(),
            strength,
            ..Default::default()
        };
        let points = [
            ap("/ap/1", "aa", "5 GHz", 100),
            ap("/ap/2", "BB", "5 GHz", 99),
            ap("/ap/3", "DD", "2.4 GHz", 80),
            ap("/ap/4", "CC", "2.4 GHz", 80),
            ap("/ap/5", "EE", "2.4 GHz", 60),
        ];
        let ordered = super::ranked_alternatives(&primary, &points);
        assert_eq!(
            ordered
                .iter()
                .map(|ap| ap.bssid.as_str())
                .collect::<Vec<_>>(),
            ["CC", "DD", "EE", "BB"]
        );
        let (_, candidate, alternatives) =
            super::resolve_connect_candidates(None, "ssid-hex:4578616d706c65", None).unwrap();
        assert!(candidate.is_none() && alternatives.is_empty());
        assert!(super::resolve_connect_candidates(None, "missing|group", None).is_err());
    }

    #[test]
    fn candidate_restrictions_require_known_matching_radio_properties() {
        use crate::model::{WifiBand, WifiProfileDetails, example_connect_target};
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../test_support/contract-v1.json")).unwrap();
        let mut profile: WifiProfileDetails =
            serde_json::from_value(fixture["profile_details"]["result"].clone()).unwrap();
        let mut candidate = super::ConnectCandidate::from_target(example_connect_target(false));
        profile.bssid = None;
        profile.band = WifiBand::Auto;
        profile.channel = None;
        assert!(super::candidate_matches_profile_restrictions(
            &candidate, &profile
        ));
        profile.band = WifiBand::Ghz5;
        assert!(!super::candidate_matches_profile_restrictions(
            &candidate, &profile
        ));
        candidate.band = Some("5 GHz".into());
        profile.channel = Some(36);
        assert!(!super::candidate_matches_profile_restrictions(
            &candidate, &profile
        ));
        candidate.channel = Some(36);
        candidate.target.bssid = Some("AA:BB:CC:DD:EE:FF".parse().unwrap());
        for (bssid, expected) in [("aa:bb:cc:dd:ee:ff", true), ("AA:BB:CC:DD:EE:00", false)] {
            profile.bssid = Some(bssid.into());
            assert_eq!(
                super::candidate_matches_profile_restrictions(&candidate, &profile),
                expected
            );
        }
    }

    #[test]
    fn dhcp_failure_can_fall_back_from_5_ghz_to_2_4_ghz() {
        let primary = ConnectCandidateInfo {
            attempt: 1,
            total: 2,
            bssid: Some("BA:9C:0F:DC:49:EE".to_string()),
            band: Some("5 GHz".to_string()),
            channel: Some(161),
            strength: Some(80),
        };
        let fallback = ConnectCandidateInfo {
            attempt: 2,
            total: 2,
            bssid: Some("BA:63:F0:DC:49:EE".to_string()),
            band: Some("2.4 GHz".to_string()),
            channel: Some(11),
            strength: Some(70),
        };

        assert!(retryable_candidate_failure(
            ConnectFailureReason::DhcpFailed
        ));
        assert_eq!(
            retry_message(&primary, &fallback, ConnectFailureReason::DhcpFailed),
            "5 GHz access point connected but did not receive an IP address; trying 2.4 GHz"
        );
        let attempts = vec![
            ConnectAttemptSummary {
                attempt: 1,
                status: "failed",
                reason: Some(ConnectFailureReason::DhcpFailed),
                bssid: primary.bssid,
                band: primary.band,
                channel: primary.channel,
                duration_ms: 90_000,
                message: "IP configuration failed".to_string(),
            },
            ConnectAttemptSummary {
                attempt: 2,
                status: "connected",
                reason: None,
                bssid: fallback.bssid,
                band: fallback.band,
                channel: fallback.channel,
                duration_ms: 3_000,
                message: "connected".to_string(),
            },
        ];
        assert_eq!(
            recovery_message("PixelSpot", &attempts),
            "Connected to PixelSpot on 2.4 GHz after 5 GHz failed"
        );
    }

    #[test]
    fn credential_authorization_validation_and_cancellation_failures_are_terminal() {
        for reason in [
            ConnectFailureReason::SecretRequired,
            ConnectFailureReason::WrongPassword,
            ConnectFailureReason::PasswordUnavailable,
            ConnectFailureReason::AuthorizationRequired,
            ConnectFailureReason::UnsupportedAuth,
            ConnectFailureReason::ValidationError,
        ] {
            assert!(!retryable_candidate_failure(reason), "{reason:?}");
        }
    }

    #[test]
    fn scan_snapshot_borrows_the_returned_points_and_precedes_completion() -> anyhow::Result<()> {
        use crate::test_support::workflows::{FakeNm, isolated};
        isolated(
            concat!(
                module_path!(),
                "::scan_snapshot_borrows_the_returned_points_and_precedes_completion"
            ),
            || {
                let fake = FakeNm::new([], false)?;
                let mut pointer = None;
                let mut events = Vec::new();
                let points =
                    super::Application::new(&fake.nm).finish_scan(false, &mut |event| {
                        match event {
                            super::ScanEvent::Snapshot {
                                access_points,
                                networks_found,
                            } => {
                                pointer = Some(access_points.as_ptr());
                                assert_eq!(*networks_found, access_points.len());
                                events.push("snapshot");
                            }
                            super::ScanEvent::Complete { .. } => events.push("complete"),
                            _ => panic!("unexpected scan event"),
                        }
                        Ok(())
                    })?;
                assert_eq!(points.len(), 2);
                assert_eq!(pointer, Some(points.as_ptr()));
                assert_eq!(events, ["snapshot", "complete"]);
                Ok(())
            },
        )
    }

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

        let excessive = ScanRequest {
            timeout: Duration::from_secs(u64::MAX),
            strict: false,
            cache: false,
            ifname: None,
            ssids: Vec::new(),
        };
        let error = excessive.prepare().unwrap_err();
        let report =
            crate::error::ErrorReport::from_error(&error, crate::error::ErrorOperation::Unknown);
        assert_eq!(report.code, crate::error::ErrorCode::ValidationError);
    }
}
