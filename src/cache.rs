mod merge;
mod storage;

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::model::{
    AccessPoint, ConnectEnginePath, ConnectFailureReason, ConnectionDetails, NetworkEntry,
    WifiConnectTarget, WifiStatus,
};

use self::merge::{mark_inactive, network_key, upsert_connected_access_point};
use self::storage::{LockedRepository, Repository};

pub(crate) use self::storage::{create_private_dir_all, log_path, reject_symlink_file};

const CACHE_VERSION: u32 = 2;
const SNAPSHOT_FILE: &str = "latest.json";
const SESSION_FILE: &str = "scan-session.json";
const STATUS_FILE: &str = "status.json";
const ACTIVE_STATUS_FILE: &str = "active-status.json";
const KNOWN_CONNECTIONS_FILE: &str = "known-connections.json";
const CONNECT_HISTORY_FILE: &str = "connects.jsonl";

#[derive(Debug, Clone)]
pub(crate) enum CacheRead<T> {
    Missing,
    Stale {
        found_version: u32,
        expected_version: u32,
    },
    Corrupt {
        message: String,
    },
    Available(T),
}

impl<T> CacheRead<T> {
    pub(crate) fn unavailable_message(&self, subject: &str) -> Option<String> {
        match self {
            Self::Missing => Some(format!("{subject} is missing")),
            Self::Stale {
                found_version,
                expected_version,
            } => Some(format!(
                "{subject} uses schema version {found_version}; expected {expected_version}"
            )),
            Self::Corrupt { message } => Some(format!("{subject} is corrupt: {message}")),
            Self::Available(_) => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct CachedSnapshot {
    version: u32,
    updated_at_ms: u128,
    scanning: bool,
    networks_found: usize,
    networks: Vec<AccessPoint>,
}

impl CachedSnapshot {
    pub(crate) fn into_networks(self) -> Vec<AccessPoint> {
        self.networks
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CachedStatus {
    version: u32,
    updated_at_ms: u128,
    state: String,
    message: String,
    timed_out: Option<bool>,
    networks_found: Option<usize>,
}

#[derive(Serialize)]
struct CachedActiveStatus<'a> {
    version: u32,
    updated_at_ms: u128,
    active: bool,
    status: &'a WifiStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CachedKnownConnections {
    version: u32,
    updated_at_ms: u128,
    connections: BTreeMap<String, ConnectionDetails>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectAttemptRecord<'a> {
    version: u32,
    timestamp_ms: u128,
    duration_ms: u128,
    status: &'a str,
    reason: Option<ConnectFailureReason>,
    path: Option<ConnectEnginePath>,
    ssid: &'a str,
    ssid_bytes: Vec<u8>,
    bssid: Option<&'a str>,
    ap_path: Option<&'a str>,
    device_iface: Option<&'a str>,
    device_path: Option<&'a str>,
    message: &'a str,
}

impl<'a> ConnectAttemptRecord<'a> {
    pub(crate) fn new(
        target: &'a WifiConnectTarget,
        status: &'a str,
        reason: Option<ConnectFailureReason>,
        path: Option<ConnectEnginePath>,
        message: &'a str,
        duration_ms: u128,
    ) -> Self {
        Self {
            version: CACHE_VERSION,
            timestamp_ms: now_ms(),
            duration_ms,
            status,
            reason,
            path,
            ssid: target.ssid.as_str(),
            ssid_bytes: target.ssid_bytes().to_vec(),
            bssid: non_empty(target.bssid.as_deref()),
            ap_path: non_empty(target.ap_path.as_deref()),
            device_iface: non_empty(target.ifname.as_deref()),
            device_path: non_empty(target.device_path.as_deref()),
            message,
        }
    }
}

pub(crate) fn write_live_scan_snapshot(scanning: bool, networks: &[AccessPoint]) -> Result<()> {
    Repository::runtime().write_transaction(|repository| {
        if !scanning {
            repository.write_json(SNAPSHOT_FILE, &snapshot_record(false, networks))?;
        }
        repository.write_json(SESSION_FILE, &snapshot_record(scanning, networks))
    })
}

pub(crate) fn write_snapshot(scanning: bool, networks: &[AccessPoint]) -> Result<()> {
    Repository::runtime().write_json(SNAPSHOT_FILE, &snapshot_record(scanning, networks))
}

pub(crate) fn write_status(state: impl Into<String>, message: impl Into<String>) -> Result<()> {
    write_status_record(CachedStatus {
        version: CACHE_VERSION,
        updated_at_ms: now_ms(),
        state: state.into(),
        message: message.into(),
        timed_out: None,
        networks_found: None,
    })
}

pub(crate) fn write_complete(timed_out: bool, networks_found: usize) -> Result<()> {
    let message = if timed_out {
        format!("scan timed out; {networks_found} networks available")
    } else {
        format!("scan complete; {networks_found} networks available")
    };
    write_status_record(CachedStatus {
        version: CACHE_VERSION,
        updated_at_ms: now_ms(),
        state: "complete".to_string(),
        message,
        timed_out: Some(timed_out),
        networks_found: Some(networks_found),
    })
}

pub(crate) fn read_snapshot() -> Result<CacheRead<CachedSnapshot>> {
    Ok(validate_version(
        Repository::runtime().read_json(SNAPSHOT_FILE)?,
        |snapshot| snapshot.version,
    ))
}

pub(crate) fn cache_connected_network_status(status: &WifiStatus) -> Result<()> {
    Repository::runtime().write_transaction(|repository| {
        let snapshot = read_snapshot_locked(repository)?;
        let known = if status.active && status.access_point.is_some() {
            Some(read_known_for_update(repository)?)
        } else {
            None
        };

        repository.write_json(ACTIVE_STATUS_FILE, &active_status_record(status))?;
        match (&status.access_point, known) {
            (Some(access_point), Some(mut known)) => {
                known.updated_at_ms = now_ms();
                known.connections.insert(
                    network_key(access_point),
                    ConnectionDetails {
                        ip4: status.ip4.clone(),
                        wireless: status.wireless.clone(),
                        metered: status.metered.clone(),
                        active_since_ms: status.active_since_ms,
                        updated_at_ms: known.updated_at_ms,
                    },
                );
                repository.write_json(KNOWN_CONNECTIONS_FILE, &known)?;
                update_snapshot(repository, snapshot, |networks| {
                    upsert_connected_access_point(networks, access_point.clone());
                })
            }
            _ => update_snapshot(repository, snapshot, |networks| mark_inactive(networks)),
        }
    })
}

pub(crate) fn attach_connection_details(networks: &mut [NetworkEntry]) -> Result<CacheRead<usize>> {
    match read_known_connections()? {
        CacheRead::Available(known) => Ok(CacheRead::Available(merge::attach_connection_details(
            networks,
            &known.connections,
        ))),
        CacheRead::Missing => Ok(CacheRead::Missing),
        CacheRead::Stale {
            found_version,
            expected_version,
        } => Ok(CacheRead::Stale {
            found_version,
            expected_version,
        }),
        CacheRead::Corrupt { message } => Ok(CacheRead::Corrupt { message }),
    }
}

pub(crate) fn clear_active_connection_cache() -> Result<()> {
    Repository::runtime().write_transaction(|repository| {
        let snapshot = read_snapshot_locked(repository)?;
        repository.remove_if_exists(ACTIVE_STATUS_FILE)?;
        update_snapshot(repository, snapshot, |networks| mark_inactive(networks))
    })
}

pub(crate) fn append_connect_attempt(record: &ConnectAttemptRecord<'_>) -> Result<()> {
    Repository::state()
        .write_transaction(|repository| repository.append_history(CONNECT_HISTORY_FILE, record))
}

fn snapshot_record(scanning: bool, networks: &[AccessPoint]) -> CachedSnapshot {
    CachedSnapshot {
        version: CACHE_VERSION,
        updated_at_ms: now_ms(),
        scanning,
        networks_found: networks.len(),
        networks: networks.to_vec(),
    }
}

fn active_status_record(status: &WifiStatus) -> CachedActiveStatus<'_> {
    CachedActiveStatus {
        version: CACHE_VERSION,
        updated_at_ms: now_ms(),
        active: status.active,
        status,
    }
}

fn write_status_record(status: CachedStatus) -> Result<()> {
    Repository::runtime().write_json(STATUS_FILE, &status)
}

fn read_snapshot_locked(repository: &LockedRepository<'_>) -> Result<CacheRead<CachedSnapshot>> {
    Ok(validate_version(
        repository.read_json(SNAPSHOT_FILE)?,
        |snapshot| snapshot.version,
    ))
}

fn read_known_connections() -> Result<CacheRead<CachedKnownConnections>> {
    Ok(validate_version(
        Repository::runtime().read_json(KNOWN_CONNECTIONS_FILE)?,
        |known| known.version,
    ))
}

fn read_known_for_update(repository: &LockedRepository<'_>) -> Result<CachedKnownConnections> {
    match validate_version(
        repository.read_json::<CachedKnownConnections>(KNOWN_CONNECTIONS_FILE)?,
        |known| known.version,
    ) {
        CacheRead::Available(known) => Ok(known),
        CacheRead::Missing => Ok(empty_known_connections()),
        state @ CacheRead::Stale { .. } => {
            tracing::warn!(
                message = %state.unavailable_message("known-connections cache").unwrap_or_default(),
                "replacing stale known-connections cache"
            );
            Ok(empty_known_connections())
        }
        CacheRead::Corrupt { message } => {
            bail!("refusing to overwrite corrupt known-connections cache: {message}")
        }
    }
}

fn empty_known_connections() -> CachedKnownConnections {
    CachedKnownConnections {
        version: CACHE_VERSION,
        updated_at_ms: now_ms(),
        connections: BTreeMap::new(),
    }
}

fn update_snapshot(
    repository: &LockedRepository<'_>,
    snapshot: CacheRead<CachedSnapshot>,
    update: impl FnOnce(&mut Vec<AccessPoint>),
) -> Result<()> {
    match snapshot {
        CacheRead::Available(snapshot) => {
            let mut networks = snapshot.into_networks();
            update(&mut networks);
            repository.write_json(SNAPSHOT_FILE, &snapshot_record(false, &networks))
        }
        CacheRead::Missing => {
            tracing::debug!("not creating Wi-Fi scan cache from status-only update");
            Ok(())
        }
        state @ (CacheRead::Stale { .. } | CacheRead::Corrupt { .. }) => {
            tracing::warn!(
                message = %state.unavailable_message("Wi-Fi scan cache").unwrap_or_default(),
                "not updating unusable Wi-Fi scan cache"
            );
            Ok(())
        }
    }
}

fn validate_version<T>(state: CacheRead<T>, version: impl FnOnce(&T) -> u32) -> CacheRead<T> {
    match state {
        CacheRead::Available(value) => {
            let found_version = version(&value);
            if found_version == CACHE_VERSION {
                CacheRead::Available(value)
            } else {
                CacheRead::Stale {
                    found_version,
                    expected_version: CACHE_VERSION,
                }
            }
        }
        other => other,
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

pub(crate) fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{CACHE_VERSION, CacheRead, validate_version};

    #[test]
    fn version_mismatch_is_stale_instead_of_missing() {
        let state = validate_version(CacheRead::Available(CACHE_VERSION - 1), |version| *version);
        assert!(matches!(
            state,
            CacheRead::Stale {
                found_version,
                expected_version: CACHE_VERSION,
            } if found_version == CACHE_VERSION - 1
        ));
    }
}
