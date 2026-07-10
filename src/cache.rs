use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{
    AccessPoint, ConnectEnginePath, ConnectFailureReason, ConnectionDetails, NetworkEntry,
    WifiConnectTarget, WifiStatus,
};

const CACHE_VERSION: u32 = 1;
const CACHE_DIR_NAME: &str = "nm-daemon";

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
            ssid: &target.ssid,
            ssid_bytes: target.ssid_bytes().into_owned(),
            bssid: non_empty(target.bssid.as_deref()),
            ap_path: non_empty(target.ap_path.as_deref()),
            device_iface: non_empty(target.ifname.as_deref()),
            device_path: non_empty(target.device_path.as_deref()),
            message,
        }
    }
}

pub(crate) fn write_live_scan_snapshot(scanning: bool, networks: &[AccessPoint]) -> Result<()> {
    if !scanning {
        write_snapshot(false, networks)?;
    }
    write_session_snapshot(scanning, networks)
}

pub(crate) fn write_snapshot(scanning: bool, networks: &[AccessPoint]) -> Result<()> {
    write_snapshot_to(snapshot_path(), scanning, networks)
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

pub(crate) fn read_snapshot() -> Result<Option<CachedSnapshot>> {
    let Some(snapshot) = read_json::<CachedSnapshot>(snapshot_path())? else {
        return Ok(None);
    };
    if snapshot.version != CACHE_VERSION {
        warn_cache_ignored(format!(
            "cache version {} is stale; expected {CACHE_VERSION}",
            snapshot.version
        ));
        return Ok(None);
    }
    Ok(Some(snapshot))
}

pub(crate) fn write_active_status(status: &WifiStatus) -> Result<()> {
    write_json(
        active_status_path(),
        &CachedActiveStatus {
            version: CACHE_VERSION,
            updated_at_ms: now_ms(),
            active: status.active,
            status,
        },
    )
}

pub(crate) fn cache_connected_network_status(status: &WifiStatus) -> Result<()> {
    write_active_status(status)?;
    match &status.access_point {
        Some(access_point) if status.active => {
            remember_connection_details(access_point, status)?;
            upsert_snapshot_access_point(access_point)
        }
        _ => mark_snapshot_inactive(),
    }
}

pub(crate) fn attach_connection_details(networks: &mut [NetworkEntry]) {
    let Ok(Some(known)) = read_known_connections() else {
        return;
    };
    for network in networks {
        network.last_connection = known
            .connections
            .get(&network_key(&network.access_point))
            .cloned();
    }
}

pub(crate) fn clear_active_connection_cache() -> Result<()> {
    remove_file_if_exists(active_status_path())?;
    mark_snapshot_inactive()
}

pub(crate) fn append_connect_attempt(record: &ConnectAttemptRecord<'_>) -> Result<()> {
    append_json_line(connect_history_path(), record)
}

fn write_session_snapshot(scanning: bool, networks: &[AccessPoint]) -> Result<()> {
    write_snapshot_to(session_path(), scanning, networks)
}

fn write_snapshot_to(path: PathBuf, scanning: bool, networks: &[AccessPoint]) -> Result<()> {
    write_json(path, &snapshot_record(scanning, networks))
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

fn remember_connection_details(access_point: &AccessPoint, status: &WifiStatus) -> Result<()> {
    let mut known = read_known_connections()?.unwrap_or_else(empty_known_connections);
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
    write_known_connections(&known)
}

fn read_known_connections() -> Result<Option<CachedKnownConnections>> {
    let Some(known) = read_json::<CachedKnownConnections>(known_connections_path())? else {
        return Ok(None);
    };
    if known.version != CACHE_VERSION {
        warn_cache_ignored(format!(
            "known connections cache version {} is stale; expected {CACHE_VERSION}",
            known.version
        ));
        return Ok(None);
    }
    Ok(Some(known))
}

fn empty_known_connections() -> CachedKnownConnections {
    CachedKnownConnections {
        version: CACHE_VERSION,
        updated_at_ms: now_ms(),
        connections: BTreeMap::new(),
    }
}

fn write_known_connections(known: &CachedKnownConnections) -> Result<()> {
    write_json(known_connections_path(), known)
}

fn network_key(access_point: &AccessPoint) -> String {
    format!(
        "{}|{}",
        bytes_hex(access_point.ssid_bytes().as_ref()),
        access_point.security
    )
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn upsert_snapshot_access_point(access_point: &AccessPoint) -> Result<()> {
    let mut networks = read_snapshot()?
        .map(CachedSnapshot::into_networks)
        .unwrap_or_default();
    upsert_connected_access_point(&mut networks, access_point.clone());
    write_snapshot(false, &networks)
}

fn upsert_connected_access_point(networks: &mut Vec<AccessPoint>, mut access_point: AccessPoint) {
    networks
        .iter_mut()
        .for_each(|network| network.active = false);
    access_point.active = true;

    if let Some(existing) = networks
        .iter_mut()
        .find(|network| same_access_point(network, &access_point))
    {
        *existing = access_point;
    } else {
        networks.insert(0, access_point);
    }
}

fn same_access_point(left: &AccessPoint, right: &AccessPoint) -> bool {
    if !left.path.is_empty() && !right.path.is_empty() {
        return left.path == right.path;
    }
    if !left.bssid.is_empty() && !right.bssid.is_empty() {
        return left.bssid.eq_ignore_ascii_case(&right.bssid);
    }
    left.ssid_bytes().as_ref() == right.ssid_bytes().as_ref() && left.security == right.security
}

fn mark_snapshot_inactive() -> Result<()> {
    let Some(snapshot) = read_snapshot()? else {
        return Ok(());
    };
    let mut networks = snapshot.into_networks();
    networks
        .iter_mut()
        .for_each(|network| network.active = false);
    write_snapshot(false, &networks)
}

fn write_status_record(status: CachedStatus) -> Result<()> {
    write_json(status_path(), &status)
}

fn read_json<T>(path: PathBuf) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    if !path.exists() {
        return Ok(None);
    }
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            warn_cache_ignored(format!("could not read {}: {err}", path.display()));
            return Ok(None);
        }
    };
    match serde_json::from_str(&text) {
        Ok(value) => Ok(Some(value)),
        Err(err) => {
            warn_cache_ignored(format!("could not parse {}: {err}", path.display()));
            Ok(None)
        }
    }
}

fn write_json<T>(path: PathBuf, value: &T) -> Result<()>
where
    T: Serialize,
{
    let parent = path.parent().context("cache path has no parent")?;
    create_private_dir_all(parent)?;
    let tmp_path = temp_path_for(&path)?;
    let text = serde_json::to_string_pretty(value).context("serialize cache JSON")?;
    write_private_file(&tmp_path, format!("{text}\n").as_bytes())
        .with_context(|| format!("write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, &path)
        .with_context(|| format!("rename {} to {}", tmp_path.display(), path.display()))
}

fn temp_path_for(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().context("cache path has no parent")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("cache path has no file name")?;
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        counter
    )))
}

pub(crate) fn create_private_dir_all(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        create_private_dir_all_unix(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))
    }
}

fn append_json_line<T>(path: PathBuf, value: &T) -> Result<()>
where
    T: Serialize,
{
    let parent = path.parent().context("state path has no parent")?;
    create_private_dir_all(parent)?;
    reject_symlink(&path)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    serde_json::to_writer(&mut file, value).context("serialize JSONL record")?;
    file.write_all(b"\n")
        .with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    Ok(())
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_dir_all_unix(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    match fs::symlink_metadata(path) {
        Ok(link_metadata) => {
            if link_metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing to use symlinked cache directory {}",
                    path.display()
                );
            }
            let metadata =
                fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
            if !metadata.is_dir() {
                anyhow::bail!("{} exists but is not a directory", path.display());
            }
            let current_uid = current_euid();
            if metadata.uid() != current_uid {
                anyhow::bail!(
                    "refusing to use {} owned by uid {}; expected uid {}",
                    path.display(),
                    metadata.uid(),
                    current_uid
                );
            }
            if metadata.mode() & 0o077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("chmod 0700 {}", path.display()))?;
            }
            return Ok(());
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("lstat {}", path.display())),
    }

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))
}

#[cfg(unix)]
fn current_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn reject_symlink(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("lstat {}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symlinked file {}", path.display());
    }
    Ok(())
}

fn remove_file_if_exists(path: PathBuf) -> Result<()> {
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

fn warn_cache_ignored(message: String) {
    tracing::warn!(message = %message, "ignoring Wi-Fi cache");
    eprintln!("warning: ignoring Wi-Fi cache: {message}");
}

fn snapshot_path() -> PathBuf {
    cache_dir().join("latest.json")
}

fn status_path() -> PathBuf {
    cache_dir().join("status.json")
}

fn active_status_path() -> PathBuf {
    cache_dir().join("active-status.json")
}

fn known_connections_path() -> PathBuf {
    cache_dir().join("known-connections.json")
}

fn connect_history_path() -> PathBuf {
    state_dir().join("connects.jsonl")
}

fn session_path() -> PathBuf {
    cache_dir().join("scan-session.json")
}

pub(crate) fn log_path() -> PathBuf {
    cache_dir().join("nm-daemon.log")
}

fn cache_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(runtime_dir) => PathBuf::from(runtime_dir).join(CACHE_DIR_NAME),
        None => std::env::temp_dir().join(format!("{CACHE_DIR_NAME}-{}", current_user_id())),
    }
}

fn state_dir() -> PathBuf {
    if let Some(state_home) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(state_home).join(CACHE_DIR_NAME);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join(CACHE_DIR_NAME);
    }
    cache_dir()
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

fn current_user_id() -> u32 {
    #[cfg(unix)]
    {
        current_euid()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

pub(crate) fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{same_access_point, temp_path_for, upsert_connected_access_point};
    use crate::model::AccessPoint;

    #[test]
    fn temp_paths_are_unique_for_same_cache_path() {
        let path = PathBuf::from("/tmp/nm-daemon/status.json");

        let first = temp_path_for(&path).expect("first temp path");
        let second = temp_path_for(&path).expect("second temp path");

        assert_ne!(first, second);
        assert_eq!(first.parent(), path.parent());
        assert_eq!(second.parent(), path.parent());
    }

    #[test]
    fn connected_access_point_replaces_cached_network_and_marks_only_it_active() {
        let mut networks = vec![test_ap("/ap/1", "00:11:22:33:44:55", false)];
        let connected = test_ap("/ap/1", "00:11:22:33:44:55", false);

        upsert_connected_access_point(&mut networks, connected);

        assert_eq!(networks.len(), 1);
        assert!(networks[0].active);
    }

    #[test]
    fn connected_access_point_can_be_matched_by_bssid_without_path() {
        let left = test_ap("", "00:11:22:33:44:55", false);
        let right = test_ap("", "00:11:22:33:44:55", true);

        assert!(same_access_point(&left, &right));
    }

    fn test_ap(path: &str, bssid: &str, active: bool) -> AccessPoint {
        AccessPoint {
            ssid: "Example".to_string(),
            ssid_bytes: b"Example".to_vec(),
            active,
            security: "WPA2/3".to_string(),
            strength: 80,
            frequency: 2412,
            channel: 1,
            band: "2.4 GHz".to_string(),
            mode: "Infra".to_string(),
            max_bitrate_mbps: 0,
            bandwidth_mhz: 0,
            ssid_hex: "4578616d706c65".to_string(),
            wpa_flags_label: "(none)".to_string(),
            rsn_flags_label: "(none)".to_string(),
            bssid: bssid.to_string(),
            last_seen: 0,
            last_seen_age_ms: None,
            path: path.to_string(),
            device_path: "/device/1".to_string(),
            device_iface: "wlan0".to_string(),
            flags: 0,
            wpa_flags: 0,
            rsn_flags: 0,
        }
    }
}
