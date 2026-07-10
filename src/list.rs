use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

use anyhow::Result;

use crate::nm::Nm;
use crate::output::print_network_entries_json;
use crate::{
    cache,
    model::{AccessPoint, NetworkEntry},
};

pub(crate) fn print_enriched_network_list(
    nm: &Nm,
    cached: bool,
    refresh_cache: bool,
    refresh_timeout: u64,
    verbose: u8,
    log_file: &Option<std::path::PathBuf>,
) -> Result<()> {
    let networks = enriched_network_list(
        nm,
        cached,
        refresh_cache,
        refresh_timeout,
        verbose,
        log_file,
    )?;
    print_network_entries_json(&networks)
}

pub(crate) fn enriched_network_list(
    nm: &Nm,
    cached: bool,
    refresh_cache: bool,
    refresh_timeout: u64,
    verbose: u8,
    log_file: &Option<std::path::PathBuf>,
) -> Result<Vec<NetworkEntry>> {
    let access_points = load_networks(
        nm,
        cached,
        refresh_cache,
        refresh_timeout,
        verbose,
        log_file,
        true,
    )?;
    let mut networks = nm.network_entries_for_access_points(access_points)?;
    cache::attach_connection_details(&mut networks);
    Ok(networks)
}

fn load_networks(
    nm: &Nm,
    cached: bool,
    refresh_cache: bool,
    refresh_timeout: u64,
    verbose: u8,
    log_file: &Option<std::path::PathBuf>,
    exact: bool,
) -> Result<Vec<AccessPoint>> {
    if cached {
        if let Some(snapshot) = cache::read_snapshot()? {
            let networks = snapshot.into_networks();
            if refresh_cache {
                spawn_cache_refresh(refresh_timeout, verbose, log_file.as_deref());
            }
            return Ok(networks);
        }

        if refresh_cache {
            return scan_and_cache(nm, Duration::from_secs(refresh_timeout));
        }
    }

    let networks = if exact {
        nm.list_all_access_points()?
    } else {
        nm.list_access_points()?
    };
    if refresh_cache {
        spawn_cache_refresh(refresh_timeout, verbose, log_file.as_deref());
    }
    Ok(networks)
}

fn scan_and_cache(nm: &Nm, timeout: Duration) -> Result<Vec<AccessPoint>> {
    if let Err(err) = nm.scan(timeout) {
        tracing::warn!(error = %format_args!("{err:#}"), "cache refresh scan failed before list");
        eprintln!("warning: scan failed: {err:#}; showing cached NetworkManager results");
    }
    let networks = nm.list_all_access_points()?;
    cache::write_snapshot(false, &networks)?;
    cache::write_complete(false, networks.len())?;
    Ok(networks)
}

fn spawn_cache_refresh(timeout: u64, verbose: u8, log_file: Option<&Path>) {
    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            tracing::warn!(error = %err, "could not find current executable for background cache refresh");
            return;
        }
    };

    let timeout_arg = timeout.to_string();
    let mut command = ProcessCommand::new(current_exe);
    for _ in 0..verbose {
        command.arg("-v");
    }
    if let Some(log_file) = log_file {
        command.arg("--log-file").arg(log_file);
    }

    match command
        .args(["wifi", "scan", "--cache", "--timeout", timeout_arg.as_str()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => tracing::info!(
            pid = child.id(),
            timeout,
            verbose,
            log_file = ?log_file,
            "spawned background Wi-Fi cache refresh"
        ),
        Err(err) => {
            tracing::warn!(error = %err, timeout, "failed to spawn background Wi-Fi cache refresh")
        }
    }
}
