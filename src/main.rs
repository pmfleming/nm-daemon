use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Command};
use crate::model::{ScanStreamOptions, WifiConnectTarget};
use crate::nm::Nm;
use crate::output::{print_access_points, print_access_points_json};

mod cache;
mod cli;
mod connect;
mod model;
mod nm;
mod output;
mod rofi;
mod stream;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let nm = Nm::new()?;

    match cli.command {
        Command::List { json, cached } => print_network_list(&nm, json, cached)?,
        Command::Scan {
            timeout,
            stream,
            strict,
            retries,
            cache,
        } => run_scan(&nm, timeout, stream, strict, retries, cache)?,
        Command::Connect {
            ssid,
            password,
            bssid,
            hidden,
            wep_key_type,
        } => connect::connect_target_with_password(
            &nm,
            &WifiConnectTarget {
                ssid,
                ap_path: None,
                bssid,
                hidden,
            },
            password.as_deref(),
            wep_key_type,
        )?,
        Command::Rofi {
            timeout,
            retries,
            rofi_args: _,
        } => rofi::run(&nm, timeout, retries)?,
        Command::Active => print_active_ssid(&nm)?,
    }

    Ok(())
}

fn print_network_list(nm: &Nm, json: bool, cached: bool) -> Result<()> {
    let networks = if cached {
        cache::read_snapshot()?.map(|snapshot| snapshot.into_networks())
    } else {
        None
    };
    let networks = match networks {
        Some(networks) => networks,
        None => nm.list_access_points()?,
    };

    if json {
        print_access_points_json(&networks)
    } else {
        print_access_points(&networks);
        Ok(())
    }
}

fn run_scan(
    nm: &Nm,
    timeout: u64,
    stream: bool,
    strict: bool,
    retries: u32,
    cache: bool,
) -> Result<()> {
    let timeout = Duration::from_secs(timeout);
    if stream {
        return nm.scan_stream(ScanStreamOptions {
            timeout,
            retries,
            cache,
        });
    }

    if let Err(err) = nm.scan(timeout) {
        if strict {
            return Err(err);
        }
        eprintln!("warning: scan failed: {err:#}; showing cached NetworkManager results");
    }
    let networks = nm.list_access_points()?;
    if cache {
        cache::write_snapshot(false, &networks)?;
        cache::write_complete(false, networks.len())?;
    }
    print_access_points(&networks);
    Ok(())
}

fn print_active_ssid(nm: &Nm) -> Result<()> {
    if let Some(ssid) = nm.active_ssid()? {
        println!("{ssid}");
    }
    Ok(())
}
