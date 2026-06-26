use anyhow::Result;
use clap::Parser;

use crate::actions;
use crate::cli::{Cli, Command};
use crate::list::{print_enriched_network_list, print_network_list};
use crate::logging;
use crate::nm::Nm;

pub fn run() -> Result<()> {
    let Cli {
        verbose,
        log_file,
        command,
    } = Cli::parse();
    let log_path = logging::init(verbose, log_file.clone())?;
    tracing::debug!(path = %log_path.display(), "using log file");

    match command {
        Command::List {
            json,
            cached,
            refresh_cache,
            refresh_timeout,
        } => print_network_list(
            json,
            cached,
            refresh_cache,
            refresh_timeout,
            verbose,
            &log_file,
        )?,
        Command::Networks {
            json,
            cached,
            refresh_cache,
            refresh_timeout,
        } => with_nm(|nm| {
            print_enriched_network_list(
                nm,
                json,
                cached,
                refresh_cache,
                refresh_timeout,
                verbose,
                &log_file,
            )
        })?,
        Command::Scan {
            timeout,
            stream,
            strict,
            retries,
            cache,
            ifname,
            ssids,
        } => with_nm(|nm| {
            actions::run_scan(
                nm,
                actions::ScanCommandOptions {
                    timeout,
                    stream,
                    strict,
                    retries,
                    cache,
                    ifname,
                    ssids,
                },
            )
        })?,
        Command::Connect {
            ssid,
            password,
            password_stdin,
            bssid,
            hidden,
            wep_key_type,
            json,
        } => with_nm(|nm| {
            actions::connect_ssid(
                nm,
                actions::ConnectSsidOptions {
                    ssid,
                    password,
                    password_stdin,
                    bssid,
                    hidden,
                    wep_key_type,
                    json,
                },
            )
        })?,
        Command::ConnectTarget {
            target_json,
            password,
            password_stdin,
            wep_key_type,
            json,
        } => with_nm(|nm| {
            actions::connect_target(
                nm,
                target_json,
                password,
                password_stdin,
                wep_key_type,
                json,
            )
        })?,
        Command::Saved { json } => with_nm(|nm| actions::print_saved_profiles(nm, json))?,
        Command::Profile { command } => with_nm(|nm| actions::run_profile_command(nm, command))?,
        Command::Status { json } => with_nm(|nm| actions::print_status(nm, json))?,
        Command::Disconnect { json } => with_nm(|nm| actions::disconnect(nm, json))?,
        Command::Connectivity { json } => {
            with_nm(|nm| actions::print_connectivity_state(nm, json))?
        }
        Command::Active => with_nm(actions::print_active_ssid)?,
        Command::ContractFixture => crate::contract::print_shelllist_contract_fixture()?,
    }

    Ok(())
}

fn with_nm<T>(f: impl FnOnce(&Nm) -> Result<T>) -> Result<T> {
    let nm = Nm::new()?;
    f(&nm)
}
