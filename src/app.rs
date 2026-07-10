use anyhow::Result;
use clap::Parser;

use crate::actions;
use crate::cli::{Cli, Command, DebugCommand, NetworkCommand, WifiCommand};
use crate::list::print_enriched_network_list;
use crate::logging;
use crate::nm::Nm;

pub fn run() -> Result<()> {
    let Cli {
        verbose,
        log_file,
        direct,
        command,
    } = Cli::parse();
    let log_path = logging::init(verbose, log_file.clone())?;
    tracing::debug!(path = %log_path.display(), "using log file");

    if !direct && std::env::var_os("NM_DAEMON_DIRECT").is_none() {
        match crate::daemon::try_forward_command(&command)? {
            crate::daemon::ForwardOutcome::Handled => return Ok(()),
            crate::daemon::ForwardOutcome::NotForwardable
            | crate::daemon::ForwardOutcome::Unavailable => {}
        }
    }

    match command {
        Command::Daemon => crate::daemon::run_daemon()?,
        Command::Wifi { command } => run_wifi_command(command, verbose, &log_file)?,
        Command::Network { command } => run_network_command(command)?,
        Command::Debug { command } => run_debug_command(command)?,
    }

    Ok(())
}

fn run_wifi_command(
    command: WifiCommand,
    verbose: u8,
    log_file: &Option<std::path::PathBuf>,
) -> Result<()> {
    match command {
        WifiCommand::Networks(options) => with_nm(|nm| {
            print_enriched_network_list(
                nm,
                options.cached,
                options.refresh_cache,
                options.refresh_timeout,
                verbose,
                log_file,
            )
        })?,
        WifiCommand::Scan(options) => with_nm(|nm| actions::run_scan(nm, options))?,
        WifiCommand::Connect(options) => with_nm(|nm| actions::connect_ssid(nm, options))?,
        WifiCommand::ConnectTarget(options) => with_nm(|nm| actions::connect_target(nm, options))?,
        WifiCommand::Saved => with_nm(actions::print_saved_profiles)?,
        WifiCommand::Profile { command } => {
            with_nm(|nm| actions::run_profile_command(nm, command))?
        }
        WifiCommand::Status => with_nm(actions::print_status)?,
        WifiCommand::Disconnect => with_nm(actions::disconnect)?,
    }
    Ok(())
}

fn run_network_command(command: NetworkCommand) -> Result<()> {
    match command {
        NetworkCommand::Connectivity => with_nm(actions::print_connectivity_state)?,
    }
    Ok(())
}

fn run_debug_command(command: DebugCommand) -> Result<()> {
    match command {
        DebugCommand::Diagnose { json } => {
            with_nm(|nm| crate::diagnose::print_diagnosis(nm, json))?
        }
        DebugCommand::ContractFixture => crate::contract::print_shelllist_contract_fixture()?,
        DebugCommand::ContractFixtures => crate::contract::print_method_contract_fixtures()?,
    }
    Ok(())
}

pub fn report_error(err: &anyhow::Error) {
    if crate::output::is_reported_error(err) {
        return;
    }

    let message = format!("{err:#}");
    let code = crate::error::classify_error(&message);
    if let Err(report_err) = crate::output::print_api_error(code, &message) {
        eprintln!("Error: {err:#}");
        eprintln!("Also failed to serialize API error response: {report_err:#}");
    }
}

fn with_nm<T>(f: impl FnOnce(&Nm) -> Result<T>) -> Result<T> {
    let nm = Nm::new()?;
    f(&nm)
}
