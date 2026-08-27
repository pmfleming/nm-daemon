use anyhow::{Context, Result};
use clap::Parser;

use crate::actions;
use crate::cli::{
    Cli, Command, DebugCommand, HotspotCommand, NetworkCommand, VpnCommand, WifiCommand,
};
use crate::logging;
use crate::nm::Nm;

pub async fn run() -> Result<()> {
    crate::error::operation_result(crate::error::ErrorOperation::Initialize, run_inner().await)
}

async fn run_inner() -> Result<()> {
    let Cli {
        verbose,
        log_file,
        direct,
        command,
    } = Cli::parse();
    let log_path = logging::init(verbose, log_file)?;
    tracing::debug!(path = %log_path.display(), "using log file");

    if matches!(command, Command::Client) {
        return crate::client::run().await;
    }

    run_blocking(move || {
        if try_forward(&command, direct)? {
            return Ok(());
        }
        run_command(command)
    })
    .await
}

async fn run_blocking<T>(task: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(task)
        .await
        .context("join blocking command task")?
}

fn try_forward(command: &Command, direct: bool) -> Result<bool> {
    if direct || std::env::var_os("NM_DAEMON_DIRECT").is_some() {
        return Ok(false);
    }
    match crate::daemon_forward::try_forward_command(command)? {
        crate::daemon_forward::ForwardOutcome::Handled => Ok(true),
        crate::daemon_forward::ForwardOutcome::DirectConnect(request) => {
            with_nm(|nm| actions::print_connect_attempt(nm, *request))?;
            Ok(true)
        }
        crate::daemon_forward::ForwardOutcome::NotForwardable
        | crate::daemon_forward::ForwardOutcome::Unavailable => Ok(false),
    }
}

fn run_command(command: Command) -> Result<()> {
    match command {
        Command::Daemon => crate::daemon::run_daemon(),
        Command::Client => unreachable!("client command is dispatched asynchronously"),
        Command::Wifi { command } => run_wifi_command(command),
        Command::Network { command } => run_network_command(command),
        Command::Hotspot { command } => run_hotspot_command(command),
        Command::Vpn { command } => run_vpn_command(command),
        Command::Debug { command } => run_debug_command(command),
    }
}

fn run_network_command(command: NetworkCommand) -> Result<()> {
    match command {
        NetworkCommand::Connectivity => with_nm(actions::print_connectivity_state),
        NetworkCommand::Status => with_nm(actions::print_network_state),
        NetworkCommand::Devices => with_nm(actions::print_network_devices),
        NetworkCommand::Connections => with_nm(actions::print_network_connections),
        NetworkCommand::Inventory => with_nm(actions::print_network_inventory),
        NetworkCommand::Activate(options) => {
            with_nm(|nm| actions::activate_network_profile(nm, &options))
        }
        NetworkCommand::Deactivate(options) => {
            with_nm(|nm| actions::deactivate_network_connection(nm, &options))
        }
    }
}

fn run_vpn_command(command: VpnCommand) -> Result<()> {
    match command {
        VpnCommand::List => with_nm(actions::print_vpn_profiles),
        VpnCommand::Status => with_nm(actions::print_vpn_status),
        VpnCommand::Connect(options) => with_nm(|nm| actions::connect_vpn(nm, &options)),
        VpnCommand::Disconnect(options) => with_nm(|nm| actions::disconnect_vpn(nm, &options)),
    }
}

fn run_hotspot_command(command: HotspotCommand) -> Result<()> {
    match command {
        HotspotCommand::Capabilities => with_nm(actions::print_hotspot_capabilities),
        HotspotCommand::Status => with_nm(actions::print_hotspot_status),
        HotspotCommand::Start(options) => with_nm(|nm| actions::start_hotspot(nm, &options)),
        HotspotCommand::Stop => with_nm(actions::stop_hotspot),
    }
}

fn run_wifi_command(command: WifiCommand) -> Result<()> {
    match command {
        WifiCommand::Networks(options) => with_nm(|nm| actions::print_networks(nm, options)),
        WifiCommand::Scan(options) => with_nm(|nm| actions::run_scan(nm, options)),
        WifiCommand::Connect(options) => with_nm(|nm| actions::connect_ssid(nm, options)),
        WifiCommand::ConnectTarget(options) => with_nm(|nm| actions::connect_target(nm, options)),
        WifiCommand::Saved => with_nm(actions::print_saved_profiles),
        WifiCommand::Profile { command } => with_nm(|nm| actions::run_profile_command(nm, command)),
        WifiCommand::Status => with_nm(actions::print_status),
        WifiCommand::Disconnect => with_nm(actions::disconnect),
    }
}

fn run_debug_command(command: DebugCommand) -> Result<()> {
    match command {
        DebugCommand::Diagnose { json } => with_nm(|nm| crate::diagnose::print_diagnosis(nm, json)),
        DebugCommand::ContractFixture => crate::contract::print_shelllist_contract_fixture(),
        DebugCommand::ContractFixtures => crate::contract::print_method_contract_fixtures(),
        DebugCommand::ProtocolRegistry => crate::output::print_api_data(
            "protocol",
            &crate::protocol::contract_registry(),
            "serialize protocol registry",
        ),
    }
}

pub fn report_error(err: &anyhow::Error) {
    if crate::output::is_reported_error(err) {
        return;
    }

    let report = crate::error::ErrorReport::from_error(err, crate::error::ErrorOperation::Unknown);
    if let Err(report_err) = crate::output::print_error_report(&report) {
        eprintln!("Error: {err:#}");
        eprintln!("Also failed to serialize API error response: {report_err:#}");
    }
}

fn with_nm<T>(f: impl FnOnce(&Nm) -> Result<T>) -> Result<T> {
    let nm = Nm::new()?;
    f(&nm)
}
