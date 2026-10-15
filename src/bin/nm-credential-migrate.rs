//! Opt-in migration tooling, never part of daemon startup.
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Inventory legacy network credential metadata without reading passwords")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read-only metadata inventory. Never reads passwords, unlocks, or connects.
    Inventory,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Inventory => nm_daemon::credential_inventory(),
    }
}
