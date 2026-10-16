//! Opt-in migration tooling, never part of daemon startup.
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    about = "Inventory or explicitly discard legacy network credentials without reading passwords"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read-only metadata inventory. Never reads passwords, unlocks, or connects.
    Inventory,
    /// Permanently delete one exact nm-daemon item WITHOUT importing its password.
    DiscardLegacy {
        #[arg(long)]
        item: String,
        #[arg(long)]
        uuid: String,
        #[arg(long)]
        setting: String,
        #[arg(long)]
        key: String,
        /// Accept losing this password even if NetworkManager has no replacement.
        #[arg(long, required = true)]
        confirm_loss: bool,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Inventory => nm_daemon::credential_inventory(),
        Command::DiscardLegacy {
            item,
            uuid,
            setting,
            key,
            confirm_loss,
        } => {
            anyhow::ensure!(confirm_loss, "explicit loss approval is required");
            nm_daemon::discard_legacy_credential(&item, &uuid, &setting, &key)
        }
    }
}
