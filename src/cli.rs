use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

use crate::model::WepKeyType;

#[derive(Parser)]
#[command(name = "nm-api")]
#[command(about = "NetworkManager JSON/JSONL API adapter")]
pub(crate) struct Cli {
    /// Increase stderr logging verbosity (-v info, -vv debug). Detailed logs always go to the log file.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub(crate) verbose: u8,
    /// Write detailed logs to this file instead of $XDG_RUNTIME_DIR/nm-api/nm-api.log.
    #[arg(long, global = true)]
    pub(crate) log_file: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Wi-Fi NetworkManager API operations.
    Wifi {
        #[command(subcommand)]
        command: WifiCommand,
    },
    /// NetworkManager-wide API operations.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Debug and unstable development probes.
    Debug {
        #[command(subcommand)]
        command: DebugCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum WifiCommand {
    /// List visible Wi-Fi networks enriched with saved-profile matches and capabilities.
    Networks(ListOptions),
    /// Request a scan, wait for completion, then emit an nm-api JSON response.
    Scan(ScanOptions),
    /// Connect to an SSID using NetworkManager D-Bus, with nmcli fallback for remaining edge cases.
    Connect(ConnectOptions),
    /// Connect to an exact JSON target request read from stdin.
    ConnectTarget(ConnectTargetOptions),
    /// List saved Wi-Fi NetworkManager profiles.
    Saved,
    /// Manage a saved Wi-Fi NetworkManager profile by D-Bus object path.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Show active Wi-Fi status and connection details.
    Status,
    /// Disconnect the active Wi-Fi connection, if any.
    Disconnect,
}

#[derive(Subcommand)]
pub(crate) enum NetworkCommand {
    /// Check NetworkManager connectivity state.
    Connectivity,
}

#[derive(Subcommand)]
pub(crate) enum DebugCommand {
    /// Compare nm-api's active/cached Wi-Fi data with nmcli.
    Diagnose {
        /// Emit JSON instead of debug text.
        #[arg(long)]
        json: bool,
    },
    /// Print the combined Shelllist contract fixture.
    ContractFixture,
    /// Print per-method contract fixtures for API/schema checks.
    ContractFixtures,
}

#[derive(Clone, Args)]
pub(crate) struct ListOptions {
    /// Use the latest cached live-scan snapshot if available.
    #[arg(long)]
    pub(crate) cached: bool,
    /// Refresh the scan cache after returning cached results. If no cache exists, scan first.
    #[arg(long)]
    pub(crate) refresh_cache: bool,
    /// Scan timeout in seconds when --refresh-cache has to scan before returning.
    #[arg(long, default_value_t = 10)]
    pub(crate) refresh_timeout: u64,
}

#[derive(Clone, Args)]
pub(crate) struct ScanOptions {
    /// Scan completion timeout in seconds.
    #[arg(long, default_value_t = 12)]
    pub(crate) timeout: u64,
    /// Emit JSON Lines snapshots while NetworkManager discovers access points.
    #[arg(long)]
    pub(crate) stream: bool,
    /// Return an error instead of printing cached results when scan fails.
    #[arg(long)]
    pub(crate) strict: bool,
    /// Number of scan request retries when NetworkManager rejects a request.
    #[arg(long, default_value_t = 2)]
    pub(crate) retries: u32,
    /// Write latest snapshot/status files under $XDG_RUNTIME_DIR/nm-api.
    #[arg(long)]
    pub(crate) cache: bool,
    /// Restrict scan to a Wi-Fi interface.
    #[arg(long)]
    pub(crate) ifname: Option<String>,
    /// Request a targeted scan for an SSID. May be repeated.
    #[arg(long = "ssid")]
    pub(crate) ssids: Vec<String>,
}

#[derive(Clone, Args)]
pub(crate) struct ConnectOptions {
    /// SSID to connect to.
    pub(crate) ssid: String,
    /// Read the Wi-Fi password from the first line of stdin.
    #[arg(long)]
    pub(crate) password_stdin: bool,
    /// Restrict connection to a visible BSSID.
    #[arg(long)]
    pub(crate) bssid: Option<String>,
    /// Treat the SSID as hidden and request a targeted scan before connecting.
    #[arg(long)]
    pub(crate) hidden: bool,
    /// Key-management/security hint for hidden or ambiguous targets: open, owe, wpa-psk, sae, wep, wpa-eap.
    #[arg(long)]
    pub(crate) key_mgmt: Option<String>,
    /// Interpret password as a WEP key or WEP passphrase.
    #[arg(long, value_enum)]
    pub(crate) wep_key_type: Option<WepKeyType>,
}

#[derive(Clone, Args)]
pub(crate) struct ConnectTargetOptions {
    /// Interpret password as a WEP key or WEP passphrase.
    #[arg(long, value_enum)]
    pub(crate) wep_key_type: Option<WepKeyType>,
}

#[derive(Subcommand)]
pub(crate) enum ProfileCommand {
    /// Delete/forget a saved Wi-Fi profile.
    Delete {
        /// NetworkManager settings object path, from `nm-api wifi saved`.
        path: String,
    },
    /// Enable or disable autoconnect for a saved Wi-Fi profile.
    Autoconnect {
        /// NetworkManager settings object path, from `nm-api wifi saved`.
        path: String,
        /// true to enable autoconnect, false to disable it.
        enabled: bool,
    },
    /// Set per-profile Wi-Fi MAC privacy.
    MacRandomization {
        /// NetworkManager settings object path, from `nm-api wifi saved`.
        path: String,
        /// true uses a stable randomized MAC, false uses the device's permanent MAC.
        randomized: bool,
    },
    /// Build a standard Wi-Fi QR payload for a shareable saved profile.
    Share {
        /// NetworkManager settings object path, from `nm-api wifi saved`.
        path: String,
    },
    /// Enable or disable sending this device's hostname through DHCP for a saved profile.
    SendHostname {
        /// NetworkManager settings object path, from `nm-api wifi saved`.
        path: String,
        /// true to send hostname, false to keep device name private.
        enabled: bool,
    },
}
