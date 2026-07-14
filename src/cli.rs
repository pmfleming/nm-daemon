use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

use crate::model::{Bssid, InterfaceName, NmObjectPath, WepKeyType};

#[derive(Parser)]
#[command(name = "nm-daemon")]
#[command(about = "NetworkManager JSON/JSONL API adapter and user D-Bus service")]
pub(crate) struct Cli {
    /// Increase stderr logging verbosity (-v info, -vv debug). Detailed logs always go to the log file.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub(crate) verbose: u8,
    /// Write detailed logs to this file instead of $XDG_RUNTIME_DIR/nm-daemon/nm-daemon.log.
    #[arg(long, global = true)]
    pub(crate) log_file: Option<PathBuf>,
    /// Bypass the user D-Bus service and run the command implementation in this process.
    #[arg(long, global = true)]
    pub(crate) direct: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Run the long-lived user D-Bus service.
    Daemon,
    /// Run a long-lived JSON Lines client session for graphical frontends.
    Client,
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
    /// Request a one-shot scan, wait for completion, then emit an nm-api JSON response.
    Scan(ScanOptions),
    /// Connect to an SSID using NetworkManager D-Bus.
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
    /// Compare nm-daemon's active/cached Wi-Fi data with nmcli.
    Diagnose {
        /// Emit JSON instead of debug text.
        #[arg(long)]
        json: bool,
    },
    /// Print the combined Shelllist contract fixture.
    ContractFixture,
    /// Print per-method contract fixtures for API/schema checks.
    ContractFixtures,
    /// Print the canonical D-Bus method and stream registry.
    ProtocolRegistry,
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
    /// Return an error instead of printing cached results when scan fails.
    #[arg(long)]
    pub(crate) strict: bool,
    /// Write latest snapshot/status files under $XDG_RUNTIME_DIR/nm-daemon.
    #[arg(long)]
    pub(crate) cache: bool,
    /// Suppress the access-point JSON response (intended for cache refresh timers).
    #[arg(long)]
    pub(crate) quiet: bool,
    /// Restrict scan to a Wi-Fi interface.
    #[arg(long)]
    pub(crate) ifname: Option<InterfaceName>,
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
    pub(crate) bssid: Option<Bssid>,
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
        /// NetworkManager settings object path, from `nm-daemon wifi saved`.
        path: NmObjectPath,
    },
    /// Enable or disable autoconnect for a saved Wi-Fi profile.
    Autoconnect {
        /// NetworkManager settings object path, from `nm-daemon wifi saved`.
        path: NmObjectPath,
        /// true to enable autoconnect, false to disable it.
        #[arg(action = ArgAction::Set)]
        enabled: bool,
    },
    /// Set per-profile Wi-Fi MAC privacy.
    MacRandomization {
        /// NetworkManager settings object path, from `nm-daemon wifi saved`.
        path: NmObjectPath,
        /// true uses a stable randomized MAC, false uses the device's permanent MAC.
        #[arg(action = ArgAction::Set)]
        randomized: bool,
    },
    /// Build a standard Wi-Fi QR payload for a shareable saved profile.
    Share {
        /// NetworkManager settings object path, from `nm-daemon wifi saved`.
        path: NmObjectPath,
    },
    /// Enable or disable sending this device's hostname through DHCP for a saved profile.
    SendHostname {
        /// NetworkManager settings object path, from `nm-daemon wifi saved`.
        path: NmObjectPath,
        /// true to send hostname, false to keep device name private.
        #[arg(action = ArgAction::Set)]
        enabled: bool,
    },
}
