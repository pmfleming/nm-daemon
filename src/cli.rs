use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

use crate::model::WepKeyType;

#[derive(Parser)]
#[command(name = "nm-wifi")]
#[command(about = "NetworkManager D-Bus Wi-Fi helper")]
pub(crate) struct Cli {
    /// Increase stderr logging verbosity (-v info, -vv debug). Detailed logs always go to the log file.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub(crate) verbose: u8,
    /// Write detailed logs to this file instead of $XDG_RUNTIME_DIR/nm-wifi/nm-wifi.log.
    #[arg(long, global = true)]
    pub(crate) log_file: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// List visible Wi-Fi networks as TSV.
    List {
        /// Emit JSON instead of TSV.
        #[arg(long)]
        json: bool,
        /// Use the latest cached live-scan snapshot if available.
        #[arg(long)]
        cached: bool,
        /// Refresh the scan cache after returning cached results. If no cache exists, scan first.
        #[arg(long)]
        refresh_cache: bool,
        /// Scan timeout in seconds when --refresh-cache has to scan before returning.
        #[arg(long, default_value_t = 10)]
        refresh_timeout: u64,
    },
    /// List visible Wi-Fi networks enriched with saved-profile matches and capabilities.
    Networks {
        /// Emit JSON instead of TSV.
        #[arg(long)]
        json: bool,
        /// Use the latest cached live-scan snapshot if available.
        #[arg(long)]
        cached: bool,
        /// Refresh the scan cache after returning cached results. If no cache exists, scan first.
        #[arg(long)]
        refresh_cache: bool,
        /// Scan timeout in seconds when --refresh-cache has to scan before returning.
        #[arg(long, default_value_t = 10)]
        refresh_timeout: u64,
    },
    /// Request a scan, wait for completion, then list visible Wi-Fi networks as TSV.
    Scan {
        /// Scan completion timeout in seconds.
        #[arg(long, default_value_t = 12)]
        timeout: u64,
        /// Emit JSON Lines snapshots while NetworkManager discovers access points.
        #[arg(long)]
        stream: bool,
        /// Return an error instead of printing cached results when scan fails.
        #[arg(long)]
        strict: bool,
        /// Number of scan request retries when NetworkManager rejects a request.
        #[arg(long, default_value_t = 2)]
        retries: u32,
        /// Write latest snapshot/status files under $XDG_RUNTIME_DIR/nm-wifi.
        #[arg(long)]
        cache: bool,
        /// Restrict scan to a Wi-Fi interface.
        #[arg(long)]
        ifname: Option<String>,
        /// Request a targeted scan for an SSID. May be repeated.
        #[arg(long = "ssid")]
        ssids: Vec<String>,
    },
    /// Connect to an SSID using the current nmcli activation fallback.
    Connect {
        /// SSID to connect to.
        ssid: String,
        /// Password for creating a new WPA/WPA2/WPA3-Personal connection over D-Bus.
        #[arg(long)]
        password: Option<String>,
        /// Read the Wi-Fi password from the first line of stdin instead of argv.
        #[arg(long, conflicts_with = "password")]
        password_stdin: bool,
        /// Restrict connection to a visible BSSID.
        #[arg(long)]
        bssid: Option<String>,
        /// Treat the SSID as hidden and request a targeted scan before connecting.
        #[arg(long)]
        hidden: bool,
        /// Interpret password as a WEP key or WEP passphrase.
        #[arg(long, value_enum)]
        wep_key_type: Option<WepKeyType>,
        /// Emit structured JSON result.
        #[arg(long)]
        json: bool,
    },
    /// Connect to an exact JSON target from `nm-wifi networks --json`.
    ConnectTarget {
        /// JSON object with ssid, ssid_bytes, ap_path/path, bssid, and hidden fields.
        target_json: String,
        /// Password for creating a new WPA/WPA2/WPA3-Personal connection over D-Bus.
        #[arg(long)]
        password: Option<String>,
        /// Read the Wi-Fi password from the first line of stdin instead of argv.
        #[arg(long, conflicts_with = "password")]
        password_stdin: bool,
        /// Interpret password as a WEP key or WEP passphrase.
        #[arg(long, value_enum)]
        wep_key_type: Option<WepKeyType>,
        /// Emit structured JSON result.
        #[arg(long)]
        json: bool,
    },
    /// List saved Wi-Fi NetworkManager profiles.
    Saved {
        /// Emit JSON instead of TSV.
        #[arg(long)]
        json: bool,
    },
    /// Manage a saved Wi-Fi NetworkManager profile by D-Bus object path.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Show active Wi-Fi status and connection details.
    Status {
        /// Emit JSON instead of plain active SSID text.
        #[arg(long)]
        json: bool,
    },
    /// Disconnect the active Wi-Fi connection, if any.
    Disconnect {
        /// Emit structured JSON result.
        #[arg(long)]
        json: bool,
    },
    /// Check NetworkManager connectivity state.
    Connectivity {
        /// Emit JSON instead of plain state text.
        #[arg(long)]
        json: bool,
    },
    /// Print the active SSID, if any.
    Active,
    /// Print a stable JSON fixture for Shelllist contract tests.
    #[command(hide = true)]
    ContractFixture,
}

#[derive(Subcommand)]
pub(crate) enum ProfileCommand {
    /// Delete/forget a saved Wi-Fi profile.
    Delete {
        /// NetworkManager settings object path, from `nm-wifi saved --json`.
        path: String,
    },
    /// Enable or disable autoconnect for a saved Wi-Fi profile.
    Autoconnect {
        /// NetworkManager settings object path, from `nm-wifi saved --json`.
        path: String,
        /// true to enable autoconnect, false to disable it.
        enabled: bool,
    },
    /// Set per-profile Wi-Fi MAC privacy.
    MacRandomization {
        /// NetworkManager settings object path, from `nm-wifi saved --json`.
        path: String,
        /// true uses a stable randomized MAC, false uses the device's permanent MAC.
        randomized: bool,
    },
    /// Enable or disable sending this device's hostname through DHCP for a saved profile.
    SendHostname {
        /// NetworkManager settings object path, from `nm-wifi saved --json`.
        path: String,
        /// true to send hostname, false to keep device name private.
        enabled: bool,
    },
}
