use clap::{Parser, Subcommand};

use crate::model::WepKeyType;

#[derive(Parser)]
#[command(name = "nm-wifi-rofi")]
#[command(about = "NetworkManager D-Bus Wi-Fi helper for rofi")]
pub(crate) struct Cli {
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
        /// Write latest snapshot/status files under $XDG_RUNTIME_DIR/nm-wifi-rofi.
        #[arg(long)]
        cache: bool,
    },
    /// Connect to an SSID using the current nmcli activation fallback.
    Connect {
        /// SSID to connect to.
        ssid: String,
        /// Password for creating a new WPA/WPA2/WPA3-Personal connection over D-Bus.
        #[arg(long)]
        password: Option<String>,
        /// Restrict connection to a visible BSSID.
        #[arg(long)]
        bssid: Option<String>,
        /// Treat the SSID as hidden and request a targeted scan before connecting.
        #[arg(long)]
        hidden: bool,
        /// Interpret password as a WEP key or WEP passphrase.
        #[arg(long, value_enum)]
        wep_key_type: Option<WepKeyType>,
    },
    /// Emit a rofi script-mode menu backed by cached live-scan snapshots.
    Rofi {
        /// Background scan timeout in seconds when selecting rescan.
        #[arg(long, default_value_t = 12)]
        timeout: u64,
        /// Background scan request retries when selecting rescan.
        #[arg(long, default_value_t = 2)]
        retries: u32,
        /// Rofi passes the selected row text as a positional argument on callbacks.
        #[arg(hide = true, trailing_var_arg = true, allow_hyphen_values = true)]
        rofi_args: Vec<String>,
    },
    /// Print the active SSID, if any.
    Active,
}
