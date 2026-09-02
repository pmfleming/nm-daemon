use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

use crate::model::{Bssid, HotspotSecurity, InterfaceName, NmObjectPath, WepKeyType, WifiBand};

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
    /// VPN and WireGuard operations.
    Vpn {
        #[command(subcommand)]
        command: VpnCommand,
    },
    /// Wi-Fi hotspot lifecycle operations.
    Hotspot {
        #[command(subcommand)]
        command: HotspotCommand,
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
    /// Show overall NetworkManager state, radios, connectivity, and primary connection.
    Status,
    /// List every NetworkManager device with type, state, and availability.
    Devices,
    /// List saved NetworkManager profiles of every connection type.
    Connections,
    /// Show devices, saved profiles, and active connections in one snapshot.
    Inventory,
    /// Activate a saved profile of any connection type.
    Activate(ActivateOptions),
    /// Deactivate an active connection.
    Deactivate(DeactivateOptions),
}

#[derive(Clone, Args)]
pub(crate) struct ActivateOptions {
    /// Saved-profile UUID, from `nm-daemon network connections`.
    #[arg(long, required_unless_present = "path")]
    pub(crate) uuid: Option<String>,
    /// NetworkManager settings object path, from `nm-daemon network connections`.
    #[arg(long)]
    pub(crate) path: Option<NmObjectPath>,
    /// Device object path or interface name to activate the profile on.
    #[arg(long)]
    pub(crate) device: Option<String>,
}

#[derive(Clone, Args)]
pub(crate) struct DeactivateOptions {
    /// Active-connection object path, from `nm-daemon network inventory`.
    #[arg(long, required_unless_present = "uuid")]
    pub(crate) path: Option<NmObjectPath>,
    /// Profile UUID of the active connection to deactivate.
    #[arg(long)]
    pub(crate) uuid: Option<String>,
}

#[derive(Subcommand)]
pub(crate) enum VpnCommand {
    /// List saved VPN and WireGuard profiles.
    List,
    /// Show active VPN and WireGuard connections.
    Status,
    /// Activate a saved VPN or WireGuard profile.
    Connect(VpnConnectOptions),
    /// Deactivate an active VPN or WireGuard connection.
    Disconnect(VpnSelectOptions),
}

#[derive(Clone, Args)]
pub(crate) struct VpnConnectOptions {
    /// Saved-profile UUID, from `nm-daemon vpn list`.
    #[arg(long, required_unless_present = "path")]
    pub(crate) uuid: Option<String>,
    /// NetworkManager settings object path, from `nm-daemon vpn list`.
    #[arg(long)]
    pub(crate) path: Option<NmObjectPath>,
    /// Seconds to wait for the VPN plugin to report a terminal state.
    #[arg(long, default_value_t = 45)]
    pub(crate) timeout: u64,
}

#[derive(Clone, Args)]
pub(crate) struct VpnSelectOptions {
    /// Active profile UUID. Omit to disconnect the only active VPN.
    #[arg(long)]
    pub(crate) uuid: Option<String>,
    /// Active-connection or settings object path.
    #[arg(long)]
    pub(crate) path: Option<NmObjectPath>,
}

#[derive(Subcommand)]
pub(crate) enum HotspotCommand {
    /// Report whether a Wi-Fi hotspot can be started, and why not when it cannot.
    Capabilities,
    /// Report the running Wi-Fi hotspot, if any.
    Status,
    /// Start a volatile Wi-Fi hotspot.
    Start(HotspotStartOptions),
    /// Stop the running Wi-Fi hotspot.
    Stop,
}

#[derive(Clone, Args)]
pub(crate) struct HotspotStartOptions {
    /// Hotspot SSID. Defaults to a hostname-derived name.
    #[arg(long)]
    pub(crate) ssid: Option<String>,
    /// Read the hotspot passphrase from the first line of stdin. A secure random
    /// passphrase is generated when omitted.
    #[arg(long)]
    pub(crate) passphrase_stdin: bool,
    /// Hotspot security. WEP and ad-hoc fallbacks are intentionally unsupported.
    #[arg(long, value_enum, default_value_t = HotspotSecurity::WpaPsk)]
    pub(crate) security: HotspotSecurity,
    /// Restrict the hotspot to a band.
    #[arg(long, value_enum, default_value_t = WifiBand::Auto)]
    pub(crate) band: WifiBand,
    /// Restrict the hotspot to a channel.
    #[arg(long)]
    pub(crate) channel: Option<u32>,
    /// Do not broadcast the SSID.
    #[arg(long)]
    pub(crate) hidden: bool,
    /// Wi-Fi device object path or interface name to host the hotspot.
    #[arg(long)]
    pub(crate) device: Option<String>,
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
    /// Refresh a missing or stale scan cache after returning available results.
    #[arg(long)]
    pub(crate) refresh_cache: bool,
    /// Background scan timeout in seconds when --refresh-cache schedules a scan.
    #[arg(long, default_value_t = 20)]
    pub(crate) refresh_timeout: u64,
}

#[derive(Clone, Args)]
pub(crate) struct ScanOptions {
    /// Scan completion timeout in seconds.
    #[arg(long, default_value_t = 20)]
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
    /// Enable or disable Cast device discovery on this network.
    Casting {
        /// NetworkManager settings object path, from `nm-daemon wifi saved`.
        path: NmObjectPath,
        /// true permits resolve-only mDNS discovery, false disables mDNS on the profile.
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
