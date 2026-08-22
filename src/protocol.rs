use std::fmt;

use serde::{Serialize, Serializer};
use serde_json::{Value, json};

use crate::error::ErrorOperation;

pub(crate) const DBUS_BUS_NAME: &str = "org.laufan.NmDaemon";
pub(crate) const DBUS_OBJECT_PATH: &str = "/org/laufan/NmDaemon";
pub(crate) const DBUS_INTERFACE: &str = "org.laufan.NmDaemon1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub(crate) enum Method {
    WifiStatus,
    WifiSetEnabled,
    RadioSetWwanEnabled,
    RadioSetAirplaneMode,
    NetworkConnectivity,
    NetworkInventory,
    NetworkDevices,
    NetworkConnections,
    NetworkState,
    NetworkActivateProfile,
    NetworkDeactivate,
    NetworkStatisticsWatch,
    HotspotCapabilities,
    HotspotStatus,
    HotspotStart,
    HotspotStop,
    VpnList,
    VpnStatus,
    VpnConnect,
    VpnDisconnect,
    WifiQrParse,
    WifiQrConnect,
    WifiNetworks,
    WifiBandStatus,
    WifiBandSet,
    WifiSaved,
    WifiScan,
    WifiConnectTarget,
    WifiDisconnect,
    WifiProfileOperation,
    WifiSecretCapabilities,
    WifiSecretProvide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ParameterKind {
    Empty,
    Enabled,
    ActivateProfile,
    Deactivate,
    StatisticsWatch,
    HotspotStart,
    VpnSelect,
    VpnConnect,
    QrPayload,
    QrConnect,
    Networks,
    BandStatus,
    BandSet,
    Scan,
    ConnectTarget,
    ProfileOperation,
    SecretCapabilities,
    SecretProvide,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MethodSpec {
    pub(crate) method: Method,
    pub(crate) name: &'static str,
    pub(crate) parameters: ParameterKind,
    pub(crate) params_example: &'static str,
    pub(crate) response_key: &'static str,
    pub(crate) stream: Option<Stream>,
    pub(crate) operation: ErrorOperation,
    pub(crate) description: &'static str,
}

pub(crate) static METHOD_REGISTRY: &[MethodSpec; 32] = &[
    MethodSpec {
        method: Method::WifiStatus,
        name: "wifi.status",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "status",
        stream: Some(Stream::WifiStatus),
        operation: ErrorOperation::Status,
        description: "Current Wi-Fi radio state, active status, and connection details.",
    },
    MethodSpec {
        method: Method::WifiSetEnabled,
        name: "wifi.setEnabled",
        parameters: ParameterKind::Enabled,
        params_example: r#"{"enabled":true}"#,
        response_key: "result",
        stream: None,
        operation: ErrorOperation::Status,
        description: "Enables or disables the NetworkManager Wi-Fi radio.",
    },
    MethodSpec {
        method: Method::RadioSetWwanEnabled,
        name: "radio.setWwanEnabled",
        parameters: ParameterKind::Enabled,
        params_example: r#"{"enabled":true}"#,
        response_key: "result",
        stream: None,
        operation: ErrorOperation::Status,
        description: "Enables or disables NetworkManager mobile-data radios.",
    },
    MethodSpec {
        method: Method::RadioSetAirplaneMode,
        name: "radio.setAirplaneMode",
        parameters: ParameterKind::Enabled,
        params_example: r#"{"enabled":true}"#,
        response_key: "result",
        stream: None,
        operation: ErrorOperation::Status,
        description: "Disables or restores NetworkManager Wi-Fi and mobile-data radios.",
    },
    MethodSpec {
        method: Method::NetworkConnectivity,
        name: "network.connectivity",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "connectivity",
        stream: Some(Stream::NetworkConnectivity),
        operation: ErrorOperation::Connectivity,
        description: "NetworkManager connectivity and captive-portal state.",
    },
    MethodSpec {
        method: Method::NetworkInventory,
        name: "network.inventory",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "inventory",
        stream: Some(Stream::NetworkInventory),
        operation: ErrorOperation::Inventory,
        description: "Devices, saved profiles, and active connections across NetworkManager connection types.",
    },
    MethodSpec {
        method: Method::NetworkDevices,
        name: "network.devices",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "devices",
        stream: Some(Stream::NetworkInventory),
        operation: ErrorOperation::Inventory,
        description: "All NetworkManager devices with type, state, reason, and availability details.",
    },
    MethodSpec {
        method: Method::NetworkConnections,
        name: "network.connections",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "connections",
        stream: Some(Stream::NetworkInventory),
        operation: ErrorOperation::Inventory,
        description: "All saved NetworkManager profiles of every connection type with availability and activation state.",
    },
    MethodSpec {
        method: Method::NetworkState,
        name: "network.status",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "network",
        stream: Some(Stream::NetworkInventory),
        operation: ErrorOperation::Inventory,
        description: "Overall NetworkManager state, radios, connectivity, and primary/activating connection identity.",
    },
    MethodSpec {
        method: Method::NetworkActivateProfile,
        name: "network.activateProfile",
        parameters: ParameterKind::ActivateProfile,
        params_example: r#"{"uuid":"0f6c...","path":null,"device":null}"#,
        response_key: "result",
        stream: Some(Stream::NetworkInventory),
        operation: ErrorOperation::Connect,
        description: "Activates one saved profile of any connection type on a compatible device.",
    },
    MethodSpec {
        method: Method::NetworkDeactivate,
        name: "network.deactivate",
        parameters: ParameterKind::Deactivate,
        params_example: r#"{"path":"/org/freedesktop/NetworkManager/ActiveConnection/1","uuid":null}"#,
        response_key: "result",
        stream: Some(Stream::NetworkInventory),
        operation: ErrorOperation::Disconnect,
        description: "Deactivates one active connection by active-connection path or profile UUID.",
    },
    MethodSpec {
        method: Method::NetworkStatisticsWatch,
        name: "network.statistics.watch",
        parameters: ParameterKind::StatisticsWatch,
        params_example: r#"{"device":"wlan0","interval_ms":1000}"#,
        response_key: "result",
        stream: Some(Stream::NetworkStatistics),
        operation: ErrorOperation::Statistics,
        description: "Starts an owner-scoped device transfer-counter watch and returns its request id.",
    },
    MethodSpec {
        method: Method::HotspotCapabilities,
        name: "hotspot.capabilities",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "hotspot",
        stream: None,
        operation: ErrorOperation::HotspotOperation,
        description: "Reports whether a Wi-Fi hotspot can be started, and why not when it cannot.",
    },
    MethodSpec {
        method: Method::HotspotStatus,
        name: "hotspot.status",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "hotspot",
        stream: None,
        operation: ErrorOperation::HotspotOperation,
        description: "Reports the running Wi-Fi hotspot, if any.",
    },
    MethodSpec {
        method: Method::HotspotStart,
        name: "hotspot.start",
        parameters: ParameterKind::HotspotStart,
        params_example: r#"{"ssid":null,"passphrase":null,"security":"wpa-psk","band":"auto","channel":null,"hidden":false,"device":null}"#,
        response_key: "result",
        stream: Some(Stream::Hotspot),
        operation: ErrorOperation::HotspotOperation,
        description: "Starts a volatile Wi-Fi hotspot and returns a cancellable request id.",
    },
    MethodSpec {
        method: Method::HotspotStop,
        name: "hotspot.stop",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "result",
        stream: None,
        operation: ErrorOperation::HotspotOperation,
        description: "Stops the running Wi-Fi hotspot and removes its volatile profile.",
    },
    MethodSpec {
        method: Method::VpnList,
        name: "vpn.list",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "vpns",
        stream: None,
        operation: ErrorOperation::VpnOperation,
        description: "Saved VPN and WireGuard profiles with plugin, secret, and activation details.",
    },
    MethodSpec {
        method: Method::VpnStatus,
        name: "vpn.status",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "vpn",
        stream: None,
        operation: ErrorOperation::VpnOperation,
        description: "Active VPN and WireGuard connections with plugin state, banner, and duration.",
    },
    MethodSpec {
        method: Method::VpnConnect,
        name: "vpn.connect",
        parameters: ParameterKind::VpnConnect,
        params_example: r#"{"uuid":"0a1c...","path":null,"timeout":45}"#,
        response_key: "result",
        stream: Some(Stream::Vpn),
        operation: ErrorOperation::VpnOperation,
        description: "Activates a saved VPN or WireGuard profile and returns a cancellable request id.",
    },
    MethodSpec {
        method: Method::VpnDisconnect,
        name: "vpn.disconnect",
        parameters: ParameterKind::VpnSelect,
        params_example: r#"{"uuid":null,"path":null}"#,
        response_key: "result",
        stream: None,
        operation: ErrorOperation::VpnOperation,
        description: "Deactivates one active VPN or WireGuard connection, or the only active one.",
    },
    MethodSpec {
        method: Method::WifiQrParse,
        name: "wifi.qr.parse",
        parameters: ParameterKind::QrPayload,
        params_example: r#"{"payload":"WIFI:T:WPA;S:Example;P:...;;"}"#,
        response_key: "qr",
        stream: None,
        operation: ErrorOperation::QrOperation,
        description: "Validates a scanned Wi-Fi QR payload without logging it or echoing its secret.",
    },
    MethodSpec {
        method: Method::WifiQrConnect,
        name: "wifi.qr.connect",
        parameters: ParameterKind::QrConnect,
        params_example: r#"{"payload":"WIFI:T:WPA;S:Example;P:...;;","ifname":null}"#,
        response_key: "result",
        stream: Some(Stream::WifiConnect),
        operation: ErrorOperation::QrOperation,
        description: "Connects to the network in a scanned Wi-Fi QR payload and returns a connect request id.",
    },
    MethodSpec {
        method: Method::WifiNetworks,
        name: "wifi.networks",
        parameters: ParameterKind::Networks,
        params_example: r#"{"cached":false,"refresh_cache":false,"refresh_timeout":10}"#,
        response_key: "networks",
        stream: Some(Stream::WifiNetworks),
        operation: ErrorOperation::Networks,
        description: "Visible networks enriched with saved-profile, capability, and snapshot freshness details; optionally emits local change deltas.",
    },
    MethodSpec {
        method: Method::WifiBandStatus,
        name: "wifi.band.status",
        parameters: ParameterKind::BandStatus,
        params_example: r#"{"path":"/org/freedesktop/NetworkManager/Settings/1"}"#,
        response_key: "band",
        stream: None,
        operation: ErrorOperation::BandOperation,
        description: "Reports the active, selected, and available bands for an active Wi-Fi profile.",
    },
    MethodSpec {
        method: Method::WifiBandSet,
        name: "wifi.band.set",
        parameters: ParameterKind::BandSet,
        params_example: r#"{"path":"/org/freedesktop/NetworkManager/Settings/1","band":"5"}"#,
        response_key: "result",
        stream: Some(Stream::WifiBand),
        operation: ErrorOperation::BandOperation,
        description: "Transactionally changes an active Wi-Fi profile band and returns a request id.",
    },
    MethodSpec {
        method: Method::WifiSaved,
        name: "wifi.saved",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "profiles",
        stream: None,
        operation: ErrorOperation::ProfileOperation,
        description: "All saved Wi-Fi NetworkManager profiles.",
    },
    MethodSpec {
        method: Method::WifiScan,
        name: "wifi.scan",
        parameters: ParameterKind::Scan,
        params_example: r#"{"timeout":12,"strict":false,"cache":false,"ifname":null,"ssids":[]}"#,
        response_key: "result",
        stream: Some(Stream::WifiScan),
        operation: ErrorOperation::Scan,
        description: "Starts an event-driven scan and returns its request id.",
    },
    MethodSpec {
        method: Method::WifiConnectTarget,
        name: "wifi.connectTarget",
        parameters: ParameterKind::ConnectTarget,
        params_example: r#"{"key":"ssid-hex:4578616d706c65|security:personal|ifname:776c616e30","password":null,"enterprise_identity":null,"enterprise":null,"wep_key_type":null}"#,
        response_key: "result",
        stream: Some(Stream::WifiConnect),
        operation: ErrorOperation::Connect,
        description: "Starts an event-driven Wi-Fi connection by opaque network key and returns its request id; legacy target requests remain accepted.",
    },
    MethodSpec {
        method: Method::WifiDisconnect,
        name: "wifi.disconnect",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "result",
        stream: None,
        operation: ErrorOperation::Disconnect,
        description: "Disconnects the active Wi-Fi connection.",
    },
    MethodSpec {
        method: Method::WifiProfileOperation,
        name: "wifi.profile.operation",
        parameters: ParameterKind::ProfileOperation,
        params_example: r#"{"operation":"set-autoconnect","path":"/org/freedesktop/NetworkManager/Settings/1","enabled":true}"#,
        response_key: "result",
        stream: None,
        operation: ErrorOperation::ProfileOperation,
        description: "Mutates or builds a share payload for one saved Wi-Fi profile.",
    },
    MethodSpec {
        method: Method::WifiSecretCapabilities,
        name: "wifi.secret.capabilities",
        parameters: ParameterKind::SecretCapabilities,
        params_example: "{}",
        response_key: "secret_agent",
        stream: Some(Stream::WifiSecret),
        operation: ErrorOperation::SecretOperation,
        description: "Reports SecretAgent and keyring capabilities.",
    },
    MethodSpec {
        method: Method::WifiSecretProvide,
        name: "wifi.secret.provide",
        parameters: ParameterKind::SecretProvide,
        params_example: r#"{"request_id":"...","values":{"psk":"..."},"save":false,"cancel":false}"#,
        response_key: "result",
        stream: Some(Stream::WifiSecret),
        operation: ErrorOperation::SecretOperation,
        description: "Answers a pending SecretAgent request.",
    },
];

impl Method {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        METHOD_REGISTRY
            .iter()
            .find(|spec| spec.name == value)
            .map(|spec| spec.method)
    }

    pub(crate) fn spec(self) -> &'static MethodSpec {
        &METHOD_REGISTRY[self as usize]
    }

    pub(crate) fn as_str(self) -> &'static str {
        self.spec().name
    }
}

impl fmt::Display for Method {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for Method {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub(crate) enum Stream {
    WifiStatus,
    NetworkConnectivity,
    NetworkInventory,
    NetworkStatistics,
    Hotspot,
    Vpn,
    NetworkHealth,
    WifiNetworks,
    WifiScan,
    WifiConnect,
    WifiBand,
    WifiSecret,
    DaemonRequest,
    DaemonSubscription,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StreamDelivery {
    Continuous,
    Operation,
    External,
    Internal,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamSpec {
    pub(crate) stream: Stream,
    pub(crate) name: &'static str,
    pub(crate) subscribable: bool,
    pub(crate) default: bool,
    pub(crate) delivery: StreamDelivery,
    pub(crate) events: &'static [&'static str],
    pub(crate) description: &'static str,
}

pub(crate) static STREAM_REGISTRY: &[StreamSpec; 14] = &[
    StreamSpec {
        stream: Stream::WifiStatus,
        name: "wifi.status",
        subscribable: true,
        default: true,
        delivery: StreamDelivery::Continuous,
        events: &["subscribed", "changed"],
        description: "Current Wi-Fi status, emitted immediately and whenever it changes.",
    },
    StreamSpec {
        stream: Stream::NetworkConnectivity,
        name: "network.connectivity",
        subscribable: true,
        default: true,
        delivery: StreamDelivery::Continuous,
        events: &["subscribed", "changed"],
        description: "Connectivity and portal state, emitted immediately and on change.",
    },
    StreamSpec {
        stream: Stream::NetworkInventory,
        name: "network.inventory",
        subscribable: true,
        default: false,
        delivery: StreamDelivery::Continuous,
        events: &["subscribed", "changed"],
        description: "Cross-type device, profile, and active-connection inventory emitted on local NetworkManager changes.",
    },
    StreamSpec {
        stream: Stream::NetworkStatistics,
        name: "network.statistics",
        subscribable: true,
        default: false,
        delivery: StreamDelivery::Operation,
        events: &["subscribed", "started", "sample", "failed", "cancelled"],
        description: "Device transfer counters and derived rates for a network.statistics.watch request id.",
    },
    StreamSpec {
        stream: Stream::Hotspot,
        name: "hotspot",
        subscribable: true,
        default: false,
        delivery: StreamDelivery::Operation,
        events: &[
            "subscribed",
            "started",
            "progress",
            "succeeded",
            "failed",
            "cancelled",
        ],
        description: "Events associated with a hotspot.start request id.",
    },
    StreamSpec {
        stream: Stream::Vpn,
        name: "vpn",
        subscribable: true,
        default: false,
        delivery: StreamDelivery::Operation,
        events: &[
            "subscribed",
            "started",
            "progress",
            "succeeded",
            "failed",
            "cancelled",
        ],
        description: "VPN and WireGuard activation state and typed failure reasons for a vpn.connect request id.",
    },
    StreamSpec {
        stream: Stream::NetworkHealth,
        name: "network.health",
        subscribable: true,
        default: false,
        delivery: StreamDelivery::External,
        events: &["subscribed", "device", "connection", "vpn"],
        description: "Typed device, active-connection, and VPN state transitions with NetworkManager's reason. Presentation stays with the frontend.",
    },
    StreamSpec {
        stream: Stream::WifiNetworks,
        name: "wifi.networks",
        subscribable: true,
        default: false,
        delivery: StreamDelivery::Continuous,
        events: &["subscribed", "changed"],
        description: "Added, removed, and changed visible networks emitted from local NetworkManager state without requesting scans.",
    },
    StreamSpec {
        stream: Stream::WifiScan,
        name: "wifi.scan",
        subscribable: true,
        default: true,
        delivery: StreamDelivery::Operation,
        events: &[
            "subscribed",
            "status",
            "warning",
            "snapshot",
            "complete",
            "cancelled",
            "failed",
        ],
        description: "Events associated with a wifi.scan request id.",
    },
    StreamSpec {
        stream: Stream::WifiConnect,
        name: "wifi.connect",
        subscribable: true,
        default: false,
        delivery: StreamDelivery::Operation,
        events: &[
            "subscribed",
            "started",
            "progress",
            "succeeded",
            "failed",
            "cancelled",
        ],
        description: "Events associated with a wifi.connectTarget request id.",
    },
    StreamSpec {
        stream: Stream::WifiBand,
        name: "wifi.band",
        subscribable: true,
        default: false,
        delivery: StreamDelivery::Operation,
        events: &[
            "subscribed",
            "started",
            "progress",
            "succeeded",
            "failed",
            "cancelled",
        ],
        description: "Events associated with a transactional wifi.band.set request id.",
    },
    StreamSpec {
        stream: Stream::WifiSecret,
        name: "wifi.secret",
        subscribable: true,
        default: false,
        delivery: StreamDelivery::External,
        events: &["subscribed", "requested", "cancelled", "persistence"],
        description: "SecretAgent prompt, cancellation, and keyring persistence events.",
    },
    StreamSpec {
        stream: Stream::DaemonRequest,
        name: "daemon.request",
        subscribable: false,
        default: false,
        delivery: StreamDelivery::Internal,
        events: &["cancelled"],
        description: "Internal request-cancellation acknowledgements.",
    },
    StreamSpec {
        stream: Stream::DaemonSubscription,
        name: "daemon.subscription",
        subscribable: false,
        default: false,
        delivery: StreamDelivery::Internal,
        events: &["cancelled"],
        description: "Internal subscription-cancellation acknowledgements.",
    },
];

impl Stream {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        STREAM_REGISTRY
            .iter()
            .find(|spec| spec.name == value)
            .map(|spec| spec.stream)
    }

    pub(crate) fn parse_subscription(value: &str) -> Option<Self> {
        Self::parse(value).filter(|stream| stream.spec().subscribable)
    }

    pub(crate) fn defaults() -> Vec<Self> {
        STREAM_REGISTRY
            .iter()
            .filter(|spec| spec.default)
            .map(|spec| spec.stream)
            .collect()
    }

    pub(crate) fn spec(self) -> &'static StreamSpec {
        &STREAM_REGISTRY[self as usize]
    }

    pub(crate) fn as_str(self) -> &'static str {
        self.spec().name
    }
}

impl fmt::Display for Stream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for Stream {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

pub(crate) fn contract_registry() -> Value {
    json!({
        "methods": METHOD_REGISTRY.iter().map(|spec| json!({
            "name": spec.name,
            "parameters": spec.parameters,
            "params_example": serde_json::from_str::<Value>(spec.params_example)
                .unwrap_or_else(|_| json!(spec.params_example)),
            "response_key": spec.response_key,
            "stream": spec.stream,
            "description": spec.description,
        })).collect::<Vec<_>>(),
        "streams": STREAM_REGISTRY.iter().map(|spec| json!({
            "name": spec.name,
            "subscribable": spec.subscribable,
            "default": spec.default,
            "delivery": spec.delivery,
            "events": spec.events,
            "description": spec.description,
        })).collect::<Vec<_>>(),
    })
}

pub(crate) fn markdown_reference() -> String {
    let mut output = String::from(
        "### Method registry\n\n| Method | Parameters | Response key | Stream | Description |\n| --- | --- | --- | --- | --- |\n",
    );
    for spec in METHOD_REGISTRY {
        let stream = spec.stream.map_or("—", Stream::as_str);
        output.push_str(&format!(
            "| `{}` | `{}` (`{:?}`) | `{}` | `{}` | {} |\n",
            spec.name,
            spec.params_example,
            spec.parameters,
            spec.response_key,
            stream,
            spec.description,
        ));
    }
    output.push_str(
        "\n### Stream registry\n\n| Stream | Subscribable | Default | Delivery | Events | Description |\n| --- | --- | --- | --- | --- | --- |\n",
    );
    for spec in STREAM_REGISTRY {
        output.push_str(&format!(
            "| `{}` | {} | {} | `{:?}` | `{}` | {} |\n",
            spec.name,
            spec.subscribable,
            spec.default,
            spec.delivery,
            spec.events.join(", "),
            spec.description,
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{METHOD_REGISTRY, Method, STREAM_REGISTRY, Stream, markdown_reference};

    #[test]
    fn registry_names_are_unique() {
        let mut names = HashSet::new();
        for spec in METHOD_REGISTRY {
            assert!(names.insert(spec.name));
            assert_eq!(Method::parse(spec.name), Some(spec.method));
            assert_eq!(spec.method.spec().name, spec.name);
        }
        assert_eq!(Method::parse("wifi.connect-target"), None);

        names.clear();
        for spec in STREAM_REGISTRY {
            assert!(names.insert(spec.name));
            assert_eq!(Stream::parse(spec.name), Some(spec.stream));
            assert_eq!(spec.stream.spec().name, spec.name);
            assert_eq!(
                Stream::parse_subscription(spec.name),
                spec.subscribable.then_some(spec.stream)
            );
        }
    }

    #[test]
    fn checked_in_protocol_reference_matches_the_registry() {
        let docs = include_str!("../docs/dbus-daemon.md");
        let generated = markdown_reference();
        let section = docs
            .split("<!-- BEGIN GENERATED PROTOCOL REGISTRY -->")
            .nth(1)
            .and_then(|value| {
                value
                    .split("<!-- END GENERATED PROTOCOL REGISTRY -->")
                    .next()
            })
            .expect("generated registry markers in docs")
            .trim();
        assert_eq!(section, generated.trim());
    }
}
