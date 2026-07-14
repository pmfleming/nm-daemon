use std::fmt;

use serde::{Serialize, Serializer};
use serde_json::{Value, json};

use crate::error::ErrorOperation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Method {
    WifiStatus,
    NetworkConnectivity,
    WifiNetworks,
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
    Networks,
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

pub(crate) const METHOD_REGISTRY: &[MethodSpec] = &[
    MethodSpec {
        method: Method::WifiStatus,
        name: "wifi.status",
        parameters: ParameterKind::Empty,
        params_example: "{}",
        response_key: "status",
        stream: Some(Stream::WifiStatus),
        operation: ErrorOperation::Status,
        description: "Current active Wi-Fi status and connection details.",
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
        method: Method::WifiNetworks,
        name: "wifi.networks",
        parameters: ParameterKind::Networks,
        params_example: r#"{"cached":false,"refresh_cache":false,"refresh_timeout":10}"#,
        response_key: "networks",
        stream: None,
        operation: ErrorOperation::Networks,
        description: "Visible networks enriched with saved-profile and capability details.",
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
        params_example: r#"{"target":{"ssid":"Example"},"password":null,"wep_key_type":null}"#,
        response_key: "result",
        stream: Some(Stream::WifiConnect),
        operation: ErrorOperation::Connect,
        description: "Starts an event-driven Wi-Fi connection and returns its request id.",
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
        METHOD_REGISTRY
            .iter()
            .find(|spec| spec.method == self)
            .expect("every Method variant must have one registry entry")
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
pub(crate) enum Stream {
    WifiStatus,
    NetworkConnectivity,
    WifiScan,
    WifiConnect,
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

pub(crate) const STREAM_REGISTRY: &[StreamSpec] = &[
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
        STREAM_REGISTRY
            .iter()
            .find(|spec| spec.stream == self)
            .expect("every Stream variant must have one registry entry")
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
        }
        assert_eq!(Method::parse("wifi.connect-target"), None);

        names.clear();
        for spec in STREAM_REGISTRY {
            assert!(names.insert(spec.name));
            assert_eq!(Stream::parse(spec.name), Some(spec.stream));
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
