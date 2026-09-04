use anyhow::Result;
use serde_json::Value;
use shelllist_daemon_core::DaemonEndpoint;
use shelllist_daemon_tokio::{
    CallFailure, CancelMode, CorrelationPolicy, JsonlClientConfig, TrackedId, TrackedKind,
    run_jsonl_client,
};

use crate::protocol::{DBUS_BUS_NAME, DBUS_INTERFACE, DBUS_OBJECT_PATH};

const ENDPOINT: DaemonEndpoint =
    DaemonEndpoint::new("nm-daemon", DBUS_BUS_NAME, DBUS_OBJECT_PATH, DBUS_INTERFACE);

#[derive(Debug, Clone, Copy)]
struct NmCorrelation;

impl CorrelationPolicy for NmCorrelation {
    fn response_id(&self, response: &Value) -> Option<TrackedId> {
        if let Some(id) = response
            .pointer("/data/result/request_id")
            .and_then(Value::as_str)
        {
            return Some(TrackedId {
                id: id.to_string(),
                kind: TrackedKind::Operation,
            });
        }
        response
            .pointer("/data/subscription/id")
            .and_then(Value::as_str)
            .map(|id| TrackedId {
                id: id.to_string(),
                kind: TrackedKind::Subscription,
            })
    }

    fn event_id(&self, stream: &str, event: &Value) -> Option<String> {
        let correlated = needs_correlation(stream)
            || event.get("event").and_then(Value::as_str) == Some("subscribed");
        correlated
            .then(|| event.get("request_id").and_then(Value::as_str))
            .flatten()
            .map(str::to_owned)
    }

    fn is_terminal(&self, stream: &str, event: &Value) -> bool {
        let terminal = matches!(
            event.get("event").and_then(Value::as_str),
            Some("complete" | "succeeded" | "failed" | "cancelled")
        );
        terminal
            && crate::protocol::Stream::parse(stream).is_some_and(|stream| {
                stream.spec().delivery == crate::protocol::StreamDelivery::Operation
            })
    }
}

fn needs_correlation(stream: &str) -> bool {
    crate::protocol::Stream::parse(stream).is_some_and(|stream| {
        matches!(
            stream.spec().delivery,
            crate::protocol::StreamDelivery::Operation
                | crate::protocol::StreamDelivery::Continuous
        )
    })
}

fn call_failure(method: &str, error: &anyhow::Error) -> CallFailure {
    tracing::warn!(%method, error = %error, error_chain = %format!("{error:#}"), "client call to daemon failed");
    CallFailure::Transport(error.to_string())
}

/// Runs one frontend D-Bus session over atomic newline-delimited JSON messages.
pub(crate) async fn run() -> Result<()> {
    run_jsonl_client(JsonlClientConfig {
        endpoint: ENDPOINT,
        correlation: NmCorrelation,
        cancel_mode: CancelMode::Unit,
        call_failure,
        pending_event_limit: 32,
        max_in_flight_requests: 64,
        shutdown_timeout: Some(std::time::Duration::from_secs(5)),
    })
    .await
}

#[cfg(test)]
mod tests {

    use super::needs_correlation;

    #[test]
    fn every_operation_and_continuous_stream_is_correlated_with_its_response() {
        for spec in crate::protocol::STREAM_REGISTRY {
            let expected = matches!(
                spec.delivery,
                crate::protocol::StreamDelivery::Operation
                    | crate::protocol::StreamDelivery::Continuous
            );
            assert_eq!(needs_correlation(spec.name), expected, "{}", spec.name);
        }
        assert!(!needs_correlation("not.a.stream"));
    }
}
