//! A failed wait is not evidence that an effect was never dispatched.
use anyhow::Result;
use serde_json::{Value, json};
use zbus::{blocking::Proxy, names::OwnedUniqueName};

use super::parse_response;
use crate::error::{DomainError, ErrorCode, ErrorSource};
use crate::protocol::{DBUS_INTERFACE, DBUS_OBJECT_PATH, Method, Stream};

pub(super) struct Reply {
    pub body: String,
    pub owner: Option<OwnedUniqueName>,
}

/// None is reserved for a broker-authenticated pre-dispatch failure. Never
/// infer safety from timeout text, a preflight owner lookup, or a daemon error.
pub(super) fn call(proxy: &Proxy<'_>, method: Method, params: &str) -> Result<Option<Reply>> {
    match proxy.call_method("Call", &(method.as_str(), params)) {
        Ok(message) => Ok(Some(Reply {
            body: message
                .body()
                .deserialize::<String>()
                .map_err(|error| unknown(method, None, error.into()))?,
            owner: message
                .header()
                .sender()
                .map(|owner| owner.to_owned().into()),
        })),
        Err(error) if not_dispatched(&error) => {
            tracing::debug!(%method, "session bus could not dispatch daemon call; direct fallback is safe");
            Ok(None)
        }
        Err(error) => Err(unknown(method, None, error.into())),
    }
}

fn not_dispatched(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, reply)
        if reply.header().sender().is_some_and(|sender| sender.as_str() == "org.freedesktop.DBus")
            && matches!(name.as_str(),
                "org.freedesktop.DBus.Error.ServiceUnknown" | "org.freedesktop.DBus.Error.NameHasNoOwner"))
}

pub(super) fn unknown(
    method: Method,
    request_id: Option<&str>,
    cause: anyhow::Error,
) -> anyhow::Error {
    let mut error = DomainError::new(
        ErrorCode::OutcomeUnknown,
        method.spec().operation,
        ErrorSource::Dbus,
        "Daemon command outcome unknown; command was not retried. Check current network state before trying again.",
    )
    .with_detail("method", method.as_str())
    .with_detail("retryable", false)
    .with_cause(cause);
    if let Some(request_id) = request_id {
        error = error.with_detail("request_id", request_id);
    }
    error.into()
}

/// Wi-Fi connect retains terminal results. Read once on the original caller's
/// connection, pinned to the daemon that acknowledged the operation. A new
/// daemon can reuse request IDs, so the well-known destination is unsafe here.
pub(super) fn recover_terminal(
    proxy: &Proxy<'_>,
    method: Method,
    stream: Stream,
    request_id: &str,
    owner: Option<&OwnedUniqueName>,
) -> Option<Value> {
    if method != Method::WifiConnectTarget {
        return None;
    }
    let owner = owner?;
    let recovery = Proxy::new(
        proxy.connection(),
        owner.as_str(),
        DBUS_OBJECT_PATH,
        DBUS_INTERFACE,
    )
    .ok()?;
    let params = json!({ "request_id": request_id }).to_string();
    let response: String = recovery
        .call("Call", &(Method::OperationStatus.as_str(), params))
        .ok()?;
    let response = parse_response(&response).ok()?;
    let status = response.pointer("/data/result")?;
    let event = status.get("event")?;
    (response["ok"] == true
        && status["request_id"] == request_id
        && status["status"] == "finished"
        && status["stream"] == stream.as_str()
        && event["protocol"] == crate::output::API_PROTOCOL
        && event["version"] == crate::output::API_VERSION
        && event["request_id"] == request_id
        && event["stream"] == stream.as_str()
        && matches!(
            event["event"].as_str(),
            Some("succeeded" | "failed" | "cancelled")
        ))
    .then(|| event.clone())
}
