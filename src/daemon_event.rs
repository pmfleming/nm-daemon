use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::error::{DomainError, ErrorOperation, best_effort};
use crate::protocol::Stream;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn next_request_id(prefix: &str) -> String {
    let value = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
    format!("{prefix}-{value}")
}

pub(crate) fn event_json(
    stream: Stream,
    request_id: Option<&str>,
    event: &str,
    mut data: Value,
) -> String {
    if let Value::Object(object) = &mut data {
        object.insert("protocol".to_string(), json!(crate::output::API_PROTOCOL));
        object.insert("version".to_string(), json!(crate::output::API_VERSION));
        object.insert("stream".to_string(), json!(stream));
        object.insert("event".to_string(), json!(event));
        if let Some(request_id) = request_id {
            object
                .entry("request_id".to_string())
                .or_insert_with(|| json!(request_id));
        }
    }
    serde_json::to_string(&data).unwrap_or_else(|err| fallback_event_json(stream, err))
}

pub(crate) fn emit_json_event(
    emitter: &SignalEmitter<'_>,
    stream: Stream,
    request_id: Option<&str>,
    event: &str,
    data: Value,
) -> Result<()> {
    if !stream.spec().events.contains(&event) {
        return Err(DomainError::internal(
            ErrorOperation::EmitEvent,
            format!("event '{event}' is not registered for stream '{stream}'"),
        )
        .with_detail("stream", stream.as_str())
        .with_detail("event", event)
        .into());
    }
    crate::daemon::emit_event_signal(emitter, stream, event_json(stream, request_id, event, data))
}

pub(crate) fn emit_json_event_nonfatal(
    emitter: &SignalEmitter<'_>,
    stream: Stream,
    request_id: Option<&str>,
    event: &str,
    data: Value,
) {
    best_effort(
        format!("failed to emit registered JSON event {stream}.{event}"),
        || emit_json_event(emitter, stream, request_id, event, data),
    );
}

fn fallback_event_json(stream: Stream, err: serde_json::Error) -> String {
    json!({
        "protocol": crate::output::API_PROTOCOL,
        "version": crate::output::API_VERSION,
        "stream": stream,
        "event": "failed",
        "message": format!("serialize event JSON: {err}"),
    })
    .to_string()
}
