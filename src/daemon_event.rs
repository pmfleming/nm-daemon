use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

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
