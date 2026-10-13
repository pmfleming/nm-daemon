use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use shelllist_daemon_core::{ApiError, ApiIdentity, Correlation, wire::Event};
use zbus::object_server::SignalEmitter;

use crate::error::{DomainError, ErrorCode, ErrorOperation, ErrorReport, best_effort};
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};

pub(crate) fn event_value(
    stream: Stream,
    request_id: Option<&str>,
    event: &str,
    mut data: Value,
) -> Value {
    let mut error = None;
    if let Some(code) = data.get("code").and_then(Value::as_str) {
        error = Some(
            ApiError::new(code, data["message"].as_str().unwrap_or("Operation failed"))
                .with_details(data["details"].clone()),
        );
    }
    // Correlation is envelope-owned. Domain IDs must not override it.
    if let Some(object) = data.as_object_mut() {
        object.remove("request_id");
    }
    let mut envelope = Event::new(
        ApiIdentity::new(crate::output::API_PROTOCOL, crate::output::API_VERSION),
        stream.as_str(),
        event,
        request_id.map_or(Correlation::None, Correlation::Request),
        data,
    );
    if let Some(error) = error {
        envelope = envelope.with_error(error);
    }
    envelope.into_value().expect("NM event is JSON")
}

pub(crate) fn event_json(
    stream: Stream,
    request_id: Option<&str>,
    event: &str,
    data: Value,
) -> String {
    event_value(stream, request_id, event, data).to_string()
}

pub(crate) fn emit_json_event(
    emitter: &SignalEmitter<'_>,
    stream: Stream,
    request_id: Option<&str>,
    event: &str,
    data: Value,
) -> Result<()> {
    emit_prepared_event(
        emitter,
        stream,
        event_value(stream, request_id, event, data),
    )
}

/// Stored operation results are already envelopes; never wrap them a second time.
pub(crate) fn emit_prepared_event(
    emitter: &SignalEmitter<'_>,
    stream: Stream,
    value: Value,
) -> Result<()> {
    let event = value["event"].as_str().unwrap_or("");
    if !stream.spec().events.contains(&event) {
        return Err(DomainError::internal(
            ErrorOperation::EmitEvent,
            format!("event '{event}' is not registered for stream '{stream}'"),
        )
        .with_detail("stream", stream.as_str())
        .with_detail("event", event)
        .into());
    }
    crate::daemon::emit_event_signal(emitter, stream, value.to_string())
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

pub(crate) fn started_response(
    method: Method,
    stream: Stream,
    request_id: &str,
    message: &str,
    mut details: Value,
) -> Result<Value> {
    let object = details.as_object_mut().ok_or_else(|| {
        DomainError::internal(
            ErrorOperation::SerializeResponse,
            "operation start response details must be a JSON object",
        )
    })?;
    object.insert("status".into(), json!("started"));
    object.insert("request_id".into(), json!(request_id));
    object.insert("stream".into(), json!(stream));
    object.insert("message".into(), json!(message));
    api_data_value(
        method.spec().response_key,
        &details,
        "serialize operation start response JSON",
    )
}

pub(crate) struct OperationEvents<'a, 'e> {
    emitter: &'a SignalEmitter<'e>,
    stream: Stream,
    request_id: &'a str,
}

impl<'a, 'e> OperationEvents<'a, 'e> {
    pub(crate) fn new(emitter: &'a SignalEmitter<'e>, stream: Stream, request_id: &'a str) -> Self {
        Self {
            emitter,
            stream,
            request_id,
        }
    }

    pub(crate) fn event(&self, event: &str, data: Value) {
        emit_json_event_nonfatal(
            self.emitter,
            self.stream,
            Some(self.request_id),
            event,
            data,
        );
    }

    pub(crate) fn phase(&self, event: &str, phase: &str) {
        self.event(
            event,
            json!({ "request_id": self.request_id, "phase": phase }),
        );
    }

    pub(crate) fn succeeded(&self, result: &impl Serialize) {
        self.event(
            "succeeded",
            json!({ "request_id": self.request_id, "phase": "complete", "result": result }),
        );
    }

    pub(crate) fn cancelled(&self, message: &str) {
        self.event(
            "cancelled",
            json!({ "request_id": self.request_id, "phase": "cancelled", "message": message }),
        );
    }

    pub(crate) fn error(
        &self,
        error: &anyhow::Error,
        operation: ErrorOperation,
        cancellation_message: &str,
    ) {
        let report = ErrorReport::from_error(error, operation);
        if report.code == ErrorCode::Cancelled {
            tracing::info!(request_id = self.request_id, stream = %self.stream, "emitting operation cancellation");
            self.cancelled(cancellation_message);
        } else {
            tracing::warn!(
                request_id = self.request_id,
                stream = %self.stream,
                code = ?report.code,
                message = %report.message,
                "emitting operation failure"
            );
            self.event(
                "failed",
                json!({
                    "request_id": self.request_id,
                    "phase": "failed",
                    "code": report.code,
                    "message": report.message,
                    "details": report.api_details(),
                }),
            );
        }
    }
}
