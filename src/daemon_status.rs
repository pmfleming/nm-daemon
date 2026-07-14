use serde_json::{Map, Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::Application;
use crate::daemon::emit_json_event_nonfatal;
use crate::daemon_runtime::SharedPayloads;
use crate::nm::Nm;
use crate::protocol::{Method, Stream, StreamDelivery};

pub(crate) struct SubscriptionState {
    id: String,
    owner: Option<String>,
    streams: Vec<Stream>,
    emitter: SignalEmitter<'static>,
    last_status: Option<Value>,
    last_connectivity: Option<Value>,
}

impl SubscriptionState {
    pub(crate) fn new(
        id: String,
        owner: Option<String>,
        streams: Vec<Stream>,
        emitter: SignalEmitter<'static>,
    ) -> Self {
        Self {
            id,
            owner,
            streams: streams
                .into_iter()
                .filter(|stream| stream.spec().delivery == StreamDelivery::Continuous)
                .collect(),
            emitter,
            last_status: None,
            last_connectivity: None,
        }
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn watches(&self, stream: Stream) -> bool {
        self.streams.contains(&stream)
    }

    pub(crate) fn owned_by(&self, owner: &str) -> bool {
        self.owner.as_deref() == Some(owner)
    }

    pub(crate) fn emit_changes(&mut self, payloads: &SharedPayloads) {
        if self.watches(Stream::WifiStatus)
            && let Some(value) = &payloads.status
        {
            emit_on_change(
                &self.emitter,
                Stream::WifiStatus,
                &self.id,
                Method::WifiStatus,
                &mut self.last_status,
                value,
            );
        }
        if self.watches(Stream::NetworkConnectivity)
            && let Some(value) = &payloads.connectivity
        {
            emit_on_change(
                &self.emitter,
                Stream::NetworkConnectivity,
                &self.id,
                Method::NetworkConnectivity,
                &mut self.last_connectivity,
                value,
            );
        }
    }
}

pub(crate) fn refresh_payloads(
    nm: &Nm,
    need_status: bool,
    need_connectivity: bool,
) -> SharedPayloads {
    let application = Application::new(nm);
    let status = need_status
        .then(|| application.status())
        .and_then(log_typed_refresh_error);
    let connectivity_from_status = status
        .as_ref()
        .and_then(|status| status.connectivity.clone());
    SharedPayloads {
        status: status.map(|status| json!(status)),
        connectivity: need_connectivity
            .then(|| match connectivity_from_status {
                Some(connectivity) => Ok(json!(connectivity)),
                None => application
                    .connectivity()
                    .map(|connectivity| json!(connectivity)),
            })
            .and_then(log_refresh_error),
    }
}

fn log_typed_refresh_error<T>(result: anyhow::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(error = %crate::error::err_chain(&error), "shared subscription refresh failed");
            None
        }
    }
}

fn log_refresh_error(result: anyhow::Result<Value>) -> Option<Value> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(error = %crate::error::err_chain(&error), "shared subscription refresh failed");
            None
        }
    }
}

fn emit_on_change(
    emitter: &SignalEmitter<'static>,
    stream: Stream,
    subscription_id: &str,
    method: Method,
    last: &mut Option<Value>,
    value: &Value,
) {
    if last.as_ref() == Some(value) {
        return;
    }
    *last = Some(value.clone());
    let mut payload = Map::new();
    payload.insert("subscription_id".to_string(), json!(subscription_id));
    payload.insert(method.spec().response_key.to_string(), value.clone());
    emit_json_event_nonfatal(
        emitter,
        stream,
        Some(subscription_id),
        "changed",
        Value::Object(payload),
    );
}
