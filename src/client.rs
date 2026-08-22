use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::blocking::{Connection, Proxy};

use crate::protocol::{DBUS_BUS_NAME, DBUS_INTERFACE, DBUS_OBJECT_PATH};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum ClientRequest {
    Call {
        id: String,
        method: String,
        #[serde(default)]
        params: Value,
    },
    Subscribe {
        id: String,
        #[serde(default)]
        streams: Vec<String>,
    },
    Cancel {
        id: String,
        request_id: String,
    },
    Shutdown {
        id: String,
    },
}

#[derive(Default)]
struct ClientState {
    active_ids: HashSet<String>,
    subscription_ids: HashSet<String>,
    pending_events: HashMap<String, Vec<(String, Value)>>,
    pending_event_order: VecDeque<String>,
}

impl ClientState {
    fn take_pending_events(&mut self, request_id: &str) -> Vec<(String, Value)> {
        self.pending_event_order.retain(|id| id != request_id);
        self.pending_events.remove(request_id).unwrap_or_default()
    }

    fn buffer_event(&mut self, request_id: String, stream: String, event: Value) {
        if !self.pending_events.contains_key(&request_id) {
            if self.pending_events.len() >= 32
                && let Some(oldest) = self.pending_event_order.pop_front()
            {
                self.pending_events.remove(&oldest);
            }
            self.pending_event_order.push_back(request_id.clone());
        }
        self.pending_events
            .entry(request_id)
            .or_default()
            .push((stream, event));
    }
}

/// Runs one frontend D-Bus session over atomic newline-delimited JSON messages.
pub(crate) fn run() -> Result<()> {
    let connection = Connection::session().context("connect frontend client to session D-Bus")?;
    let proxy = Proxy::new(&connection, DBUS_BUS_NAME, DBUS_OBJECT_PATH, DBUS_INTERFACE)
        .context("create nm-daemon frontend proxy")?;
    let output_lock = Arc::new(Mutex::new(()));
    let state = Arc::new(Mutex::new(ClientState::default()));
    spawn_event_forwarder(
        connection.clone(),
        Arc::clone(&output_lock),
        Arc::clone(&state),
    )?;

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.context("read frontend client request")?;
        if handle_line(&proxy, &line, &output_lock, &state)? {
            break;
        }
    }

    cancel_all(&proxy, &state);
    Ok(())
}

fn handle_line(
    proxy: &Proxy<'_>,
    line: &str,
    output_lock: &Mutex<()>,
    state: &Mutex<ClientState>,
) -> Result<bool> {
    if line.trim().is_empty() {
        return Ok(false);
    }
    match serde_json::from_str::<ClientRequest>(line) {
        Ok(request) => handle_request(proxy, request, output_lock, state),
        Err(error) => {
            emit(
                output_lock,
                &json!({ "kind": "protocol-error", "error": error.to_string() }),
            )?;
            Ok(false)
        }
    }
}

fn handle_request(
    proxy: &Proxy<'_>,
    request: ClientRequest,
    output_lock: &Mutex<()>,
    state: &Mutex<ClientState>,
) -> Result<bool> {
    match request {
        ClientRequest::Call { id, method, params } => {
            let params_json = serde_json::to_string(&params).context("serialize call params")?;
            let result: zbus::Result<String> =
                proxy.call("Call", &(method.as_str(), params_json.as_str()));
            emit_dbus_response(output_lock, state, &id, result)?;
        }
        ClientRequest::Subscribe { id, streams } => {
            let result: zbus::Result<String> = proxy.call("Subscribe", &(streams,));
            emit_dbus_response(output_lock, state, &id, result)?;
        }
        ClientRequest::Cancel { id, request_id } => {
            handle_cancel(proxy, output_lock, state, &id, request_id)?;
        }
        ClientRequest::Shutdown { id } => {
            emit_transport_response(output_lock, &id, Ok(json!({ "shutdown": true })))?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn handle_cancel(
    proxy: &Proxy<'_>,
    output_lock: &Mutex<()>,
    state: &Mutex<ClientState>,
    id: &str,
    request_id: String,
) -> Result<()> {
    let result = proxy
        .call::<_, _, ()>("Cancel", &(request_id.as_str(),))
        .inspect(|()| forget_cancelled_subscription(state, &request_id));
    emit_transport_response(
        output_lock,
        id,
        result.map(|()| json!({ "cancelled": request_id })),
    )
}

fn emit_dbus_response(
    output_lock: &Mutex<()>,
    state: &Mutex<ClientState>,
    id: &str,
    result: zbus::Result<String>,
) -> Result<()> {
    let response_json = match result {
        Ok(response) => response,
        Err(error) => return emit_response_error(output_lock, id, error.to_string()),
    };
    let response = match serde_json::from_str::<Value>(&response_json) {
        Ok(response) => response,
        Err(error) => {
            return emit_response_error(
                output_lock,
                id,
                format!("invalid nm-api response: {error}"),
            );
        }
    };
    let active_id = response_active_id(&response).map(ToString::to_string);
    let subscription_id = response_subscription_id(&response).map(ToString::to_string);
    emit(
        output_lock,
        &json!({ "kind": "response", "id": id, "ok": true, "response": response }),
    )?;
    flush_pending_events(output_lock, state, active_id, subscription_id)
}

fn emit_response_error(output_lock: &Mutex<()>, id: &str, error: String) -> Result<()> {
    emit(
        output_lock,
        &json!({ "kind": "response", "id": id, "ok": false, "error": error }),
    )
}

fn flush_pending_events(
    output_lock: &Mutex<()>,
    state: &Mutex<ClientState>,
    active_id: Option<String>,
    subscription_id: Option<String>,
) -> Result<()> {
    let Some(active_id) = active_id else {
        return Ok(());
    };
    let pending = {
        let mut state = recover_lock(state, "frontend client state");
        let pending = state.take_pending_events(&active_id);
        state.active_ids.insert(active_id.clone());
        if subscription_id.as_deref() == Some(active_id.as_str()) {
            state.subscription_ids.insert(active_id);
        }
        pending
    };
    for (stream, event) in pending {
        emit(
            output_lock,
            &json!({ "kind": "event", "stream": stream, "event": event }),
        )?;
        forget_terminal_id(state, &stream, &event);
    }
    Ok(())
}

fn emit_transport_response(
    output_lock: &Mutex<()>,
    id: &str,
    result: zbus::Result<Value>,
) -> Result<()> {
    match result {
        Ok(response) => emit(
            output_lock,
            &json!({ "kind": "response", "id": id, "ok": true, "response": response }),
        ),
        Err(error) => emit_response_error(output_lock, id, error.to_string()),
    }
}

fn response_active_id(response: &Value) -> Option<&str> {
    response
        .pointer("/data/result/request_id")
        .or_else(|| response.pointer("/data/subscription/id"))
        .and_then(Value::as_str)
}

fn response_subscription_id(response: &Value) -> Option<&str> {
    response
        .pointer("/data/subscription/id")
        .and_then(Value::as_str)
}

fn spawn_event_forwarder(
    connection: Connection,
    output_lock: Arc<Mutex<()>>,
    state: Arc<Mutex<ClientState>>,
) -> Result<()> {
    std::thread::Builder::new()
        .name("nm-frontend-events".to_string())
        .spawn(move || {
            let result = (|| -> Result<()> {
                let proxy =
                    Proxy::new(&connection, DBUS_BUS_NAME, DBUS_OBJECT_PATH, DBUS_INTERFACE)?;
                let mut events = proxy.receive_signal("Event")?;
                for message in &mut events {
                    let (stream, event_json): (String, String) = message.body().deserialize()?;
                    let event = serde_json::from_str::<Value>(&event_json)
                        .unwrap_or_else(|_| json!({ "raw": event_json }));
                    forward_event(&output_lock, &state, stream, event)?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                let _ = emit(
                    &output_lock,
                    &json!({ "kind": "transport-error", "error": error.to_string() }),
                );
            }
        })
        .context("spawn frontend event forwarding thread")?;
    Ok(())
}

fn forward_event(
    output_lock: &Mutex<()>,
    state: &Mutex<ClientState>,
    stream: String,
    event: Value,
) -> Result<()> {
    let request_id = event.get("request_id").and_then(Value::as_str);
    let correlated = needs_correlation(&stream)
        || event.get("event").and_then(Value::as_str) == Some("subscribed");
    if correlated && let Some(request_id) = request_id {
        let mut state = recover_lock(state, "frontend client state");
        if !state.active_ids.contains(request_id) {
            state.buffer_event(request_id.to_string(), stream, event);
            return Ok(());
        }
    }
    emit(
        output_lock,
        &json!({ "kind": "event", "stream": stream, "event": event }),
    )?;
    forget_terminal_id(state, &stream, &event);
    Ok(())
}

/// True for streams whose events are only meaningful next to the response that
/// produced their request id. Buffering those until the caller has seen the
/// response keeps a fast `started` event from arriving before it. The set is
/// derived from the stream registry so a newly added operation stream is
/// correlated without editing a second list.
fn needs_correlation(stream: &str) -> bool {
    crate::protocol::Stream::parse(stream).is_some_and(|stream| {
        matches!(
            stream.spec().delivery,
            crate::protocol::StreamDelivery::Operation
                | crate::protocol::StreamDelivery::Continuous
        )
    })
}

fn forget_terminal_id(state: &Mutex<ClientState>, stream: &str, event: &Value) {
    let terminal = matches!(
        event.get("event").and_then(Value::as_str),
        Some("complete" | "succeeded" | "failed" | "cancelled")
    );
    let operation_stream = crate::protocol::Stream::parse(stream)
        .is_some_and(|stream| stream.spec().delivery == crate::protocol::StreamDelivery::Operation);
    if !terminal || !operation_stream {
        return;
    }
    if let Some(request_id) = event.get("request_id").and_then(Value::as_str) {
        recover_lock(state, "frontend client state")
            .active_ids
            .remove(request_id);
    }
}

fn forget_cancelled_subscription(state: &Mutex<ClientState>, request_id: &str) {
    let mut state = recover_lock(state, "frontend client state");
    if state.subscription_ids.remove(request_id) {
        state.active_ids.remove(request_id);
    }
}

fn cancel_all(proxy: &Proxy<'_>, state: &Mutex<ClientState>) {
    let ids = {
        let mut state = recover_lock(state, "frontend client state");
        state.subscription_ids.clear();
        state.active_ids.drain().collect::<Vec<_>>()
    };
    for id in ids {
        let _ = proxy.call::<_, _, ()>("Cancel", &(id.as_str(),));
    }
}

fn recover_lock<'a, T>(mutex: &'a Mutex<T>, name: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!(resource = name, "recovering poisoned frontend client lock");
            poisoned.into_inner()
        }
    }
}

fn emit(output_lock: &Mutex<()>, value: &Value) -> Result<()> {
    let _guard = recover_lock(output_lock, "frontend output");
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, value).context("serialize frontend JSON Line")?;
    stdout.write_all(b"\n").context("write frontend newline")?;
    stdout.flush().context("flush frontend JSON Line")
}

#[cfg(test)]
mod tests {
    use super::{
        ClientState, forget_cancelled_subscription, forget_terminal_id, response_active_id,
        response_subscription_id,
    };
    use serde_json::json;
    use std::sync::Mutex;

    #[test]
    fn buffered_events_evict_the_oldest_request() {
        let mut state = ClientState::default();
        for index in 0..33 {
            state.buffer_event(
                format!("request-{index}"),
                "wifi.scan".to_string(),
                json!({ "index": index }),
            );
        }
        assert!(!state.pending_events.contains_key("request-0"));
        assert!(state.pending_events.contains_key("request-1"));
        assert!(state.pending_events.contains_key("request-32"));
        assert_eq!(
            state.pending_event_order.front().map(String::as_str),
            Some("request-1")
        );
    }

    #[test]
    fn every_operation_and_continuous_stream_is_correlated_with_its_response() {
        for spec in crate::protocol::STREAM_REGISTRY {
            let expected = matches!(
                spec.delivery,
                crate::protocol::StreamDelivery::Operation
                    | crate::protocol::StreamDelivery::Continuous
            );
            assert_eq!(
                super::needs_correlation(spec.name),
                expected,
                "{}",
                spec.name
            );
        }
        assert!(!super::needs_correlation("not.a.stream"));
    }

    #[test]
    fn tracks_async_request_and_subscription_lifetimes() {
        let active = Mutex::new(ClientState::default());
        let operation = json!({ "data": { "result": { "request_id": "scan-1" } } });
        let subscription = json!({ "data": { "subscription": { "id": "sub-1" } } });
        {
            let mut state = active.lock().unwrap();
            state
                .active_ids
                .insert(response_active_id(&operation).unwrap().to_string());
            let subscription_id = response_subscription_id(&subscription).unwrap().to_string();
            state.active_ids.insert(subscription_id.clone());
            state.subscription_ids.insert(subscription_id);
        }

        // The daemon's immediate cancellation acknowledgement is internal;
        // the operation remains correlated until its own stream terminates.
        forget_terminal_id(
            &active,
            "daemon.request",
            &json!({ "event": "cancelled", "request_id": "scan-1" }),
        );
        assert!(active.lock().unwrap().active_ids.contains("scan-1"));
        forget_terminal_id(
            &active,
            "wifi.scan",
            &json!({ "event": "cancelled", "request_id": "scan-1" }),
        );
        assert!(!active.lock().unwrap().active_ids.contains("scan-1"));

        forget_cancelled_subscription(&active, "sub-1");
        let active = active.lock().unwrap();
        assert!(!active.active_ids.contains("sub-1"));
        assert!(!active.subscription_ids.contains("sub-1"));
    }
}
