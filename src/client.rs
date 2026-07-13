use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::blocking::{Connection, Proxy};

use crate::daemon::{DBUS_BUS_NAME, DBUS_INTERFACE, DBUS_OBJECT_PATH};

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
    pending_events: HashMap<String, Vec<(String, Value)>>,
}

/// Run one frontend-owned D-Bus session over newline-delimited JSON.
///
/// Calls and events share stdout, so each emitted line is an atomic JSON object. The process keeps
/// a single session-bus connection and cancels every known request/subscription when stdin closes.
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
    );

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.context("read frontend client request")?;
        if line.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<ClientRequest>(&line) {
            Ok(request) => request,
            Err(error) => {
                emit(
                    &output_lock,
                    &json!({ "kind": "protocol-error", "error": error.to_string() }),
                )?;
                continue;
            }
        };
        if handle_request(&proxy, request, &output_lock, &state)? {
            break;
        }
    }

    cancel_all(&proxy, &state);
    Ok(())
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
            let result = proxy.call::<_, _, ()>("Cancel", &(request_id.as_str(),));
            if result.is_ok() {
                state
                    .lock()
                    .expect("frontend client state poisoned")
                    .active_ids
                    .remove(&request_id);
            }
            emit_transport_response(
                output_lock,
                &id,
                result.map(|()| json!({ "cancelled": request_id })),
            )?;
        }
        ClientRequest::Shutdown { id } => {
            emit_transport_response(output_lock, &id, Ok(json!({ "shutdown": true })))?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn emit_dbus_response(
    output_lock: &Mutex<()>,
    state: &Mutex<ClientState>,
    id: &str,
    result: zbus::Result<String>,
) -> Result<()> {
    match result {
        Ok(response_json) => match serde_json::from_str::<Value>(&response_json) {
            Ok(response) => {
                let active_id = response_active_id(&response).map(ToString::to_string);
                emit(
                    output_lock,
                    &json!({ "kind": "response", "id": id, "ok": true, "response": response }),
                )?;
                if let Some(active_id) = active_id {
                    let pending = {
                        let mut state = state.lock().expect("frontend client state poisoned");
                        state.active_ids.insert(active_id.clone());
                        state.pending_events.remove(&active_id).unwrap_or_default()
                    };
                    for (stream, event) in pending {
                        emit(
                            output_lock,
                            &json!({ "kind": "event", "stream": stream, "event": event }),
                        )?;
                        forget_terminal_id(state, &event);
                    }
                }
                Ok(())
            }
            Err(error) => emit(
                output_lock,
                &json!({ "kind": "response", "id": id, "ok": false, "error": format!("invalid nm-api response: {error}") }),
            ),
        },
        Err(error) => emit(
            output_lock,
            &json!({ "kind": "response", "id": id, "ok": false, "error": error.to_string() }),
        ),
    }
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
        Err(error) => emit(
            output_lock,
            &json!({ "kind": "response", "id": id, "ok": false, "error": error.to_string() }),
        ),
    }
}

fn response_active_id(response: &Value) -> Option<&str> {
    response
        .pointer("/data/result/request_id")
        .or_else(|| response.pointer("/data/subscription/id"))
        .and_then(Value::as_str)
}

fn spawn_event_forwarder(
    connection: Connection,
    output_lock: Arc<Mutex<()>>,
    state: Arc<Mutex<ClientState>>,
) {
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
        .expect("spawn frontend event forwarding thread");
}

fn forward_event(
    output_lock: &Mutex<()>,
    state: &Mutex<ClientState>,
    stream: String,
    event: Value,
) -> Result<()> {
    let request_id = event.get("request_id").and_then(Value::as_str);
    let correlated = matches!(
        stream.as_str(),
        "wifi.status" | "network.connectivity" | "wifi.scan" | "wifi.connect"
    ) || event.get("event").and_then(Value::as_str) == Some("subscribed");
    if correlated && let Some(request_id) = request_id {
        let mut state = state.lock().expect("frontend client state poisoned");
        if !state.active_ids.contains(request_id) {
            if state.pending_events.len() >= 32
                && let Some(oldest) = state.pending_events.keys().next().cloned()
            {
                state.pending_events.remove(&oldest);
            }
            state
                .pending_events
                .entry(request_id.to_string())
                .or_default()
                .push((stream, event));
            return Ok(());
        }
    }
    emit(
        output_lock,
        &json!({ "kind": "event", "stream": stream, "event": event }),
    )?;
    forget_terminal_id(state, &event);
    Ok(())
}

fn forget_terminal_id(state: &Mutex<ClientState>, event: &Value) {
    let terminal = matches!(
        event.get("event").and_then(Value::as_str),
        Some("complete" | "succeeded" | "failed" | "cancelled")
    );
    if !terminal {
        return;
    }
    if let Some(request_id) = event.get("request_id").and_then(Value::as_str) {
        state
            .lock()
            .expect("frontend client state poisoned")
            .active_ids
            .remove(request_id);
    }
}

fn cancel_all(proxy: &Proxy<'_>, state: &Mutex<ClientState>) {
    let ids = state
        .lock()
        .expect("frontend client state poisoned")
        .active_ids
        .drain()
        .collect::<Vec<_>>();
    for id in ids {
        let _ = proxy.call::<_, _, ()>("Cancel", &(id.as_str(),));
    }
}

fn emit(output_lock: &Mutex<()>, value: &Value) -> Result<()> {
    let _guard = output_lock.lock().expect("frontend output lock poisoned");
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, value).context("serialize frontend JSON Line")?;
    stdout.write_all(b"\n").context("write frontend newline")?;
    stdout.flush().context("flush frontend JSON Line")
}

#[cfg(test)]
mod tests {
    use super::{ClientState, forget_terminal_id, response_active_id};
    use serde_json::json;
    use std::sync::Mutex;

    #[test]
    fn tracks_async_request_and_subscription_lifetimes() {
        let active = Mutex::new(ClientState::default());
        for response in [
            json!({ "data": { "result": { "request_id": "scan-1" } } }),
            json!({ "data": { "subscription": { "id": "sub-1" } } }),
        ] {
            active
                .lock()
                .unwrap()
                .active_ids
                .insert(response_active_id(&response).unwrap().to_string());
        }
        assert_eq!(active.lock().unwrap().active_ids.len(), 2);

        forget_terminal_id(
            &active,
            &json!({ "event": "complete", "request_id": "scan-1" }),
        );
        let active = active.lock().unwrap();
        assert!(!active.active_ids.contains("scan-1"));
        assert!(active.active_ids.contains("sub-1"));
    }
}
