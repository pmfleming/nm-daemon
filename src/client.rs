use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

use crate::protocol::{DBUS_BUS_NAME, DBUS_INTERFACE, DBUS_OBJECT_PATH};

const OUTPUT_QUEUE_CAPACITY: usize = 64;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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

    fn activate_response(&mut self, response: &Value) -> Vec<(String, Value)> {
        let Some(active_id) = response_active_id(response).map(ToString::to_string) else {
            return Vec::new();
        };
        let pending = self.take_pending_events(&active_id);
        self.active_ids.insert(active_id.clone());
        if response_subscription_id(response) == Some(active_id.as_str()) {
            self.subscription_ids.insert(active_id);
        }
        pending
    }

    fn forget_cancelled_subscription(&mut self, request_id: &str) {
        if self.subscription_ids.remove(request_id) {
            self.active_ids.remove(request_id);
            self.take_pending_events(request_id);
        }
    }

    fn forget_terminal_id(&mut self, stream: &str, event: &Value) {
        let terminal = matches!(
            event.get("event").and_then(Value::as_str),
            Some("complete" | "succeeded" | "failed" | "cancelled")
        );
        let operation_stream = crate::protocol::Stream::parse(stream).is_some_and(|stream| {
            stream.spec().delivery == crate::protocol::StreamDelivery::Operation
        });
        if terminal
            && operation_stream
            && let Some(request_id) = event.get("request_id").and_then(Value::as_str)
        {
            self.active_ids.remove(request_id);
        }
    }

    fn active_ids(&self) -> Vec<String> {
        let mut ids = self.active_ids.iter().cloned().collect::<Vec<_>>();
        ids.sort();
        ids
    }
}

enum OutputCommand {
    Response {
        id: String,
        result: std::result::Result<Value, String>,
        cancelled_request_id: Option<String>,
    },
    Event {
        stream: String,
        event: Value,
    },
    ProtocolError(String),
    TransportError(String),
    ActiveIds(oneshot::Sender<Vec<String>>),
    Shutdown(String),
}

type OutputSender = mpsc::Sender<OutputCommand>;

/// Runs one frontend D-Bus session over atomic newline-delimited JSON messages.
pub(crate) async fn run() -> Result<()> {
    let connection = zbus::Connection::session()
        .await
        .context("connect frontend client to session D-Bus")?;
    let (output_tx, output_rx) = mpsc::channel(OUTPUT_QUEUE_CAPACITY);
    let output_task = tokio::spawn(run_output_actor(output_rx));
    let event_task = spawn_event_forwarder(connection.clone(), output_tx.clone());
    let owner_task = spawn_owner_watcher(connection.clone(), output_tx.clone());

    let mut calls = JoinSet::new();
    let shutdown_id = request_loop(&connection, &output_tx, &mut calls).await?;
    drain_calls(&mut calls).await;
    cancel_active(&connection, &output_tx).await;

    event_task.abort();
    owner_task.abort();
    if let Some(id) = shutdown_id {
        output_tx
            .send(OutputCommand::Shutdown(id))
            .await
            .context("queue client shutdown response")?;
    }
    drop(output_tx);
    output_task
        .await
        .context("join client output task")?
        .context("run client output task")
}

async fn request_loop(
    connection: &zbus::Connection,
    output: &OutputSender,
    calls: &mut JoinSet<()>,
) -> Result<Option<String>> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await.context("read frontend request")? {
        let Some(request) = decode_and_report(&line, output).await? else {
            continue;
        };
        match request {
            ClientRequest::Shutdown { id } => return Ok(Some(id)),
            request => spawn_request(calls, connection.clone(), output.clone(), request),
        }
        reap_finished_calls(calls);
    }
    Ok(None)
}

async fn decode_and_report(line: &str, output: &OutputSender) -> Result<Option<ClientRequest>> {
    if line.trim().is_empty() {
        return Ok(None);
    }
    match serde_json::from_str(line) {
        Ok(request) => Ok(Some(request)),
        Err(error) => {
            output
                .send(OutputCommand::ProtocolError(error.to_string()))
                .await
                .context("queue client protocol error")?;
            Ok(None)
        }
    }
}

fn spawn_request(
    calls: &mut JoinSet<()>,
    connection: zbus::Connection,
    output: OutputSender,
    request: ClientRequest,
) {
    calls.spawn(async move {
        let (id, result, cancelled_request_id) = match request {
            ClientRequest::Call { id, method, params } => {
                let result = call_daemon(&connection, &method, params)
                    .await
                    .map_err(|error| error.to_string());
                (id, result, None)
            }
            ClientRequest::Subscribe { id, streams } => {
                let result = call_subscribe(&connection, streams)
                    .await
                    .map_err(|error| error.to_string());
                (id, result, None)
            }
            ClientRequest::Cancel { id, request_id } => {
                let result = call_cancel(&connection, &request_id)
                    .await
                    .map(|()| json!({ "cancelled": request_id }))
                    .map_err(|error| error.to_string());
                let cancelled = result.as_ref().ok().map(|_| request_id);
                (id, result, cancelled)
            }
            ClientRequest::Shutdown { .. } => unreachable!("shutdown is handled by request loop"),
        };
        let _ = output
            .send(OutputCommand::Response {
                id,
                result,
                cancelled_request_id,
            })
            .await;
    });
}

fn reap_finished_calls(calls: &mut JoinSet<()>) {
    while let Some(result) = calls.try_join_next() {
        if let Err(error) = result {
            tracing::warn!(%error, "frontend call task failed");
        }
    }
}

async fn drain_calls(calls: &mut JoinSet<()>) {
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
        while let Some(result) = calls.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "frontend call task failed during shutdown");
            }
        }
    })
    .await
    .is_err()
    {
        tracing::warn!("frontend shutdown timed out while waiting for calls");
        calls.abort_all();
        while calls.join_next().await.is_some() {}
    }
}

async fn cancel_active(connection: &zbus::Connection, output: &OutputSender) {
    let (reply, active_ids) = oneshot::channel();
    if output.send(OutputCommand::ActiveIds(reply)).await.is_err() {
        return;
    }
    let Ok(active_ids) = active_ids.await else {
        return;
    };
    for request_id in active_ids {
        if let Err(error) = call_cancel(connection, &request_id).await {
            tracing::debug!(%request_id, %error, "could not cancel request during client shutdown");
        }
    }
}

async fn daemon_proxy(connection: &zbus::Connection) -> Result<zbus::Proxy<'_>> {
    zbus::Proxy::new(connection, DBUS_BUS_NAME, DBUS_OBJECT_PATH, DBUS_INTERFACE)
        .await
        .context("create nm-daemon frontend proxy")
}

async fn call_daemon(connection: &zbus::Connection, method: &str, params: Value) -> Result<Value> {
    let proxy = daemon_proxy(connection).await?;
    let params_json = serde_json::to_string(&params).context("serialize call parameters")?;
    let response: String = proxy
        .call("Call", &(method, params_json.as_str()))
        .await
        .context("call nm-daemon")?;
    serde_json::from_str(&response).context("decode nm-daemon response")
}

async fn call_subscribe(connection: &zbus::Connection, streams: Vec<String>) -> Result<Value> {
    let proxy = daemon_proxy(connection).await?;
    let response: String = proxy
        .call("Subscribe", &(streams,))
        .await
        .context("subscribe to nm-daemon")?;
    serde_json::from_str(&response).context("decode nm-daemon subscription response")
}

async fn call_cancel(connection: &zbus::Connection, request_id: &str) -> Result<()> {
    let proxy = daemon_proxy(connection).await?;
    proxy
        .call::<_, _, ()>("Cancel", &(request_id,))
        .await
        .context("cancel nm-daemon request")
}

fn spawn_event_forwarder(connection: zbus::Connection, output: OutputSender) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) = forward_events(&connection, &output).await {
            let _ = output
                .send(OutputCommand::TransportError(error.to_string()))
                .await;
        }
    })
}

async fn forward_events(connection: &zbus::Connection, output: &OutputSender) -> Result<()> {
    let proxy = daemon_proxy(connection).await?;
    let mut events = proxy
        .receive_signal("Event")
        .await
        .context("receive nm-daemon events")?;
    while let Some(message) = events.next().await {
        let (stream, event_json): (String, String) = message
            .body()
            .deserialize()
            .context("decode nm-daemon event signal")?;
        let event = serde_json::from_str::<Value>(&event_json)
            .unwrap_or_else(|_| json!({ "raw": event_json }));
        output
            .send(OutputCommand::Event { stream, event })
            .await
            .context("queue nm-daemon event")?;
    }
    anyhow::bail!("nm-daemon event stream ended")
}

fn spawn_owner_watcher(connection: zbus::Connection, output: OutputSender) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) = watch_daemon_owner(&connection).await {
            let _ = output
                .send(OutputCommand::TransportError(error.to_string()))
                .await;
        }
    })
}

async fn watch_daemon_owner(connection: &zbus::Connection) -> Result<()> {
    let proxy = zbus::Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    .context("create D-Bus owner proxy")?;
    let mut changes = proxy
        .receive_signal("NameOwnerChanged")
        .await
        .context("receive D-Bus owner changes")?;
    while let Some(message) = changes.next().await {
        let (name, old_owner, new_owner): (String, String, String) =
            message
                .body()
                .deserialize()
                .context("decode D-Bus owner change")?;
        if name == DBUS_BUS_NAME && !old_owner.is_empty() && old_owner != new_owner {
            anyhow::bail!("nm-daemon restarted; reconnecting");
        }
    }
    anyhow::bail!("D-Bus owner-change stream ended")
}

async fn run_output_actor(mut commands: mpsc::Receiver<OutputCommand>) -> Result<()> {
    let mut output = tokio::io::stdout();
    let mut state = ClientState::default();
    while let Some(command) = commands.recv().await {
        match command {
            OutputCommand::Response {
                id,
                result,
                cancelled_request_id,
            } => {
                emit_response(&mut output, &id, &result).await?;
                if let Some(request_id) = cancelled_request_id {
                    state.forget_cancelled_subscription(&request_id);
                }
                if let Ok(response) = result {
                    for (stream, event) in state.activate_response(&response) {
                        emit_event(&mut output, &stream, &event).await?;
                        state.forget_terminal_id(&stream, &event);
                    }
                }
            }
            OutputCommand::Event { stream, event } => {
                if should_buffer_event(&state, &stream, &event) {
                    if let Some(request_id) = event.get("request_id").and_then(Value::as_str) {
                        state.buffer_event(request_id.to_string(), stream, event);
                    }
                    continue;
                }
                emit_event(&mut output, &stream, &event).await?;
                state.forget_terminal_id(&stream, &event);
            }
            OutputCommand::ProtocolError(error) => {
                emit_line(
                    &mut output,
                    &json!({ "kind": "protocol-error", "error": error }),
                )
                .await?;
            }
            OutputCommand::TransportError(error) => {
                emit_line(
                    &mut output,
                    &json!({ "kind": "transport-error", "error": error }),
                )
                .await?;
            }
            OutputCommand::ActiveIds(reply) => {
                let _ = reply.send(state.active_ids());
            }
            OutputCommand::Shutdown(id) => {
                emit_line(
                    &mut output,
                    &json!({ "kind": "response", "id": id, "ok": true, "response": { "shutdown": true } }),
                )
                .await?;
            }
        }
    }
    Ok(())
}

fn should_buffer_event(state: &ClientState, stream: &str, event: &Value) -> bool {
    let request_id = event.get("request_id").and_then(Value::as_str);
    let correlated = needs_correlation(stream)
        || event.get("event").and_then(Value::as_str) == Some("subscribed");
    correlated && request_id.is_some_and(|request_id| !state.active_ids.contains(request_id))
}

/// True for streams whose events are only meaningful next to the response that
/// produced their request id. The set is derived from the stream registry.
fn needs_correlation(stream: &str) -> bool {
    crate::protocol::Stream::parse(stream).is_some_and(|stream| {
        matches!(
            stream.spec().delivery,
            crate::protocol::StreamDelivery::Operation
                | crate::protocol::StreamDelivery::Continuous
        )
    })
}

async fn emit_response<W>(
    output: &mut W,
    id: &str,
    result: &std::result::Result<Value, String>,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let value = match result {
        Ok(response) => json!({ "kind": "response", "id": id, "ok": true, "response": response }),
        Err(error) => json!({ "kind": "response", "id": id, "ok": false, "error": error }),
    };
    emit_line(output, &value).await
}

async fn emit_event<W>(output: &mut W, stream: &str, event: &Value) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    emit_line(
        output,
        &json!({ "kind": "event", "stream": stream, "event": event }),
    )
    .await
}

async fn emit_line<W>(output: &mut W, value: &Value) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut bytes = serde_json::to_vec(value).context("serialize frontend JSON line")?;
    bytes.push(b'\n');
    output
        .write_all(&bytes)
        .await
        .context("write frontend JSON line")?;
    output.flush().await.context("flush frontend JSON line")
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ClientRequest, ClientState, needs_correlation, response_active_id,
        response_subscription_id, should_buffer_event,
    };

    #[test]
    fn every_jsonl_request_variant_decodes() {
        let call = serde_json::from_str::<ClientRequest>(
            r#"{"op":"call","id":"call-1","method":"wifi.status"}"#,
        )
        .unwrap();
        assert!(matches!(
            call,
            ClientRequest::Call { id, method, params }
                if id == "call-1" && method == "wifi.status" && params.is_null()
        ));
        let subscribe = serde_json::from_str::<ClientRequest>(
            r#"{"op":"subscribe","id":"sub-1","streams":["wifi.status"]}"#,
        )
        .unwrap();
        assert!(matches!(
            subscribe,
            ClientRequest::Subscribe { id, streams }
                if id == "sub-1" && streams == ["wifi.status"]
        ));
        let cancel = serde_json::from_str::<ClientRequest>(
            r#"{"op":"cancel","id":"cancel-1","request_id":"scan-1"}"#,
        )
        .unwrap();
        assert!(matches!(
            cancel,
            ClientRequest::Cancel { id, request_id }
                if id == "cancel-1" && request_id == "scan-1"
        ));
        let shutdown =
            serde_json::from_str::<ClientRequest>(r#"{"op":"shutdown","id":"shutdown-1"}"#)
                .unwrap();
        assert!(matches!(
            shutdown,
            ClientRequest::Shutdown { id } if id == "shutdown-1"
        ));
        assert!(serde_json::from_str::<ClientRequest>("not-json").is_err());
    }

    #[test]
    fn response_activation_releases_correlated_events_after_the_response() {
        let mut state = ClientState::default();
        let event = json!({ "request_id": "scan-1", "event": "status" });
        assert!(should_buffer_event(&state, "wifi.scan", &event));
        state.buffer_event("scan-1".into(), "wifi.scan".into(), event);
        let response = json!({ "data": { "result": { "request_id": "scan-1" } } });
        let pending = state.activate_response(&response);
        assert!(state.active_ids.contains("scan-1"));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, "wifi.scan");
        assert_eq!(pending[0].1["event"], "status");
        assert!(!state.pending_events.contains_key("scan-1"));
    }

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
            assert_eq!(needs_correlation(spec.name), expected, "{}", spec.name);
        }
        assert!(!needs_correlation("not.a.stream"));
    }

    #[test]
    fn tracks_async_request_and_subscription_lifetimes() {
        let mut state = ClientState::default();
        let operation = json!({ "data": { "result": { "request_id": "scan-1" } } });
        let subscription = json!({ "data": { "subscription": { "id": "sub-1" } } });
        state.activate_response(&operation);
        state.activate_response(&subscription);

        state.forget_terminal_id(
            "daemon.request",
            &json!({ "event": "cancelled", "request_id": "scan-1" }),
        );
        assert!(state.active_ids.contains("scan-1"));
        state.forget_terminal_id(
            "wifi.scan",
            &json!({ "event": "cancelled", "request_id": "scan-1" }),
        );
        assert!(!state.active_ids.contains("scan-1"));

        state.forget_cancelled_subscription("sub-1");
        assert!(!state.active_ids.contains("sub-1"));
        assert!(!state.subscription_ids.contains("sub-1"));
    }

    #[test]
    fn response_identifiers_follow_the_wire_contract() {
        let operation = json!({ "data": { "result": { "request_id": "scan-1" } } });
        let subscription = json!({ "data": { "subscription": { "id": "sub-1" } } });
        assert_eq!(response_active_id(&operation), Some("scan-1"));
        assert_eq!(response_active_id(&subscription), Some("sub-1"));
        assert_eq!(response_subscription_id(&subscription), Some("sub-1"));
    }
}
