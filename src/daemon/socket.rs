//! Direct in-process ingress to the same object exported on D-Bus. No proxy.
#[cfg(test)]
mod tests;
use super::{DBUS_OBJECT_PATH, NmDaemonInterface};
use anyhow::Result;
use serde_json::Value;
use shelllist_daemon_tokio::{JsonlListener, JsonlSocketConfig, LocalJsonlService, SocketSession};
use std::sync::Arc;

pub(super) struct Service {
    pub connection: zbus::Connection,
}
impl LocalJsonlService for Service {
    async fn call(&self, session: &SocketSession, method: &str, params: Value) -> Result<Value> {
        let interface = self
            .connection
            .object_server()
            .interface::<_, NmDaemonInterface>(DBUS_OBJECT_PATH)
            .await?;
        let daemon = interface.get().await;
        decode(
            daemon
                .call_owned(
                    method,
                    &params.to_string(),
                    Some(session.owner().into()),
                    session.clone().into(),
                )
                .await,
        )
    }
    async fn subscribe(&self, session: &SocketSession, streams: Vec<String>) -> Result<Value> {
        let interface = self
            .connection
            .object_server()
            .interface::<_, NmDaemonInterface>(DBUS_OBJECT_PATH)
            .await?;
        let daemon = interface.get().await;
        decode(
            daemon
                .subscribe_owned(
                    streams,
                    Some(session.owner().into()),
                    session.clone().into(),
                )
                .await,
        )
    }
    async fn cancel(&self, session: &SocketSession, id: &str) -> Result<Value> {
        let interface = self
            .connection
            .object_server()
            .interface::<_, NmDaemonInterface>(DBUS_OBJECT_PATH)
            .await?;
        let daemon = interface.get().await;
        decode(
            daemon
                .cancel_owned(id, Some(session.owner().into()), session.clone().into())
                .await,
        )
    }
    async fn disconnected(&self, session: &SocketSession) {
        if let Ok(interface) = self
            .connection
            .object_server()
            .interface::<_, NmDaemonInterface>(DBUS_OBJECT_PATH)
            .await
        {
            let daemon = interface.get().await;
            // Idempotent, owner-scoped task cancellation, activation abort, health
            // feedback and subscription cleanup. Also repeated after late work.
            daemon.runtime.drop_owner(session.owner().into()).await;
        }
    }
}
fn decode(response: String) -> Result<Value> {
    Ok(serde_json::from_str(&response)?)
}

pub(super) async fn listen(
    connection: zbus::Connection,
    stop: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| anyhow::anyhow!("XDG_RUNTIME_DIR is required for the NM socket"))?;
    let listener = JsonlListener::bind(std::path::Path::new(&runtime), "nm-daemon").await?;
    listener
        .serve(
            Arc::new(Service { connection }),
            crate::client::NmCorrelation,
            JsonlSocketConfig::default(),
            stop,
        )
        .await
}
