//! Registration follows the NM bus owner, not an installed version string.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::StreamExt;
use zbus::{Connection, Proxy};

use super::{AGENT_MANAGER_IFACE, AGENT_MANAGER_PATH, REGISTERED, SECRET_AGENT_ID};
use crate::daemon_runtime::DaemonRuntime;
use crate::nm::NM_DEST;

#[cfg(test)]
mod tests;

const RETRY: Duration = Duration::from_secs(2);
const REGISTER_TIMEOUT: Duration = Duration::from_secs(5);
type Registration = Pin<Box<dyn Future<Output = Result<bool>> + Send>>;

struct ResetOnDrop(Arc<DaemonRuntime>);
impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        super::change_network_manager_owner(&self.0, None);
    }
}

pub(crate) async fn watch_network_manager(runtime: Arc<DaemonRuntime>) {
    let _reset = ResetOnDrop(Arc::clone(&runtime));
    let connection = runtime.network_manager_connection().inner().clone();
    loop {
        if let Err(error) = watch(&connection, &runtime).await {
            tracing::warn!(%error, "NetworkManager owner watch interrupted; retrying");
        }
        super::change_network_manager_owner(&runtime, None);
        tokio::time::sleep(RETRY).await;
    }
}

async fn current_owner(bus: &zbus::fdo::DBusProxy<'_>) -> Result<Option<String>> {
    match bus.get_name_owner(NM_DEST.try_into()?).await {
        Ok(owner) => Ok(Some(owner.to_string())),
        Err(zbus::fdo::Error::NameHasNoOwner(_)) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn watch(connection: &Connection, runtime: &Arc<DaemonRuntime>) -> Result<()> {
    let bus = zbus::fdo::DBusProxy::new(connection).await?;
    // Subscribe before the initial lookup: no gap between discovery and watch.
    let mut changes = bus
        .receive_name_owner_changed_with_args(&[(0, NM_DEST)])
        .await?;
    let mut tick = tokio::time::interval(RETRY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut owner = None;
    let mut registration: Option<Registration> = None;
    let mut retry_at = tokio::time::Instant::now();
    loop {
        let completed = tokio::select! {
            signal = changes.next() => {
                anyhow::ensure!(signal.is_some(), "NetworkManager owner stream ended");
                None
            }
            _ = tick.tick() => None,
            result = async { registration.as_mut().expect("guarded registration").await }, if registration.is_some() => Some(result),
        };
        // GetNameOwner never auto-starts NM. Re-read even on a signal because
        // several transitions may already be queued (including stop/start/stop).
        let current = current_owner(&bus).await?;
        if current != owner {
            registration = None; // Drop the in-flight call; never replay it.
            super::change_network_manager_owner(runtime, current.clone());
            owner = current;
            retry_at = tokio::time::Instant::now();
        } else if let Some(result) = completed {
            registration = None;
            match result {
                Ok(vpn_hints) => {
                    super::with_pending_registry(|registry| {
                        if registry.is_current_owner(owner.as_deref()) {
                            REGISTERED.store(true, Ordering::Release);
                        }
                    });
                    tracing::info!(vpn_hints, "registered NetworkManager SecretAgent");
                }
                Err(error) => tracing::warn!(%error, "SecretAgent registration failed; retrying"),
            }
            retry_at = tokio::time::Instant::now() + RETRY;
        }
        if let Some(owner) = owner.as_ref()
            && registration.is_none()
            && !REGISTERED.load(Ordering::Acquire)
            && tokio::time::Instant::now() >= retry_at
        {
            let connection = connection.clone();
            let owner = owner.clone();
            let runtime = Arc::clone(runtime);
            registration = Some(Box::pin(async move {
                tokio::task::spawn_blocking(move || runtime.refresh_network_manager_scope())
                    .await
                    .context("refresh NetworkManager owner scope")??;
                tokio::time::timeout(REGISTER_TIMEOUT, register_for_owner(&connection, &owner))
                    .await
                    .context("SecretAgent registration timed out")?
            }));
        }
    }
}

async fn register_for_owner(connection: &Connection, owner: &str) -> Result<bool> {
    // Unique destination prevents activation and registration with a replacement
    // owner if NM exits while this call is in flight.
    let manager = Proxy::new(connection, owner, AGENT_MANAGER_PATH, AGENT_MANAGER_IFACE).await?;
    const VPN_HINTS: u32 = 0x1;
    match manager
        .call::<_, _, ()>("RegisterWithCapabilities", &(SECRET_AGENT_ID, VPN_HINTS))
        .await
    {
        Ok(()) => Ok(true),
        Err(zbus::Error::MethodError(name, _, _))
            if name.as_str() == "org.freedesktop.DBus.Error.UnknownMethod" =>
        {
            manager
                .call::<_, _, ()>("Register", &(SECRET_AGENT_ID,))
                .await?;
            Ok(false)
        }
        Err(error) => Err(error).context("register NetworkManager SecretAgent"),
    }
}
