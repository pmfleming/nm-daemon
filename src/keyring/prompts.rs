//! One outstanding unlock per provider. Timeout retires the *waiter*, not the
//! provider's dialog: GNOME keyring can crash on Dismiss during an active unlock.
//! The monitor retains only public object paths and a bus connection, never secrets.
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use zvariant::{OwnedObjectPath, OwnedValue};

use super::{NULL_PROMPT, SECRET_PROMPT_IFACE, SECRET_SERVICE_IFACE, SECRET_SERVICE_PATH};

type Completion = Result<Vec<OwnedObjectPath>, String>;
#[derive(Default)]
struct State {
    result: Option<Completion>,
    timed_out: bool,
}
#[derive(Default)]
struct Pending {
    state: Mutex<State>,
    changed: Condvar,
}
static ACTIVE: OnceLock<Mutex<HashMap<String, Arc<Pending>>>> = OnceLock::new();

pub(super) fn unlock(
    connection: &zbus::blocking::Connection,
    destination: &str,
    objects: Vec<OwnedObjectPath>,
    timeout: Duration,
) -> Result<Vec<OwnedObjectPath>> {
    let key = format!("{}/{}", connection.inner().server_guid(), destination);
    let active = ACTIVE.get_or_init(Default::default);
    let (pending, started) = {
        let mut active = active.lock().unwrap_or_else(|p| p.into_inner());
        match active.get(&key) {
            Some(pending) => (pending.clone(), false),
            None => {
                let pending = Arc::new(Pending::default());
                active.insert(key.clone(), pending.clone());
                (pending, true)
            }
        }
    };
    if started {
        let connection = connection.inner().clone();
        let destination = destination.to_owned();
        let objects = objects.clone();
        let worker = pending.clone();
        let worker_key = key.clone();
        let spawn = std::thread::Builder::new()
            .name("keyring-unlock".into())
            .spawn(move || {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("start keyring prompt monitor")
                    .and_then(|runtime| runtime.block_on(run(&connection, &destination, objects)))
                    .map_err(|error| format!("{error:#}"));
                // Remove before waking joiners so their follow-up Unlock sees a fresh slot.
                active
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&worker_key);
                worker
                    .state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .result = Some(result);
                worker.changed.notify_all();
            });
        if let Err(error) = spawn {
            active
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&key);
            pending
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .result = Some(Err(error.to_string()));
            pending.changed.notify_all();
        }
    }
    let state = pending.state.lock().unwrap_or_else(|p| p.into_inner());
    let (mut state, _) = pending
        .changed
        .wait_timeout_while(state, timeout, |s| s.result.is_none() && !s.timed_out)
        .unwrap_or_else(|p| p.into_inner());
    let Some(result) = state.result.clone() else {
        state.timed_out = true;
        pending.changed.notify_all();
        bail!(
            "desktop keyring unlock timed out or is still pending; finish the existing dialog and retry saving"
        );
    };
    drop(state);
    let result = result.map_err(anyhow::Error::msg)?;
    if started {
        Ok(result)
    } else {
        // The joined unlock may target a different collection/item. Re-query our
        // objects, serially; do not return somebody else's unlock result.
        unlock(connection, destination, objects, timeout)
    }
}

#[cfg(test)]
pub(super) fn is_pending(connection: &zbus::blocking::Connection, destination: &str) -> bool {
    let key = format!("{}/{}", connection.inner().server_guid(), destination);
    ACTIVE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(&key)
}

async fn run(
    connection: &zbus::Connection,
    destination: &str,
    objects: Vec<OwnedObjectPath>,
) -> Result<Vec<OwnedObjectPath>> {
    let service = zbus::Proxy::new(
        connection,
        destination,
        SECRET_SERVICE_PATH,
        SECRET_SERVICE_IFACE,
    )
    .await?;
    let mut owner = if connection.is_bus() {
        Some(service.receive_owner_changed().await?)
    } else {
        None
    };
    let operation = async {
        let (mut unlocked, path): (Vec<OwnedObjectPath>, OwnedObjectPath) =
            service.call("Unlock", &(objects,)).await?;
        if path.as_str() == NULL_PROMPT {
            return Ok(unlocked);
        }
        let prompt =
            zbus::Proxy::new(connection, destination, path.as_str(), SECRET_PROMPT_IFACE).await?;
        let mut completed = prompt.receive_signal("Completed").await?;
        prompt.call::<_, _, ()>("Prompt", &("",)).await?;
        let message = completed
            .next()
            .await
            .context("desktop keyring prompt disconnected")?;
        let (dismissed, result): (bool, OwnedValue) = message.body().deserialize()?;
        if dismissed {
            bail!("desktop keyring unlock cancelled; unlock it and retry saving");
        }
        unlocked.extend(
            Vec::<OwnedObjectPath>::try_from(result).context("decode keyring unlock result")?,
        );
        Ok(unlocked)
    };
    tokio::select! {
        result = operation => result,
        _ = async {
            match &mut owner {
                Some(owner) => { owner.next().await; }
                None => futures::future::pending::<()>().await,
            }
        } => bail!("desktop keyring provider exited during unlock; retry saving"),
    }
}
