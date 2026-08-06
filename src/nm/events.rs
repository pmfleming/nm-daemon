use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result};
use zbus::MatchRule;
use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Type;

use super::NM_DEST;
use crate::generated::NETWORKMANAGER_EVENT_RETRY_DELAY;

#[derive(Default)]
pub(super) struct NetworkEvents {
    generation: Mutex<u64>,
    changed: Condvar,
    listeners: Mutex<Vec<Arc<dyn Fn() + Send + Sync>>>,
}

impl NetworkEvents {
    pub(super) fn start(connection: Connection) -> Arc<Self> {
        let events = Arc::new(Self::default());
        let monitor_events = Arc::clone(&events);
        if let Err(error) = std::thread::Builder::new()
            .name("nm-events".to_string())
            .spawn(move || loop {
                if let Err(error) = monitor_signals(connection.clone(), &monitor_events) {
                    tracing::warn!(error = %crate::error::err_chain(&error), "NetworkManager event monitor interrupted; retrying");
                }
                std::thread::sleep(NETWORKMANAGER_EVENT_RETRY_DELAY);
            })
        {
            tracing::error!(%error, "failed to spawn NetworkManager event monitor");
        }
        events
    }

    pub(super) fn generation(&self) -> u64 {
        *recover_lock(&self.generation)
    }

    pub(super) fn wait_for_change(&self, observed: u64, timeout: Duration) -> u64 {
        let generation = recover_lock(&self.generation);
        if *generation != observed {
            return *generation;
        }
        let (generation, _) = self
            .changed
            .wait_timeout(generation, timeout)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *generation
    }

    pub(super) fn subscribe(&self, listener: Arc<dyn Fn() + Send + Sync>) {
        recover_lock(&self.listeners).push(listener);
    }

    pub(super) fn notify(&self) {
        let mut generation = recover_lock(&self.generation);
        *generation = generation.wrapping_add(1);
        self.changed.notify_all();
        drop(generation);

        for listener in recover_lock(&self.listeners).iter() {
            listener();
        }
    }
}

fn recover_lock<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn monitor_signals(connection: Connection, events: &NetworkEvents) -> Result<()> {
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(NM_DEST)
        .context("match NetworkManager signal sender")?
        .build();
    let mut messages = MessageIterator::for_match_rule(rule, &connection, Some(64))
        .context("subscribe to NetworkManager signals")?;
    events.notify();
    for message in &mut messages {
        message.context("receive NetworkManager signal")?;
        events.notify();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::NetworkEvents;

    #[test]
    fn notifications_advance_generation_and_wake_shared_listeners() {
        let events = NetworkEvents::default();
        let notifications = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&notifications);
        events.subscribe(Arc::new(move || {
            observed.fetch_add(1, Ordering::Relaxed);
        }));
        let before = events.generation();

        events.notify();
        events.notify();

        assert_ne!(events.generation(), before);
        assert_eq!(notifications.load(Ordering::Relaxed), 2);
    }
}
