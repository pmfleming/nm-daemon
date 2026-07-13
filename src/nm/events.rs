use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use zbus::MatchRule;
use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Type;

use super::NM_DEST;

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
        std::thread::Builder::new()
            .name("nm-events".to_string())
            .spawn(move || {
                loop {
                    if let Err(error) = monitor_signals(connection.clone(), &monitor_events) {
                        tracing::warn!(error = %format_args!("{error:#}"), "NetworkManager event monitor interrupted; retrying");
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            })
            .expect("spawn NetworkManager event monitor");
        events
    }

    pub(super) fn generation(&self) -> u64 {
        *self
            .generation
            .lock()
            .expect("NM event generation poisoned")
    }

    pub(super) fn wait_for_change(&self, observed: u64, timeout: Duration) -> u64 {
        let generation = self
            .generation
            .lock()
            .expect("NM event generation poisoned");
        if *generation != observed {
            return *generation;
        }
        let (generation, _) = self
            .changed
            .wait_timeout(generation, timeout)
            .expect("NM event condvar poisoned");
        *generation
    }

    pub(super) fn subscribe(&self, listener: Arc<dyn Fn() + Send + Sync>) {
        self.listeners
            .lock()
            .expect("NM event listeners poisoned")
            .push(listener);
    }

    pub(super) fn notify(&self) {
        let mut generation = self
            .generation
            .lock()
            .expect("NM event generation poisoned");
        *generation = generation.wrapping_add(1);
        self.changed.notify_all();
        drop(generation);

        for listener in self
            .listeners
            .lock()
            .expect("NM event listeners poisoned")
            .iter()
        {
            listener();
        }
    }
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
