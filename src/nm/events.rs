use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result};
use zbus::MatchRule;
use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Type;

use super::NM_DEST;
use crate::generated::NETWORKMANAGER_EVENT_RETRY_DELAY;

const DEVICE_IFACE: &str = "org.freedesktop.NetworkManager.Device";
const ACTIVE_CONNECTION_IFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const VPN_CONNECTION_IFACE: &str = "org.freedesktop.NetworkManager.VPN.Connection";

/// Which NetworkManager object reported a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum HealthSubject {
    Device,
    ActiveConnection,
    Vpn,
}

impl HealthSubject {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::ActiveConnection => "connection",
            Self::Vpn => "vpn",
        }
    }
}

/// One NetworkManager state transition, carried with the reason NetworkManager
/// only ever reports on the signal itself.
#[derive(Debug, Clone)]
pub(crate) struct HealthSignal {
    pub(crate) subject: HealthSubject,
    pub(crate) path: String,
    pub(crate) state: u32,
    pub(crate) previous_state: Option<u32>,
    pub(crate) reason: u32,
}

type HealthListener = Arc<dyn Fn(HealthSignal) + Send + Sync>;

#[derive(Default)]
pub(super) struct NetworkEvents {
    generation: Mutex<u64>,
    changed: Condvar,
    listeners: Mutex<Vec<Arc<dyn Fn() + Send + Sync>>>,
    health_listeners: Mutex<Vec<HealthListener>>,
    latest_health: Mutex<HashMap<(HealthSubject, String), HealthSignal>>,
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

    pub(super) fn subscribe_health(&self, listener: HealthListener) {
        recover_lock(&self.health_listeners).push(listener);
    }

    fn notify_health(&self, signal: HealthSignal) {
        recover_lock(&self.latest_health)
            .insert((signal.subject, signal.path.clone()), signal.clone());
        for listener in recover_lock(&self.health_listeners).iter() {
            listener(signal.clone());
        }
    }

    pub(super) fn latest_health(&self, subject: HealthSubject, path: &str) -> Option<HealthSignal> {
        recover_lock(&self.latest_health)
            .get(&(subject, path.to_string()))
            .cloned()
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
        let message = message.context("receive NetworkManager signal")?;
        if let Some(signal) = health_signal(&message) {
            events.notify_health(signal);
        }
        events.notify();
    }
    Ok(())
}

/// Extracts a state transition from the signals that carry NetworkManager's
/// reason code. Every other NetworkManager signal still advances the shared
/// generation; only these carry health detail.
fn health_signal(message: &zbus::Message) -> Option<HealthSignal> {
    let header = message.header();
    let interface = header.interface()?.as_str().to_string();
    let member = header.member()?.as_str().to_string();
    let path = header.path()?.as_str().to_string();
    let body = message.body();
    match (interface.as_str(), member.as_str()) {
        (DEVICE_IFACE, "StateChanged") => {
            let (state, previous_state, reason): (u32, u32, u32) = body.deserialize().ok()?;
            Some(HealthSignal {
                subject: HealthSubject::Device,
                path,
                state,
                previous_state: Some(previous_state),
                reason,
            })
        }
        (ACTIVE_CONNECTION_IFACE, "StateChanged") => {
            let (state, reason): (u32, u32) = body.deserialize().ok()?;
            Some(HealthSignal {
                subject: HealthSubject::ActiveConnection,
                path,
                state,
                previous_state: None,
                reason,
            })
        }
        (VPN_CONNECTION_IFACE, "VpnStateChanged") => {
            let (state, reason): (u32, u32) = body.deserialize().ok()?;
            Some(HealthSignal {
                subject: HealthSubject::Vpn,
                path,
                state,
                previous_state: None,
                reason,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{HealthSignal, HealthSubject, NetworkEvents};

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

    #[test]
    fn health_listeners_receive_each_transition_without_disturbing_the_generation() {
        let events = NetworkEvents::default();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = Arc::clone(&seen);
        events.subscribe_health(Arc::new(move |signal: HealthSignal| {
            observed.lock().expect("health signals").push(signal);
        }));
        let before = events.generation();

        events.notify_health(HealthSignal {
            subject: HealthSubject::Device,
            path: "/devices/1".to_string(),
            state: 120,
            previous_state: Some(70),
            reason: 7,
        });

        assert_eq!(events.generation(), before);
        let seen = seen.lock().expect("health signals");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].subject, HealthSubject::Device);
        assert_eq!(seen[0].reason, 7);
        let latest = events
            .latest_health(HealthSubject::Device, "/devices/1")
            .expect("latest transition");
        assert_eq!(latest.state, 120);
        assert_eq!(latest.reason, 7);
    }

    #[test]
    fn health_subject_names_are_stable() {
        assert_eq!(HealthSubject::Device.as_str(), "device");
        assert_eq!(HealthSubject::ActiveConnection.as_str(), "connection");
        assert_eq!(HealthSubject::Vpn.as_str(), "vpn");
    }
}
