use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use zbus::MatchRule;
use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Type;

use crate::generated::NETWORKMANAGER_EVENT_RETRY_DELAY;

use super::{ACTIVE_CONNECTION_IFACE, DEVICE_IFACE, recover_lock};
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
    pub(crate) owner: String,
    pub(crate) subject: HealthSubject,
    pub(crate) path: String,
    pub(crate) state: u32,
    pub(crate) previous_state: Option<u32>,
    pub(crate) reason: u32,
    pub(crate) observed_at: Instant,
}

type HealthListener = Arc<dyn Fn(HealthSignal) + Send + Sync>;

#[derive(Default)]
pub(super) struct NetworkEvents {
    generation: Mutex<u64>,
    changed: Condvar,
    listeners: Mutex<Vec<Arc<dyn Fn() + Send + Sync>>>,
    health_listeners: Mutex<Vec<HealthListener>>,
    latest_health: Mutex<HashMap<(HealthSubject, String), HealthSignal>>,
    latest_detailed_health: Mutex<HashMap<(HealthSubject, String), HealthSignal>>,
}

impl NetworkEvents {
    pub(super) fn start(connection: Connection, destination: String) -> Arc<Self> {
        let events = Arc::new(Self::default());
        let monitor_events = Arc::clone(&events);
        if let Err(error) = std::thread::Builder::new()
            .name("nm-events".to_string())
            .spawn(move || monitor_events.monitor(&connection, &destination))
        {
            tracing::error!(%error, "failed to spawn NetworkManager event monitor");
        }
        events
    }

    fn monitor(&self, connection: &Connection, destination: &str) {
        loop {
            if let Err(error) = monitor_signals(connection, destination, self) {
                tracing::warn!(error = %crate::error::err_chain(&error), "NetworkManager event monitor interrupted; retrying");
            }
            std::thread::sleep(NETWORKMANAGER_EVENT_RETRY_DELAY);
        }
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
        let key = (signal.subject, signal.path.clone());
        recover_lock(&self.latest_health).insert(key.clone(), signal.clone());
        if signal.reason != 0 {
            recover_lock(&self.latest_detailed_health).insert(key, signal.clone());
        }
        for listener in recover_lock(&self.health_listeners).iter() {
            listener(signal.clone());
        }
    }

    pub(super) fn latest_health(&self, subject: HealthSubject, path: &str) -> Option<HealthSignal> {
        recover_lock(&self.latest_health)
            .get(&(subject, path.to_string()))
            .cloned()
    }

    pub(super) fn latest_detailed_health(
        &self,
        subject: HealthSubject,
        path: &str,
    ) -> Option<HealthSignal> {
        recover_lock(&self.latest_detailed_health)
            .get(&(subject, path.to_string()))
            .cloned()
    }

    pub(super) fn clear_health(&self) {
        recover_lock(&self.latest_health).clear();
        recover_lock(&self.latest_detailed_health).clear();
        self.notify();
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

fn monitor_signals(
    connection: &Connection,
    destination: &str,
    events: &NetworkEvents,
) -> Result<()> {
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(destination)
        .context("match NetworkManager signal sender")?
        .build();
    let mut messages = MessageIterator::for_match_rule(rule, connection, Some(64))
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
    let subject = match (header.interface()?.as_str(), header.member()?.as_str()) {
        (DEVICE_IFACE, "StateChanged") => HealthSubject::Device,
        (ACTIVE_CONNECTION_IFACE, "StateChanged") => HealthSubject::ActiveConnection,
        (VPN_CONNECTION_IFACE, "VpnStateChanged") => HealthSubject::Vpn,
        _ => return None,
    };
    let body = message.body();
    let (state, previous_state, reason) = match subject {
        HealthSubject::Device => {
            let (state, previous, reason): (u32, u32, u32) = body.deserialize().ok()?;
            (state, Some(previous), reason)
        }
        _ => {
            let (state, reason): (u32, u32) = body.deserialize().ok()?;
            (state, None, reason)
        }
    };
    Some(HealthSignal {
        owner: header.sender()?.to_string(),
        subject,
        path: header.path()?.to_string(),
        state,
        previous_state,
        reason,
        observed_at: Instant::now(),
    })
}

#[cfg(test)]
mod tests {

    use std::time::Instant;

    use super::{HealthSignal, HealthSubject, NetworkEvents};

    #[test]
    fn health_signals_require_the_matching_member_body_and_sender() -> anyhow::Result<()> {
        use super::{ACTIVE_CONNECTION_IFACE, DEVICE_IFACE, VPN_CONNECTION_IFACE, health_signal};
        for (interface, member, subject, previous) in [
            (
                DEVICE_IFACE,
                "StateChanged",
                HealthSubject::Device,
                Some(70),
            ),
            (
                ACTIVE_CONNECTION_IFACE,
                "StateChanged",
                HealthSubject::ActiveConnection,
                None,
            ),
            (
                VPN_CONNECTION_IFACE,
                "VpnStateChanged",
                HealthSubject::Vpn,
                None,
            ),
        ] {
            let builder = zbus::Message::signal("/object/1", interface, member)?.sender(":1.2")?;
            let message = match previous {
                Some(previous) => builder.build(&(120_u32, previous, 17_u32))?,
                None => builder.build(&(120_u32, 17_u32))?,
            };
            let signal = health_signal(&message).expect("valid state signal");
            assert_eq!((signal.subject, signal.previous_state), (subject, previous));
            assert_eq!((signal.state, signal.reason), (120, 17));
            assert_eq!(
                (signal.owner.as_str(), signal.path.as_str()),
                (":1.2", "/object/1")
            );
            for message in [
                zbus::Message::signal("/object/1", interface, member)?
                    .sender(":1.2")?
                    .build(&"bad body")?,
                zbus::Message::signal("/object/1", interface, "Other")?
                    .sender(":1.2")?
                    .build(&(120_u32, 17_u32))?,
                zbus::Message::signal("/object/1", interface, member)?.build(&(120_u32, 17_u32))?,
            ] {
                assert!(health_signal(&message).is_none());
            }
        }
        Ok(())
    }

    #[test]
    fn owner_loss_clears_both_health_caches_and_wakes_waiters() {
        let events = NetworkEvents::default();
        events.notify_health(HealthSignal {
            owner: ":1.0".into(),
            subject: HealthSubject::Device,
            path: "/devices/1".into(),
            state: 120,
            previous_state: Some(70),
            reason: 17,
            observed_at: Instant::now(),
        });
        let before = events.generation();
        events.clear_health();
        assert!(
            events
                .latest_health(HealthSubject::Device, "/devices/1")
                .is_none()
        );
        assert!(
            events
                .latest_detailed_health(HealthSubject::Device, "/devices/1")
                .is_none()
        );
        assert_ne!(events.generation(), before);
    }

    #[test]
    fn neutral_followup_does_not_erase_recent_detailed_health_reason() {
        let events = NetworkEvents::default();
        let signal = |reason| HealthSignal {
            owner: ":1.0".into(),
            subject: HealthSubject::Device,
            path: "/devices/1".to_string(),
            state: 30,
            previous_state: Some(120),
            reason,
            observed_at: Instant::now(),
        };
        events.notify_health(signal(17));
        events.notify_health(signal(0));

        assert_eq!(
            events
                .latest_health(HealthSubject::Device, "/devices/1")
                .unwrap()
                .reason,
            0
        );
        assert_eq!(
            events
                .latest_detailed_health(HealthSubject::Device, "/devices/1")
                .unwrap()
                .reason,
            17
        );
    }
}
