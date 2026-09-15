//! Single-owner subscription state and coalesced refresh scheduling.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use zbus::object_server::SignalEmitter;

use super::{CancelOutcome, DaemonRuntime, next_request_id};
use crate::daemon_status::{SubscriptionState, refresh_payloads};
use crate::error::ErrorOperation;
use crate::protocol::Stream;

const NETWORK_CHANGE_DEBOUNCE: Duration = Duration::from_millis(75);

pub(super) enum Control {
    Subscribe {
        subscription: SubscriptionState,
        reply: oneshot::Sender<()>,
    },
    CancelSubscription {
        id: String,
        owner: Option<String>,
        task_found: bool,
        reply: oneshot::Sender<CancelOutcome>,
    },
    SubscriberOwners {
        stream: Stream,
        reply: oneshot::Sender<Vec<String>>,
    },
    Owners(oneshot::Sender<Vec<String>>),
    ExternalEvent {
        stream: Stream,
        request_id: String,
        event: &'static str,
        data: Value,
    },
    DropOwner(String),
    HealthSignal(crate::nm::HealthSignal),
    NetworkChanged,
    Refreshed(SharedPayloads),
    Shutdown(oneshot::Sender<()>),
}

impl Control {
    pub(super) fn subscribe(
        id: String,
        owner: Option<String>,
        streams: Vec<Stream>,
        emitter: SignalEmitter<'static>,
        reply: oneshot::Sender<()>,
    ) -> Self {
        Self::Subscribe {
            subscription: SubscriptionState::new(id, owner, streams, emitter),
            reply,
        }
    }
}

pub(crate) struct SharedPayloads {
    pub(crate) status: Option<Value>,
    pub(crate) connectivity: Option<Value>,
    pub(crate) inventory: Option<Value>,
    pub(crate) networks: Option<Value>,
}

pub(super) fn start(
    tokio: &tokio::runtime::Handle,
    runtime: Weak<DaemonRuntime>,
    receiver: mpsc::Receiver<Control>,
) {
    tokio.spawn(run_event_loop(runtime, receiver));
}

async fn run_event_loop(runtime: Weak<DaemonRuntime>, mut receiver: mpsc::Receiver<Control>) {
    let mut subscriptions = HashMap::<String, SubscriptionState>::new();
    let mut refresh = RefreshGate::default();
    let mut network_change_deadline = None;
    loop {
        tokio::select! {
            control = receiver.recv() => {
                let Some(control) = control else { return };
                if let Control::Shutdown(reply) = control {
                    subscriptions.clear();
                    let _ = reply.send(());
                    return;
                }
                if matches!(&control, Control::NetworkChanged) {
                    // One deadline for a burst, not one snapshot per property signal.
                    network_change_deadline.get_or_insert_with(|| {
                        tokio::time::Instant::now() + NETWORK_CHANGE_DEBOUNCE
                    });
                    continue;
                }
                let Some(runtime) = runtime.upgrade() else { return };
                handle_control(control, &runtime, &mut subscriptions, &mut refresh);
            }
            () = wait_for_deadline(network_change_deadline), if network_change_deadline.is_some() => {
                network_change_deadline = None;
                let Some(runtime) = runtime.upgrade() else { return };
                request_shared_refresh(&runtime, &subscriptions, &mut refresh);
            }
        }
    }
}

async fn wait_for_deadline(deadline: Option<tokio::time::Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    } else {
        std::future::pending().await
    }
}

fn handle_control(
    control: Control,
    runtime: &Arc<DaemonRuntime>,
    subscriptions: &mut HashMap<String, SubscriptionState>,
    refresh: &mut RefreshGate,
) {
    match control {
        Control::Subscribe {
            subscription,
            reply,
        } => add_subscription(subscription, reply, runtime, subscriptions, refresh),
        Control::CancelSubscription {
            id,
            owner,
            task_found,
            reply,
        } => remove_subscription(id, owner.as_deref(), task_found, reply, subscriptions),
        Control::SubscriberOwners { stream, reply } => {
            let owners = subscriptions
                .values()
                .filter(|subscription| subscription.watches(stream))
                .filter_map(|subscription| subscription.owner().map(ToString::to_string))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let _ = reply.send(owners);
        }
        Control::Owners(reply) => {
            let _ = reply.send(
                subscriptions
                    .values()
                    .filter_map(|subscription| subscription.owner().map(str::to_owned))
                    .collect(),
            );
        }
        Control::ExternalEvent {
            stream,
            request_id,
            event,
            data,
        } => emit_external_to_subscribers(subscriptions, stream, &request_id, event, &data),
        Control::DropOwner(owner) => drop_subscriptions_for_owner(&owner, subscriptions),
        Control::HealthSignal(signal) => publish_health_signal(signal, runtime, subscriptions),
        Control::NetworkChanged => {
            unreachable!("network changes are debounced by the control actor")
        }
        Control::Refreshed(payloads) => {
            complete_shared_refresh(payloads, runtime, subscriptions, refresh)
        }
        Control::Shutdown(_) => unreachable!("shutdown is handled by the control actor"),
    }
}

fn add_subscription(
    subscription: SubscriptionState,
    reply: oneshot::Sender<()>,
    runtime: &Arc<DaemonRuntime>,
    subscriptions: &mut HashMap<String, SubscriptionState>,
    refresh: &mut RefreshGate,
) {
    subscriptions.insert(subscription.id().to_string(), subscription);
    let _ = reply.send(());
    request_shared_refresh(runtime, subscriptions, refresh);
}

fn remove_subscription(
    id: String,
    owner: Option<&str>,
    task_found: bool,
    reply: oneshot::Sender<CancelOutcome>,
    subscriptions: &mut HashMap<String, SubscriptionState>,
) {
    let subscription = subscriptions
        .get(&id)
        .filter(|subscription| subscription.owner() == owner)
        .map(|_| id.clone())
        .and_then(|id| subscriptions.remove(&id));
    let _ = reply.send(CancelOutcome {
        task: task_found,
        subscription: subscription.is_some(),
    });
}

fn drop_subscriptions_for_owner(
    owner: &str,
    subscriptions: &mut HashMap<String, SubscriptionState>,
) {
    subscriptions.retain(|_, subscription| !subscription.owned_by(owner));
}

/// Resolve and fan out health only while somebody is watching.
fn publish_health_signal(
    signal: crate::nm::HealthSignal,
    runtime: &Arc<DaemonRuntime>,
    subscriptions: &HashMap<String, SubscriptionState>,
) {
    if !subscriptions
        .values()
        .any(|subscription| subscription.watches(Stream::NetworkHealth))
    {
        return;
    }
    let event = signal.subject.as_str();
    let control = runtime.control.clone();
    let queued = runtime.submit_fast(ErrorOperation::Status, Box::new(move |nm| {
        let request_id = next_request_id("health");
        match nm.network_health_event(&signal) {
            Ok(health) => {
                let _ = control.blocking_send(Control::ExternalEvent {
                    stream: Stream::NetworkHealth, request_id: request_id.clone(), event,
                    data: serde_json::json!({ "request_id": request_id, "health": health }),
                });
            }
            Err(error) => tracing::warn!(error = %crate::error::err_chain(&error), "could not describe a NetworkManager health transition"),
        }
    }));
    if let Err(error) = queued {
        tracing::warn!(error = %crate::error::err_chain(&error), "could not queue a NetworkManager health transition");
    }
}

fn emit_external_to_subscribers(
    subscriptions: &HashMap<String, SubscriptionState>,
    stream: Stream,
    request_id: &str,
    event: &str,
    data: &Value,
) {
    let mut emitted_owners = HashSet::new();
    subscriptions
        .values()
        .filter(|subscription| subscription.watches(stream))
        .filter(|subscription| {
            subscription
                .owner()
                .is_some_and(|owner| emitted_owners.insert(owner.to_string()))
        })
        .for_each(|subscription| {
            subscription.emit_external(stream, request_id, event, data.clone())
        });
}

fn complete_shared_refresh(
    payloads: SharedPayloads,
    runtime: &Arc<DaemonRuntime>,
    subscriptions: &mut HashMap<String, SubscriptionState>,
    refresh: &mut RefreshGate,
) {
    let refresh_again = refresh.complete();
    subscriptions
        .values_mut()
        .for_each(|subscription| subscription.emit_changes(&payloads));
    if refresh_again {
        request_shared_refresh(runtime, subscriptions, refresh);
    }
}

fn request_shared_refresh(
    runtime: &Arc<DaemonRuntime>,
    subscriptions: &HashMap<String, SubscriptionState>,
    refresh: &mut RefreshGate,
) {
    if !refresh.invalidate() || subscriptions.is_empty() {
        return;
    }
    let needs = required_shared_payloads(subscriptions);
    if !needs.any() {
        return;
    }
    submit_shared_refresh(runtime, refresh, needs);
}

#[derive(Debug, Clone, Copy)]
struct SharedPayloadDemand {
    status: bool,
    connectivity: bool,
    inventory: bool,
    networks: bool,
}

impl SharedPayloadDemand {
    fn any(self) -> bool {
        self.status || self.connectivity || self.inventory || self.networks
    }
}

fn required_shared_payloads(
    subscriptions: &HashMap<String, SubscriptionState>,
) -> SharedPayloadDemand {
    let watches = |stream| {
        subscriptions
            .values()
            .any(|subscription| subscription.watches(stream))
    };
    SharedPayloadDemand {
        status: watches(Stream::WifiStatus),
        connectivity: watches(Stream::NetworkConnectivity),
        inventory: watches(Stream::NetworkInventory),
        networks: watches(Stream::WifiNetworks),
    }
}

fn submit_shared_refresh(
    runtime: &Arc<DaemonRuntime>,
    refresh: &mut RefreshGate,
    needs: SharedPayloadDemand,
) {
    let control = runtime.control.clone();
    match runtime.submit_fast(
        ErrorOperation::Status,
        Box::new(move |nm| {
            let payloads = refresh_payloads(
                nm,
                needs.status,
                needs.connectivity,
                needs.inventory,
                needs.networks,
            );
            let _ = control.blocking_send(Control::Refreshed(payloads));
        }),
    ) {
        Ok(()) => refresh.started(),
        Err(error) => {
            tracing::warn!(error = %crate::error::err_chain(&error), "could not queue shared status refresh")
        }
    }
}

#[derive(Default)]
struct RefreshGate {
    in_flight: bool,
    dirty: bool,
}

impl RefreshGate {
    fn invalidate(&mut self) -> bool {
        if self.in_flight {
            self.dirty = true;
            false
        } else {
            true
        }
    }
    fn started(&mut self) {
        self.in_flight = true;
    }
    fn complete(&mut self) -> bool {
        self.in_flight = false;
        std::mem::take(&mut self.dirty)
    }
}

#[cfg(test)]
mod tests {
    use super::RefreshGate;
    #[test]
    fn coalescing_preserves_one_final_refresh_and_resets_after_completion() {
        let mut gate = RefreshGate::default();
        assert!(gate.invalidate());
        gate.started();
        assert!(!gate.invalidate());
        assert!(!gate.invalidate());
        assert!(gate.complete());
        assert!(gate.invalidate());
        gate.started();
        assert!(!gate.complete());
        assert!(gate.invalidate());
    }
}
