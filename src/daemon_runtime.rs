use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;
use zbus::object_server::SignalEmitter;

use crate::application::{Application, BackgroundScanScheduler, ScanRequest};
use crate::daemon_status::{SubscriptionState, refresh_payloads};
use crate::error::{DomainError, ErrorCode, ErrorOperation, ErrorSource};
use crate::nm::Nm;
use crate::protocol::Stream;

const WORKER_COUNT: usize = 3;
const WORK_QUEUE_CAPACITY: usize = 16;
const CONTROL_QUEUE_CAPACITY: usize = 64;

type Job = Box<dyn FnOnce(&Nm) + Send + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskKind {
    Connect,
    Scan,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CancelOutcome {
    pub(crate) task: bool,
    pub(crate) subscription: bool,
}

impl CancelOutcome {
    pub(crate) fn found(self) -> bool {
        self.task || self.subscription
    }
}

struct TaskHandle {
    kind: TaskKind,
    cancellation: Arc<AtomicBool>,
}

pub(crate) struct DaemonRuntime {
    nm: Arc<Nm>,
    work: SyncSender<Job>,
    control: SyncSender<Control>,
    tasks: Mutex<HashMap<String, TaskHandle>>,
    cache_refresh_pending: AtomicBool,
}

impl DaemonRuntime {
    pub(crate) fn start(nm: Nm) -> Arc<Self> {
        let nm = Arc::new(nm);
        let (work_tx, work_rx) = mpsc::sync_channel(WORK_QUEUE_CAPACITY);
        let (control_tx, control_rx) = mpsc::sync_channel(CONTROL_QUEUE_CAPACITY);
        start_workers(Arc::clone(&nm), work_rx);

        let runtime = Arc::new(Self {
            nm,
            work: work_tx,
            control: control_tx,
            tasks: Mutex::new(HashMap::new()),
            cache_refresh_pending: AtomicBool::new(false),
        });
        start_event_loop(Arc::downgrade(&runtime), control_rx);
        let control = runtime.control.clone();
        runtime.nm.subscribe_events(Arc::new(move || {
            let _ = control.try_send(Control::NetworkChanged);
        }));
        runtime
    }

    pub(crate) fn network_manager_connection(&self) -> zbus::blocking::Connection {
        self.nm.connection()
    }

    pub(crate) fn call<T>(
        &self,
        operation: ErrorOperation,
        task: impl FnOnce(&Nm) -> Result<T> + Send + 'static,
    ) -> Result<T>
    where
        T: Send + 'static,
    {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.submit(
            operation,
            Box::new(move |nm| {
                let _ = reply_tx.send(task(nm));
            }),
        )?;
        reply_rx.recv().map_err(|_| runtime_stopped(operation))?
    }

    pub(crate) fn start_cancellable(
        self: &Arc<Self>,
        request_id: String,
        kind: TaskKind,
        task: impl FnOnce(&Nm, &AtomicBool) + Send + 'static,
    ) -> Result<()> {
        let cancellation = Arc::new(AtomicBool::new(false));
        self.tasks.lock().expect("daemon task map poisoned").insert(
            request_id.clone(),
            TaskHandle {
                kind,
                cancellation: Arc::clone(&cancellation),
            },
        );
        let runtime = Arc::downgrade(self);
        let operation = kind.operation();
        let task_cancellation = Arc::clone(&cancellation);
        let submit = self.submit(
            operation,
            Box::new(move |nm| {
                task(nm, &task_cancellation);
                if let Some(runtime) = runtime.upgrade() {
                    runtime
                        .tasks
                        .lock()
                        .expect("daemon task map poisoned")
                        .remove(&request_id);
                }
            }),
        );
        if submit.is_err() {
            self.tasks
                .lock()
                .expect("daemon task map poisoned")
                .retain(|_, handle| !Arc::ptr_eq(&handle.cancellation, &cancellation));
        }
        submit
    }

    pub(crate) fn subscribe(
        &self,
        subscription_id: String,
        owner: Option<String>,
        streams: Vec<Stream>,
        emitter: SignalEmitter<'static>,
    ) -> Result<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.control
            .try_send(Control::Subscribe {
                subscription: SubscriptionState::new(subscription_id, owner, streams, emitter),
                reply: reply_tx,
            })
            .map_err(|error| queue_error(ErrorOperation::Subscribe, "control", error))?;
        reply_rx
            .recv()
            .map_err(|_| runtime_stopped(ErrorOperation::Subscribe))
    }

    pub(crate) fn cancel(&self, request_id: &str) -> CancelOutcome {
        let task_kind = self
            .tasks
            .lock()
            .expect("daemon task map poisoned")
            .get(request_id)
            .map(|task| {
                task.cancellation.store(true, Ordering::Relaxed);
                task.kind
            });
        self.nm.wake_waiters();

        if task_kind == Some(TaskKind::Connect) {
            let request_id = request_id.to_string();
            if let Err(error) = self.submit(
                ErrorOperation::Disconnect,
                Box::new(move |nm| match Application::new(nm).disconnect() {
                    Ok(result) => tracing::info!(
                        %request_id,
                        message = %result.message,
                        "aborted NetworkManager activation after cancellation"
                    ),
                    Err(error) => tracing::warn!(
                        %request_id,
                        error = %format_args!("{error:#}"),
                        "failed to abort NetworkManager activation after cancellation"
                    ),
                }),
            ) {
                tracing::warn!(error = %format_args!("{error:#}"), "could not queue activation abort");
            }
        }

        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        if self
            .control
            .try_send(Control::CancelSubscription {
                id: request_id.to_string(),
                task_found: task_kind.is_some(),
                reply: reply_tx,
            })
            .is_err()
        {
            return CancelOutcome {
                task: task_kind.is_some(),
                subscription: false,
            };
        }
        reply_rx.recv().unwrap_or(CancelOutcome {
            task: task_kind.is_some(),
            subscription: false,
        })
    }

    pub(crate) fn drop_owner(&self, owner: String) {
        if let Err(error) = self.control.try_send(Control::DropOwner(owner)) {
            tracing::warn!(error = ?error, "could not queue disconnected D-Bus owner cleanup");
        }
    }

    pub(crate) fn background_scans(self: &Arc<Self>) -> RuntimeBackgroundScan {
        RuntimeBackgroundScan {
            runtime: Arc::clone(self),
        }
    }

    fn schedule_cache_refresh(self: &Arc<Self>, timeout: Duration) {
        if self
            .cache_refresh_pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            tracing::debug!("coalesced duplicate daemon cache refresh");
            return;
        }
        let runtime = Arc::downgrade(self);
        let submit = self.submit(
            ErrorOperation::Scan,
            Box::new(move |nm| {
                let result = Application::new(nm).scan(
                    ScanRequest {
                        timeout,
                        strict: false,
                        cache: true,
                        ifname: None,
                        ssids: Vec::new(),
                    },
                    |_| Ok(()),
                );
                if let Err(error) = result {
                    tracing::warn!(error = %format_args!("{error:#}"), "daemon cache refresh failed");
                }
                if let Some(runtime) = runtime.upgrade() {
                    runtime
                        .cache_refresh_pending
                        .store(false, Ordering::Release);
                }
            }),
        );
        if let Err(error) = submit {
            self.cache_refresh_pending.store(false, Ordering::Release);
            tracing::warn!(error = %format_args!("{error:#}"), "could not queue daemon cache refresh");
        }
    }

    fn submit(&self, operation: ErrorOperation, job: Job) -> Result<()> {
        self.work
            .try_send(job)
            .map_err(|error| queue_error(operation, "work", error))
    }
}

pub(crate) struct RuntimeBackgroundScan {
    runtime: Arc<DaemonRuntime>,
}

impl BackgroundScanScheduler for RuntimeBackgroundScan {
    fn schedule_scan(&self, timeout: Duration) {
        self.runtime.schedule_cache_refresh(timeout);
    }
}

impl TaskKind {
    fn operation(self) -> ErrorOperation {
        match self {
            Self::Connect => ErrorOperation::Connect,
            Self::Scan => ErrorOperation::Scan,
        }
    }
}

enum Control {
    Subscribe {
        subscription: SubscriptionState,
        reply: SyncSender<()>,
    },
    CancelSubscription {
        id: String,
        task_found: bool,
        reply: SyncSender<CancelOutcome>,
    },
    DropOwner(String),
    NetworkChanged,
    Refreshed(SharedPayloads),
}

pub(crate) struct SharedPayloads {
    pub(crate) status: Option<Value>,
    pub(crate) connectivity: Option<Value>,
}

fn start_workers(nm: Arc<Nm>, receiver: Receiver<Job>) {
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..WORKER_COUNT {
        let nm = Arc::clone(&nm);
        let receiver = Arc::clone(&receiver);
        std::thread::Builder::new()
            .name(format!("nm-worker-{index}"))
            .spawn(move || {
                loop {
                    let job = receiver
                        .lock()
                        .expect("daemon work receiver poisoned")
                        .recv();
                    let Ok(job) = job else {
                        break;
                    };
                    job(&nm);
                }
            })
            .expect("spawn daemon worker");
    }
}

fn start_event_loop(runtime: Weak<DaemonRuntime>, receiver: Receiver<Control>) {
    std::thread::Builder::new()
        .name("nm-runtime".to_string())
        .spawn(move || {
            let mut subscriptions = HashMap::<String, SubscriptionState>::new();
            let mut refresh = RefreshGate::default();
            while let Ok(control) = receiver.recv() {
                let Some(runtime) = runtime.upgrade() else {
                    break;
                };
                match control {
                    Control::Subscribe {
                        subscription,
                        reply,
                    } => {
                        subscriptions.insert(subscription.id().to_string(), subscription);
                        let _ = reply.send(());
                        request_shared_refresh(&runtime, &subscriptions, &mut refresh);
                    }
                    Control::CancelSubscription {
                        id,
                        task_found,
                        reply,
                    } => {
                        let subscription = subscriptions.remove(&id);
                        let subscription_found = subscription.is_some();
                        let _ = reply.send(CancelOutcome {
                            task: task_found,
                            subscription: subscription_found,
                        });
                    }
                    Control::DropOwner(owner) => {
                        subscriptions.retain(|_, subscription| !subscription.owned_by(&owner));
                    }
                    Control::NetworkChanged => {
                        request_shared_refresh(&runtime, &subscriptions, &mut refresh)
                    }
                    Control::Refreshed(payloads) => {
                        let refresh_again = refresh.complete();
                        for subscription in subscriptions.values_mut() {
                            subscription.emit_changes(&payloads);
                        }
                        if refresh_again {
                            request_shared_refresh(&runtime, &subscriptions, &mut refresh);
                        }
                    }
                }
            }
        })
        .expect("spawn daemon event runtime");
}

fn request_shared_refresh(
    runtime: &Arc<DaemonRuntime>,
    subscriptions: &HashMap<String, SubscriptionState>,
    refresh: &mut RefreshGate,
) {
    if !refresh.invalidate() || subscriptions.is_empty() {
        return;
    }
    let need_status = subscriptions
        .values()
        .any(|subscription| subscription.watches(Stream::WifiStatus));
    let need_connectivity = subscriptions
        .values()
        .any(|subscription| subscription.watches(Stream::NetworkConnectivity));
    if !need_status && !need_connectivity {
        return;
    }
    let control = runtime.control.clone();
    match runtime.submit(
        ErrorOperation::Status,
        Box::new(move |nm| {
            let payloads = refresh_payloads(nm, need_status, need_connectivity);
            let _ = control.send(Control::Refreshed(payloads));
        }),
    ) {
        Ok(()) => refresh.started(),
        Err(error) => {
            tracing::warn!(error = %format_args!("{error:#}"), "could not queue shared status refresh");
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

fn queue_error<T>(
    operation: ErrorOperation,
    queue: &'static str,
    error: TrySendError<T>,
) -> anyhow::Error {
    let message = match error {
        TrySendError::Full(_) => "daemon work queue is full",
        TrySendError::Disconnected(_) => "daemon runtime has stopped",
    };
    DomainError::new(
        ErrorCode::InternalError,
        operation,
        ErrorSource::Internal,
        message,
    )
    .with_detail("queue", queue)
    .into()
}

fn runtime_stopped(operation: ErrorOperation) -> anyhow::Error {
    DomainError::new(
        ErrorCode::InternalError,
        operation,
        ErrorSource::Internal,
        "daemon runtime stopped before replying",
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::RefreshGate;

    #[test]
    fn refresh_gate_coalesces_invalidations_without_losing_a_change() {
        let mut refresh = RefreshGate::default();
        assert!(refresh.invalidate());
        refresh.started();

        assert!(!refresh.invalidate());
        assert!(!refresh.invalidate());
        assert!(refresh.complete());

        assert!(refresh.invalidate());
        refresh.started();
        assert!(!refresh.complete());
    }
}
