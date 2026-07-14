use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

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
    target_ssid: Option<Vec<u8>>,
    cancellation: Arc<AtomicBool>,
}

pub(crate) struct DaemonRuntime {
    nm: Arc<Nm>,
    work: SyncSender<Job>,
    control: SyncSender<Control>,
    tasks: Mutex<HashMap<String, TaskHandle>>,
    tasks_changed: Condvar,
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
            tasks_changed: Condvar::new(),
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
        target_ssid: Option<Vec<u8>>,
        task: impl FnOnce(&Nm, &AtomicBool) + Send + 'static,
    ) -> Result<()> {
        let cancellation = Arc::new(AtomicBool::new(false));
        self.tasks.lock().expect("daemon task map poisoned").insert(
            request_id.clone(),
            TaskHandle {
                kind,
                target_ssid,
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
                    runtime.tasks_changed.notify_all();
                }
            }),
        );
        if submit.is_err() {
            self.tasks
                .lock()
                .expect("daemon task map poisoned")
                .retain(|_, handle| !Arc::ptr_eq(&handle.cancellation, &cancellation));
            self.tasks_changed.notify_all();
        }
        submit
    }

    pub(crate) fn cancel_connects_for_ssid(
        &self,
        forget_request_id: &str,
        ssid: &[u8],
    ) -> Vec<String> {
        let mut tasks = self.tasks.lock().expect("daemon task map poisoned");
        let mut request_ids = tasks
            .iter_mut()
            .filter_map(|(request_id, handle)| {
                (handle.kind == TaskKind::Connect && handle.target_ssid.as_deref() == Some(ssid))
                    .then(|| {
                        handle.cancellation.store(true, Ordering::Relaxed);
                        request_id.clone()
                    })
            })
            .collect::<Vec<_>>();
        request_ids.sort();
        drop(tasks);
        if !request_ids.is_empty() {
            tracing::info!(
                request_id = forget_request_id,
                connect_request_ids = ?request_ids,
                requests = request_ids.len(),
                "cancelling in-flight Wi-Fi connections before forget"
            );
            self.nm.wake_waiters();
        }
        request_ids
    }

    pub(crate) fn wait_for_tasks(&self, request_ids: &[String], timeout: Duration) -> Vec<String> {
        if request_ids.is_empty() {
            return Vec::new();
        }
        let deadline = Instant::now() + timeout;
        let mut tasks = self.tasks.lock().expect("daemon task map poisoned");
        loop {
            let mut pending = request_ids
                .iter()
                .filter(|request_id| tasks.contains_key(*request_id))
                .cloned()
                .collect::<Vec<_>>();
            pending.sort();
            if pending.is_empty() || Instant::now() >= deadline {
                return pending;
            }
            let wait = deadline.saturating_duration_since(Instant::now());
            let (next_tasks, _) = self
                .tasks_changed
                .wait_timeout(tasks, wait)
                .expect("daemon task map poisoned while waiting for cancellation");
            tasks = next_tasks;
        }
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
        let task_kind = self.cancel_task(request_id);
        self.nm.wake_waiters();
        self.abort_cancelled_connect(request_id, task_kind);
        self.cancel_subscription(request_id, task_kind.is_some())
    }

    fn cancel_task(&self, request_id: &str) -> Option<TaskKind> {
        self.tasks
            .lock()
            .expect("daemon task map poisoned")
            .get(request_id)
            .map(|task| {
                task.cancellation.store(true, Ordering::Relaxed);
                task.kind
            })
    }

    fn abort_cancelled_connect(&self, request_id: &str, task_kind: Option<TaskKind>) {
        if task_kind == Some(TaskKind::Connect)
            && let Err(error) = self.submit_activation_abort(request_id.to_string())
        {
            tracing::warn!(error = %crate::error::err_chain(&error), "could not queue activation abort");
        }
    }

    fn submit_activation_abort(&self, request_id: String) -> Result<()> {
        self.submit(
            ErrorOperation::Disconnect,
            Box::new(move |nm| {
                log_activation_abort(&request_id, Application::new(nm).disconnect())
            }),
        )
    }

    fn cancel_subscription(&self, request_id: &str, task_found: bool) -> CancelOutcome {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        if self
            .control
            .try_send(Control::CancelSubscription {
                id: request_id.to_string(),
                task_found,
                reply: reply_tx,
            })
            .is_err()
        {
            return CancelOutcome {
                task: task_found,
                subscription: false,
            };
        }
        reply_rx.recv().unwrap_or(CancelOutcome {
            task: task_found,
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
                    None,
                    |_| Ok(()),
                );
                if let Err(error) = result {
                    tracing::warn!(error = %crate::error::err_chain(&error), "daemon cache refresh failed");
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
            tracing::warn!(error = %crate::error::err_chain(&error), "could not queue daemon cache refresh");
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
        .spawn(move || run_event_loop(runtime, receiver))
        .expect("spawn daemon event runtime");
}

fn run_event_loop(runtime: Weak<DaemonRuntime>, receiver: Receiver<Control>) {
    let mut subscriptions = HashMap::<String, SubscriptionState>::new();
    let mut refresh = RefreshGate::default();
    while let Some((runtime, control)) = next_control(&runtime, &receiver) {
        handle_control(control, &runtime, &mut subscriptions, &mut refresh);
    }
}

fn next_control(
    runtime: &Weak<DaemonRuntime>,
    receiver: &Receiver<Control>,
) -> Option<(Arc<DaemonRuntime>, Control)> {
    let control = receiver.recv().ok()?;
    Some((runtime.upgrade()?, control))
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
            task_found,
            reply,
        } => remove_subscription(id, task_found, reply, subscriptions),
        Control::DropOwner(owner) => drop_subscriptions_for_owner(&owner, subscriptions),
        Control::NetworkChanged => request_shared_refresh(runtime, subscriptions, refresh),
        Control::Refreshed(payloads) => {
            complete_shared_refresh(payloads, runtime, subscriptions, refresh)
        }
    }
}

fn add_subscription(
    subscription: SubscriptionState,
    reply: SyncSender<()>,
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
    task_found: bool,
    reply: SyncSender<CancelOutcome>,
    subscriptions: &mut HashMap<String, SubscriptionState>,
) {
    let subscription = subscriptions.remove(&id);
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
    let (need_status, need_connectivity) = required_shared_payloads(subscriptions);
    if !need_status && !need_connectivity {
        return;
    }
    submit_shared_refresh(runtime, refresh, need_status, need_connectivity);
}

fn required_shared_payloads(subscriptions: &HashMap<String, SubscriptionState>) -> (bool, bool) {
    let watches = |stream| {
        subscriptions
            .values()
            .any(|subscription| subscription.watches(stream))
    };
    (
        watches(Stream::WifiStatus),
        watches(Stream::NetworkConnectivity),
    )
}

fn submit_shared_refresh(
    runtime: &Arc<DaemonRuntime>,
    refresh: &mut RefreshGate,
    need_status: bool,
    need_connectivity: bool,
) {
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
            tracing::warn!(error = %crate::error::err_chain(&error), "could not queue shared status refresh");
        }
    }
}

fn log_activation_abort(request_id: &str, result: Result<crate::model::DisconnectResult>) {
    match result {
        Ok(result) => {
            tracing::info!(%request_id, message = %result.message, "aborted NetworkManager activation after cancellation")
        }
        Err(error) => {
            tracing::warn!(%request_id, error = %crate::error::err_chain(&error), "failed to abort NetworkManager activation after cancellation")
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
