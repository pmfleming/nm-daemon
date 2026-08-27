use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::Value;
use tokio::sync::{Notify, Semaphore, mpsc as tokio_mpsc, oneshot, watch};
use zbus::object_server::SignalEmitter;

use crate::application::{Application, BackgroundScanScheduler, ScanRequest};
use crate::daemon_status::{SubscriptionState, refresh_payloads};
use crate::error::{DomainError, ErrorOperation};
use crate::generated::{CONTROL_QUEUE_CAPACITY, WORK_QUEUE_CAPACITY, WORKER_COUNT};
use crate::nm::Nm;
use crate::protocol::Stream;

type Job = Box<dyn FnOnce(&Nm) + Send + 'static>;

const FAST_WORKER_COUNT: usize = 1;
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct BlockingLane {
    sender: tokio_mpsc::Sender<Job>,
    name: &'static str,
    shutdown: watch::Sender<bool>,
    dispatcher: Mutex<Option<tokio::task::JoinHandle<()>>>,
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

impl BlockingLane {
    fn start(
        tokio: &tokio::runtime::Handle,
        nm: Arc<Nm>,
        name: &'static str,
        capacity: usize,
        concurrency: usize,
    ) -> Self {
        let (sender, receiver) = tokio_mpsc::channel(capacity);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let active = Arc::new(AtomicUsize::new(0));
        let idle = Arc::new(Notify::new());
        let dispatcher = tokio.spawn(run_blocking_lane(
            nm,
            name,
            concurrency,
            receiver,
            shutdown_rx,
            Arc::clone(&active),
            Arc::clone(&idle),
        ));
        Self {
            sender,
            name,
            shutdown,
            dispatcher: Mutex::new(Some(dispatcher)),
            active,
            idle,
        }
    }

    fn try_submit(&self, operation: ErrorOperation, job: Job) -> Result<()> {
        self.sender
            .try_send(job)
            .map_err(|error| tokio_queue_error(operation, self.name, error))
    }

    async fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        let dispatcher = recover_lock(&self.dispatcher, "blocking lane dispatcher").take();
        if let Some(dispatcher) = dispatcher
            && tokio::time::timeout(RUNTIME_SHUTDOWN_TIMEOUT, dispatcher)
                .await
                .is_err()
        {
            tracing::warn!(
                lane = self.name,
                "blocking lane dispatcher did not stop in time"
            );
        }
        if tokio::time::timeout(RUNTIME_SHUTDOWN_TIMEOUT, self.wait_until_idle())
            .await
            .is_err()
        {
            tracing::warn!(
                lane = self.name,
                active = self.active.load(Ordering::Acquire),
                "blocking lane jobs did not stop in time"
            );
        }
    }

    async fn wait_until_idle(&self) {
        loop {
            let notified = self.idle.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

async fn run_blocking_lane(
    nm: Arc<Nm>,
    name: &'static str,
    concurrency: usize,
    mut receiver: tokio_mpsc::Receiver<Job>,
    mut shutdown: watch::Receiver<bool>,
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
) {
    let permits = Arc::new(Semaphore::new(concurrency));
    loop {
        let permit = tokio::select! {
            _ = shutdown.changed() => return,
            permit = Arc::clone(&permits).acquire_owned() => {
                let Ok(permit) = permit else { return; };
                permit
            }
        };
        let job = tokio::select! {
            _ = shutdown.changed() => return,
            job = receiver.recv() => {
                let Some(job) = job else { return; };
                job
            }
        };
        let nm = Arc::clone(&nm);
        let active = Arc::clone(&active);
        let idle = Arc::clone(&idle);
        active.fetch_add(1, Ordering::AcqRel);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if catch_unwind(AssertUnwindSafe(|| job(&nm))).is_err() {
                tracing::error!(
                    lane = name,
                    "daemon blocking job panicked; lane remains available"
                );
            }
            active.fetch_sub(1, Ordering::AcqRel);
            idle.notify_waiters();
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskKind {
    Connect,
    Scan,
    Band,
    Statistics,
    Hotspot,
    Vpn,
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
    owner: Option<String>,
    target_ssid: Option<Arc<[u8]>>,
    cancellation: Arc<AtomicBool>,
}

struct TaskRegistration {
    runtime: Weak<DaemonRuntime>,
    request_id: String,
    cancellation: Arc<AtomicBool>,
}

impl Drop for TaskRegistration {
    fn drop(&mut self) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        recover_lock(&runtime.tasks, "daemon task map").retain(|request_id, handle| {
            request_id != &self.request_id || !Arc::ptr_eq(&handle.cancellation, &self.cancellation)
        });
        runtime.tasks_changed.notify_all();
    }
}

struct CancelledTask {
    kind: TaskKind,
    target_ssid: Option<Arc<[u8]>>,
}

pub(crate) struct DaemonRuntime {
    nm: Arc<Nm>,
    work: BlockingLane,
    fast_work: BlockingLane,
    control: tokio_mpsc::Sender<Control>,
    tasks: Mutex<HashMap<String, TaskHandle>>,
    tasks_changed: Condvar,
    cache_refresh_pending: AtomicBool,
}

impl DaemonRuntime {
    pub(crate) fn start(nm: Nm, tokio: tokio::runtime::Handle) -> Result<Arc<Self>> {
        let nm = Arc::new(nm);
        let work = BlockingLane::start(
            &tokio,
            Arc::clone(&nm),
            "work",
            WORK_QUEUE_CAPACITY,
            WORKER_COUNT,
        );
        let fast_work = BlockingLane::start(
            &tokio,
            Arc::clone(&nm),
            "fast-work",
            WORK_QUEUE_CAPACITY,
            FAST_WORKER_COUNT,
        );
        let (control_tx, control_rx) = tokio_mpsc::channel(CONTROL_QUEUE_CAPACITY);

        let runtime = Arc::new(Self {
            nm,
            work,
            fast_work,
            control: control_tx,
            tasks: Mutex::new(HashMap::new()),
            tasks_changed: Condvar::new(),
            cache_refresh_pending: AtomicBool::new(false),
        });
        start_event_loop(&tokio, Arc::downgrade(&runtime), control_rx);
        let control = runtime.control.clone();
        runtime.nm.subscribe_events(Arc::new(move || {
            let _ = control.try_send(Control::NetworkChanged);
        }));
        let health_control = runtime.control.clone();
        runtime.nm.subscribe_health(Arc::new(move |signal| {
            let _ = health_control.try_send(Control::HealthSignal(signal));
        }));
        Ok(runtime)
    }

    pub(crate) fn network_manager_connection(&self) -> zbus::blocking::Connection {
        self.nm.connection()
    }

    pub(crate) async fn shutdown(&self) {
        {
            let tasks = recover_lock(&self.tasks, "daemon task map");
            tasks
                .values()
                .for_each(|task| task.cancellation.store(true, Ordering::Release));
        }
        self.nm.wake_waiters();

        let (reply, stopped) = oneshot::channel();
        if self.control.send(Control::Shutdown(reply)).await.is_ok() {
            let _ = tokio::time::timeout(RUNTIME_SHUTDOWN_TIMEOUT, stopped).await;
        }
        tokio::join!(self.work.shutdown(), self.fast_work.shutdown());
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
        self.submit_fast(
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
        owner: Option<String>,
        target_ssid: Option<Vec<u8>>,
        task: impl FnOnce(&Nm, &AtomicBool) + Send + 'static,
    ) -> Result<()> {
        let cancellation = Arc::new(AtomicBool::new(false));
        let target_ssid = target_ssid.map(Arc::from);
        recover_lock(&self.tasks, "daemon task map").insert(
            request_id.clone(),
            TaskHandle {
                kind,
                owner,
                target_ssid,
                cancellation: Arc::clone(&cancellation),
            },
        );
        let registration = TaskRegistration {
            runtime: Arc::downgrade(self),
            request_id,
            cancellation: Arc::clone(&cancellation),
        };
        let operation = kind.operation();
        self.submit(
            operation,
            Box::new(move |nm| {
                let _registration = registration;
                task(nm, &cancellation);
            }),
        )
    }

    pub(crate) fn cancel_connects_for_ssid(
        &self,
        forget_request_id: &str,
        ssid: &[u8],
    ) -> Vec<String> {
        let mut tasks = recover_lock(&self.tasks, "daemon task map");
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
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut tasks = recover_lock(&self.tasks, "daemon task map");
        while request_ids.iter().any(|id| tasks.contains_key(id)) {
            if Instant::now() >= deadline {
                break;
            }
            let waited = self
                .tasks_changed
                .wait_timeout(tasks, deadline.saturating_duration_since(Instant::now()));
            tasks = match waited {
                Ok((tasks, _)) => tasks,
                Err(poisoned) => {
                    tracing::error!(
                        "recovering poisoned daemon task map while waiting for cancellation"
                    );
                    poisoned.into_inner().0
                }
            };
        }
        pending_task_ids(&tasks, request_ids)
    }

    pub(crate) fn subscribe(
        &self,
        subscription_id: String,
        owner: Option<String>,
        streams: Vec<Stream>,
        emitter: SignalEmitter<'static>,
    ) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.control
            .try_send(Control::Subscribe {
                subscription: SubscriptionState::new(subscription_id, owner, streams, emitter),
                reply: reply_tx,
            })
            .map_err(|error| tokio_queue_error(ErrorOperation::Subscribe, "control", error))?;
        reply_rx
            .blocking_recv()
            .map_err(|_| runtime_stopped(ErrorOperation::Subscribe))
    }

    pub(crate) fn cancel(&self, request_id: &str, owner: Option<&str>) -> CancelOutcome {
        let task = self.cancel_task(request_id, owner);
        self.nm.wake_waiters();
        self.abort_cancelled_connect(request_id, task.as_ref());
        self.cancel_subscription(request_id, owner, task.is_some())
    }

    fn cancel_task(&self, request_id: &str, owner: Option<&str>) -> Option<CancelledTask> {
        recover_lock(&self.tasks, "daemon task map")
            .get(request_id)
            .filter(|task| task.owner.as_deref() == owner)
            .map(|task| {
                task.cancellation.store(true, Ordering::Relaxed);
                CancelledTask {
                    kind: task.kind,
                    target_ssid: task.target_ssid.as_ref().map(Arc::clone),
                }
            })
    }

    fn abort_cancelled_connect(&self, request_id: &str, task: Option<&CancelledTask>) {
        let Some(target_ssid) = task
            .filter(|task| task.kind == TaskKind::Connect)
            .and_then(|task| task.target_ssid.as_ref().map(Arc::clone))
        else {
            return;
        };
        if let Err(error) = self.submit_activation_abort(request_id.to_string(), target_ssid) {
            tracing::warn!(error = %crate::error::err_chain(&error), "could not queue activation abort");
        }
    }

    fn submit_activation_abort(&self, request_id: String, target_ssid: Arc<[u8]>) -> Result<()> {
        self.submit_fast(
            ErrorOperation::Disconnect,
            Box::new(move |nm| {
                log_activation_abort(
                    &request_id,
                    Application::new(nm).disconnect_wifi_for_ssid(&target_ssid),
                )
            }),
        )
    }

    fn cancel_subscription(
        &self,
        request_id: &str,
        owner: Option<&str>,
        task_found: bool,
    ) -> CancelOutcome {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .control
            .try_send(Control::CancelSubscription {
                id: request_id.to_string(),
                owner: owner.map(ToString::to_string),
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
        reply_rx.blocking_recv().unwrap_or(CancelOutcome {
            task: task_found,
            subscription: false,
        })
    }

    fn cancel_tasks_for_owner(&self, owner: &str) -> Vec<(String, CancelledTask)> {
        recover_lock(&self.tasks, "daemon task map")
            .iter()
            .filter(|(_, task)| task.owner.as_deref() == Some(owner))
            .map(|(request_id, task)| {
                task.cancellation.store(true, Ordering::Relaxed);
                (
                    request_id.clone(),
                    CancelledTask {
                        kind: task.kind,
                        target_ssid: task.target_ssid.as_ref().map(Arc::clone),
                    },
                )
            })
            .collect()
    }

    pub(crate) fn drop_owner(&self, owner: String) {
        let cancelled = self.cancel_tasks_for_owner(&owner);
        if !cancelled.is_empty() {
            self.nm.wake_waiters();
            for (request_id, task) in cancelled {
                self.abort_cancelled_connect(&request_id, Some(&task));
            }
        }
        if let Err(error) = self.control.try_send(Control::DropOwner(owner)) {
            tracing::warn!(error = ?error, "could not queue disconnected D-Bus owner cleanup");
        }
    }

    pub(crate) fn subscriber_owners(&self, stream: Stream) -> Vec<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .control
            .try_send(Control::SubscriberOwners {
                stream,
                reply: reply_tx,
            })
            .is_err()
        {
            return Vec::new();
        }
        reply_rx.blocking_recv().unwrap_or_default()
    }

    pub(crate) fn emit_external(
        &self,
        stream: Stream,
        request_id: String,
        event: &'static str,
        data: Value,
    ) {
        if let Err(error) = self.control.try_send(Control::ExternalEvent {
            stream,
            request_id,
            event,
            data,
        }) {
            tracing::warn!(?error, "could not queue external daemon event");
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
        self.work.try_submit(operation, job)
    }

    fn submit_fast(&self, operation: ErrorOperation, job: Job) -> Result<()> {
        self.fast_work.try_submit(operation, job)
    }
}

impl BackgroundScanScheduler for Arc<DaemonRuntime> {
    fn schedule_scan(&self, timeout: Duration) {
        self.schedule_cache_refresh(timeout);
    }
}

impl TaskKind {
    fn operation(self) -> ErrorOperation {
        match self {
            Self::Connect => ErrorOperation::Connect,
            Self::Scan => ErrorOperation::Scan,
            Self::Band => ErrorOperation::BandOperation,
            Self::Statistics => ErrorOperation::Statistics,
            Self::Hotspot => ErrorOperation::HotspotOperation,
            Self::Vpn => ErrorOperation::VpnOperation,
        }
    }
}

enum Control {
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

pub(crate) struct SharedPayloads {
    pub(crate) status: Option<Value>,
    pub(crate) connectivity: Option<Value>,
    pub(crate) inventory: Option<Value>,
    pub(crate) networks: Option<Value>,
}

fn pending_task_ids(tasks: &HashMap<String, TaskHandle>, request_ids: &[String]) -> Vec<String> {
    let mut pending = request_ids
        .iter()
        .filter(|id| tasks.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    pending.sort();
    pending
}

fn recover_lock<'a, T>(mutex: &'a Mutex<T>, name: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!(resource = name, "recovering poisoned daemon runtime lock");
            poisoned.into_inner()
        }
    }
}

fn start_event_loop(
    tokio: &tokio::runtime::Handle,
    runtime: Weak<DaemonRuntime>,
    receiver: tokio_mpsc::Receiver<Control>,
) {
    tokio.spawn(run_event_loop(runtime, receiver));
}

async fn run_event_loop(runtime: Weak<DaemonRuntime>, mut receiver: tokio_mpsc::Receiver<Control>) {
    let mut subscriptions = HashMap::<String, SubscriptionState>::new();
    let mut refresh = RefreshGate::default();
    while let Some(control) = receiver.recv().await {
        if let Control::Shutdown(reply) = control {
            subscriptions.clear();
            let _ = reply.send(());
            return;
        }
        let Some(runtime) = runtime.upgrade() else {
            return;
        };
        handle_control(control, &runtime, &mut subscriptions, &mut refresh);
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
        Control::ExternalEvent {
            stream,
            request_id,
            event,
            data,
        } => emit_external_to_subscribers(subscriptions, stream, &request_id, event, &data),
        Control::DropOwner(owner) => drop_subscriptions_for_owner(&owner, subscriptions),
        Control::HealthSignal(signal) => publish_health_signal(signal, runtime, subscriptions),
        Control::NetworkChanged => request_shared_refresh(runtime, subscriptions, refresh),
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

/// Builds and fans out one `network.health` event. The payload is only
/// resolved while somebody is watching, so an idle daemon does no D-Bus work
/// for every NetworkManager transition.
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
    let queued = runtime.submit_fast(
        ErrorOperation::Status,
        Box::new(move |nm| {
            let request_id = crate::daemon_event::next_request_id("health");
            match nm.network_health_event(&signal) {
                Ok(health) => {
                    let _ = control.blocking_send(Control::ExternalEvent {
                        stream: Stream::NetworkHealth,
                        request_id: request_id.clone(),
                        event,
                        data: serde_json::json!({ "request_id": request_id, "health": health }),
                    });
                }
                Err(error) => {
                    tracing::warn!(error = %crate::error::err_chain(&error), "could not describe a NetworkManager health transition");
                }
            }
        }),
    );
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
    let SharedPayloadDemand {
        status: need_status,
        connectivity: need_connectivity,
        inventory: need_inventory,
        networks: need_networks,
    } = needs;
    let control = runtime.control.clone();
    match runtime.submit_fast(
        ErrorOperation::Status,
        Box::new(move |nm| {
            let payloads = refresh_payloads(
                nm,
                need_status,
                need_connectivity,
                need_inventory,
                need_networks,
            );
            let _ = control.blocking_send(Control::Refreshed(payloads));
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
        Ok(result) if result.status == "disconnected" => {
            tracing::info!(%request_id, message = %result.message, "aborted NetworkManager activation after cancellation")
        }
        Ok(result) => {
            tracing::info!(%request_id, message = %result.message, "skipped activation abort after cancelled target stopped matching")
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

fn tokio_queue_error<T>(
    operation: ErrorOperation,
    queue: &'static str,
    error: tokio_mpsc::error::TrySendError<T>,
) -> anyhow::Error {
    let message = match error {
        tokio_mpsc::error::TrySendError::Full(_) => "daemon work queue is full",
        tokio_mpsc::error::TrySendError::Closed(_) => "daemon runtime has stopped",
    };
    DomainError::internal(operation, message)
        .with_detail("queue", queue)
        .into()
}

fn runtime_stopped(operation: ErrorOperation) -> anyhow::Error {
    DomainError::internal(operation, "daemon runtime stopped before replying").into()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{RefreshGate, recover_lock};

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

    #[test]
    fn poisoned_runtime_locks_recover_the_last_consistent_value() {
        let value = Arc::new(Mutex::new(7_u32));
        let poisoned = Arc::clone(&value);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().expect("initial lock");
            panic!("poison test lock");
        })
        .join();

        assert_eq!(*recover_lock(&value, "test lock"), 7);
        *recover_lock(&value, "test lock") = 8;
        assert_eq!(*recover_lock(&value, "test lock"), 8);
    }
}
