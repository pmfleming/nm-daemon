use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::Value;
use tokio::sync::{mpsc as tokio_mpsc, oneshot};
use zbus::object_server::SignalEmitter;

use crate::application::{Application, BackgroundScanScheduler, ScanRequest};
use crate::error::{DomainError, ErrorOperation};
use crate::generated::{CONTROL_QUEUE_CAPACITY, WORK_QUEUE_CAPACITY, WORKER_COUNT};
use crate::nm::Nm;
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};

mod lanes;
mod subscriptions;
use lanes::BlockingLane;
use subscriptions::Control;
pub(crate) use subscriptions::SharedPayloads;

type Job = Box<dyn FnOnce(&Nm) + Send + 'static>;

static REQUEST_IDS: shelllist_daemon_core::IdSequence = shelllist_daemon_core::IdSequence::new(1);

pub(crate) fn next_request_id(prefix: &str) -> String {
    REQUEST_IDS.next(prefix)
}

const FAST_WORKER_COUNT: usize = 1;
const READ_WORKER_COUNT: usize = 4;
const STATUS_CACHE_TTL: Duration = Duration::from_secs(1);
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const WRONG_PASSWORD_RETRY_DELAY: Duration = Duration::from_secs(10);
const TERMINAL_RESULT_TTL: Duration = Duration::from_secs(300);
const TERMINAL_RESULT_LIMIT: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskKind {
    Connect,
    Scan,
    Band,
    Statistics,
    Hotspot,
    Vpn,
}

impl TaskKind {
    fn stream(self) -> Stream {
        match self {
            Self::Connect => Stream::WifiConnect,
            Self::Scan => Stream::WifiScan,
            Self::Band => Stream::WifiBand,
            Self::Statistics => Stream::NetworkStatistics,
            Self::Hotspot => Stream::Hotspot,
            Self::Vpn => Stream::Vpn,
        }
    }
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

struct TerminalRequestResult {
    recorded_at: Instant,
    owner: Option<String>,
    stream: Stream,
    event: Value,
}

fn prune_terminal_results(results: &mut HashMap<String, TerminalRequestResult>) {
    results.retain(|_, result| result.recorded_at.elapsed() <= TERMINAL_RESULT_TTL);
}

fn terminal_request_status(
    results: &HashMap<String, TerminalRequestResult>,
    request_id: &str,
    owner: Option<&str>,
) -> Option<Value> {
    results.get(request_id).and_then(|result| {
        (result.owner.as_deref() == owner).then(|| {
            serde_json::json!({
                "request_id": request_id,
                "status": "finished",
                "stream": result.stream,
                "event": result.event,
            })
        })
    })
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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct ConnectAttemptKey {
    identity: String,
    credential_fingerprint: u64,
    supplied_credentials: bool,
}

impl ConnectAttemptKey {
    pub(crate) fn new(
        identity: String,
        credential_material: &[u8],
        supplied_credentials: bool,
    ) -> Self {
        let mut fingerprint = DefaultHasher::new();
        credential_material.hash(&mut fingerprint);
        Self {
            identity,
            credential_fingerprint: fingerprint.finish(),
            supplied_credentials,
        }
    }
}

#[derive(Default)]
struct ConnectAttemptPolicy {
    active_identities: HashSet<String>,
    blocked_until: HashMap<(String, u64), Instant>,
    stale_credentials: HashSet<String>,
}

enum ConnectAdmission {
    Active,
    RetryAfter(Duration),
    CredentialsRequired,
}

impl ConnectAttemptPolicy {
    fn admit(
        &mut self,
        attempt: &ConnectAttemptKey,
        now: Instant,
    ) -> std::result::Result<(), ConnectAdmission> {
        self.blocked_until.retain(|_, deadline| *deadline > now);
        if self.active_identities.contains(&attempt.identity) {
            return Err(ConnectAdmission::Active);
        }
        if self.stale_credentials.contains(&attempt.identity) && !attempt.supplied_credentials {
            return Err(ConnectAdmission::CredentialsRequired);
        }
        if let Some(deadline) = self
            .blocked_until
            .get(&(attempt.identity.clone(), attempt.credential_fingerprint))
        {
            return Err(ConnectAdmission::RetryAfter(
                deadline.saturating_duration_since(now),
            ));
        }
        self.active_identities.insert(attempt.identity.clone());
        Ok(())
    }

    fn complete(
        &mut self,
        attempt: &ConnectAttemptKey,
        reason: Option<crate::model::ConnectFailureReason>,
        succeeded: bool,
        now: Instant,
    ) {
        self.active_identities.remove(&attempt.identity);
        if succeeded {
            self.stale_credentials.remove(&attempt.identity);
            self.blocked_until
                .retain(|(identity, _), _| identity != &attempt.identity);
            return;
        }
        if matches!(
            reason,
            Some(
                crate::model::ConnectFailureReason::WrongPassword
                    | crate::model::ConnectFailureReason::PasswordUnavailable
                    | crate::model::ConnectFailureReason::SecretRequired
            )
        ) {
            self.stale_credentials.insert(attempt.identity.clone());
        }
        if reason == Some(crate::model::ConnectFailureReason::WrongPassword) {
            self.blocked_until.insert(
                (attempt.identity.clone(), attempt.credential_fingerprint),
                now + WRONG_PASSWORD_RETRY_DELAY,
            );
        }
    }

    fn abandon(&mut self, attempt: &ConnectAttemptKey) {
        self.active_identities.remove(&attempt.identity);
    }
}

pub(crate) struct ConnectAttemptGuard {
    runtime: Weak<DaemonRuntime>,
    attempt: ConnectAttemptKey,
    finished: bool,
}

impl ConnectAttemptGuard {
    pub(crate) fn finish(
        mut self,
        reason: Option<crate::model::ConnectFailureReason>,
        succeeded: bool,
    ) {
        if let Some(runtime) = self.runtime.upgrade() {
            recover_lock(&runtime.connect_attempts, "Wi-Fi connect attempt policy").complete(
                &self.attempt,
                reason,
                succeeded,
                Instant::now(),
            );
        }
        self.finished = true;
    }
}

impl Drop for ConnectAttemptGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(runtime) = self.runtime.upgrade() {
            recover_lock(&runtime.connect_attempts, "Wi-Fi connect attempt policy")
                .abandon(&self.attempt);
        }
    }
}

struct CachedStatus {
    recorded_at: Instant,
    response: Value,
}

pub(crate) struct DaemonRuntime {
    nm: Arc<Nm>,
    work: BlockingLane,
    fast_work: BlockingLane,
    read_work: BlockingLane,
    control: tokio_mpsc::Sender<Control>,
    tasks: Mutex<HashMap<String, TaskHandle>>,
    terminal_results: Mutex<HashMap<String, TerminalRequestResult>>,
    tasks_changed: Condvar,
    connect_attempts: Mutex<ConnectAttemptPolicy>,
    status_cache: Mutex<Option<CachedStatus>>,
    status_generation: AtomicUsize,
    cache_refresh_pending: AtomicBool,
}

impl DaemonRuntime {
    pub(crate) fn start(nm: Nm, tokio: tokio::runtime::Handle) -> Result<Arc<Self>> {
        let nm = Arc::new(nm);
        let work = BlockingLane::start(&tokio, "work", WORK_QUEUE_CAPACITY, WORKER_COUNT);
        let fast_work =
            BlockingLane::start(&tokio, "fast-work", WORK_QUEUE_CAPACITY, FAST_WORKER_COUNT);
        let read_work =
            BlockingLane::start(&tokio, "read-work", WORK_QUEUE_CAPACITY, READ_WORKER_COUNT);
        let (control_tx, control_rx) = tokio_mpsc::channel(CONTROL_QUEUE_CAPACITY);

        let runtime = Arc::new(Self {
            nm,
            work,
            fast_work,
            read_work,
            control: control_tx,
            tasks: Mutex::new(HashMap::new()),
            terminal_results: Mutex::new(HashMap::new()),
            tasks_changed: Condvar::new(),
            connect_attempts: Mutex::new(ConnectAttemptPolicy::default()),
            status_cache: Mutex::new(None),
            status_generation: AtomicUsize::new(0),
            cache_refresh_pending: AtomicBool::new(false),
        });
        subscriptions::start(&tokio, Arc::downgrade(&runtime), control_rx);
        let control = runtime.control.clone();
        let event_runtime = Arc::downgrade(&runtime);
        runtime.nm.subscribe_events(Arc::new(move || {
            if let Some(runtime) = event_runtime.upgrade() {
                runtime.invalidate_status();
            }
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

    pub(crate) fn store_terminal_result(
        &self,
        request_id: &str,
        owner: Option<String>,
        stream: Stream,
        event: Value,
    ) {
        let mut results = recover_lock(&self.terminal_results, "terminal request results");
        prune_terminal_results(&mut results);
        if results.len() >= TERMINAL_RESULT_LIMIT
            && let Some(oldest) = results
                .iter()
                .min_by_key(|(_, result)| result.recorded_at)
                .map(|(request_id, _)| request_id.clone())
        {
            results.remove(&oldest);
        }
        results.insert(
            request_id.to_string(),
            TerminalRequestResult {
                recorded_at: Instant::now(),
                owner,
                stream,
                event,
            },
        );
    }

    pub(crate) fn request_status(&self, request_id: &str, owner: Option<&str>) -> Value {
        {
            let mut results = recover_lock(&self.terminal_results, "terminal request results");
            prune_terminal_results(&mut results);
            if let Some(status) = terminal_request_status(&results, request_id, owner) {
                return status;
            }
        }
        let tasks = recover_lock(&self.tasks, "daemon task map");
        if let Some(task) = tasks
            .get(request_id)
            .filter(|task| task.owner.as_deref() == owner)
        {
            return serde_json::json!({
                "request_id": request_id,
                "status": "running",
                "stream": task.kind.stream(),
            });
        }
        serde_json::json!({
            "request_id": request_id,
            "status": "unknown",
        })
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
        tokio::join!(
            self.work.shutdown(),
            self.fast_work.shutdown(),
            self.read_work.shutdown()
        );
    }

    /// Serialize application results at the transport boundary. Preserve the
    /// read lane for the existing read-only methods; other calls stay serialized.
    pub(crate) fn call_application<T: serde::Serialize>(
        self: &Arc<Self>,
        method: Method,
        action: impl FnOnce(&Application<'_>) -> Result<T> + Send + 'static,
    ) -> Result<Value> {
        let spec = method.spec();
        let call = move |nm: &Nm| {
            api_data_value(
                spec.response_key,
                &action(&Application::new(nm))?,
                "serialize daemon method response JSON",
            )
        };
        if matches!(
            method,
            Method::NetworkConnectivity
                | Method::NetworkInventory
                | Method::NetworkDevices
                | Method::NetworkConnections
                | Method::NetworkState
                | Method::DiscoveryServices
                | Method::WifiSaved
        ) {
            self.call_read(spec.operation, call)
        } else {
            self.call(spec.operation, call)
        }
    }

    pub(crate) fn call_status(self: &Arc<Self>) -> Result<Value> {
        if let Some(response) = self.cached_status() {
            return Ok(response);
        }
        let generation = self.status_generation.load(Ordering::Acquire);
        let runtime = Arc::downgrade(self);
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.submit_read(
            ErrorOperation::Status,
            Box::new(move |nm| {
                let application = Application::new(nm);
                match application.status_snapshot().and_then(|status| {
                    let response = api_data_value(
                        Method::WifiStatus.spec().response_key,
                        &status,
                        "serialize daemon method response JSON",
                    )?;
                    Ok((response, status))
                }) {
                    Ok((response, status)) => {
                        if let Some(runtime) = runtime.upgrade() {
                            runtime.store_status(generation, response.clone());
                        }
                        // Release the interactive response before filesystem
                        // cache maintenance, which is only best-effort state.
                        let _ = reply_tx.send(Ok(response));
                        application.persist_status(&status);
                    }
                    Err(error) => {
                        let _ = reply_tx.send(Err(error));
                    }
                }
            }),
        )?;
        reply_rx
            .recv()
            .map_err(|_| runtime_stopped(ErrorOperation::Status))?
    }

    fn cached_status(&self) -> Option<Value> {
        let mut cached = recover_lock(&self.status_cache, "Wi-Fi status cache");
        if cached
            .as_ref()
            .is_some_and(|status| status.recorded_at.elapsed() <= STATUS_CACHE_TTL)
        {
            return cached.as_ref().map(|status| status.response.clone());
        }
        cached.take();
        None
    }

    fn store_status(&self, generation: usize, response: Value) {
        if self.status_generation.load(Ordering::Acquire) == generation {
            *recover_lock(&self.status_cache, "Wi-Fi status cache") = Some(CachedStatus {
                recorded_at: Instant::now(),
                response,
            });
        }
    }

    fn invalidate_status(&self) {
        self.status_generation.fetch_add(1, Ordering::AcqRel);
        recover_lock(&self.status_cache, "Wi-Fi status cache").take();
    }

    pub(crate) fn call<T>(
        &self,
        operation: ErrorOperation,
        task: impl FnOnce(&Nm) -> Result<T> + Send + 'static,
    ) -> Result<T>
    where
        T: Send + 'static,
    {
        self.call_on_lane(&self.fast_work, operation, task)
    }

    pub(crate) fn call_read<T>(
        &self,
        operation: ErrorOperation,
        task: impl FnOnce(&Nm) -> Result<T> + Send + 'static,
    ) -> Result<T>
    where
        T: Send + 'static,
    {
        self.call_on_lane(&self.read_work, operation, task)
    }

    fn call_on_lane<T>(
        &self,
        lane: &BlockingLane,
        operation: ErrorOperation,
        task: impl FnOnce(&Nm) -> Result<T> + Send + 'static,
    ) -> Result<T>
    where
        T: Send + 'static,
    {
        let nm = Arc::clone(&self.nm);
        lane.call(operation, move || task(&nm))
    }

    pub(crate) fn begin_connect_attempt(
        self: &Arc<Self>,
        attempt: ConnectAttemptKey,
    ) -> Result<ConnectAttemptGuard> {
        let admission = recover_lock(&self.connect_attempts, "Wi-Fi connect attempt policy")
            .admit(&attempt, Instant::now());
        if let Err(admission) = admission {
            let error = match admission {
                ConnectAdmission::Active => DomainError::connect(
                    crate::model::ConnectFailureReason::ActivationFailed,
                    "A connection attempt for this network is already running",
                ),
                ConnectAdmission::CredentialsRequired => DomainError::connect(
                    crate::model::ConnectFailureReason::SecretRequired,
                    "The saved Wi-Fi credentials failed; provide replacement credentials",
                ),
                ConnectAdmission::RetryAfter(delay) => DomainError::connect(
                    crate::model::ConnectFailureReason::WrongPassword,
                    "NetworkManager is temporarily ignoring this access point after a failed password",
                )
                .with_detail("retry_after_ms", delay.as_millis() as u64),
            };
            return Err(error.into());
        }
        Ok(ConnectAttemptGuard {
            runtime: Arc::downgrade(self),
            attempt,
            finished: false,
        })
    }

    pub(crate) fn start_cancellable(
        self: &Arc<Self>,
        request_prefix: &str,
        kind: TaskKind,
        owner: Option<String>,
        target_ssid: Option<Vec<u8>>,
        task: impl FnOnce(&Nm, &AtomicBool, &str) + Send + 'static,
    ) -> Result<String> {
        let request_id = next_request_id(request_prefix);
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
            request_id: request_id.clone(),
            cancellation: Arc::clone(&cancellation),
        };
        let worker_request_id = request_id.clone();
        let operation = kind.operation();
        self.submit(
            operation,
            Box::new(move |nm| {
                let _registration = registration;
                task(nm, &cancellation, &worker_request_id);
            }),
        )?;
        Ok(request_id)
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
            .try_send(Control::subscribe(
                subscription_id,
                owner,
                streams,
                emitter,
                reply_tx,
            ))
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
            tracing::debug!(
                trigger = "cache-refresh",
                disposition = "coalesced",
                "coalesced duplicate daemon cache refresh"
            );
            return;
        }
        tracing::info!(
            trigger = "cache-refresh",
            disposition = "started",
            timeout_ms = timeout.as_millis(),
            "scheduled background Wi-Fi cache refresh"
        );
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
        self.submit_on_lane(&self.work, operation, job)
    }

    fn submit_fast(&self, operation: ErrorOperation, job: Job) -> Result<()> {
        self.submit_on_lane(&self.fast_work, operation, job)
    }

    fn submit_read(&self, operation: ErrorOperation, job: Job) -> Result<()> {
        self.submit_on_lane(&self.read_work, operation, job)
    }

    fn submit_on_lane(
        &self,
        lane: &BlockingLane,
        operation: ErrorOperation,
        job: Job,
    ) -> Result<()> {
        let nm = Arc::clone(&self.nm);
        lane.try_submit(operation, Box::new(move || job(&nm)))
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
    use std::collections::HashMap;

    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::{
        ConnectAdmission, ConnectAttemptKey, ConnectAttemptPolicy, TERMINAL_RESULT_TTL,
        TerminalRequestResult, WRONG_PASSWORD_RETRY_DELAY, prune_terminal_results,
        terminal_request_status,
    };
    use crate::model::ConnectFailureReason;
    use crate::protocol::Stream;
    #[test]
    fn connect_attempt_policy_owns_duplicate_retry_and_stale_secret_rules() {
        let now = std::time::Instant::now();
        let saved = ConnectAttemptKey::new("network".into(), b"saved", false);
        let wrong = ConnectAttemptKey::new("network".into(), b"wrong", true);
        let replacement = ConnectAttemptKey::new("network".into(), b"replacement", true);
        let mut policy = ConnectAttemptPolicy::default();

        assert!(policy.admit(&wrong, now).is_ok());
        assert!(matches!(
            policy.admit(&wrong, now),
            Err(ConnectAdmission::Active)
        ));
        policy.complete(
            &wrong,
            Some(ConnectFailureReason::WrongPassword),
            false,
            now,
        );
        assert!(matches!(
            policy.admit(&wrong, now),
            Err(ConnectAdmission::RetryAfter(delay)) if delay == WRONG_PASSWORD_RETRY_DELAY
        ));
        assert!(matches!(
            policy.admit(&saved, now),
            Err(ConnectAdmission::CredentialsRequired)
        ));
        assert!(policy.admit(&replacement, now).is_ok());
        policy.complete(&replacement, None, true, now);
        assert!(policy.admit(&saved, now).is_ok());
    }

    #[test]
    fn terminal_request_results_are_owner_scoped_and_expire() {
        let mut results = HashMap::from([(
            "connect-1".to_string(),
            TerminalRequestResult {
                recorded_at: Instant::now(),
                owner: Some(":1.42".to_string()),
                stream: Stream::WifiConnect,
                event: json!({ "event": "succeeded" }),
            },
        )]);

        let status = terminal_request_status(&results, "connect-1", Some(":1.42")).unwrap();
        assert_eq!(status["status"], "finished");
        assert_eq!(status["event"]["event"], "succeeded");
        assert!(terminal_request_status(&results, "connect-1", Some(":1.99")).is_none());

        results.get_mut("connect-1").unwrap().recorded_at =
            Instant::now() - TERMINAL_RESULT_TTL - Duration::from_millis(1);
        prune_terminal_results(&mut results);
        assert!(results.is_empty());
    }
}
