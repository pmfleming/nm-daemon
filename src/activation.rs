//! Correlate SecretAgent requests with the exact native activation that owns
//! their time budget. No secrets or SSID-based cross-device matching live here.
use crate::error::DomainError;
use crate::model::ConnectFailureReason;
use crate::nm::ConnectionSettings;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests;

pub(crate) const AUTHENTICATION_RESERVE: Duration = Duration::from_secs(15);
type Key = (String, String);
static ACTIVE: OnceLock<Mutex<HashMap<Key, Weak<State>>>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub(crate) enum CredentialStop {
    Cancelled,
    Expired,
    Unavailable,
}
impl CredentialStop {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Unavailable => "agent-unavailable",
        }
    }
}

pub(crate) struct State {
    pub(crate) deadline: Instant,
    finished: AtomicBool,
    pending_credentials: AtomicUsize,
    missing_frontend: AtomicBool,
    failure: Mutex<Option<CredentialStop>>,
    wake: Box<dyn Fn() + Send + Sync>,
}
impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivationState")
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}
impl State {
    pub(crate) fn live(&self) -> bool {
        !self.finished.load(Ordering::Acquire)
            && Instant::now() < self.deadline
            && self
                .failure
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_none()
    }
    pub(crate) fn credential_deadline(&self) -> Instant {
        self.deadline
            .checked_sub(AUTHENTICATION_RESERVE)
            .unwrap_or(self.deadline)
    }
    pub(crate) fn note_frontend_availability(&self, available: bool) {
        self.missing_frontend.store(!available, Ordering::Release);
    }
    pub(crate) fn activation_error(&self, error: anyhow::Error) -> anyhow::Error {
        // Our agent declining a request is not proof that NM cannot obtain
        // credentials from another agent. Annotate only NM's terminal failure.
        if self.missing_frontend.load(Ordering::Acquire)
            && matches!(
                crate::connect_error::connect_failure_reason(&error),
                ConnectFailureReason::PasswordUnavailable | ConnectFailureReason::SecretRequired
            )
        {
            self.stop(CredentialStop::Unavailable);
        }
        self.error().unwrap_or(error)
    }
    pub(crate) fn track_credentials(self: &Arc<Self>) -> CredentialGuard {
        self.pending_credentials.fetch_add(1, Ordering::AcqRel);
        CredentialGuard(Arc::clone(self))
    }
    pub(crate) fn stop(&self, reason: CredentialStop) {
        let mut failure = self.failure.lock().unwrap_or_else(|p| p.into_inner());
        if failure.is_none() {
            *failure = Some(reason);
            drop(failure);
            (self.wake)();
        }
    }
    pub(crate) fn error(&self) -> Option<anyhow::Error> {
        // The verifier also enforces the credential budget when a keyring
        // lookup or queued worker has not returned to its own deadline check.
        if !self.finished.load(Ordering::Acquire)
            && self.pending_credentials.load(Ordering::Acquire) > 0
            && Instant::now() >= self.credential_deadline()
        {
            self.stop(CredentialStop::Expired);
        }
        let reason = (*self.failure.lock().unwrap_or_else(|p| p.into_inner()))?;
        let error = match reason {
            CredentialStop::Cancelled => DomainError::cancelled("Wi-Fi credential entry cancelled"),
            CredentialStop::Expired => DomainError::connect(
                ConnectFailureReason::Timeout,
                "Wi-Fi credential entry expired; connect again to retry",
            ),
            CredentialStop::Unavailable => DomainError::connect(
                ConnectFailureReason::PasswordUnavailable,
                "No credential frontend is available; open Shelllist and connect again",
            ),
        };
        Some(
            error
                .with_detail("credential_outcome", reason.name())
                .into(),
        )
    }
}

pub(crate) struct CredentialGuard(Arc<State>);
impl Drop for CredentialGuard {
    fn drop(&mut self) {
        self.0.pending_credentials.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
pub(crate) struct Guard {
    key: Key,
    pub(crate) state: Arc<State>,
}
impl Guard {
    pub(crate) fn new(
        owner: String,
        identity: String,
        deadline: Instant,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        let key = (owner, identity);
        let state = Arc::new(State {
            deadline,
            finished: AtomicBool::new(false),
            pending_credentials: AtomicUsize::new(0),
            missing_frontend: AtomicBool::new(false),
            failure: Mutex::new(None),
            wake: Box::new(wake),
        });
        let mut active = ACTIVE
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        active.retain(|_, state| state.strong_count() > 0);
        let previous = active
            .insert(key.clone(), Arc::downgrade(&state))
            .and_then(|s| s.upgrade());
        drop(active);
        if let Some(previous) = previous {
            previous.finished.store(true, Ordering::Release);
            previous.stop(CredentialStop::Cancelled);
        }
        Self { key, state }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.state.finished.store(true, Ordering::Release);
        let mut active = ACTIVE
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if active
            .get(&self.key)
            .and_then(Weak::upgrade)
            .is_some_and(|s| Arc::ptr_eq(&s, &self.state))
        {
            active.remove(&self.key);
        }
    }
}

pub(crate) fn identity(settings: &ConnectionSettings, path: &str) -> String {
    settings
        .get("connection")
        .and_then(|s| crate::variant::setting::<&str>(s, "uuid"))
        .filter(|uuid| !uuid.is_empty())
        .map(|uuid| format!("uuid:{uuid}"))
        .unwrap_or_else(|| format!("path:{path}"))
}
pub(crate) fn find(owner: &str, settings: &ConnectionSettings, path: &str) -> Option<Arc<State>> {
    ACTIVE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&(owner.into(), identity(settings, path)))
        .and_then(Weak::upgrade)
}
