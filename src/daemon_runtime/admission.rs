//! Connection admission owns its own lifetime; guards never retain a daemon.
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::error::{DomainError, recover_lock};
use crate::model::ConnectFailureReason;

const WRONG_PASSWORD_RETRY_DELAY: Duration = Duration::from_secs(10);

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
    // Borrow the identity on lookup; allocate it only when recording a failure.
    blocked_until: HashMap<String, HashMap<u64, Instant>>,
    stale_credentials: HashSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum ConnectAdmission {
    Active,
    RetryAfter(Duration),
    CredentialsRequired,
}

impl From<ConnectAdmission> for DomainError {
    fn from(admission: ConnectAdmission) -> Self {
        match admission {
            ConnectAdmission::Active => Self::connect(
                ConnectFailureReason::ActivationFailed,
                "A connection attempt for this network is already running",
            ),
            ConnectAdmission::CredentialsRequired => Self::connect(
                ConnectFailureReason::SecretRequired,
                "The saved Wi-Fi credentials failed; provide replacement credentials",
            ),
            ConnectAdmission::RetryAfter(delay) => Self::connect(
                ConnectFailureReason::WrongPassword,
                "NetworkManager is temporarily ignoring this access point after a failed password",
            )
            .with_detail("retry_after_ms", delay.as_millis() as u64),
        }
    }
}

impl ConnectAttemptPolicy {
    fn admit(
        &mut self,
        attempt: &ConnectAttemptKey,
        now: Instant,
    ) -> std::result::Result<(), ConnectAdmission> {
        self.blocked_until.retain(|_, fingerprints| {
            fingerprints.retain(|_, deadline| *deadline > now);
            !fingerprints.is_empty()
        });
        if self.active_identities.contains(&attempt.identity) {
            return Err(ConnectAdmission::Active);
        }
        if self.stale_credentials.contains(&attempt.identity) && !attempt.supplied_credentials {
            return Err(ConnectAdmission::CredentialsRequired);
        }
        if let Some(deadline) = self
            .blocked_until
            .get(&attempt.identity)
            .and_then(|fingerprints| fingerprints.get(&attempt.credential_fingerprint))
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
        reason: Option<ConnectFailureReason>,
        succeeded: bool,
        now: Instant,
    ) {
        self.abandon(attempt);
        if succeeded {
            self.stale_credentials.remove(&attempt.identity);
            self.blocked_until.remove(&attempt.identity);
            return;
        }
        if matches!(
            reason,
            Some(
                ConnectFailureReason::WrongPassword
                    | ConnectFailureReason::PasswordUnavailable
                    | ConnectFailureReason::SecretRequired
            )
        ) {
            self.stale_credentials.insert(attempt.identity.clone());
        }
        if reason == Some(ConnectFailureReason::WrongPassword) {
            self.blocked_until
                .entry(attempt.identity.clone())
                .or_default()
                .insert(
                    attempt.credential_fingerprint,
                    now + WRONG_PASSWORD_RETRY_DELAY,
                );
        }
    }

    fn abandon(&mut self, attempt: &ConnectAttemptKey) {
        self.active_identities.remove(&attempt.identity);
    }
}

#[derive(Default)]
pub(super) struct ConnectAttempts(Arc<Mutex<ConnectAttemptPolicy>>);

impl ConnectAttempts {
    pub(super) fn begin(&self, attempt: ConnectAttemptKey) -> Result<ConnectAttemptGuard> {
        recover_lock(&self.0, "Wi-Fi connect attempt policy")
            .admit(&attempt, Instant::now())
            .map_err(DomainError::from)?;
        Ok(ConnectAttemptGuard {
            policy: Arc::clone(&self.0),
            attempt,
            finished: false,
        })
    }
}

pub(crate) struct ConnectAttemptGuard {
    policy: Arc<Mutex<ConnectAttemptPolicy>>,
    attempt: ConnectAttemptKey,
    finished: bool,
}

impl ConnectAttemptGuard {
    pub(crate) fn finish(mut self, reason: Option<ConnectFailureReason>, succeeded: bool) {
        recover_lock(&self.policy, "Wi-Fi connect attempt policy").complete(
            &self.attempt,
            reason,
            succeeded,
            Instant::now(),
        );
        self.finished = true;
    }
}

impl Drop for ConnectAttemptGuard {
    fn drop(&mut self) {
        if !self.finished {
            recover_lock(&self.policy, "Wi-Fi connect attempt policy").abandon(&self.attempt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectAdmission, ConnectAttemptKey, ConnectAttemptPolicy, ConnectAttempts,
        WRONG_PASSWORD_RETRY_DELAY,
    };
    use crate::model::ConnectFailureReason;
    use std::time::Instant;

    fn key(credential: &[u8], supplied: bool) -> ConnectAttemptKey {
        ConnectAttemptKey::new("network".into(), credential, supplied)
    }

    #[test]
    fn duplicate_retry_expiry_and_stale_secret_rules_are_independent() {
        let now = Instant::now();
        let saved = key(b"saved", false);
        let wrong = key(b"wrong", true);
        let replacement = key(b"replacement", true);
        let mut policy = ConnectAttemptPolicy::default();
        assert_eq!(policy.admit(&wrong, now), Ok(()));
        assert_eq!(policy.admit(&wrong, now), Err(ConnectAdmission::Active));
        policy.complete(
            &wrong,
            Some(ConnectFailureReason::WrongPassword),
            false,
            now,
        );
        assert_eq!(
            policy.admit(&wrong, now),
            Err(ConnectAdmission::RetryAfter(WRONG_PASSWORD_RETRY_DELAY))
        );
        assert_eq!(
            policy.admit(&saved, now),
            Err(ConnectAdmission::CredentialsRequired)
        );
        assert_eq!(policy.admit(&replacement, now), Ok(()));
        policy.complete(
            &replacement,
            Some(ConnectFailureReason::WrongPassword),
            false,
            now,
        );
        assert_eq!(policy.blocked_until["network"].len(), 2);
        assert_eq!(
            policy.admit(&wrong, now + WRONG_PASSWORD_RETRY_DELAY),
            Ok(())
        );
        assert!(policy.blocked_until.is_empty());
        policy.abandon(&wrong);
        assert_eq!(
            policy.admit(&saved, now + WRONG_PASSWORD_RETRY_DELAY),
            Err(ConnectAdmission::CredentialsRequired)
        );
        assert_eq!(
            policy.admit(&replacement, now + WRONG_PASSWORD_RETRY_DELAY),
            Ok(())
        );
        policy.complete(&replacement, None, true, now);
        assert_eq!(policy.admit(&saved, now), Ok(()));
    }

    #[test]
    fn simultaneous_callers_admit_exactly_one_guard() {
        let attempts = ConnectAttempts::default();
        let barrier = std::sync::Barrier::new(4);
        let admitted = std::thread::scope(|scope| {
            let threads = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        let guard = attempts.begin(key(b"same", true));
                        barrier.wait(); // Keep the winner admitted until every caller tried.
                        guard.is_ok()
                    })
                })
                .collect::<Vec<_>>();
            threads
                .into_iter()
                .map(|thread| usize::from(thread.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(admitted, 1);
        assert!(attempts.begin(key(b"same", true)).is_ok());
    }

    #[test]
    fn guards_release_admission_on_abandon_unwind_and_completion() {
        let attempts = ConnectAttempts::default();
        let guard = attempts.begin(key(b"one", true)).unwrap();
        assert!(attempts.begin(key(b"two", true)).is_err());
        drop(guard);
        let guard = attempts.begin(key(b"two", true)).unwrap();
        assert!(
            std::panic::catch_unwind(|| {
                let _guard = guard;
                panic!("worker failed")
            })
            .is_err()
        );
        attempts
            .begin(key(b"three", true))
            .unwrap()
            .finish(None, true);
        let guard = attempts.begin(key(b"four", true)).unwrap();
        // Finishing the previous guard must not release this newer attempt.
        assert!(attempts.begin(key(b"five", true)).is_err());
        drop(attempts);
        drop(guard);
    }
}
