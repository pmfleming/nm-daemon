//! Dispatch the D-Bus response before starting bounded, serialized durable writes.
use super::{DaemonRuntime, SECRET_TIMEOUT, SecretPersistenceOutcome};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use zbus::object_server::ResponseDispatchNotifier;

pub(super) type Save = Box<dyn FnOnce() -> SecretPersistenceOutcome + Send>;
static CAPACITY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);
static WRITER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type Tickets = HashMap<String, Vec<Weak<AtomicBool>>>;
static TICKETS: OnceLock<Mutex<Tickets>> = OnceLock::new();

fn ticket(path: &str) -> Arc<AtomicBool> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut tickets = TICKETS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    tickets.retain(|_, flags| {
        flags.retain(|flag| flag.strong_count() > 0);
        !flags.is_empty()
    });
    tickets
        .entry(path.into())
        .or_default()
        .push(Arc::downgrade(&cancelled));
    cancelled
}

pub(super) fn invalidate(path: &str) {
    let mut tickets = TICKETS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for flag in tickets
        .remove(path)
        .into_iter()
        .flatten()
        .filter_map(|flag| flag.upgrade())
    {
        flag.store(true, Ordering::Release);
    }
}

pub(super) async fn deletion_guard() -> tokio::sync::MutexGuard<'static, ()> {
    WRITER.lock().await
}

pub(super) fn after_reply<T>(
    response: T,
    runtime: Weak<DaemonRuntime>,
    request_id: String,
    profile_path: String,
    owner: Option<String>,
    delivered: bool,
    save: Option<Save>,
) -> ResponseDispatchNotifier<T> {
    let cancelled = save.as_ref().map(|_| ticket(&profile_path));
    let (response, dispatched) = ResponseDispatchNotifier::new(response);
    tokio::spawn(async move {
        dispatched.await;
        if super::ensure_secret_owner(owner.as_deref()).is_err() {
            return;
        }
        if delivered {
            super::emit_secret_event(
                &runtime,
                &request_id,
                "delivered",
                serde_json::json!({"request_id": request_id}),
            );
        }
        let Some(save) = save else { return };
        let outcome = persist(
            owner,
            cancelled.expect("save has cancellation ticket"),
            save,
        )
        .await;
        super::emit_secret_persistence(&runtime, &request_id, &profile_path, outcome);
    });
    response
}

#[cfg(test)]
#[test]
fn queued_saves_cannot_resurrect_deleted_secrets_and_capacity_is_bounded() -> anyhow::Result<()> {
    crate::test_support::workflows::isolated(
        concat!(
            module_path!(),
            "::queued_saves_cannot_resurrect_deleted_secrets_and_capacity_is_bounded"
        ),
        || {
            tokio::runtime::Handle::current().block_on(async {
                let writer = WRITER.lock().await;
                let flag = ticket("/forgotten");
                let pending = tokio::spawn(persist(
                    None,
                    flag,
                    Box::new(|| panic!("forgotten secret was persisted")),
                ));
                tokio::task::yield_now().await;
                invalidate("/forgotten");
                drop(writer);
                assert!(matches!(
                    pending.await.unwrap(),
                    SecretPersistenceOutcome::Failed(_)
                ));
                let _full = CAPACITY.acquire_many(8).await.unwrap();
                let result = persist(
                    None,
                    ticket("/full"),
                    Box::new(|| panic!("full queue accepted a save")),
                )
                .await;
                assert!(matches!(result, SecretPersistenceOutcome::Failed(_)));
            });
            Ok(())
        },
    )
}

async fn persist(
    owner: Option<String>,
    cancelled: Arc<AtomicBool>,
    save: Save,
) -> SecretPersistenceOutcome {
    let Ok(_capacity) = CAPACITY.try_acquire() else {
        return SecretPersistenceOutcome::Failed("Keyring save queue is full; retry saving".into());
    };
    let Ok(_writer) = tokio::time::timeout(SECRET_TIMEOUT, WRITER.lock()).await else {
        return SecretPersistenceOutcome::Failed(
            "Keyring save expired in queue; retry saving".into(),
        );
    };
    if cancelled.load(Ordering::Acquire) {
        return SecretPersistenceOutcome::Failed(
            "Credential saving cancelled before storage".into(),
        );
    }
    if super::ensure_secret_owner(owner.as_deref()).is_err() {
        return SecretPersistenceOutcome::Failed("NetworkManager changed before saving".into());
    }
    tokio::task::spawn_blocking(save).await.unwrap_or_else(|_| {
        SecretPersistenceOutcome::Failed("Keyring save worker stopped; retry saving".into())
    })
}
