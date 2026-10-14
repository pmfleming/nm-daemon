//! Short-lived, one-shot handoff from NM's SaveSecrets to GetSecrets. A locked
//! keyring must not hide the password NM just supplied while creating a profile.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use super::{ConnectionSettings, PendingSecretRequest, SECRET_TIMEOUT, connection_secret_values};
use crate::keyring::KeyringSecret;

#[derive(Default)]
struct Handoff {
    entries: HashMap<(String, String, String), Entry>,
}
struct Entry {
    deadline: Instant,
    values: HashMap<String, Vec<(String, String)>>,
}
static HANDOFF: OnceLock<Mutex<Handoff>> = OnceLock::new();
fn access<T>(f: impl FnOnce(&mut Handoff) -> T) -> T {
    let mut cache = HANDOFF
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    cache.entries.retain(|_, e| e.deadline > Instant::now());
    f(&mut cache)
}
fn uuid(connection: &ConnectionSettings) -> Option<String> {
    crate::variant::setting::<&str>(connection.get("connection")?, "uuid")
        .filter(|uuid| !uuid.is_empty())
        .map(str::to_owned)
}

pub(super) fn stage(owner: &str, path: &str, connection: &ConnectionSettings) {
    let Some(uuid) = uuid(connection) else { return };
    let values = connection_secret_values(connection)
        .into_iter()
        .collect::<HashMap<_, _>>();
    access(|cache| {
        cache.entries.retain(|(_, p, _), _| p != path);
        if values.is_empty() {
            return;
        }
        if cache.entries.len() >= 32
            && let Some(key) = cache
                .entries
                .iter()
                .min_by_key(|(_, e)| e.deadline)
                .map(|(k, _)| k.clone())
        {
            cache.entries.remove(&key);
        }
        cache.entries.insert(
            (owner.into(), path.into(), uuid),
            Entry {
                deadline: Instant::now() + SECRET_TIMEOUT,
                values,
            },
        );
    });
    // Expire even if the connection never requests its password.
    tokio::spawn(async {
        tokio::time::sleep(SECRET_TIMEOUT).await;
        access(|_| ());
    });
}

pub(super) fn take(
    request: &PendingSecretRequest,
    connection: &ConnectionSettings,
) -> Vec<KeyringSecret> {
    let Some(uuid) = uuid(connection) else {
        return Vec::new();
    };
    access(|cache| {
        let key = (
            request.nm_owner.clone().unwrap_or_default(),
            request.connection_path.clone(),
            uuid,
        );
        let Some(entry) = cache.entries.get_mut(&key) else {
            return Vec::new();
        };
        let values = entry
            .values
            .remove(&request.setting_name)
            .unwrap_or_default();
        if entry.values.is_empty() {
            cache.entries.remove(&key);
        }
        values
            .into_iter()
            .filter(|(key, _)| request.secret_keys.contains(key))
            .map(|(key, password)| KeyringSecret { key, password })
            .collect()
    })
}

#[cfg(test)]
#[test]
fn native_handoff_is_bounded_and_expires_without_reusing_profile_identity() -> anyhow::Result<()> {
    crate::test_support::workflows::isolated(
        concat!(
            module_path!(),
            "::native_handoff_is_bounded_and_expires_without_reusing_profile_identity"
        ),
        || {
            let connection = ConnectionSettings::from([
                (
                    "connection".into(),
                    crate::variant::value_map([("uuid", "synthetic-uuid".into())])?,
                ),
                (
                    "802-11-wireless-security".into(),
                    crate::variant::value_map([("psk", "synthetic-password".into())])?,
                ),
            ]);
            for n in 0..40 {
                stage(":1.owner", &format!("/profile/{n}"), &connection);
            }
            access(|cache| {
                assert_eq!(cache.entries.len(), 32);
                assert!(
                    !cache
                        .entries
                        .keys()
                        .any(|(_, path, _)| path == "/profile/0")
                );
                for entry in cache.entries.values_mut() {
                    entry.deadline = Instant::now();
                }
            });
            access(|cache| assert!(cache.entries.is_empty()));
            Ok(())
        },
    )
}

pub(super) fn clear(path: Option<&str>) {
    access(|cache| {
        cache
            .entries
            .retain(|(_, p, _), _| path.is_some_and(|path| path != p))
    });
}
