//! NM-only retention policy and post-activation persistence confirmation.
//! No Secret Service access. No GetSecrets or mutation before reply dispatch.
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use zbus::Proxy;
use zvariant::{OwnedObjectPath, OwnedValue};

use super::{ConnectionSettings, PendingSecretRequest, SecretPersistenceOutcome, persistence};
use crate::network_credentials::{self as schema, AGENT_OWNED, NOT_SAVED};
use crate::variant::owned_value;

const ROOT: &str = "/org/freedesktop/NetworkManager";
const NM: &str = "org.freedesktop.NetworkManager";
const PROFILE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";

#[derive(Default)]
pub(super) struct Policy {
    pub(super) persistent: HashSet<String>,
    pub(super) migration_required: bool,
}
impl Policy {
    pub(super) fn from_request(
        settings: &ConnectionSettings,
        section: &str,
        keys: &[String],
    ) -> Result<Self> {
        ensure!(
            !keys.is_empty(),
            "request has no supported credential names"
        );
        let mut policy = Self::default();
        for key in keys {
            let flags = schema::flags(settings, section, key)?;
            ensure!(
                section != "wifi-p2p" || flags & NOT_SAVED != 0,
                "WPS enrollment requires explicit temporary policy"
            );
            if flags & NOT_SAVED != 0 {
                continue;
            }
            if flags & AGENT_OWNED != 0 {
                policy.migration_required = true;
            } else {
                policy.persistent.insert(key.clone());
            }
        }
        Ok(policy)
    }
    pub(super) fn rejection(&self, save: bool) -> Option<&'static str> {
        if !save && !self.persistent.is_empty() {
            Some("temporary-activation-required")
        } else if save && self.migration_required {
            Some("networkmanager-migration-required")
        } else {
            None
        }
    }
}

fn bounded<T>(operation: impl Future<Output = zbus::Result<T>>) -> Result<T> {
    tokio::runtime::Handle::current().block_on(async {
        tokio::time::timeout(Duration::from_secs(3), operation)
            .await
            .map_err(|_| anyhow::anyhow!("NetworkManager confirmation timed out"))?
            .map_err(|_| anyhow::anyhow!("NetworkManager confirmation call failed"))
    })
}
fn proxy(request: &PendingSecretRequest, path: &str, interface: &str) -> Result<Proxy<'static>> {
    let connection = request
        .nm_connection
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("request transport unavailable"))?;
    let owner = request
        .nm_owner
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("request owner unavailable"))?;
    Ok(
        zbus::blocking::proxy::Builder::<zbus::blocking::Proxy<'static>>::new(connection)
            .destination(owner.clone())?
            .path(path.to_string())?
            .interface(interface.to_string())?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()?
            .into_inner(),
    )
}
fn current(request: &PendingSecretRequest, cancelled: &AtomicBool) -> Result<()> {
    ensure!(
        !cancelled.load(Ordering::Acquire),
        "credential confirmation superseded or cancelled"
    );
    super::ensure_request_owner(request)
        .map_err(|_| anyhow::anyhow!("credential request retired"))?;
    let connection = request
        .nm_connection
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("request transport unavailable"))?;
    let bus = zbus::blocking::fdo::DBusProxy::new(connection)?
        .into_inner()
        .into_inner();
    let owner: String = bounded(bus.call("GetNameOwner", &(NM,)))?;
    ensure!(
        request.nm_owner.as_deref() == Some(owner.as_str()),
        "NetworkManager owner changed"
    );
    Ok(())
}

struct Context {
    public: ConnectionSettings,
    filename: String,
    active: OwnedObjectPath,
}

fn capture(request: &PendingSecretRequest, supplied: &ConnectionSettings) -> Result<Context> {
    let profile = proxy(request, &request.connection_path, PROFILE)?;
    let version = bounded(profile.get_property::<u64>("VersionId"))?;
    ensure!(version != 0, "profile version unavailable");
    let public: ConnectionSettings = bounded(profile.call("GetSettings", &()))?;
    ensure!(
        schema::public_settings(&public)? == schema::public_settings(supplied)?,
        "profile changed during credential prompting"
    );
    ensure!(
        !bounded(profile.get_property::<bool>("Unsaved"))?,
        "profile has staged changes"
    );
    let filename = bounded(profile.get_property::<String>("Filename"))?;
    ensure!(
        filename.starts_with("/etc/NetworkManager/system-connections/"),
        "profile is not durably file-backed"
    );
    ensure!(
        bounded(profile.get_property::<u64>("VersionId"))? == version,
        "profile changed during confirmation setup"
    );
    let root = proxy(request, ROOT, NM)?;
    let running: String = bounded(root.get_property("Version"))?;
    ensure!(
        crate::networkmanager_compatibility::validated_storage_version(&running),
        "unvalidated NetworkManager storage semantics"
    );
    let paths: Vec<OwnedObjectPath> = bounded(root.get_property("ActiveConnections"))?;
    let mut matching = Vec::new();
    for path in paths {
        let active = proxy(request, path.as_str(), ACTIVE)?;
        let connection: OwnedObjectPath = bounded(active.get_property("Connection"))?;
        if connection.as_str() == request.connection_path
            && bounded(active.get_property::<u32>("State"))? == 1
        {
            matching.push(path);
        }
    }
    ensure!(
        matching.len() == 1,
        "no unambiguous pending activation boundary; storage is unconfirmed"
    );
    Ok(Context {
        public: schema::public_settings(&public)?,
        filename,
        active: matching.remove(0),
    })
}

pub(super) fn prepare(
    request: &Arc<PendingSecretRequest>,
    settings: &ConnectionSettings,
    mut values: HashMap<String, String>,
) -> persistence::Save {
    values.retain(|key, _| request.policy.persistent.contains(key));
    // Only public properties are queried while NM awaits our callback. Even a
    // failed capture must not turn native delivery success into authentication
    // failure; report the separate confirmation failure after dispatch.
    let context = if values.is_empty() {
        Err(anyhow::anyhow!("request contains no saveable credentials"))
    } else {
        capture(request, settings)
    };
    let request = Arc::clone(request);
    Box::new(move |cancelled| {
        let result = context.and_then(|context| confirm(&request, &context, &values, cancelled));
        match result {
            Ok(()) => SecretPersistenceOutcome::Stored,
            Err(error) => SecretPersistenceOutcome::Failed(error.to_string()),
        }
    })
}

fn confirm(
    request: &PendingSecretRequest,
    context: &Context,
    values: &HashMap<String, String>,
    cancelled: &AtomicBool,
) -> Result<()> {
    let active = proxy(request, context.active.as_str(), ACTIVE)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        current(request, cancelled)?;
        match bounded(active.get_property::<u32>("State"))? {
            2 => break,
            1 => {}
            _ => anyhow::bail!("activation ended before durable storage could be confirmed"),
        }
        ensure!(
            Instant::now() < deadline,
            "activation boundary timed out; storage is unconfirmed"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // State was ACTIVATING when captured and is now ACTIVATED: NM has consumed
    // the reply. Reply dispatch alone is deliberately not this synchronization.
    let profile = proxy(request, &request.connection_path, PROFILE)?;
    let version = bounded(profile.get_property::<u64>("VersionId"))?;
    let public: ConnectionSettings = bounded(profile.call("GetSettings", &()))?;
    ensure!(
        schema::public_settings(&public)? == context.public,
        "profile changed before confirmation"
    );
    ensure!(
        !bounded(profile.get_property::<bool>("Unsaved"))?,
        "staged changes must not be flushed by credential confirmation"
    );
    ensure!(
        bounded(profile.get_property::<String>("Filename"))? == context.filename,
        "profile storage changed"
    );
    for key in values.keys() {
        ensure!(
            schema::flags(&public, &request.setting_name, key)? & (AGENT_OWNED | NOT_SAVED) == 0,
            "credential retention changed"
        );
    }
    // Do not start background authorization dialogs; explicit foreground
    // authorization can be retried separately when these permissions are absent.
    let permissions: HashMap<String, String> =
        bounded(proxy(request, ROOT, NM)?.call("GetPermissions", &()))?;
    let acl = public
        .get("connection")
        .map(|s| crate::variant::setting_strings(s, "permissions"))
        .unwrap_or_default();
    let permission = if acl.len() == 1 {
        "org.freedesktop.NetworkManager.settings.modify.own"
    } else {
        "org.freedesktop.NetworkManager.settings.modify.system"
    };
    ensure!(
        permissions.get(permission).is_some_and(|v| v == "yes"),
        "authorization needed for durable confirmation"
    );
    current(request, cancelled)?;
    ensure!(
        bounded(profile.get_property::<u64>("VersionId"))? == version,
        "profile changed before secret verification"
    );
    let stored: ConnectionSettings =
        bounded(profile.call("GetSecrets", &(request.setting_name.as_str(),)))?;
    let expected = version
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("profile version exhausted"))?;
    ensure!(
        bounded(profile.get_property::<u64>("VersionId"))? == expected,
        "concurrent edit during secret verification"
    );
    for (key, value) in values {
        ensure!(
            schema::text(&stored, &request.setting_name, key).as_deref() == Some(value.as_str()),
            "credential changed or was not retained by NetworkManager"
        );
    }
    current(request, cancelled)?;
    ensure!(
        !bounded(profile.get_property::<bool>("Unsaved"))?,
        "profile has staged changes"
    );
    // Empty Update2 commits NM's *current* settings; it never overlays our old
    // response, drops an unrelated secret, or converts agent/temporary policy.
    let args = HashMap::from([("version-id", owned_value(expected)?)]);
    let _: HashMap<String, OwnedValue> =
        bounded(profile.call("Update2", &(ConnectionSettings::new(), 1u32, args)))?;
    current(request, cancelled)?;
    ensure!(
        bounded(profile.get_property::<u64>("VersionId"))?
            == expected
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("profile version exhausted"))?,
        "profile changed after commit; storage outcome needs verification"
    );
    ensure!(
        !bounded(profile.get_property::<bool>("Unsaved"))?,
        "profile remains unsaved"
    );
    ensure!(
        bounded(profile.get_property::<String>("Filename"))? == context.filename,
        "profile storage changed after commit"
    );
    Ok(())
}

#[cfg(test)]
mod confirmation_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variant::value_map;
    #[test]
    fn vpn_messages_are_not_credentials_or_permission_to_guess_a_password() -> Result<()> {
        let keys = crate::daemon_secret::secret_keys_for(
            "vpn",
            &[
                "vpn.secrets.cookie".into(),
                "x-vpn-message:Enter a fresh token".into(),
            ],
        );
        assert_eq!(keys, ["cookie"]);
        let keys = crate::daemon_secret::secret_keys_for(
            "vpn",
            &["x-vpn-message:Enter a fresh token".into()],
        );
        assert!(Policy::from_request(&ConnectionSettings::new(), "vpn", &keys).is_err());
        Ok(())
    }

    #[test]
    fn mixed_agent_and_system_ownership_requires_migration_not_implicit_conversion() -> Result<()> {
        let settings = ConnectionSettings::from([(
            "802-1x".into(),
            value_map([
                ("password-flags", 0u32.into()),
                ("private-key-password-flags", 1u32.into()),
            ])?,
        )]);
        let policy = Policy::from_request(
            &settings,
            "802-1x",
            &["password".into(), "private-key-password".into()],
        )?;
        assert_eq!(
            policy.rejection(false),
            Some("temporary-activation-required")
        );
        assert_eq!(
            policy.rejection(true),
            Some("networkmanager-migration-required")
        );
        Ok(())
    }

    #[test]
    fn retention_is_per_secret_and_no_save_cannot_silently_persist() -> Result<()> {
        let settings = ConnectionSettings::from([(
            "802-1x".into(),
            value_map([("password-flags", 0u32.into()), ("pin-flags", 2u32.into())])?,
        )]);
        let policy = Policy::from_request(&settings, "802-1x", &["password".into(), "pin".into()])?;
        assert!(policy.persistent.contains("password"));
        assert!(!policy.persistent.contains("pin"));
        assert_eq!(
            policy.rejection(false),
            Some("temporary-activation-required")
        );
        assert_eq!(policy.rejection(true), None);
        let temporary = Policy::from_request(&settings, "802-1x", &["pin".into()])?;
        assert_eq!(temporary.rejection(false), None);
        assert!(temporary.persistent.is_empty());
        Ok(())
    }
}
