use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::blocking::Connection;
use zbus::message::Header;

mod lifecycle;
mod persistence;
#[cfg(test)]
mod regressions;
mod session;
pub(crate) use lifecycle::watch_network_manager;
use zvariant::{OwnedObjectPath, OwnedValue};

use crate::daemon_runtime::DaemonRuntime;
use crate::error::best_effort;
use crate::generated::SECRET_TIMEOUT;
use crate::nm::{ConnectionSettings, NM_DEST};
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};
use crate::variant::{value_string, value_string_map};

// AgentManager.Register accepts an identifier, not an object path. NM always
// calls agents at this standardized path, even when registration succeeded.
pub(crate) const SECRET_AGENT_OBJECT_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";

const AGENT_MANAGER_PATH: &str = "/org/freedesktop/NetworkManager/AgentManager";
const AGENT_MANAGER_IFACE: &str = "org.freedesktop.NetworkManager.AgentManager";
const SECRET_AGENT_ID: &str = "nm-daemon";

// NM_SECRET_AGENT_GET_SECRETS_FLAG_*
const ALLOW_INTERACTION: u32 = 0x1;
const REQUEST_NEW: u32 = 0x2;

static REGISTERED: AtomicBool = AtomicBool::new(false);
static PENDING: OnceLock<Mutex<PendingRegistry>> = OnceLock::new();

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop")]
enum SecretAgentError {
    #[zbus(name = "NetworkManager.SecretAgent.UserCanceled")]
    UserCanceled(String),
    #[zbus(name = "NetworkManager.SecretAgent.NoSecrets")]
    NoSecrets(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
}

type SecretResult<T> = Result<T, SecretAgentError>;

impl From<zbus::fdo::Error> for SecretAgentError {
    fn from(error: zbus::fdo::Error) -> Self {
        match error {
            zbus::fdo::Error::AccessDenied(message) => Self::AccessDenied(message),
            error => Self::Failed(error.to_string()),
        }
    }
}

pub(crate) struct SecretAgentInterface {
    runtime: Weak<DaemonRuntime>,
}

impl SecretAgentInterface {
    fn new(runtime: &Arc<DaemonRuntime>) -> Self {
        Self {
            runtime: Arc::downgrade(runtime),
        }
    }

    async fn authorize(&self, header: &Header<'_>) -> zbus::fdo::Result<String> {
        let runtime = self
            .runtime
            .upgrade()
            .ok_or_else(|| zbus::fdo::Error::Failed("SecretAgent stopped".into()))?;
        let conn = runtime.network_manager_connection();
        let owner = zbus::fdo::DBusProxy::new(conn.inner())
            .await?
            .get_name_owner(NM_DEST.try_into().expect("constant bus name"))
            .await?;
        if header.sender().map(|sender| sender.as_str()) != Some(owner.as_str())
            || !with_pending_registry(|registry| registry.is_current_owner(Some(owner.as_str())))
        {
            return Err(zbus::fdo::Error::AccessDenied(
                "SecretAgent caller is not the current NetworkManager owner".into(),
            ));
        }
        Ok(owner.to_string())
    }
}

pub(crate) fn export_secret_agent(
    system_connection: &Connection,
    runtime: &Arc<DaemonRuntime>,
) -> Result<()> {
    system_connection
        .object_server()
        .at(SECRET_AGENT_OBJECT_PATH, SecretAgentInterface::new(runtime))
        .context("export nm-daemon SecretAgent on system D-Bus")?;
    Ok(())
}

fn change_network_manager_owner(runtime: &Arc<DaemonRuntime>, owner: Option<String>) {
    let cancelled = with_pending_registry(|registry| {
        REGISTERED.store(false, Ordering::Release);
        registry.nm_owner = owner.clone();
        for (_, cancelled) in registry.inflight.drain() {
            cancelled.store(true, Ordering::Release);
        }
        registry
            .requests
            .drain()
            .map(|(id, entry)| (id, entry.sender))
            .collect::<Vec<_>>()
    });
    session::clear(None);
    runtime.network_manager_owner_changed(owner.as_deref());
    let weak = Arc::downgrade(runtime);
    for (id, sender) in cancelled {
        let _ = sender.send(SecretResponse::cancelled());
        emit_secret_cancelled(&weak, &id);
    }
}

fn ensure_request_owner(request: &PendingSecretRequest) -> SecretResult<()> {
    if request.cancelled.load(Ordering::Acquire) {
        return Err(SecretAgentError::UserCanceled(
            "NetworkManager cancelled the secret request".into(),
        ));
    }
    ensure_secret_owner(request.nm_owner.as_deref()).map_err(Into::into)
}

fn ensure_secret_owner(owner: Option<&str>) -> zbus::fdo::Result<()> {
    with_pending_registry(|registry| {
        if registry.is_current_owner(owner) {
            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed(
                "NetworkManager changed during the secret request".into(),
            ))
        }
    })
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.SecretAgent")]
impl SecretAgentInterface {
    async fn get_secrets(
        &self,
        connection: ConnectionSettings,
        connection_path: OwnedObjectPath,
        setting_name: &str,
        hints: Vec<String>,
        flags: u32,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<zbus::object_server::ResponseDispatchNotifier<ConnectionSettings>, SecretAgentError>
    {
        let mut request = PendingSecretRequest::new(connection_path, setting_name, hints, flags);
        request.save_supported = request
            .secret_keys
            .iter()
            .all(|key| secret_may_be_saved(&connection, setting_name, key));
        request.nm_owner = Some(self.authorize(&header).await?);
        let runtime = self.runtime.clone();
        // Register before scheduling/performing keyring I/O, not only when a prompt is needed.
        let inflight = InflightRegistration::new(&request, &runtime)?;
        let request_id = request.id.clone();
        let profile_path = request.connection_path.clone();
        let owner = request.nm_owner.clone();
        let (connection, save) = secret_worker(move || {
            let _inflight = inflight;
            let mut save = None;
            let connection = resolve_secret_request(
                request,
                connection,
                apply_stored_secret,
                |request, connection| {
                    wait_for_secret_response(&runtime, request, connection, &mut save)
                },
            )?;
            Ok::<_, SecretAgentError>((connection, save))
        })
        .await?;
        Ok(persistence::after_reply(
            connection,
            self.runtime.clone(),
            request_id,
            profile_path,
            owner,
            true,
            save,
        ))
    }

    async fn cancel_get_secrets(
        &self,
        connection_path: OwnedObjectPath,
        setting_name: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        self.authorize(&header).await?;
        session::clear(Some(connection_path.as_str()));
        tracing::info!(%connection_path, setting_name, "NetworkManager cancelled SecretAgent request");
        let key = PendingSecretRequest::key_for(connection_path.as_str(), setting_name);
        if let Some((request_id, sender)) = cancel_pending_by_key(&key) {
            let _ = sender.send(SecretResponse::cancelled());
            emit_secret_cancelled(&self.runtime, &request_id);
        }
        Ok(())
    }

    async fn save_secrets(
        &self,
        connection: ConnectionSettings,
        connection_path: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<zbus::object_server::ResponseDispatchNotifier<()>> {
        let owner = self.authorize(&header).await?;
        ensure_secret_owner(Some(&owner))?;
        // NM may strip agent-owned passwords before GetSecrets. Retain a
        // bounded, owner/UUID-scoped handoff before keyring I/O can block.
        session::stage(&owner, connection_path.as_str(), &connection);
        let request_id = connection_path.to_string();
        let profile_path = request_id.clone();
        let save = Box::new(
            move || match save_connection_secrets(&connection_path, &connection) {
                Ok(()) => SecretPersistenceOutcome::Stored,
                Err(error) => SecretPersistenceOutcome::Failed(format!("{error:#}")),
            },
        );
        Ok(persistence::after_reply(
            (),
            self.runtime.clone(),
            request_id,
            profile_path,
            Some(owner),
            false,
            Some(save),
        ))
    }

    async fn delete_secrets(
        &self,
        connection: ConnectionSettings,
        connection_path: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let owner = self.authorize(&header).await?;
        session::clear(Some(connection_path.as_str()));
        persistence::invalidate(connection_path.as_str());
        // Finish any already-running write, then delete; queued saves cannot
        // resurrect a forgotten profile's password after this reply.
        let _writer = persistence::deletion_guard().await;
        secret_worker(move || {
            ensure_secret_owner(Some(&owner))?;
            delete_connection_secrets(&connection_path, &connection);
            Ok(())
        })
        .await
    }
}

async fn secret_worker<T: Send + 'static, E: From<zbus::fdo::Error> + Send + 'static>(
    work: impl FnOnce() -> Result<T, E> + Send + 'static,
) -> Result<T, E> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| zbus::fdo::Error::Failed("SecretAgent worker stopped".into()))?
}

fn resolve_secret_request(
    request: PendingSecretRequest,
    mut connection: ConnectionSettings,
    stored: impl FnOnce(&PendingSecretRequest, &mut ConnectionSettings) -> zbus::fdo::Result<bool>,
    interact: impl FnOnce(PendingSecretRequest, ConnectionSettings) -> SecretResult<ConnectionSettings>,
) -> SecretResult<ConnectionSettings> {
    ensure_request_owner(&request)?;
    // A fresh request must not reuse a password NetworkManager already rejected.
    if request.flags & REQUEST_NEW != 0 {
        session::clear(Some(&request.connection_path));
    }
    let complete = request.flags & REQUEST_NEW == 0 && stored(&request, &mut connection)?;
    ensure_request_owner(&request)?;
    if complete {
        return Ok(connection);
    }
    // Fail before registering a pending request or emitting a frontend event.
    if request.flags & ALLOW_INTERACTION == 0 {
        return Err(SecretAgentError::NoSecrets(
            "no usable stored secret and interaction is prohibited".to_string(),
        ));
    }
    interact(request, connection)
}

fn apply_stored_secret(
    request: &PendingSecretRequest,
    connection: &mut ConnectionSettings,
) -> zbus::fdo::Result<bool> {
    let supplied = session::take(request, connection);
    if apply_stored_values(request, connection, supplied)? {
        return Ok(true);
    }
    let stored = lookup_stored_secrets(request, connection);
    apply_stored_values(request, connection, stored)
}

fn apply_stored_values(
    request: &PendingSecretRequest,
    connection: &mut ConnectionSettings,
    stored: Vec<crate::keyring::KeyringSecret>,
) -> zbus::fdo::Result<bool> {
    for secret in stored {
        // A partial native handoff may contain a freshly supplied password;
        // filling other keys from storage must never replace it with an old one.
        if !secret_value_present(request, connection, &secret.key) {
            apply_password(
                connection,
                &request.setting_name,
                &secret.key,
                secret.password,
            )?;
        }
    }
    Ok(request_values_complete(request, connection))
}

fn request_values_complete(
    request: &PendingSecretRequest,
    connection: &ConnectionSettings,
) -> bool {
    request
        .secret_keys
        .iter()
        .all(|key| secret_value_present(request, connection, key))
}

fn secret_value_present(
    request: &PendingSecretRequest,
    connection: &ConnectionSettings,
    key: &str,
) -> bool {
    let Some(section) = connection.get(&request.setting_name) else {
        return false;
    };
    if request.setting_name == "vpn" {
        return section
            .get("secrets")
            .and_then(value_string_map)
            .and_then(|values| values.get(key).copied())
            .is_some_and(|value| !value.is_empty());
    }
    crate::variant::setting::<&str>(section, key).is_some_and(|value| !value.is_empty())
}

fn wait_for_secret_response(
    runtime: &Weak<DaemonRuntime>,
    request: PendingSecretRequest,
    mut connection: ConnectionSettings,
    save: &mut Option<persistence::Save>,
) -> SecretResult<ConnectionSettings> {
    let owners = runtime
        .upgrade()
        .map(|runtime| runtime.subscriber_owners(Stream::WifiSecret))
        .unwrap_or_default();
    if owners.is_empty() {
        return Err(SecretAgentError::NoSecrets(
            "no frontend is subscribed to secret requests".into(),
        ));
    }
    let (registration, displaced_request_id) = register_pending(&request, owners)?;
    if let Some(displaced_request_id) = displaced_request_id {
        emit_secret_cancelled(runtime, &displaced_request_id);
    }
    // Publication and NM cancellation share the registry lock: a cancelled lookup
    // cannot publish a prompt, nor can "requested" be queued after "cancelled".
    with_pending_registry(|registry| {
        if !registry.requests.contains_key(&request.id) || request.cancelled.load(Ordering::Acquire)
        {
            return Err(SecretAgentError::UserCanceled(
                "secret request cancelled before prompting".into(),
            ));
        }
        emit_secret_requested(runtime, &request);
        Ok(())
    })?;

    let response = registration.recv_timeout(SECRET_TIMEOUT).map_err(|_| {
        // Retire before publishing expiry, including a reply racing that event.
        remove_pending(&request.id);
        // A late submission must not look like a successful credential handoff.
        emit_secret_event(
            runtime,
            &request.id,
            "cancelled",
            json!({"request_id": request.id, "reason": "expired"}),
        );
        SecretAgentError::NoSecrets(format!("timed out waiting for secret {}", request.id))
    })?;
    ensure_request_owner(&request)?;
    *save = apply_secret_response(&mut connection, &request, response)?;
    Ok(connection)
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct SecretCapabilitiesParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretProvideParams {
    request_id: String,
    #[serde(default = "default_save")]
    save: bool,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    values: HashMap<String, String>,
    #[serde(default)]
    cancel: bool,
}

fn default_save() -> bool {
    true
}

pub(crate) fn capabilities(_: SecretCapabilitiesParams) -> Result<Value> {
    let keyring_available = crate::keyring::available();
    api_data_value(
        Method::WifiSecretCapabilities.spec().response_key,
        &json!({
            "registered": REGISTERED.load(Ordering::Relaxed),
            "agent_path": SECRET_AGENT_OBJECT_PATH,
            "keyring": {
                "available": keyring_available,
                "persistence_supported": keyring_available,
                "default_save": true,
                "prompt_handling": "unlock",
                "prompt_policy": "interactive_unlock_with_timeout",
            },
            "events": {
                "stream": Stream::WifiSecret,
                "implemented": true,
                "persistence_outcomes": true,
            },
            "message": "SecretAgent delivers credentials before deferred keyring saving; only saves may open a bounded desktop unlock dialog",
        }),
        "serialize secret-agent capabilities response JSON",
    )
}

pub(crate) fn provide(owner: Option<&str>, params: SecretProvideParams) -> Result<Value> {
    let accepted = if let Some(sender) = remove_pending_for_owner(&params.request_id, owner) {
        sender
            .send(SecretResponse {
                password: params.password,
                values: params.values,
                save: params.save,
                cancelled: params.cancel,
            })
            .is_ok()
    } else {
        false
    };
    api_data_value(
        Method::WifiSecretProvide.spec().response_key,
        &json!({
            "status": if accepted && params.cancel { "cancelled" } else if accepted { "accepted" } else { "unavailable" },
            "request_id": params.request_id,
            "accepted": accepted,
            "save_requested": params.save && !params.cancel,
            "persistence_status": match (accepted, params.cancel, params.save) {
                (true, true, _) => "not_requested",
                (true, false, true) => "pending",
                (true, false, false) => "not_requested",
                (false, _, _) => "not_started",
            },
            "message": match (accepted, params.cancel, params.save) {
                (true, true, _) => "Pending NetworkManager secret request cancelled",
                (true, false, true) => "Secret received; the wifi.secret stream reports NetworkManager delivery and persistence separately",
                (true, false, false) => "Secret received; waiting for NetworkManager delivery",
                (false, _, _) => "No pending SecretAgent request matched request_id",
            },
        }),
        "serialize secret provide response JSON",
    )
}

fn register_pending(
    request: &PendingSecretRequest,
    owners: Vec<String>,
) -> SecretResult<(PendingRegistration, Option<String>)> {
    let (tx, rx) = mpsc::channel();
    let displaced = with_pending_registry(|registry| {
        if !registry.is_current_owner(request.nm_owner.as_deref()) {
            return Err(SecretAgentError::Failed(
                "NetworkManager changed before secret registration".into(),
            ));
        }
        if request.cancelled.load(Ordering::Acquire) {
            return Err(SecretAgentError::UserCanceled(
                "secret request cancelled during lookup".into(),
            ));
        }
        Ok(registry.insert(request.id.clone(), request.key.clone(), owners, tx))
    })?;
    let displaced_request_id = displaced.map(|(request_id, sender)| {
        let _ = sender.send(SecretResponse::cancelled());
        tracing::warn!(%request_id, key = %request.key, "replaced duplicate pending SecretAgent request");
        request_id
    });
    Ok((
        PendingRegistration {
            request_id: request.id.clone(),
            receiver: rx,
        },
        displaced_request_id,
    ))
}

fn remove_pending(request_id: &str) -> Option<Sender<SecretResponse>> {
    with_pending_registry(|registry| registry.remove(request_id))
}

fn remove_pending_for_owner(
    request_id: &str,
    owner: Option<&str>,
) -> Option<Sender<SecretResponse>> {
    with_pending_registry(|registry| registry.remove_for_owner(request_id, owner))
}

fn cancel_pending_by_key(key: &str) -> Option<(String, Sender<SecretResponse>)> {
    with_pending_registry(|registry| registry.cancel_by_key(key))
}

/// Kept alive through lookup, frontend response, and completion. A late guard
/// must not remove a replacement request for the same connection/setting.
struct InflightRegistration {
    key: String,
    cancelled: Arc<AtomicBool>,
}

impl InflightRegistration {
    fn new(request: &PendingSecretRequest, runtime: &Weak<DaemonRuntime>) -> SecretResult<Self> {
        with_pending_registry(|registry| {
            if !registry.is_current_owner(request.nm_owner.as_deref()) {
                return Err(SecretAgentError::Failed(
                    "NetworkManager changed before lookup".into(),
                ));
            }
            if let Some((id, sender)) = registry.cancel_by_key(&request.key) {
                let _ = sender.send(SecretResponse::cancelled());
                emit_secret_cancelled(runtime, &id);
            }
            registry
                .inflight
                .insert(request.key.clone(), Arc::clone(&request.cancelled));
            Ok(Self {
                key: request.key.clone(),
                cancelled: Arc::clone(&request.cancelled),
            })
        })
    }
}

impl Drop for InflightRegistration {
    fn drop(&mut self) {
        with_pending_registry(|registry| {
            if registry
                .inflight
                .get(&self.key)
                .is_some_and(|flag| Arc::ptr_eq(flag, &self.cancelled))
            {
                registry.inflight.remove(&self.key);
            }
        });
    }
}

fn pending() -> &'static Mutex<PendingRegistry> {
    PENDING.get_or_init(|| Mutex::new(PendingRegistry::default()))
}

fn with_pending_registry<T>(action: impl FnOnce(&mut PendingRegistry) -> T) -> T {
    let mut registry = match pending().lock() {
        Ok(registry) => registry,
        Err(poisoned) => {
            tracing::error!("recovering poisoned SecretAgent pending-request registry");
            poisoned.into_inner()
        }
    };
    action(&mut registry)
}

fn emit_secret_requested(runtime: &Weak<DaemonRuntime>, request: &PendingSecretRequest) {
    emit_secret_event(
        runtime,
        &request.id,
        "requested",
        json!({
            "request_id": request.id,
            "connection_path": request.connection_path,
            "setting_name": request.setting_name,
            "hints": request.hints,
            "secret_keys": request.secret_keys,
            "primary_secret_key": request.primary_secret_key(),
            "flags": request.flags,
            "flag_details": secret_flag_details(request.flags),
            "plugin_defined_secret_names": accepts_plugin_secret_names(&request.setting_name),
            "save_supported": request.save_supported,
            "timeout_ms": SECRET_TIMEOUT.as_millis(),
        }),
    );
}

/// NM_SECRET_AGENT_GET_SECRETS_FLAG_* decoded for the frontend, so a form can
/// tell a routine re-prompt from a user-requested one and honour a temporary
/// secret that must not be offered for saving.
fn secret_flag_details(flags: u32) -> Value {
    json!({
        "allow_interaction": flags & ALLOW_INTERACTION != 0,
        "request_new": flags & REQUEST_NEW != 0,
        "user_requested": flags & 0x4 != 0,
        "wps_pbc": flags & 0x8 != 0,
        "only_system": flags & 0x80000000_u32 != 0,
        "no_errors": flags & 0x40000000_u32 != 0,
    })
}

fn emit_secret_cancelled(runtime: &Weak<DaemonRuntime>, request_id: &str) {
    emit_secret_event(
        runtime,
        request_id,
        "cancelled",
        json!({ "request_id": request_id }),
    );
}

fn emit_secret_persistence(
    runtime: &Weak<DaemonRuntime>,
    request_id: &str,
    connection_path: &str,
    outcome: SecretPersistenceOutcome,
) {
    let mut data = match outcome {
        SecretPersistenceOutcome::Stored => json!({
            "request_id": request_id,
            "status": "stored",
        }),
        SecretPersistenceOutcome::PromptUnsupported { operation, prompt } => json!({
            "request_id": request_id,
            "status": "prompt_unsupported",
            "operation": operation.to_string(),
            "prompt": prompt,
        }),
        SecretPersistenceOutcome::Failed(error) => json!({
            "request_id": request_id,
            "status": "failed",
            "error": error,
        }),
    };
    data["connection_path"] = json!(connection_path);
    emit_secret_event(runtime, request_id, "persistence", data);
}

fn emit_secret_event(
    runtime: &Weak<DaemonRuntime>,
    request_id: &str,
    event: &'static str,
    data: Value,
) {
    let Some(runtime) = runtime.upgrade() else {
        tracing::warn!(request_id, "daemon runtime unavailable for secret event");
        return;
    };
    runtime.emit_external(Stream::WifiSecret, request_id.to_string(), event, data);
}

fn lookup_stored_secrets(
    request: &PendingSecretRequest,
    connection: &ConnectionSettings,
) -> Vec<crate::keyring::KeyringSecret> {
    // Never put a desktop unlock dialog on NetworkManager's delivery deadline.
    let keyring = crate::keyring::Keyring::new();
    let result = keyring.and_then(|keyring| {
        keyring.lookup_secrets(
            &request.connection_path,
            connection,
            &request.setting_name,
            &request.secret_keys,
        )
    });
    match result {
        Ok(crate::keyring::KeyringOutcome::Completed(secret)) => secret,
        Ok(crate::keyring::KeyringOutcome::PromptUnsupported {
            operation,
            prompt,
            completed,
        }) => {
            tracing::info!(request_id = %request.id, %operation, %prompt, "keyring lookup requires an unsupported desktop prompt");
            completed
        }
        Err(err) => {
            tracing::debug!(request_id = %request.id, error = %crate::error::err_chain(&err), "keyring lookup failed");
            Vec::new()
        }
    }
}

fn apply_secret_response(
    connection: &mut ConnectionSettings,
    request: &PendingSecretRequest,
    response: SecretResponse,
) -> SecretResult<Option<persistence::Save>> {
    reject_cancelled_response(response.cancelled)?;
    let mut values = response_values(request, response.password, response.values);
    values.retain(|key, value| request.secret_keys.contains(key) && !value.is_empty());
    if values.is_empty() {
        return Err(SecretAgentError::NoSecrets(
            "secret request contained no requested values".to_string(),
        ));
    }
    apply_response_values(connection, request, &values)?;
    if !request_values_complete(request, connection) {
        return Err(SecretAgentError::NoSecrets(
            "not all requested secrets were supplied".into(),
        ));
    }
    if !response.save {
        return Ok(None);
    }
    // Only public identity metadata is needed by the deferred save; do not
    // duplicate the whole connection or unrelated credentials.
    let mut identity = HashMap::new();
    if let Some(section) = connection.get("connection") {
        for key in ["uuid", "id"] {
            if let Some(value) = section.get(key).and_then(value_string) {
                identity.insert(key.to_string(), owned_value(value)?);
            }
        }
    }
    let settings = ConnectionSettings::from([("connection".into(), identity)]);
    let request = request.clone();
    Ok(Some(Box::new(move || {
        if !request.save_supported {
            return SecretPersistenceOutcome::Failed(
                "This connection requires temporary credentials; the password was not saved."
                    .into(),
            );
        }
        if ensure_request_owner(&request).is_err() {
            return SecretPersistenceOutcome::Failed(
                "Credential request cancelled before saving".into(),
            );
        }
        persistence_outcome(&request, &settings, &values)
    })))
}

fn reject_cancelled_response(cancelled: bool) -> SecretResult<()> {
    if cancelled {
        return Err(SecretAgentError::UserCanceled(
            "secret request cancelled by frontend".to_string(),
        ));
    }
    Ok(())
}

fn response_values(
    request: &PendingSecretRequest,
    password: Option<String>,
    mut values: HashMap<String, String>,
) -> HashMap<String, String> {
    if let Some(password) = password.filter(|password| !password.is_empty()) {
        values
            .entry(request.primary_secret_key().to_string())
            .or_insert(password);
    }
    values
}

fn apply_response_values(
    connection: &mut ConnectionSettings,
    request: &PendingSecretRequest,
    values: &HashMap<String, String>,
) -> zbus::fdo::Result<()> {
    values.iter().try_for_each(|(key, value)| {
        apply_password(connection, &request.setting_name, key, value.to_string())
    })
}

fn persistence_outcome(
    request: &PendingSecretRequest,
    connection: &ConnectionSettings,
    values: &HashMap<String, String>,
) -> SecretPersistenceOutcome {
    let keyring = match crate::keyring::Keyring::interactive() {
        Ok(keyring) => keyring,
        Err(error) => return SecretPersistenceOutcome::Failed(format!("{error:#}")),
    };
    values
        .iter()
        .map(|(key, value)| store_secret_outcome(&keyring, request, connection, key, value))
        .find(|outcome| !matches!(outcome, SecretPersistenceOutcome::Stored))
        .unwrap_or(SecretPersistenceOutcome::Stored)
}

fn apply_password(
    connection: &mut ConnectionSettings,
    setting_name: &str,
    key: &str,
    password: String,
) -> zbus::fdo::Result<()> {
    if setting_name == "vpn" {
        return apply_vpn_secret(connection, key, password);
    }
    connection
        .entry(setting_name.to_string())
        .or_default()
        .insert(key.to_string(), owned_value(password)?);
    Ok(())
}

/// NetworkManager reads VPN secrets from the plugin's own `vpn.secrets`
/// string map; a value written beside it in the `vpn` section is ignored.
fn apply_vpn_secret(
    connection: &mut ConnectionSettings,
    key: &str,
    password: String,
) -> zbus::fdo::Result<()> {
    let vpn = connection.entry("vpn".to_string()).or_default();
    let mut secrets = vpn
        .get("secrets")
        .and_then(value_string_map)
        .unwrap_or_default();
    secrets.insert(key, &password);
    let secrets = OwnedValue::try_from(zvariant::Value::new(secrets))
        .map_err(|err| zbus::fdo::Error::Failed(format!("create VPN secret map: {err:#}")))?;
    vpn.insert("secrets".to_string(), secrets);
    Ok(())
}

fn store_secret_outcome(
    keyring: &crate::keyring::Keyring,
    request: &PendingSecretRequest,
    connection: &ConnectionSettings,
    key: &str,
    password: &str,
) -> SecretPersistenceOutcome {
    match keyring.store_secret(
        &request.connection_path,
        connection,
        &request.setting_name,
        key,
        password,
    ) {
        Ok(crate::keyring::KeyringOutcome::Completed(())) => SecretPersistenceOutcome::Stored,
        Ok(crate::keyring::KeyringOutcome::PromptUnsupported {
            operation, prompt, ..
        }) => {
            tracing::warn!(request_id = %request.id, %operation, %prompt, "secret was not stored because the keyring requires an unsupported desktop prompt");
            SecretPersistenceOutcome::PromptUnsupported { operation, prompt }
        }
        Err(err) => {
            tracing::warn!(request_id = %request.id, error = %crate::error::err_chain(&err), "failed to store secret in keyring");
            SecretPersistenceOutcome::Failed(format!("{err:#}"))
        }
    }
}

fn save_connection_secrets(
    connection_path: &OwnedObjectPath,
    connection: &ConnectionSettings,
) -> Result<()> {
    let keyring = crate::keyring::Keyring::interactive()?;
    for (setting, secrets) in connection_secret_values(connection) {
        for (key, password) in secrets {
            match keyring.store_secret(
                connection_path.as_str(),
                connection,
                &setting,
                &key,
                &password,
            )? {
                crate::keyring::KeyringOutcome::Completed(()) => {}
                crate::keyring::KeyringOutcome::PromptUnsupported { operation, .. } => {
                    anyhow::bail!("password was not saved: unsupported keyring {operation} prompt");
                }
            }
        }
    }
    Ok(())
}

fn delete_connection_secrets(connection_path: &OwnedObjectPath, connection: &ConnectionSettings) {
    let Some(keyring) = best_effort(
        format!(
            "failed to open keyring while deleting NetworkManager secrets for {connection_path}"
        ),
        crate::keyring::Keyring::new,
    ) else {
        return;
    };
    connection
        .keys()
        .flat_map(|setting| {
            known_secret_keys(setting)
                .iter()
                .copied()
                .map(move |key| (setting.as_str(), key))
        })
        .for_each(|(setting, key)| {
            delete_connection_secret(&keyring, connection_path, connection, setting, key)
        });
}

fn delete_connection_secret(
    keyring: &crate::keyring::Keyring,
    connection_path: &OwnedObjectPath,
    connection: &ConnectionSettings,
    setting_name: &str,
    key: &str,
) {
    let outcome = best_effort(
        format!(
            "failed to delete NetworkManager secret {setting_name}.{key} for {connection_path}"
        ),
        || keyring.delete_secret(connection_path.as_str(), connection, setting_name, key),
    );
    match outcome {
        Some(crate::keyring::KeyringOutcome::Completed(deleted)) => {
            tracing::debug!(%connection_path, setting_name, key, deleted, "deleted NetworkManager secrets from keyring");
        }
        Some(crate::keyring::KeyringOutcome::PromptUnsupported {
            operation,
            prompt,
            completed,
        }) => {
            tracing::warn!(%connection_path, setting_name, key, %operation, %prompt, deleted = completed, "keyring delete stopped because it requires an unsupported desktop prompt");
        }
        None => {}
    }
}

fn connection_secret_values(
    connection: &ConnectionSettings,
) -> Vec<(String, Vec<(String, String)>)> {
    connection
        .iter()
        .filter_map(|(setting_name, values)| {
            let secrets = known_secret_keys(setting_name)
                .iter()
                .filter(|key| secret_may_be_saved(connection, setting_name, key))
                .filter_map(|key| {
                    values
                        .get(*key)
                        .and_then(value_string)
                        .filter(|value| !value.is_empty())
                        .map(|value| ((*key).to_string(), value))
                })
                .collect::<Vec<_>>();
            (!secrets.is_empty()).then(|| (setting_name.clone(), secrets))
        })
        .collect()
}

fn owned_value(value: String) -> zbus::fdo::Result<OwnedValue> {
    crate::variant::owned_value(value)
        .map_err(|err| zbus::fdo::Error::Failed(format!("create D-Bus secret variant: {err:#}")))
}

fn secret_may_be_saved(connection: &ConnectionSettings, setting: &str, key: &str) -> bool {
    let flags_key = if key.starts_with("wep-key") {
        "wep-key-flags".to_string()
    } else {
        format!("{key}-flags")
    };
    let flags = connection
        .get(setting)
        .and_then(|values| crate::variant::setting::<u32>(values, &flags_key))
        .unwrap_or(0);
    flags & 2 == 0 // NetworkManager NOT_SAVED
}

#[derive(Clone)]
struct PendingSecretRequest {
    save_supported: bool,
    cancelled: Arc<AtomicBool>,
    nm_owner: Option<String>,
    id: String,
    key: String,
    connection_path: String,
    setting_name: String,
    hints: Vec<String>,
    secret_keys: Vec<String>,
    flags: u32,
}

impl PendingSecretRequest {
    fn new(
        connection_path: OwnedObjectPath,
        setting_name: &str,
        hints: Vec<String>,
        flags: u32,
    ) -> Self {
        let connection_path = connection_path.to_string();
        let secret_keys = secret_keys_for(setting_name, &hints);
        Self {
            save_supported: true,
            cancelled: Arc::new(AtomicBool::new(false)),
            nm_owner: None,
            id: crate::daemon_runtime::next_request_id("secret"),
            key: Self::key_for(&connection_path, setting_name),
            connection_path,
            setting_name: setting_name.to_string(),
            hints,
            secret_keys,
            flags,
        }
    }

    fn key_for(connection_path: &str, setting_name: &str) -> String {
        format!("{connection_path}\n{setting_name}")
    }

    fn primary_secret_key(&self) -> &str {
        self.secret_keys
            .first()
            .map(String::as_str)
            .unwrap_or_else(|| default_secret_key_for_setting(&self.setting_name))
    }
}

fn secret_keys_for(setting_name: &str, hints: &[String]) -> Vec<String> {
    // VPN plugins define their own secret names — OpenConnect alone uses
    // cookie, gateway, gwcert, resolve, and xmlconfig, and OpenVPN can ask for
    // an ssh-agent socket. Filtering those against a fixed list would drop the
    // request, so plugin settings accept whatever NetworkManager hints.
    if accepts_plugin_secret_names(setting_name) {
        let mut keys = hints
            .iter()
            .map(|hint| normalize_plugin_hint(setting_name, hint))
            .filter(|hint| !hint.is_empty())
            .collect::<Vec<_>>();
        keys.dedup();
        if keys.is_empty() {
            keys.push(default_secret_key_for_setting(setting_name).to_string());
        }
        return keys;
    }
    let known = known_secret_keys(setting_name);
    let mut keys = hints
        .iter()
        .filter(|hint| known.contains(&hint.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if keys.is_empty() {
        keys.push(default_secret_key_for_setting(setting_name).to_string());
    }
    keys
}

/// Settings whose secret names come from a plugin rather than the NetworkManager
/// schema.
fn accepts_plugin_secret_names(setting_name: &str) -> bool {
    matches!(setting_name, "vpn" | "wireguard")
}

/// With VPN-hint capabilities NetworkManager may prefix hints with
/// `vpn.secrets.`; peer keys arrive as `peers.<public-key>.preshared-key`.
fn normalize_plugin_hint(setting_name: &str, hint: &str) -> String {
    let hint = hint.strip_prefix("vpn.secrets.").unwrap_or(hint);
    let hint = hint
        .strip_prefix(&format!("{setting_name}."))
        .unwrap_or(hint);
    hint.to_string()
}

pub(crate) fn known_secret_keys(setting_name: &str) -> &'static [&'static str] {
    match setting_name {
        "802-11-wireless-security" => &[
            "psk",
            "wep-key0",
            "wep-key1",
            "wep-key2",
            "wep-key3",
            "leap-password",
        ],
        "802-1x" => &["password", "private-key-password", "pin"],
        "wifi-p2p" => &["wps-pin"],
        "gsm" | "cdma" => &["password", "pin"],
        _ => &["password"],
    }
}

fn default_secret_key_for_setting(setting_name: &str) -> &'static str {
    match setting_name {
        "802-11-wireless-security" => "psk",
        "wifi-p2p" => "wps-pin",
        "wireguard" => "private-key",
        _ => "password",
    }
}

struct SecretResponse {
    password: Option<String>,
    values: HashMap<String, String>,
    save: bool,
    cancelled: bool,
}

impl SecretResponse {
    fn cancelled() -> Self {
        Self {
            password: None,
            values: HashMap::new(),
            save: false,
            cancelled: true,
        }
    }
}

enum SecretPersistenceOutcome {
    Stored,
    PromptUnsupported {
        operation: crate::keyring::KeyringPromptOperation,
        prompt: OwnedObjectPath,
    },
    Failed(String),
}

struct PendingEntry {
    key: String,
    owners: HashSet<String>,
    sender: Sender<SecretResponse>,
}

#[derive(Default)]
struct PendingRegistry {
    inflight: HashMap<String, Arc<AtomicBool>>,
    nm_owner: Option<String>,
    requests: HashMap<String, PendingEntry>,
}

impl PendingRegistry {
    fn is_current_owner(&self, owner: Option<&str>) -> bool {
        self.nm_owner.as_deref() == owner
    }

    fn insert(
        &mut self,
        request_id: String,
        key: String,
        owners: Vec<String>,
        sender: Sender<SecretResponse>,
    ) -> Option<(String, Sender<SecretResponse>)> {
        let duplicate = self
            .requests
            .iter()
            .find_map(|(id, entry)| (entry.key == key).then(|| id.clone()));
        let displaced =
            duplicate.and_then(|id| self.requests.remove(&id).map(|entry| (id, entry.sender)));
        if let Some(replaced) = self.requests.insert(
            request_id.clone(),
            PendingEntry {
                key,
                owners: owners.into_iter().collect(),
                sender,
            },
        ) {
            tracing::warn!(%request_id, "replaced colliding SecretAgent request id");
            let _ = replaced.sender.send(SecretResponse::cancelled());
        }
        displaced
    }

    fn remove(&mut self, request_id: &str) -> Option<Sender<SecretResponse>> {
        self.requests.remove(request_id).map(|entry| entry.sender)
    }

    fn remove_for_owner(
        &mut self,
        request_id: &str,
        owner: Option<&str>,
    ) -> Option<Sender<SecretResponse>> {
        let authorized = self
            .requests
            .get(request_id)
            .is_some_and(|entry| owner.is_some_and(|owner| entry.owners.contains(owner)));
        authorized.then(|| self.remove(request_id)).flatten()
    }

    fn cancel_by_key(&mut self, key: &str) -> Option<(String, Sender<SecretResponse>)> {
        if let Some(cancelled) = self.inflight.get(key) {
            cancelled.store(true, Ordering::Release);
        }
        self.remove_by_key(key)
    }

    fn remove_by_key(&mut self, key: &str) -> Option<(String, Sender<SecretResponse>)> {
        let request_id = self
            .requests
            .iter()
            .find_map(|(id, entry)| (entry.key == key).then(|| id.clone()))?;
        self.remove(&request_id).map(|sender| (request_id, sender))
    }
}

struct PendingRegistration {
    request_id: String,
    receiver: Receiver<SecretResponse>,
}

impl PendingRegistration {
    fn recv_timeout(&self, timeout: Duration) -> Result<SecretResponse, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

impl Drop for PendingRegistration {
    fn drop(&mut self) {
        remove_pending(&self.request_id);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::{
        PendingRegistry, PendingSecretRequest, SecretResponse, apply_secret_response,
        register_pending, remove_pending,
    };
    use crate::nm::ConnectionSettings;
    use crate::variant::value_string;
    #[test]
    fn secret_request_respects_flags_before_lookup_or_interaction() {
        for flags in 0..=7 {
            for stored_available in [false, true] {
                let mut request = pending_request("flag-policy", "flag-policy-key");
                request.flags = flags;
                let mut looked_up = false;
                let mut prompted = false;
                let result = super::resolve_secret_request(
                    request,
                    ConnectionSettings::new(),
                    |request, connection| {
                        looked_up = true;
                        if stored_available {
                            super::apply_password(
                                connection,
                                &request.setting_name,
                                "psk",
                                "stored".into(),
                            )?;
                        }
                        Ok(stored_available)
                    },
                    |request, mut connection| {
                        prompted = true;
                        super::apply_password(
                            &mut connection,
                            &request.setting_name,
                            "psk",
                            "fresh".into(),
                        )?;
                        Ok(connection)
                    },
                );
                let use_stored = flags & super::REQUEST_NEW == 0 && stored_available;
                let should_prompt = !use_stored && flags & super::ALLOW_INTERACTION != 0;
                assert_eq!(looked_up, flags & super::REQUEST_NEW == 0);
                assert_eq!(prompted, should_prompt);
                if use_stored || should_prompt {
                    let connection = result.unwrap();
                    assert_eq!(
                        value_string(&connection["802-11-wireless-security"]["psk"]).as_deref(),
                        Some(if use_stored { "stored" } else { "fresh" }),
                    );
                } else {
                    assert!(matches!(result, Err(super::SecretAgentError::NoSecrets(_))));
                }
            }
        }
    }

    #[test]
    fn nm_cancellation_during_lookup_prevents_prompt_and_stored_reply() {
        use zbus::DBusError;
        for complete in [false, true] {
            let mut request = pending_request("early-cancel", "early-cancel-key");
            request.flags = super::ALLOW_INTERACTION;
            let key = request.key.clone();
            let guard =
                super::InflightRegistration::new(&request, &std::sync::Weak::new()).unwrap();
            let (entered, started) = mpsc::channel();
            let (release, wait) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let _guard = guard;
                super::resolve_secret_request(
                    request,
                    ConnectionSettings::new(),
                    |_, _| {
                        entered.send(()).unwrap();
                        wait.recv_timeout(Duration::from_secs(2)).unwrap();
                        Ok(complete)
                    },
                    |_, _| panic!("cancelled lookup published a frontend prompt"),
                )
            });
            started.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(
                super::cancel_pending_by_key(&key).is_none(),
                "no frontend prompt exists yet"
            );
            release.send(()).unwrap();
            let error = worker.join().unwrap().unwrap_err();
            assert_eq!(
                error.name().as_str(),
                "org.freedesktop.NetworkManager.SecretAgent.UserCanceled"
            );
            super::with_pending_registry(|registry| {
                assert!(!registry.inflight.contains_key(&key));
                assert!(!registry.requests.contains_key("early-cancel"));
            });
        }
    }

    #[test]
    fn cancelled_lookup_cannot_register_and_old_guard_cannot_remove_replacement() {
        let old = pending_request("old-lookup", "replaced-lookup-key");
        let current = pending_request("new-lookup", "replaced-lookup-key");
        let runtime = std::sync::Weak::new();
        let old_guard = super::InflightRegistration::new(&old, &runtime).unwrap();
        let current_guard = super::InflightRegistration::new(&current, &runtime).unwrap();
        assert!(matches!(
            register_pending(&old, vec![":1.1".into()]),
            Err(super::SecretAgentError::UserCanceled(_))
        ));
        drop(old_guard);
        super::cancel_pending_by_key(&current.key);
        assert!(current.cancelled.load(std::sync::atomic::Ordering::Acquire));
        assert!(matches!(
            register_pending(&current, vec![":1.1".into()]),
            Err(super::SecretAgentError::UserCanceled(_))
        ));
        drop(current_guard);
    }

    #[test]
    fn stored_secrets_must_cover_all_hints_before_suppressing_prompt() {
        for setting in ["802-1x", "vpn"] {
            for complete in [false, true] {
                let mut request = pending_request("multi-key", "multi-key-key");
                request.setting_name = setting.into();
                request.secret_keys = vec!["password".into(), "pin".into()];
                request.flags = super::ALLOW_INTERACTION;
                let mut prompted = false;
                let connection = super::resolve_secret_request(
                    request,
                    ConnectionSettings::new(),
                    |request, connection| {
                        let mut stored = vec![crate::keyring::KeyringSecret {
                            key: "password".into(),
                            password: "stored-password".into(),
                        }];
                        if complete {
                            stored.push(crate::keyring::KeyringSecret {
                                key: "pin".into(),
                                password: "1234".into(),
                            });
                        }
                        super::apply_stored_values(request, connection, stored)
                    },
                    |request, mut connection| {
                        prompted = true;
                        // Supplying only the missing key preserves the stored password.
                        apply_secret_response(
                            &mut connection,
                            &request,
                            SecretResponse {
                                password: None,
                                values: HashMap::from([
                                    ("pin".into(), "1234".into()),
                                    ("not-requested".into(), "ignored".into()),
                                ]),
                                save: false,
                                cancelled: false,
                            },
                        )?;
                        Ok(connection)
                    },
                )
                .unwrap();
                assert_eq!(prompted, !complete);
                let values = if setting == "vpn" {
                    super::value_string_map(&connection[setting]["secrets"]).unwrap()
                } else {
                    connection[setting]
                        .iter()
                        .map(|(key, value)| (key.as_str(), <&str>::try_from(value).unwrap()))
                        .collect()
                };
                assert_eq!(values["password"], "stored-password");
                assert_eq!(values["pin"], "1234");
                assert!(!values.contains_key("not-requested"));
            }
        }
    }

    #[test]
    fn no_subscribers_fails_without_registering_or_waiting() {
        use zbus::DBusError;
        let request = pending_request("no-subscribers", "no-subscribers-key");
        let started = Instant::now();
        let error = super::wait_for_secret_response(
            &std::sync::Weak::new(),
            request,
            ConnectionSettings::new(),
            &mut None,
        )
        .unwrap_err();
        assert_eq!(
            error.name().as_str(),
            "org.freedesktop.NetworkManager.SecretAgent.NoSecrets"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(remove_pending("no-subscribers").is_none());
    }

    #[test]
    fn pending_secrets_are_owner_scoped_and_timed_out_registrations_are_removed() {
        let mut registry = PendingRegistry::default();
        let (sender, _receiver) = mpsc::channel();
        registry.insert(
            "owned".into(),
            "connection\nsetting".into(),
            vec![":1.7".into()],
            sender,
        );

        assert!(registry.remove_for_owner("owned", Some(":1.8")).is_none());
        assert!(registry.requests.contains_key("owned"));
        assert!(registry.remove_for_owner("owned", None).is_none());
        assert!(registry.remove_for_owner("owned", Some(":1.7")).is_some());
        assert!(!registry.requests.contains_key("owned"));

        let timed_out = pending_request("timed-out", "timed-out-key");
        let (registration, displaced) = register_pending(&timed_out, vec![":1.1".into()]).unwrap();
        assert!(displaced.is_none());
        assert!(matches!(
            registration.recv_timeout(Duration::from_millis(10)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(registration);
        assert!(remove_pending("timed-out").is_none());
    }
    #[test]
    fn remember_defaults_on_but_native_not_saved_wins() -> anyhow::Result<()> {
        let params: super::SecretProvideParams =
            serde_json::from_value(serde_json::json!({"request_id": "test"}))?;
        assert!(params.save);
        let params: super::SecretProvideParams =
            serde_json::from_value(serde_json::json!({"request_id": "test", "save": false}))?;
        assert!(!params.save);
        let settings = ConnectionSettings::from([(
            "802-11-wireless-security".into(),
            crate::variant::value_map([
                ("psk", "temporary-secret".into()),
                ("psk-flags", 2_u32.into()),
            ])?,
        )]);
        assert!(!super::secret_may_be_saved(
            &settings,
            "802-11-wireless-security",
            "psk"
        ));
        assert!(super::connection_secret_values(&settings).is_empty());
        Ok(())
    }

    fn pending_request(id: &str, key: &str) -> PendingSecretRequest {
        PendingSecretRequest {
            save_supported: true,
            cancelled: Default::default(),
            nm_owner: None,
            id: id.to_string(),
            key: key.to_string(),
            connection_path: "/test/connection".to_string(),
            setting_name: "802-11-wireless-security".to_string(),
            hints: Vec::new(),
            secret_keys: vec!["psk".to_string()],
            flags: 0,
        }
    }
}
