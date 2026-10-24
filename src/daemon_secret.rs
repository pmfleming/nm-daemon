use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::blocking::Connection;
use zbus::message::Header;

#[cfg(test)]
mod activation_tests;
mod lifecycle;
mod persistence;
#[cfg(test)]
mod regressions;
mod session;
mod storage;
pub(crate) use lifecycle::watch_network_manager;
use zvariant::OwnedObjectPath;

use crate::daemon_runtime::DaemonRuntime;
use crate::generated::SECRET_TIMEOUT;
use crate::network_credentials::{
    self as credential_schema, SecretValue, accepts_plugin_secret_names,
    default_secret_key_for_setting, secret_keys_for,
};
use crate::nm::{ConnectionSettings, NM_DEST};
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};
#[cfg(test)]
use crate::variant::value_string_map;

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
        let owner = self.authorize(&header).await?;
        request.nm_connection = self
            .runtime
            .upgrade()
            .map(|runtime| runtime.network_manager_connection());
        if request.hints.is_empty()
            && setting_name == "802-11-wireless-security"
            && let Some(security) = connection.get(setting_name)
        {
            if crate::variant::setting::<&str>(security, "key-mgmt") == Some("none") {
                let index = crate::variant::setting::<u32>(security, "wep-tx-keyidx")
                    .unwrap_or(0)
                    .min(3);
                request.secret_keys = vec![format!("wep-key{index}")];
            } else if crate::variant::setting::<&str>(security, "auth-alg") == Some("leap") {
                request.secret_keys = vec!["leap-password".into()];
            }
        }
        request.policy =
            storage::Policy::from_request(&connection, setting_name, &request.secret_keys)
                .map_err(|_| {
                    SecretAgentError::NoSecrets(
                        "Unsupported or ambiguous credential retention policy".into(),
                    )
                })?;
        request.save_supported =
            !request.policy.persistent.is_empty() && !request.policy.migration_required;
        persistence::invalidate(&request.connection_path);
        request.activation = crate::activation::find(&owner, &connection, &request.connection_path);
        request.nm_owner = Some(owner);
        if let Some(activation) = &request.activation {
            request.deadline = request.deadline.min(activation.credential_deadline());
        }
        let request = Arc::new(request);
        let _credential_guard = request
            .activation
            .as_ref()
            .map(|scope| scope.track_credentials());
        let runtime = self.runtime.clone();
        // Register before scheduling work, not only when a prompt is needed.
        let inflight = InflightRegistration::new(&request, &runtime)?;
        let delivery_request = Arc::clone(&request);
        let (connection, save) = secret_worker(move || {
            let _inflight = inflight;
            let mut save = None;
            let connection = resolve_secret_request(
                &request,
                connection,
                apply_stored_secret,
                |request, connection| {
                    wait_for_secret_response(&runtime, request, connection, &mut save)
                },
            )?;
            Ok::<_, SecretAgentError>((connection, save))
        })
        .await?;
        if let Err(error) = ensure_delivery_live(&delivery_request) {
            emit_secret_retired(&self.runtime, &delivery_request);
            return Err(error);
        }
        Ok(persistence::after_reply(
            connection,
            self.runtime.clone(),
            delivery_request.id.clone(),
            delivery_request.connection_path.clone(),
            delivery_request.nm_owner.clone(),
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
        persistence::invalidate(connection_path.as_str());
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
        // This is a bounded live-request handoff, never a durable copy.
        session::stage(&owner, connection_path.as_str(), &connection);
        // NM can invoke this even for system-owned credentials. It must retain
        // those itself; this agent never acknowledges a durable agent save.
        // Rejecting every callback also covers opaque/unknown secret values
        // that the text-only transient handoff cannot represent.
        Err(zbus::fdo::Error::NotSupported(
            "Durable SecretAgent storage is unavailable; NetworkManager owns storage. Explicitly migrate agent-owned profiles.".into(),
        ))
    }

    async fn delete_secrets(
        &self,
        _connection: ConnectionSettings,
        connection_path: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let owner = self.authorize(&header).await?;
        session::clear(Some(connection_path.as_str()));
        persistence::invalidate(connection_path.as_str());
        ensure_secret_owner(Some(&owner))?;
        let cancelled =
            with_pending_registry(|registry| registry.cancel_connection(connection_path.as_str()));
        for (request_id, sender) in cancelled {
            let _ = sender.send(SecretResponse::cancelled());
            emit_secret_cancelled(&self.runtime, &request_id);
        }
        // NM owns deletion. Never recurse into NM or wait on a confirmation
        // that may itself be waiting for this callback. An empty NM commit
        // cannot restore an old response; cancellation/version fences retire it.
        // Legacy keyring items are untouched.
        Ok(())
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
    request: &Arc<PendingSecretRequest>,
    mut connection: ConnectionSettings,
    stored: impl FnOnce(&PendingSecretRequest, &mut ConnectionSettings) -> zbus::fdo::Result<bool>,
    interact: impl FnOnce(
        &Arc<PendingSecretRequest>,
        ConnectionSettings,
    ) -> SecretResult<ConnectionSettings>,
) -> SecretResult<ConnectionSettings> {
    ensure_delivery_live(request)?;
    // A fresh request must not reuse a password NetworkManager already rejected.
    if request.flags & REQUEST_NEW != 0 {
        session::clear(Some(&request.connection_path));
    }
    let complete = request.flags & REQUEST_NEW == 0 && stored(request, &mut connection)?;
    ensure_delivery_live(request)?;
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
    apply_stored_values(request, connection, supplied)
}

fn apply_stored_values(
    request: &PendingSecretRequest,
    connection: &mut ConnectionSettings,
    stored: Vec<SecretValue>,
) -> zbus::fdo::Result<bool> {
    for secret in stored {
        // A partial native handoff may contain a freshly supplied password;
        // filling other keys from storage must never replace it with an old one.
        if !secret_value_present(request, connection, &secret.key) {
            apply_password(
                connection,
                &request.setting_name,
                &secret.key,
                &secret.password,
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
    credential_schema::text(connection, &request.setting_name, key)
        .is_some_and(|value| !value.is_empty())
}

fn wait_for_secret_response(
    runtime: &Weak<DaemonRuntime>,
    request: &Arc<PendingSecretRequest>,
    mut connection: ConnectionSettings,
    save: &mut Option<persistence::Save>,
) -> SecretResult<ConnectionSettings> {
    let owners = runtime
        .upgrade()
        .map(|runtime| runtime.subscriber_owners(Stream::WifiSecret))
        .unwrap_or_default();
    ensure_delivery_live(request)?;
    if let Some(activation) = &request.activation {
        activation.note_frontend_availability(!owners.is_empty());
    }
    if owners.is_empty() {
        return Err(SecretAgentError::NoSecrets(
            "no frontend is subscribed to secret requests".into(),
        ));
    }
    let (registration, displaced_request_id) =
        register_pending(request, owners).or_else(|error| {
            ensure_delivery_live(request)?;
            Err(error)
        })?;
    if let Some(displaced_request_id) = displaced_request_id {
        emit_secret_cancelled(runtime, &displaced_request_id);
    }
    // Publication and NM cancellation share the registry lock: a cancelled lookup
    // cannot publish a prompt, nor can "requested" be queued after "cancelled".
    with_pending_registry(|registry| {
        if !registry.requests.contains_key(&request.id) || !request.live() {
            return Err(SecretAgentError::UserCanceled(
                "secret request cancelled before prompting".into(),
            ));
        }
        emit_secret_requested(runtime, request);
        Ok(())
    })
    .or_else(|error| {
        ensure_delivery_live(request)?;
        Err(error)
    })?;

    let response = receive_live_response(&registration, request).inspect_err(|_| {
        remove_pending(&request.id);
        emit_secret_retired(runtime, request);
    })?;
    if response.cancelled {
        request.stop(crate::activation::CredentialStop::Cancelled);
    }
    *save = apply_secret_response(&mut connection, request, response)?;
    Ok(connection)
}

fn emit_secret_retired(runtime: &Weak<DaemonRuntime>, request: &PendingSecretRequest) {
    emit_secret_event(
        runtime,
        &request.id,
        "cancelled",
        json!({
            "request_id": request.id,
            "reason": if Instant::now() >= request.deadline { "expired" } else { "activation-finished" },
        }),
    );
}

fn ensure_delivery_live(request: &PendingSecretRequest) -> SecretResult<()> {
    ensure_request_owner(request)?;
    if Instant::now() >= request.deadline {
        request.stop(crate::activation::CredentialStop::Expired);
        return Err(SecretAgentError::NoSecrets(
            "Credential entry deadline expired".into(),
        ));
    }
    if request
        .activation
        .as_ref()
        .is_some_and(|activation| !activation.live())
    {
        return Err(SecretAgentError::UserCanceled(
            "The owning activation ended".into(),
        ));
    }
    Ok(())
}

fn receive_live_response(
    registration: &PendingRegistration,
    request: &PendingSecretRequest,
) -> SecretResult<SecretResponse> {
    loop {
        ensure_delivery_live(request)?;
        let remaining = request.deadline.saturating_duration_since(Instant::now());
        match registration
            .receiver
            .recv_timeout(remaining.min(Duration::from_millis(100)))
        {
            Ok(response) => {
                ensure_delivery_live(request)?;
                return Ok(response);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                ensure_delivery_live(request)?;
                return Err(SecretAgentError::UserCanceled(
                    "Credential request retired".into(),
                ));
            }
        }
    }
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
    api_data_value(
        Method::WifiSecretCapabilities.spec().response_key,
        &capabilities_json(REGISTERED.load(Ordering::Relaxed)),
        "serialize secret-agent capabilities response JSON",
    )
}

pub(crate) fn capabilities_json(registered: bool) -> Value {
    json!({
        "registered": registered,
        "agent_path": SECRET_AGENT_OBJECT_PATH,
        "keyring": {
            "available": false,
            "persistence_supported": false,
            "default_save": false,
            "prompt_handling": "none",
            "prompt_policy": "none",
            "deprecated": true,
        },
        "storage": {
            "provider": "networkmanager",
            "persistence_supported": true,
            "default_save": true,
            "confirmation": "terminal_activation_and_explicit_to_disk",
            "temporary_saved_profile": "separate_volatile_clone",
            "legacy_agent_owned": "explicit_migration_required",
        },
        "events": {
            "stream": Stream::WifiSecret,
            "implemented": true,
            "persistence_outcomes": true,
        },
        "message": "NetworkManager owns durable credentials; delivery and verified persistence are separate outcomes",
    })
}

pub(crate) fn provide(owner: Option<&str>, params: SecretProvideParams) -> Result<Value> {
    if !params.cancel {
        let rejection = with_pending_registry(|registry| {
            registry
                .requests
                .get(&params.request_id)
                .filter(|entry| {
                    owner.is_some_and(|owner| entry.owners.contains(owner)) && entry.request.live()
                })
                .and_then(|entry| entry.request.policy.rejection(params.save))
        });
        if let Some(reason) = rejection {
            return Err(crate::error::DomainError::validation(crate::error::ErrorOperation::SecretOperation,
                "This retention choice cannot be honored by the current profile; use a temporary connection or explicit migration")
                .with_detail("reason", reason).with_detail("delivered", false).into());
        }
    }
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
    request: &Arc<PendingSecretRequest>,
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
        if !request.live() {
            return Err(SecretAgentError::NoSecrets(
                "Credential request no longer belongs to a live activation".into(),
            ));
        }
        Ok(registry.insert(Arc::clone(request), owners, tx))
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
            "save_required": !request.policy.persistent.is_empty(),
            "storage_provider": "networkmanager",
            "migration_required": request.policy.migration_required,
            "timeout_ms": request.deadline.saturating_duration_since(Instant::now()).as_millis(),
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
        SecretPersistenceOutcome::Failed(error) => json!({
            "request_id": request_id,
            "status": "failed",
            "error": error,
        }),
    };
    data["connection_path"] = json!(connection_path);
    data["storage_provider"] = json!("networkmanager");
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

fn apply_secret_response(
    connection: &mut ConnectionSettings,
    request: &Arc<PendingSecretRequest>,
    response: SecretResponse,
) -> SecretResult<Option<persistence::Save>> {
    reject_cancelled_response(response.cancelled)?;
    if let Some(reason) = request.policy.rejection(response.save) {
        return Err(SecretAgentError::NoSecrets(reason.into()));
    }
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
    Ok(Some(storage::prepare(request, connection, values)))
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
    values
        .iter()
        .try_for_each(|(key, value)| apply_password(connection, &request.setting_name, key, value))
}

fn apply_password(
    connection: &mut ConnectionSettings,
    setting_name: &str,
    key: &str,
    password: &str,
) -> zbus::fdo::Result<()> {
    credential_schema::set_text(connection, setting_name, key, password).map_err(|_| {
        zbus::fdo::Error::NotSupported("Unsupported secret field or peer identity".into())
    })
}

fn connection_secret_values(connection: &ConnectionSettings) -> Vec<(String, String, String)> {
    credential_schema::values(connection)
        .unwrap_or_default()
        .into_iter()
        .filter(|(section, key, _)| {
            credential_schema::flags(connection, section, key)
                .is_ok_and(|flags| flags & credential_schema::NOT_SAVED == 0)
        })
        .collect()
}

struct PendingSecretRequest {
    deadline: Instant,
    activation: Option<Arc<crate::activation::State>>,
    save_supported: bool,
    policy: storage::Policy,
    nm_connection: Option<Connection>,
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
            deadline: Instant::now() + SECRET_TIMEOUT,
            activation: None,
            save_supported: true,
            policy: storage::Policy::default(),
            nm_connection: None,
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

    fn live(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire)
            && Instant::now() < self.deadline
            && self
                .activation
                .as_ref()
                .is_none_or(|activation| activation.live())
    }
    fn stop(&self, reason: crate::activation::CredentialStop) {
        if let Some(activation) = &self.activation {
            activation.stop(reason);
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
    Failed(String),
}

struct PendingEntry {
    request: Arc<PendingSecretRequest>,
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
        request: Arc<PendingSecretRequest>,
        owners: Vec<String>,
        sender: Sender<SecretResponse>,
    ) -> Option<(String, Sender<SecretResponse>)> {
        let displaced = self.remove_by_key(&request.key);
        let request_id = request.id.clone();
        if let Some(replaced) = self.requests.insert(
            request_id.clone(),
            PendingEntry {
                request,
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
        if !authorized {
            return None;
        }
        let entry = self.requests.remove(request_id)?;
        entry.request.live().then_some(entry.sender)
    }

    fn cancel_by_key(&mut self, key: &str) -> Option<(String, Sender<SecretResponse>)> {
        if let Some(cancelled) = self.inflight.get(key) {
            cancelled.store(true, Ordering::Release);
        }
        self.remove_by_key(key)
    }

    fn cancel_connection(&mut self, path: &str) -> Vec<(String, Sender<SecretResponse>)> {
        for (key, cancelled) in &self.inflight {
            if key
                .split_once('\n')
                .is_some_and(|(connection, _)| connection == path)
            {
                cancelled.store(true, Ordering::Release);
            }
        }
        let keys = self
            .requests
            .values()
            .filter(|entry| entry.request.connection_path == path)
            .map(|entry| entry.request.key.clone())
            .collect::<Vec<_>>();
        keys.into_iter()
            .filter_map(|key| self.cancel_by_key(&key))
            .collect()
    }

    fn remove_by_key(&mut self, key: &str) -> Option<(String, Sender<SecretResponse>)> {
        let request_id = self
            .requests
            .iter()
            .find_map(|(id, entry)| (entry.request.key == key).then(|| id.clone()))?;
        self.remove(&request_id).map(|sender| (request_id, sender))
    }
}

struct PendingRegistration {
    request_id: String,
    receiver: Receiver<SecretResponse>,
}

impl Drop for PendingRegistration {
    fn drop(&mut self) {
        remove_pending(&self.request_id);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use super::{
        PendingSecretRequest, SecretResponse, SecretValue, apply_secret_response, register_pending,
        storage,
    };
    use crate::nm::ConnectionSettings;
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
                    &Arc::new(request),
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
        let old = Arc::new(pending_request("old-lookup", "replaced-lookup-key"));
        let current = Arc::new(pending_request("new-lookup", "replaced-lookup-key"));
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
        for (setting, complete, password) in [
            ("802-1x", false, "fresh-password"),
            ("802-1x", true, "stored-password"),
            ("vpn", false, "fresh-password"),
            ("vpn", true, "stored-password"),
        ] {
            let mut request = pending_request("multi-key", "multi-key-key");
            request.setting_name = setting.into();
            request.secret_keys = vec!["password".into(), "pin".into()];
            request.flags = super::ALLOW_INTERACTION;
            request.save_supported = false;
            let mut prompted = false;
            let connection = super::resolve_secret_request(
                &Arc::new(request),
                ConnectionSettings::new(),
                |request, connection| {
                    if !complete {
                        super::apply_password(connection, setting, "password", "fresh-password")?;
                    }
                    let mut stored = vec![SecretValue {
                        key: "password".into(),
                        password: "stored-password".into(),
                    }];
                    if complete {
                        stored.push(SecretValue {
                            key: "pin".into(),
                            password: "1234".into(),
                        });
                    }
                    super::apply_stored_values(request, connection, stored)
                },
                |request, mut connection| {
                    prompted = true;
                    // Supplying only the missing key preserves the stored password.
                    let deferred = apply_secret_response(
                        &mut connection,
                        request,
                        SecretResponse {
                            password: None,
                            values: HashMap::from([
                                ("pin".into(), "1234".into()),
                                ("not-requested".into(), "ignored".into()),
                            ]),
                            save: true,
                            cancelled: false,
                        },
                    )?;
                    assert!(matches!(
                        deferred.unwrap()(&std::sync::atomic::AtomicBool::new(false)),
                        super::SecretPersistenceOutcome::Failed(_)
                    ));
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
            assert_eq!(
                values,
                HashMap::from([("password", password), ("pin", "1234")])
            );
        }
    }

    fn pending_request(id: &str, key: &str) -> PendingSecretRequest {
        PendingSecretRequest {
            deadline: Instant::now() + super::SECRET_TIMEOUT,
            activation: None,
            save_supported: true,
            policy: storage::Policy::default(),
            nm_connection: None,
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
