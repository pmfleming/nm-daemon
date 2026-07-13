use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::blocking::{Connection, Proxy};
use zbus::object_server::SignalEmitter;
use zvariant::{OwnedObjectPath, OwnedValue, Value as ZValue};

use crate::daemon::{DBUS_OBJECT_PATH, emit_json_event_best_effort};
use crate::nm::{ConnectionSettings, NM_DEST};
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};

pub(crate) const SECRET_AGENT_OBJECT_PATH: &str = "/org/laufan/NmDaemon/SecretAgent";

const AGENT_MANAGER_PATH: &str = "/org/freedesktop/NetworkManager/AgentManager";
const AGENT_MANAGER_IFACE: &str = "org.freedesktop.NetworkManager.AgentManager";
const SECRET_AGENT_ID: &str = "nm-daemon";
const SECRET_TIMEOUT: Duration = Duration::from_secs(90);

static REGISTERED: AtomicBool = AtomicBool::new(false);
static PENDING: OnceLock<Mutex<PendingRegistry>> = OnceLock::new();

pub(crate) struct SecretAgentInterface {
    event_connection: zbus::Connection,
}

impl SecretAgentInterface {
    fn new(session_connection: &Connection) -> Self {
        Self {
            event_connection: session_connection.inner().clone(),
        }
    }
}

pub(crate) fn register_secret_agent(
    session_connection: &Connection,
    system_connection: &Connection,
) -> Result<()> {
    system_connection
        .object_server()
        .at(
            SECRET_AGENT_OBJECT_PATH,
            SecretAgentInterface::new(session_connection),
        )
        .context("export nm-daemon SecretAgent on system D-Bus")?;
    let manager = Proxy::new(
        system_connection,
        NM_DEST,
        AGENT_MANAGER_PATH,
        AGENT_MANAGER_IFACE,
    )
    .context("create NetworkManager SecretAgent manager proxy")?;
    manager
        .call::<_, _, ()>("Register", &(SECRET_AGENT_ID,))
        .context("register NetworkManager SecretAgent")?;
    REGISTERED.store(true, Ordering::Relaxed);
    tracing::info!(
        path = SECRET_AGENT_OBJECT_PATH,
        "registered NetworkManager SecretAgent"
    );
    Ok(())
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.SecretAgent")]
impl SecretAgentInterface {
    fn get_secrets(
        &self,
        mut connection: ConnectionSettings,
        connection_path: OwnedObjectPath,
        setting_name: &str,
        hints: Vec<String>,
        flags: u32,
    ) -> zbus::fdo::Result<ConnectionSettings> {
        let request = PendingSecretRequest::new(connection_path, setting_name, hints, flags);
        if let Some(stored) = lookup_stored_secret(&request, &connection) {
            apply_password(&mut connection, setting_name, &stored.key, stored.password)?;
            return Ok(connection);
        }

        let (registration, displaced_request_id) = register_pending(&request);
        if let Some(displaced_request_id) = displaced_request_id {
            emit_secret_cancelled(&self.event_connection, &displaced_request_id);
        }
        emit_secret_requested(&self.event_connection, &request);

        let response = registration.recv_timeout(SECRET_TIMEOUT).map_err(|_| {
            zbus::fdo::Error::NoReply(format!("timed out waiting for secret {}", request.id))
        })?;
        if let Some(persistence) = apply_secret_response(&mut connection, &request, response)? {
            emit_secret_persistence(&self.event_connection, &request.id, persistence);
        }
        Ok(connection)
    }

    fn cancel_get_secrets(&self, connection_path: OwnedObjectPath, setting_name: &str) {
        tracing::info!(%connection_path, setting_name, "NetworkManager cancelled SecretAgent request");
        let key = PendingSecretRequest::key_for(connection_path.as_str(), setting_name);
        if let Some((request_id, sender)) = remove_pending_by_key(&key) {
            let _ = sender.send(SecretResponse::cancelled());
            emit_secret_cancelled(&self.event_connection, &request_id);
        }
    }

    fn save_secrets(&self, connection: ConnectionSettings, connection_path: OwnedObjectPath) {
        save_connection_secrets_best_effort(&connection_path, &connection);
    }

    fn delete_secrets(&self, connection: ConnectionSettings, connection_path: OwnedObjectPath) {
        delete_connection_secrets_best_effort(&connection_path, &connection);
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct SecretCapabilitiesParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretProvideParams {
    request_id: String,
    #[serde(default)]
    save: bool,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    values: HashMap<String, String>,
    #[serde(default)]
    cancel: bool,
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
                "default_save": false,
                "prompt_handling": "unsupported",
                "prompt_policy": "dismiss_and_report",
            },
            "events": {
                "stream": Stream::WifiSecret,
                "implemented": true,
                "persistence_outcomes": true,
            },
            "message": "SecretAgent is registered when NetworkManager is available; save:true persists only when the user's Secret Service keyring can complete without a desktop prompt",
        }),
        "serialize secret-agent capabilities response JSON",
    )
}

pub(crate) fn provide(params: SecretProvideParams) -> Result<Value> {
    let accepted = if let Some(sender) = remove_pending(&params.request_id) {
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
                (true, false, true) => "Secret provided to pending NetworkManager request; the wifi.secret stream reports the persistence outcome",
                (true, false, false) => "Secret provided to pending NetworkManager request",
                (false, _, _) => "No pending SecretAgent request matched request_id",
            },
        }),
        "serialize secret provide response JSON",
    )
}

fn register_pending(request: &PendingSecretRequest) -> (PendingRegistration, Option<String>) {
    let (tx, rx) = mpsc::channel();
    let displaced = with_pending_registry(|registry| {
        registry.insert(request.id.clone(), request.key.clone(), tx)
    });
    let displaced_request_id = displaced.map(|(request_id, sender)| {
        let _ = sender.send(SecretResponse::cancelled());
        tracing::warn!(%request_id, key = %request.key, "replaced duplicate pending SecretAgent request");
        request_id
    });
    (
        PendingRegistration {
            request_id: request.id.clone(),
            receiver: rx,
        },
        displaced_request_id,
    )
}

fn remove_pending(request_id: &str) -> Option<Sender<SecretResponse>> {
    with_pending_registry(|registry| registry.remove(request_id))
}

fn remove_pending_by_key(key: &str) -> Option<(String, Sender<SecretResponse>)> {
    with_pending_registry(|registry| registry.remove_by_key(key))
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

fn emit_secret_requested(bus: &zbus::Connection, request: &PendingSecretRequest) {
    emit_secret_event(
        bus,
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
            "save_supported": true,
            "timeout_ms": SECRET_TIMEOUT.as_millis(),
        }),
    );
}

fn emit_secret_cancelled(bus: &zbus::Connection, request_id: &str) {
    emit_secret_event(
        bus,
        request_id,
        "cancelled",
        json!({ "request_id": request_id }),
    );
}

fn emit_secret_persistence(
    bus: &zbus::Connection,
    request_id: &str,
    outcome: SecretPersistenceOutcome,
) {
    let data = match outcome {
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
    emit_secret_event(bus, request_id, "persistence", data);
}

fn emit_secret_event(bus: &zbus::Connection, request_id: &str, event: &str, data: Value) {
    let Ok(emitter) = SignalEmitter::new(bus, DBUS_OBJECT_PATH) else {
        tracing::warn!(
            request_id,
            "failed to create main-path SignalEmitter for secret request"
        );
        return;
    };
    emit_json_event_best_effort(&emitter, Stream::WifiSecret, Some(request_id), event, data);
}

fn lookup_stored_secret(
    request: &PendingSecretRequest,
    connection: &ConnectionSettings,
) -> Option<crate::keyring::KeyringSecret> {
    match crate::keyring::lookup_secret(
        &request.connection_path,
        connection,
        &request.setting_name,
        &request.secret_keys,
    ) {
        Ok(crate::keyring::KeyringOutcome::Completed(secret)) => secret,
        Ok(crate::keyring::KeyringOutcome::PromptUnsupported {
            operation, prompt, ..
        }) => {
            tracing::info!(request_id = %request.id, %operation, %prompt, "keyring lookup requires an unsupported desktop prompt");
            None
        }
        Err(err) => {
            tracing::debug!(request_id = %request.id, error = %format_args!("{err:#}"), "keyring lookup failed");
            None
        }
    }
}

fn apply_secret_response(
    connection: &mut ConnectionSettings,
    request: &PendingSecretRequest,
    response: SecretResponse,
) -> zbus::fdo::Result<Option<SecretPersistenceOutcome>> {
    if response.cancelled {
        return Err(zbus::fdo::Error::Failed(
            "secret request cancelled by frontend".to_string(),
        ));
    }
    let mut values = response.values;
    if let Some(password) = response.password.filter(|password| !password.is_empty()) {
        values
            .entry(request.primary_secret_key().to_string())
            .or_insert(password);
    }
    values.retain(|key, value| request.secret_keys.contains(key) && !value.is_empty());
    if values.is_empty() {
        return Err(zbus::fdo::Error::Failed(
            "secret request contained no requested values".to_string(),
        ));
    }
    for (key, value) in &values {
        apply_password(connection, &request.setting_name, key, value.to_string())?;
    }
    Ok(response.save.then(|| {
        values
            .iter()
            .map(|(key, value)| store_secret_outcome(request, connection, key, value))
            .find(|outcome| !matches!(outcome, SecretPersistenceOutcome::Stored))
            .unwrap_or(SecretPersistenceOutcome::Stored)
    }))
}

fn apply_password(
    connection: &mut ConnectionSettings,
    setting_name: &str,
    key: &str,
    password: String,
) -> zbus::fdo::Result<()> {
    connection
        .entry(setting_name.to_string())
        .or_default()
        .insert(key.to_string(), owned_value(password)?);
    Ok(())
}

fn store_secret_outcome(
    request: &PendingSecretRequest,
    connection: &ConnectionSettings,
    key: &str,
    password: &str,
) -> SecretPersistenceOutcome {
    match crate::keyring::store_secret(
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
            tracing::warn!(request_id = %request.id, error = %format_args!("{err:#}"), "failed to store secret in keyring");
            SecretPersistenceOutcome::Failed(format!("{err:#}"))
        }
    }
}

fn save_connection_secrets_best_effort(
    connection_path: &OwnedObjectPath,
    connection: &ConnectionSettings,
) {
    for (setting_name, secrets) in connection_secret_values(connection) {
        for (key, password) in secrets {
            match crate::keyring::store_secret(
                connection_path.as_str(),
                connection,
                &setting_name,
                &key,
                &password,
            ) {
                Ok(crate::keyring::KeyringOutcome::Completed(())) => {}
                Ok(crate::keyring::KeyringOutcome::PromptUnsupported {
                    operation, prompt, ..
                }) => {
                    tracing::warn!(%connection_path, setting_name, key, %operation, %prompt, "NetworkManager secret was not saved because the keyring requires an unsupported desktop prompt");
                }
                Err(err) => {
                    tracing::warn!(%connection_path, setting_name, key, error = %format_args!("{err:#}"), "failed to save NetworkManager secret to keyring");
                }
            }
        }
    }
}

fn delete_connection_secrets_best_effort(
    connection_path: &OwnedObjectPath,
    connection: &ConnectionSettings,
) {
    for setting_name in connection.keys() {
        for key in known_secret_keys(setting_name) {
            match crate::keyring::delete_secret(
                connection_path.as_str(),
                connection,
                setting_name,
                key,
            ) {
                Ok(crate::keyring::KeyringOutcome::Completed(deleted)) => {
                    tracing::debug!(%connection_path, setting_name, key, deleted, "deleted NetworkManager secrets from keyring");
                }
                Ok(crate::keyring::KeyringOutcome::PromptUnsupported {
                    operation,
                    prompt,
                    completed,
                }) => {
                    tracing::warn!(%connection_path, setting_name, key, %operation, %prompt, deleted = completed, "keyring delete stopped because it requires an unsupported desktop prompt");
                }
                Err(err) => {
                    tracing::warn!(%connection_path, setting_name, key, error = %format_args!("{err:#}"), "failed to delete NetworkManager secret from keyring");
                }
            }
        }
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

fn value_string(value: &OwnedValue) -> Option<String> {
    String::try_from(value.clone()).ok()
}

fn owned_value(value: String) -> zbus::fdo::Result<OwnedValue> {
    OwnedValue::try_from(ZValue::new(value))
        .map_err(|err| zbus::fdo::Error::Failed(format!("create D-Bus secret variant: {err}")))
}

struct PendingSecretRequest {
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
            id: crate::daemon_event::next_request_id("secret"),
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

fn known_secret_keys(setting_name: &str) -> &'static [&'static str] {
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
        "vpn" | "gsm" | "cdma" => &["password", "pin"],
        _ => &["password"],
    }
}

fn default_secret_key_for_setting(setting_name: &str) -> &'static str {
    match setting_name {
        "802-11-wireless-security" => "psk",
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
    sender: Sender<SecretResponse>,
}

#[derive(Default)]
struct PendingRegistry {
    requests: HashMap<String, PendingEntry>,
}

impl PendingRegistry {
    fn insert(
        &mut self,
        request_id: String,
        key: String,
        sender: Sender<SecretResponse>,
    ) -> Option<(String, Sender<SecretResponse>)> {
        let duplicate = self
            .requests
            .iter()
            .find_map(|(id, entry)| (entry.key == key).then(|| id.clone()));
        let displaced =
            duplicate.and_then(|id| self.requests.remove(&id).map(|entry| (id, entry.sender)));
        if let Some(replaced) = self
            .requests
            .insert(request_id.clone(), PendingEntry { key, sender })
        {
            tracing::warn!(%request_id, "replaced colliding SecretAgent request id");
            let _ = replaced.sender.send(SecretResponse::cancelled());
        }
        displaced
    }

    fn remove(&mut self, request_id: &str) -> Option<Sender<SecretResponse>> {
        self.requests.remove(request_id).map(|entry| entry.sender)
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
    use std::time::Instant;

    use super::*;

    #[test]
    fn pending_registry_replaces_one_request_per_connection_setting() {
        let mut registry = PendingRegistry::default();
        let (first_sender, first_receiver) = mpsc::channel();
        let (second_sender, _second_receiver) = mpsc::channel();

        assert!(
            registry
                .insert("first".into(), "connection\nsetting".into(), first_sender)
                .is_none()
        );
        let (displaced_id, displaced_sender) = registry
            .insert("second".into(), "connection\nsetting".into(), second_sender)
            .expect("duplicate key should displace its prior request");
        displaced_sender
            .send(SecretResponse::cancelled())
            .expect("displaced receiver remains active");

        assert_eq!(displaced_id, "first");
        assert!(
            first_receiver
                .recv()
                .expect("cancellation")
                .password
                .is_none()
        );
        assert_eq!(
            registry
                .remove_by_key("connection\nsetting")
                .map(|(id, _)| id),
            Some("second".into())
        );
        assert!(registry.requests.is_empty());
    }

    #[test]
    fn pending_registration_removes_itself_when_waiting_scope_ends() {
        let request_id = "test-secret-registration-raii";
        remove_pending(request_id);
        let (sender, receiver) = mpsc::channel();
        with_pending_registry(|registry| {
            let _ = registry.insert(
                request_id.into(),
                "test-connection\ntest-setting".into(),
                sender,
            );
        });
        let registration = PendingRegistration {
            request_id: request_id.into(),
            receiver,
        };

        assert!(with_pending_registry(|registry| registry
            .requests
            .contains_key(request_id)));
        drop(registration);
        assert!(!with_pending_registry(|registry| registry
            .requests
            .contains_key(request_id)));
    }

    #[test]
    fn pending_secret_delivery_observes_delay_and_timeout_cleanup() {
        let delivered = pending_request("timed-delivery", "timed-delivery-key");
        let (registration, displaced) = register_pending(&delivered);
        assert!(displaced.is_none());
        let sender = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(20));
            remove_pending("timed-delivery")
                .expect("timed request remains registered")
                .send(SecretResponse {
                    password: Some("secret".to_string()),
                    values: HashMap::new(),
                    save: true,
                    cancelled: false,
                })
                .unwrap();
        });
        let started = Instant::now();
        let response = registration
            .recv_timeout(Duration::from_millis(250))
            .unwrap();
        sender.join().unwrap();
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert_eq!(response.password.as_deref(), Some("secret"));
        assert!(response.save);
        drop(registration);

        let timed_out = pending_request("timed-out", "timed-out-key");
        let (registration, displaced) = register_pending(&timed_out);
        assert!(displaced.is_none());
        assert!(matches!(
            registration.recv_timeout(Duration::from_millis(10)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(registration);
        assert!(remove_pending("timed-out").is_none());
    }

    #[test]
    fn secret_response_applies_only_requested_named_values() {
        let request = PendingSecretRequest {
            id: "named-values".to_string(),
            key: "named-values-key".to_string(),
            connection_path: "/test/connection".to_string(),
            setting_name: "802-1x".to_string(),
            hints: Vec::new(),
            secret_keys: vec!["password".to_string(), "pin".to_string()],
            flags: 0,
        };
        let mut connection = ConnectionSettings::new();
        let response = SecretResponse {
            password: None,
            values: HashMap::from([
                ("password".to_string(), "secret".to_string()),
                ("pin".to_string(), "1234".to_string()),
                ("not-requested".to_string(), "ignored".to_string()),
            ]),
            save: false,
            cancelled: false,
        };

        assert!(
            apply_secret_response(&mut connection, &request, response)
                .unwrap()
                .is_none()
        );
        let values = &connection["802-1x"];
        assert_eq!(value_string(&values["password"]).as_deref(), Some("secret"));
        assert_eq!(value_string(&values["pin"]).as_deref(), Some("1234"));
        assert!(!values.contains_key("not-requested"));
    }

    fn pending_request(id: &str, key: &str) -> PendingSecretRequest {
        PendingSecretRequest {
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
