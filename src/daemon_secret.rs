use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
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

pub(crate) const SECRET_AGENT_OBJECT_PATH: &str = "/org/laufan/NmDaemon/SecretAgent";

const AGENT_MANAGER_PATH: &str = "/org/freedesktop/NetworkManager/AgentManager";
const AGENT_MANAGER_IFACE: &str = "org.freedesktop.NetworkManager.AgentManager";
const SECRET_AGENT_ID: &str = "nm-daemon";
const SECRET_TIMEOUT: Duration = Duration::from_secs(90);

static REGISTERED: AtomicBool = AtomicBool::new(false);
static PENDING: OnceLock<Mutex<HashMap<String, Sender<SecretResponse>>>> = OnceLock::new();
static PENDING_KEYS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

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

pub(crate) fn register_secret_agent(session_connection: &Connection) -> Result<Connection> {
    let system_connection = Connection::system().context("connect to system D-Bus")?;
    system_connection
        .object_server()
        .at(
            SECRET_AGENT_OBJECT_PATH,
            SecretAgentInterface::new(session_connection),
        )
        .context("export nm-daemon SecretAgent on system D-Bus")?;
    let manager = Proxy::new(
        &system_connection,
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
    Ok(system_connection)
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

        let request_id = request.id.clone();
        let rx = register_pending(&request);
        emit_secret_requested(&self.event_connection, &request);

        let response = rx.recv_timeout(SECRET_TIMEOUT).map_err(|_| {
            remove_pending(&request_id);
            zbus::fdo::Error::NoReply(format!("timed out waiting for secret {request_id}"))
        })?;
        remove_pending(&request_id);
        apply_secret_response(&mut connection, &request, response)?;
        Ok(connection)
    }

    fn cancel_get_secrets(&self, connection_path: OwnedObjectPath, setting_name: &str) {
        tracing::info!(%connection_path, setting_name, "NetworkManager cancelled SecretAgent request");
        let key = PendingSecretRequest::key_for(connection_path.as_str(), setting_name);
        if let Some((request_id, sender)) = remove_pending_by_key(&key) {
            let _ = sender.send(SecretResponse {
                password: None,
                save: false,
            });
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
}

pub(crate) fn capabilities(_: SecretCapabilitiesParams) -> Result<Value> {
    let keyring_available = crate::keyring::available();
    api_data_value(
        "secret_agent",
        &json!({
            "registered": REGISTERED.load(Ordering::Relaxed),
            "agent_path": SECRET_AGENT_OBJECT_PATH,
            "keyring": {
                "available": keyring_available,
                "persistence_supported": keyring_available,
                "default_save": false,
            },
            "events": {
                "stream": "wifi.secret",
                "implemented": true,
            },
            "message": "SecretAgent is registered when NetworkManager is available; save:true uses the user's Secret Service keyring when available",
        }),
        "serialize secret-agent capabilities response JSON",
    )
}

pub(crate) fn provide(params: SecretProvideParams) -> Result<Value> {
    let accepted = if let Some(sender) = remove_pending(&params.request_id) {
        sender
            .send(SecretResponse {
                password: params.password,
                save: params.save,
            })
            .is_ok()
    } else {
        false
    };
    api_data_value(
        "result",
        &json!({
            "status": if accepted { "accepted" } else { "unavailable" },
            "request_id": params.request_id,
            "accepted": accepted,
            "save_requested": params.save,
            "message": if accepted { "Secret provided to pending NetworkManager request" } else { "No pending SecretAgent request matched request_id" },
        }),
        "serialize secret provide response JSON",
    )
}

fn register_pending(request: &PendingSecretRequest) -> mpsc::Receiver<SecretResponse> {
    let (tx, rx) = mpsc::channel();
    pending()
        .lock()
        .expect("secret pending map poisoned")
        .insert(request.id.clone(), tx);
    pending_keys()
        .lock()
        .expect("secret pending key map poisoned")
        .insert(request.key.clone(), request.id.clone());
    rx
}

fn remove_pending(request_id: &str) -> Option<Sender<SecretResponse>> {
    pending_keys()
        .lock()
        .expect("secret pending key map poisoned")
        .retain(|_, id| id != request_id);
    pending()
        .lock()
        .expect("secret pending map poisoned")
        .remove(request_id)
}

fn remove_pending_by_key(key: &str) -> Option<(String, Sender<SecretResponse>)> {
    let request_id = pending_keys()
        .lock()
        .expect("secret pending key map poisoned")
        .remove(key)?;
    let sender = pending()
        .lock()
        .expect("secret pending map poisoned")
        .remove(&request_id)?;
    Some((request_id, sender))
}

fn pending() -> &'static Mutex<HashMap<String, Sender<SecretResponse>>> {
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn pending_keys() -> &'static Mutex<HashMap<String, String>> {
    PENDING_KEYS.get_or_init(|| Mutex::new(HashMap::new()))
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

fn emit_secret_event(bus: &zbus::Connection, request_id: &str, event: &str, data: Value) {
    let Ok(emitter) = SignalEmitter::new(bus, DBUS_OBJECT_PATH) else {
        tracing::warn!(
            request_id,
            "failed to create main-path SignalEmitter for secret request"
        );
        return;
    };
    emit_json_event_best_effort(&emitter, "wifi.secret", Some(request_id), event, data);
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
        Ok(secret) => secret,
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
) -> zbus::fdo::Result<()> {
    let Some(password) = response.password.filter(|password| !password.is_empty()) else {
        return Err(zbus::fdo::Error::Failed(
            "secret request cancelled or empty password supplied".to_string(),
        ));
    };
    let key = request.primary_secret_key();
    if response.save {
        store_secret_best_effort(request, connection, key, &password);
    }
    apply_password(connection, &request.setting_name, key, password)
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

fn store_secret_best_effort(
    request: &PendingSecretRequest,
    connection: &ConnectionSettings,
    key: &str,
    password: &str,
) {
    if let Err(err) = crate::keyring::store_secret(
        &request.connection_path,
        connection,
        &request.setting_name,
        key,
        password,
    ) {
        tracing::warn!(request_id = %request.id, error = %format_args!("{err:#}"), "failed to store secret in keyring");
    }
}

fn save_connection_secrets_best_effort(
    connection_path: &OwnedObjectPath,
    connection: &ConnectionSettings,
) {
    for (setting_name, secrets) in connection_secret_values(connection) {
        for (key, password) in secrets {
            if let Err(err) = crate::keyring::store_secret(
                connection_path.as_str(),
                connection,
                &setting_name,
                &key,
                &password,
            ) {
                tracing::warn!(%connection_path, setting_name, key, error = %format_args!("{err:#}"), "failed to save NetworkManager secret to keyring");
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
            if let Err(err) = crate::keyring::delete_secret(
                connection_path.as_str(),
                connection,
                setting_name,
                key,
            ) {
                tracing::warn!(%connection_path, setting_name, key, error = %format_args!("{err:#}"), "failed to delete NetworkManager secret from keyring");
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
    save: bool,
}
