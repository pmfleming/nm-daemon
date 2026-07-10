use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use zbus::blocking::{Connection, Proxy};
use zvariant::{DynamicType, OwnedObjectPath, OwnedValue, Value};

use crate::nm::ConnectionSettings;

const SECRET_DEST: &str = "org.freedesktop.secrets";
const SECRET_SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SECRET_SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const SECRET_COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_LABEL_KEY: &str = "org.freedesktop.Secret.Item.Label";
const ITEM_ATTRIBUTES_KEY: &str = "org.freedesktop.Secret.Item.Attributes";
const DEFAULT_COLLECTION: &str = "default";
const LOGIN_COLLECTION: &str = "login";
const NULL_PROMPT: &str = "/";

pub(crate) fn available() -> bool {
    SecretServiceClient::new().is_ok()
}

pub(crate) struct KeyringSecret {
    pub(crate) key: String,
    pub(crate) password: String,
}

pub(crate) fn lookup_secret(
    connection_path: &str,
    settings: &ConnectionSettings,
    setting_name: &str,
    keys: &[String],
) -> Result<Option<KeyringSecret>> {
    let client = SecretServiceClient::new()?;
    for key in keys {
        for attrs in secret_attribute_sets(connection_path, settings, setting_name, key) {
            if let Some(password) = client.lookup(&attrs)? {
                return Ok(Some(KeyringSecret {
                    key: key.clone(),
                    password,
                }));
            }
        }
    }
    Ok(None)
}

pub(crate) fn store_secret(
    connection_path: &str,
    settings: &ConnectionSettings,
    setting_name: &str,
    key: &str,
    password: &str,
) -> Result<()> {
    let client = SecretServiceClient::new()?;
    let attrs = primary_secret_attributes(connection_path, settings, setting_name, key);
    let label = secret_label(settings, setting_name, key);
    client.store(&attrs, &label, password)
}

pub(crate) fn delete_secret(
    connection_path: &str,
    settings: &ConnectionSettings,
    setting_name: &str,
    key: &str,
) -> Result<usize> {
    let client = SecretServiceClient::new()?;
    let mut deleted = 0;
    for attrs in secret_attribute_sets(connection_path, settings, setting_name, key) {
        deleted += client.delete(&attrs)?;
    }
    Ok(deleted)
}

struct SecretServiceClient {
    connection: Connection,
    session: OwnedObjectPath,
}

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

impl SecretServiceClient {
    fn new() -> Result<Self> {
        let connection = Connection::session().context("connect to session D-Bus for keyring")?;
        let service = service_proxy(&connection)?;
        let (_output, session): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Value::new("")))
            .context("open Secret Service session")?;
        drop(service);
        Ok(Self {
            connection,
            session,
        })
    }

    fn lookup(&self, attrs: &HashMap<String, String>) -> Result<Option<String>> {
        let service = service_proxy(&self.connection)?;
        let (mut unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
            .call("SearchItems", &(attrs,))
            .context("search Secret Service items")?;
        if !locked.is_empty() {
            unlocked.extend(self.unlock(locked)?);
        }
        let Some(item) = unlocked.into_iter().next() else {
            return Ok(None);
        };
        let secrets: HashMap<OwnedObjectPath, Secret> = service
            .call("GetSecrets", &(vec![item.clone()], self.session.clone()))
            .context("read Secret Service item secret")?;
        Ok(secrets
            .get(&item)
            .and_then(|secret| String::from_utf8(secret.2.clone()).ok()))
    }

    fn store(&self, attrs: &HashMap<String, String>, label: &str, password: &str) -> Result<()> {
        let collection = self.collection()?;
        let collection_proxy = Proxy::new(
            &self.connection,
            SECRET_DEST,
            collection.as_str(),
            SECRET_COLLECTION_IFACE,
        )
        .context("create Secret Service collection proxy")?;
        let props = HashMap::from([
            (ITEM_LABEL_KEY.to_string(), owned_value(label.to_string())?),
            (ITEM_ATTRIBUTES_KEY.to_string(), owned_value(attrs.clone())?),
        ]);
        let secret: Secret = (
            self.session.clone(),
            Vec::new(),
            password.as_bytes().to_vec(),
            "text/plain".to_string(),
        );
        let (_item, prompt): (OwnedObjectPath, OwnedObjectPath) = collection_proxy
            .call("CreateItem", &(props, secret, true))
            .context("create Secret Service item")?;
        if prompt.as_str() != NULL_PROMPT {
            tracing::debug!(%prompt, "Secret Service create prompt was returned and is not handled yet");
        }
        Ok(())
    }

    fn delete(&self, attrs: &HashMap<String, String>) -> Result<usize> {
        let service = service_proxy(&self.connection)?;
        let (mut unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
            .call("SearchItems", &(attrs,))
            .context("search Secret Service items for delete")?;
        if !locked.is_empty() {
            unlocked.extend(self.unlock(locked)?);
        }
        let mut deleted = 0;
        for item in unlocked {
            let item_proxy = Proxy::new(
                &self.connection,
                SECRET_DEST,
                item.as_str(),
                "org.freedesktop.Secret.Item",
            )
            .context("create Secret Service item proxy")?;
            let prompt: OwnedObjectPath = item_proxy
                .call("Delete", &())
                .context("delete Secret Service item")?;
            if prompt.as_str() != NULL_PROMPT {
                tracing::debug!(%prompt, "Secret Service delete prompt was returned and is not handled yet");
            }
            deleted += 1;
        }
        Ok(deleted)
    }

    fn collection(&self) -> Result<OwnedObjectPath> {
        let service = service_proxy(&self.connection)?;
        let default: OwnedObjectPath = service
            .call("ReadAlias", &(DEFAULT_COLLECTION,))
            .context("read default Secret Service collection")?;
        if default.as_str() != NULL_PROMPT {
            return Ok(default);
        }
        let login: OwnedObjectPath = service
            .call("ReadAlias", &(LOGIN_COLLECTION,))
            .context("read login Secret Service collection")?;
        if login.as_str() != NULL_PROMPT {
            return Ok(login);
        }
        bail!("no default or login Secret Service collection is available")
    }

    fn unlock(&self, locked: Vec<OwnedObjectPath>) -> Result<Vec<OwnedObjectPath>> {
        let service = service_proxy(&self.connection)?;
        let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
            .call("Unlock", &(locked,))
            .context("unlock Secret Service items")?;
        if prompt.as_str() != NULL_PROMPT {
            tracing::debug!(%prompt, "Secret Service unlock prompt was returned and is not handled yet");
        }
        Ok(unlocked)
    }
}

fn service_proxy(connection: &Connection) -> Result<Proxy<'_>> {
    Proxy::new(
        connection,
        SECRET_DEST,
        SECRET_SERVICE_PATH,
        SECRET_SERVICE_IFACE,
    )
    .context("create Secret Service proxy")
}

fn primary_secret_attributes(
    connection_path: &str,
    settings: &ConnectionSettings,
    setting_name: &str,
    key: &str,
) -> HashMap<String, String> {
    let mut attrs = base_secret_attributes(setting_name, key);
    if !insert_setting_string(settings, "connection", "uuid", &mut attrs) {
        attrs.insert("connection_path".to_string(), connection_path.to_string());
    }
    attrs
}

fn secret_attribute_sets(
    connection_path: &str,
    settings: &ConnectionSettings,
    setting_name: &str,
    key: &str,
) -> Vec<HashMap<String, String>> {
    let mut sets = vec![primary_secret_attributes(
        connection_path,
        settings,
        setting_name,
        key,
    )];
    let mut path_attrs = base_secret_attributes(setting_name, key);
    path_attrs.insert("connection_path".to_string(), connection_path.to_string());
    sets.push(path_attrs);
    sets
}

fn base_secret_attributes(setting_name: &str, key: &str) -> HashMap<String, String> {
    HashMap::from([
        ("application".to_string(), "nm-daemon".to_string()),
        ("setting".to_string(), setting_name.to_string()),
        ("key".to_string(), key.to_string()),
    ])
}

fn insert_setting_string(
    settings: &ConnectionSettings,
    section: &str,
    key: &str,
    attrs: &mut HashMap<String, String>,
) -> bool {
    if let Some(value) = settings
        .get(section)
        .and_then(|section| section.get(key))
        .and_then(value_string)
    {
        attrs.insert(key.to_string(), value);
        true
    } else {
        false
    }
}

fn secret_label(settings: &ConnectionSettings, setting_name: &str, key: &str) -> String {
    let connection_id = settings
        .get("connection")
        .and_then(|section| section.get("id"))
        .and_then(value_string)
        .unwrap_or_else(|| "Wi-Fi network".to_string());
    format!("nm-daemon {connection_id} {setting_name}.{key}")
}

fn value_string(value: &OwnedValue) -> Option<String> {
    String::try_from(value.clone()).ok()
}

fn owned_value<T>(value: T) -> Result<OwnedValue>
where
    T: Into<Value<'static>> + DynamicType,
{
    OwnedValue::try_from(Value::new(value)).context("create Secret Service variant")
}
