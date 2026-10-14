use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use zbus::blocking::{Connection, Proxy};
use zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::nm::ConnectionSettings;
use crate::variant::{owned_value, setting};

const SECRET_DEST: &str = "org.freedesktop.secrets";
const SECRET_SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SECRET_SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const SECRET_COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const SECRET_PROMPT_IFACE: &str = "org.freedesktop.Secret.Prompt";
const ITEM_LABEL_KEY: &str = "org.freedesktop.Secret.Item.Label";
const ITEM_ATTRIBUTES_KEY: &str = "org.freedesktop.Secret.Item.Attributes";
const DEFAULT_COLLECTION: &str = "default";
const LOGIN_COLLECTION: &str = "login";
const NULL_PROMPT: &str = "/";

pub(crate) fn available() -> bool {
    let Ok(connection) = Connection::session() else {
        return false;
    };
    let destination = SECRET_DEST.to_string();
    let Ok(service) = service_proxy(&connection, &destination) else {
        return false;
    };
    service
        .call::<_, _, OwnedObjectPath>("ReadAlias", &(DEFAULT_COLLECTION,))
        .is_ok()
}

pub(crate) struct KeyringSecret {
    pub(crate) key: String,
    pub(crate) password: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyringPromptOperation {
    Unlock,
    Create,
    Delete,
}

impl std::fmt::Display for KeyringPromptOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unlock => "unlock",
            Self::Create => "create",
            Self::Delete => "delete",
        })
    }
}

#[derive(Debug)]
pub(crate) enum KeyringOutcome<T> {
    Completed(T),
    PromptUnsupported {
        operation: KeyringPromptOperation,
        prompt: OwnedObjectPath,
        completed: T,
    },
}

pub(crate) struct Keyring {
    client: SecretServiceClient,
}

impl Keyring {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            client: SecretServiceClient::new()?,
        })
    }

    /// Only credential requests allowing interaction and explicit saves may
    /// open the desktop's unlock dialog. Background reads remain noninteractive.
    pub(crate) fn interactive() -> Result<Self> {
        let mut keyring = Self::new()?;
        keyring.client.interactive = true;
        Ok(keyring)
    }

    pub(crate) fn lookup_secrets(
        &self,
        connection_path: &str,
        settings: &ConnectionSettings,
        setting_name: &str,
        keys: &[String],
    ) -> Result<KeyringOutcome<Vec<KeyringSecret>>> {
        let mut secrets = Vec::new();
        for key in keys {
            match self.lookup_key(connection_path, settings, setting_name, key)? {
                KeyringOutcome::Completed(Some(password)) if !password.is_empty() => {
                    secrets.push(KeyringSecret {
                        key: key.clone(),
                        password,
                    });
                }
                KeyringOutcome::Completed(_) => {}
                KeyringOutcome::PromptUnsupported {
                    operation, prompt, ..
                } => {
                    return Ok(KeyringOutcome::PromptUnsupported {
                        operation,
                        prompt,
                        completed: secrets,
                    });
                }
            }
        }
        Ok(KeyringOutcome::Completed(secrets))
    }

    fn lookup_key(
        &self,
        connection_path: &str,
        settings: &ConnectionSettings,
        setting_name: &str,
        key: &str,
    ) -> Result<KeyringOutcome<Option<String>>> {
        for attrs in secret_attribute_sets(connection_path, settings, setting_name, key) {
            let outcome = self.client.lookup(&attrs)?;
            if !matches!(outcome, KeyringOutcome::Completed(None)) {
                return Ok(outcome);
            }
        }
        Ok(KeyringOutcome::Completed(None))
    }

    pub(crate) fn store_secret(
        &self,
        connection_path: &str,
        settings: &ConnectionSettings,
        setting_name: &str,
        key: &str,
        password: &str,
    ) -> Result<KeyringOutcome<()>> {
        let attrs = primary_secret_attributes(connection_path, settings, setting_name, key);
        let label = secret_label(settings, setting_name, key);
        self.client.store(&attrs, &label, password)
    }

    pub(crate) fn delete_secret(
        &self,
        connection_path: &str,
        settings: &ConnectionSettings,
        setting_name: &str,
        key: &str,
    ) -> Result<KeyringOutcome<usize>> {
        let mut deleted = 0;
        for attrs in secret_attribute_sets(connection_path, settings, setting_name, key) {
            match self.client.delete(&attrs)? {
                KeyringOutcome::Completed(count) => deleted += count,
                KeyringOutcome::PromptUnsupported {
                    operation,
                    prompt,
                    completed,
                } => {
                    return Ok(KeyringOutcome::PromptUnsupported {
                        operation,
                        prompt,
                        completed: deleted + completed,
                    });
                }
            }
        }
        Ok(KeyringOutcome::Completed(deleted))
    }
}

struct SecretServiceClient {
    interactive: bool,
    connection: Connection,
    destination: String,
    session: OwnedObjectPath,
}

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

impl SecretServiceClient {
    fn new() -> Result<Self> {
        let connection = Connection::session().context("connect to session D-Bus for keyring")?;
        let destination = SECRET_DEST.to_string();
        let service = service_proxy(&connection, &destination)?;
        let (_output, session): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Value::new("")))
            .context("open Secret Service session")?;
        drop(service);
        Ok(Self {
            interactive: false,
            connection,
            destination,
            session,
        })
    }

    fn lookup(&self, attrs: &HashMap<String, String>) -> Result<KeyringOutcome<Option<String>>> {
        let service = self.service_proxy()?;
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
            .call("SearchItems", &(attrs,))
            .context("search Secret Service items")?;
        let unlocked = match self.unlock_items(unlocked, locked)? {
            KeyringOutcome::Completed(items) => items,
            KeyringOutcome::PromptUnsupported {
                operation, prompt, ..
            } => {
                return Ok(KeyringOutcome::PromptUnsupported {
                    operation,
                    prompt,
                    completed: None,
                });
            }
        };
        self.read_first_secret(&service, unlocked)
    }

    fn unlock_items(
        &self,
        mut unlocked: Vec<OwnedObjectPath>,
        locked: Vec<OwnedObjectPath>,
    ) -> Result<KeyringOutcome<Vec<OwnedObjectPath>>> {
        if locked.is_empty() {
            return Ok(KeyringOutcome::Completed(unlocked));
        }
        match self.unlock(locked)? {
            KeyringOutcome::Completed(items) => {
                unlocked.extend(items);
                Ok(KeyringOutcome::Completed(unlocked))
            }
            KeyringOutcome::PromptUnsupported {
                operation, prompt, ..
            } => Ok(KeyringOutcome::PromptUnsupported {
                operation,
                prompt,
                completed: unlocked,
            }),
        }
    }

    fn read_first_secret(
        &self,
        service: &Proxy<'_>,
        unlocked: Vec<OwnedObjectPath>,
    ) -> Result<KeyringOutcome<Option<String>>> {
        let Some(item) = unlocked.into_iter().next() else {
            return Ok(KeyringOutcome::Completed(None));
        };
        let mut secrets: HashMap<OwnedObjectPath, Secret> = service
            .call("GetSecrets", &(std::slice::from_ref(&item), &self.session))
            .context("read Secret Service item secret")?;
        Ok(KeyringOutcome::Completed(
            secrets
                .remove(&item)
                .and_then(|secret| String::from_utf8(secret.2).ok()),
        ))
    }

    fn store(
        &self,
        attrs: &HashMap<String, String>,
        label: &str,
        password: &str,
    ) -> Result<KeyringOutcome<()>> {
        let collection = self.collection()?;
        let collection_proxy = Proxy::new(
            &self.connection,
            self.destination.as_str(),
            collection.as_str(),
            SECRET_COLLECTION_IFACE,
        )
        .context("create Secret Service collection proxy")?;
        if collection_proxy.get_property::<bool>("Locked")? {
            match self.unlock(vec![collection.clone()])? {
                KeyringOutcome::Completed(_) => {
                    if collection_proxy.get_property::<bool>("Locked")? {
                        bail!("desktop keyring is still locked; unlock it and retry saving");
                    }
                }
                KeyringOutcome::PromptUnsupported {
                    operation, prompt, ..
                } => {
                    return Ok(KeyringOutcome::PromptUnsupported {
                        operation,
                        prompt,
                        completed: (),
                    });
                }
            }
        }
        let props = HashMap::from([
            (ITEM_LABEL_KEY.to_string(), owned_value(label.to_string())?),
            (ITEM_ATTRIBUTES_KEY.to_string(), owned_value(attrs.clone())?),
        ]);
        // The synchronous call serializes these borrows before returning; no
        // extra password buffer or session-path copy is needed.
        let secret = (
            &self.session,
            &[] as &[u8],
            password.as_bytes(),
            "text/plain",
        );
        let (_item, prompt): (OwnedObjectPath, OwnedObjectPath) = collection_proxy
            .call("CreateItem", &(props, secret, true))
            .context("create Secret Service item")?;
        if prompt.as_str() == NULL_PROMPT {
            Ok(KeyringOutcome::Completed(()))
        } else {
            self.dismiss_prompt(prompt, KeyringPromptOperation::Create, ())
        }
    }

    fn delete(&self, attrs: &HashMap<String, String>) -> Result<KeyringOutcome<usize>> {
        let service = self.service_proxy()?;
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
            .call("SearchItems", &(attrs,))
            .context("search Secret Service items for delete")?;
        let unlocked = match self.unlock_items(unlocked, locked)? {
            KeyringOutcome::Completed(items) => items,
            KeyringOutcome::PromptUnsupported {
                operation, prompt, ..
            } => {
                return Ok(KeyringOutcome::PromptUnsupported {
                    operation,
                    prompt,
                    completed: 0,
                });
            }
        };
        self.delete_items(unlocked)
    }

    fn delete_items(&self, items: Vec<OwnedObjectPath>) -> Result<KeyringOutcome<usize>> {
        let mut deleted = 0;
        for item in items {
            let prompt = self.delete_item(&item)?;
            if prompt.as_str() == NULL_PROMPT {
                deleted += 1;
            } else {
                return self.dismiss_prompt(prompt, KeyringPromptOperation::Delete, deleted);
            }
        }
        Ok(KeyringOutcome::Completed(deleted))
    }

    fn delete_item(&self, item: &OwnedObjectPath) -> Result<OwnedObjectPath> {
        let item_proxy = Proxy::new(
            &self.connection,
            self.destination.as_str(),
            item.as_str(),
            "org.freedesktop.Secret.Item",
        )
        .context("create Secret Service item proxy")?;
        item_proxy
            .call("Delete", &())
            .context("delete Secret Service item")
    }

    fn collection(&self) -> Result<OwnedObjectPath> {
        let service = self.service_proxy()?;
        for alias in [DEFAULT_COLLECTION, LOGIN_COLLECTION] {
            let collection: OwnedObjectPath = service
                .call("ReadAlias", &(alias,))
                .with_context(|| format!("read {alias} Secret Service collection"))?;
            if collection.as_str() != NULL_PROMPT {
                return Ok(collection);
            }
        }
        bail!("no default or login Secret Service collection is available")
    }

    fn unlock(&self, locked: Vec<OwnedObjectPath>) -> Result<KeyringOutcome<Vec<OwnedObjectPath>>> {
        let service = self.service_proxy()?;
        let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
            .call("Unlock", &(locked,))
            .context("unlock Secret Service items")?;
        if prompt.as_str() == NULL_PROMPT {
            Ok(KeyringOutcome::Completed(unlocked))
        } else if self.interactive {
            let result = self.complete_prompt(&prompt, std::time::Duration::from_secs(45))?;
            let mut items = unlocked;
            items.extend(
                Vec::<OwnedObjectPath>::try_from(result)
                    .context("decode Secret Service unlock result")?,
            );
            Ok(KeyringOutcome::Completed(items))
        } else {
            self.dismiss_prompt(prompt, KeyringPromptOperation::Unlock, unlocked)
        }
    }

    fn complete_prompt(
        &self,
        path: &OwnedObjectPath,
        timeout: std::time::Duration,
    ) -> Result<OwnedValue> {
        use futures::StreamExt;
        // This code runs on a blocking worker, never on the daemon executor.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let proxy = zbus::Proxy::new(
                    self.connection.inner(),
                    self.destination.as_str(),
                    path.as_str(),
                    SECRET_PROMPT_IFACE,
                )
                .await?;
                // Subscribe before Prompt: a provider may complete synchronously.
                let mut completed = proxy.receive_signal("Completed").await?;
                proxy.call::<_, _, ()>("Prompt", &("",)).await?;
                let result = tokio::time::timeout(timeout, completed.next()).await;
                match result {
                    Ok(Some(message)) => {
                        let (dismissed, value): (bool, OwnedValue) =
                            message.body().deserialize()?;
                        if dismissed {
                            bail!("desktop keyring unlock cancelled; unlock it and retry");
                        }
                        Ok(value)
                    }
                    _ => {
                        let _ = proxy.call::<_, _, ()>("Dismiss", &()).await;
                        bail!("desktop keyring unlock timed out; unlock it and retry")
                    }
                }
            })
    }

    fn dismiss_prompt<T>(
        &self,
        prompt: OwnedObjectPath,
        operation: KeyringPromptOperation,
        completed: T,
    ) -> Result<KeyringOutcome<T>> {
        let prompt_proxy = Proxy::new(
            &self.connection,
            self.destination.as_str(),
            prompt.as_str(),
            SECRET_PROMPT_IFACE,
        )
        .with_context(|| format!("create Secret Service {operation} prompt proxy"))?;
        prompt_proxy
            .call::<_, _, ()>("Dismiss", &())
            .with_context(|| format!("dismiss unsupported Secret Service {operation} prompt"))?;
        drop(prompt_proxy);
        Ok(KeyringOutcome::PromptUnsupported {
            operation,
            prompt,
            completed,
        })
    }

    fn service_proxy(&self) -> Result<Proxy<'_>> {
        service_proxy(&self.connection, &self.destination)
    }
}

fn service_proxy<'a>(connection: &'a Connection, destination: &'a str) -> Result<Proxy<'a>> {
    Proxy::new(
        connection,
        destination,
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
    let identity = settings
        .get("connection")
        .and_then(|section| setting::<&str>(section, "uuid"))
        .filter(|uuid| !uuid.is_empty())
        .map(|uuid| ("uuid", uuid))
        .unwrap_or(("connection_path", connection_path));
    let mut attrs = base_secret_attributes(setting_name, key);
    attrs.insert(identity.0.to_string(), identity.1.to_string());
    attrs
}

fn secret_attribute_sets(
    connection_path: &str,
    settings: &ConnectionSettings,
    setting_name: &str,
    key: &str,
) -> Vec<HashMap<String, String>> {
    // NM settings paths are reused after restart. A UUID identifies the profile
    // exclusively; never read or delete a different profile's legacy path entry.
    vec![primary_secret_attributes(
        connection_path,
        settings,
        setting_name,
        key,
    )]
}

fn base_secret_attributes(setting_name: &str, key: &str) -> HashMap<String, String> {
    HashMap::from([
        ("application".to_string(), "nm-daemon".to_string()),
        ("setting".to_string(), setting_name.to_string()),
        ("key".to_string(), key.to_string()),
    ])
}

fn secret_label(settings: &ConnectionSettings, setting_name: &str, key: &str) -> String {
    let connection_id = settings
        .get("connection")
        .and_then(|section| setting::<&str>(section, "id"))
        .unwrap_or("Wi-Fi network");
    format!("nm-daemon {connection_id} {setting_name}.{key}")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use zvariant::{OwnedObjectPath, OwnedValue};

    use super::{
        KeyringOutcome, KeyringPromptOperation, NULL_PROMPT, SECRET_SERVICE_PATH, Secret,
        SecretServiceClient,
    };
    use crate::test_support::TestPeer;

    const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/test";
    const PROMPT_PATH: &str = "/org/freedesktop/secrets/prompt/test";
    const ITEM_ONE_PATH: &str = "/org/freedesktop/secrets/collection/test/1";
    const ITEM_TWO_PATH: &str = "/org/freedesktop/secrets/collection/test/2";

    struct FakeSecretService;

    #[zbus::interface(name = "org.freedesktop.Secret.Service")]
    impl FakeSecretService {
        fn search_items(
            &self,
            _attributes: HashMap<String, String>,
        ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
            (
                vec![object_path(ITEM_ONE_PATH), object_path(ITEM_TWO_PATH)],
                Vec::new(),
            )
        }

        fn get_secrets(
            &self,
            _items: Vec<OwnedObjectPath>,
            session: OwnedObjectPath,
        ) -> HashMap<OwnedObjectPath, Secret> {
            HashMap::from([(
                object_path(ITEM_ONE_PATH),
                (session, Vec::new(), b"secret".to_vec(), "text/plain".into()),
            )])
        }

        fn unlock(
            &self,
            _objects: Vec<OwnedObjectPath>,
        ) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
            (Vec::new(), object_path(PROMPT_PATH))
        }

        fn read_alias(&self, _name: &str) -> OwnedObjectPath {
            object_path(COLLECTION_PATH)
        }
    }

    struct LookupService {
        searches: Arc<std::sync::Mutex<Vec<HashMap<String, String>>>>,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Service")]
    impl LookupService {
        fn search_items(
            &self,
            attributes: HashMap<String, String>,
        ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
            self.searches.lock().unwrap().push(attributes.clone());
            // A legacy path item belongs to another profile after NM restarts.
            let matches = attributes
                .get("uuid")
                .is_some_and(|uuid| uuid == "profile-uuid")
                || attributes.contains_key("connection_path");
            let item = match attributes.get("key").map(String::as_str) {
                Some("password") => ITEM_ONE_PATH,
                Some("pin") => ITEM_TWO_PATH,
                _ => return (Vec::new(), Vec::new()),
            };
            (
                if matches {
                    vec![object_path(item)]
                } else {
                    Vec::new()
                },
                Vec::new(),
            )
        }

        fn get_secrets(
            &self,
            items: Vec<OwnedObjectPath>,
            session: OwnedObjectPath,
        ) -> HashMap<OwnedObjectPath, Secret> {
            items
                .into_iter()
                .map(|item| {
                    let value = if item.as_str() == ITEM_ONE_PATH {
                        "password-value"
                    } else {
                        "1234"
                    };
                    (
                        item,
                        (
                            session.clone(),
                            Vec::new(),
                            value.as_bytes().to_vec(),
                            "text/plain".into(),
                        ),
                    )
                })
                .collect()
        }
    }

    #[test]
    fn lookups_collect_every_key_and_never_fall_back_from_uuid_to_reused_path() -> anyhow::Result<()>
    {
        let peer = TestPeer::new(":1.0", ":1.1");
        let searches = Arc::new(std::sync::Mutex::new(Vec::new()));
        peer.server.object_server().at(
            SECRET_SERVICE_PATH,
            LookupService {
                searches: searches.clone(),
            },
        )?;
        peer.server
            .object_server()
            .at(ITEM_ONE_PATH, FakeItem { prompt: false })?;
        let keyring = super::Keyring {
            client: SecretServiceClient {
                interactive: false,
                connection: peer.client.clone(),
                destination: ":1.0".into(),
                session: object_path("/session/test"),
            },
        };
        let mut settings = crate::nm::ConnectionSettings::from([(
            "connection".into(),
            crate::variant::value_map([("uuid", "profile-uuid".into())])?,
        )]);
        let keys = vec!["password".into(), "pin".into(), "missing".into()];
        let KeyringOutcome::Completed(secrets) =
            keyring.lookup_secrets("/reused", &settings, "802-1x", &keys)?
        else {
            panic!("unexpected prompt")
        };
        assert_eq!(
            secrets
                .iter()
                .map(|secret| (secret.key.as_str(), secret.password.as_str()))
                .collect::<Vec<_>>(),
            [("password", "password-value"), ("pin", "1234")]
        );
        assert!(matches!(
            keyring.delete_secret("/reused", &settings, "802-1x", "password")?,
            KeyringOutcome::Completed(1)
        ));

        settings
            .get_mut("connection")
            .unwrap()
            .insert("uuid".into(), crate::variant::owned_value("new-profile")?);
        assert!(
            matches!(keyring.lookup_secrets("/reused", &settings, "802-1x", &keys)?, KeyringOutcome::Completed(secrets) if secrets.is_empty())
        );
        assert!(matches!(
            keyring.delete_secret("/reused", &settings, "802-1x", "password")?,
            KeyringOutcome::Completed(0)
        ));
        assert!(
            searches
                .lock()
                .unwrap()
                .iter()
                .all(|attrs| attrs.contains_key("uuid") && !attrs.contains_key("connection_path"))
        );

        searches.lock().unwrap().clear();
        settings.clear();
        assert!(
            matches!(keyring.lookup_secrets("/reused", &settings, "802-1x", &["password".into()])?, KeyringOutcome::Completed(secrets) if secrets.len() == 1)
        );
        assert!(matches!(
            keyring.delete_secret("/reused", &settings, "802-1x", "password")?,
            KeyringOutcome::Completed(1)
        ));
        let searches = searches.lock().unwrap();
        assert_eq!(
            searches.len(),
            2,
            "UUID-less lookups/deletes must not repeat the same path query"
        );
        assert!(
            searches
                .iter()
                .all(|attrs| !attrs.contains_key("uuid") && attrs["connection_path"] == "/reused")
        );
        Ok(())
    }

    struct FakeCollection;

    #[zbus::interface(name = "org.freedesktop.Secret.Collection")]
    impl FakeCollection {
        #[zbus(property)]
        fn locked(&self) -> bool {
            false
        }

        fn create_item(
            &self,
            _properties: HashMap<String, OwnedValue>,
            _secret: Secret,
            _replace: bool,
        ) -> (OwnedObjectPath, OwnedObjectPath) {
            (object_path(NULL_PROMPT), object_path(PROMPT_PATH))
        }
    }

    struct FakeItem {
        prompt: bool,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Item")]
    impl FakeItem {
        fn delete(&self) -> OwnedObjectPath {
            object_path(if self.prompt {
                PROMPT_PATH
            } else {
                NULL_PROMPT
            })
        }
    }

    struct FakePrompt {
        dismissals: Arc<AtomicUsize>,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
    impl FakePrompt {
        fn dismiss(&self) {
            self.dismissals.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn fake_secret_service_prompts_are_dismissed_and_never_counted_as_success() -> anyhow::Result<()>
    {
        crate::test_support::workflows::isolated(
            concat!(
                module_path!(),
                "::fake_secret_service_prompts_are_dismissed_and_never_counted_as_success"
            ),
            || {
                run_prompt_test();
                Ok(())
            },
        )
    }

    fn run_prompt_test() {
        let peer = TestPeer::new(":1.0", ":1.1");
        let dismissals = Arc::new(AtomicUsize::new(0));
        peer.server
            .object_server()
            .at(SECRET_SERVICE_PATH, FakeSecretService)
            .unwrap();
        peer.server
            .object_server()
            .at(COLLECTION_PATH, FakeCollection)
            .unwrap();
        peer.server
            .object_server()
            .at(ITEM_ONE_PATH, FakeItem { prompt: false })
            .unwrap();
        peer.server
            .object_server()
            .at(ITEM_TWO_PATH, FakeItem { prompt: true })
            .unwrap();
        peer.server
            .object_server()
            .at(
                PROMPT_PATH,
                FakePrompt {
                    dismissals: Arc::clone(&dismissals),
                },
            )
            .unwrap();
        let client = SecretServiceClient {
            interactive: false,
            connection: peer.client,
            destination: ":1.0".to_string(),
            session: object_path("/org/freedesktop/secrets/session/test"),
        };

        let service = client.service_proxy().unwrap();
        for (items, expected) in [
            (vec![object_path(ITEM_ONE_PATH)], Some("secret")),
            (
                vec![object_path(ITEM_TWO_PATH), object_path(ITEM_ONE_PATH)],
                None,
            ),
            (Vec::new(), None),
        ] {
            assert!(matches!(
                client.read_first_secret(&service, items).unwrap(),
                KeyringOutcome::Completed(secret) if secret.as_deref() == expected
            ));
        }
        assert!(matches!(
            client.store(&HashMap::new(), "test", "secret").unwrap(),
            KeyringOutcome::PromptUnsupported {
                operation: KeyringPromptOperation::Create,
                completed: (),
                ..
            }
        ));
        assert!(matches!(
            client.delete(&HashMap::new()).unwrap(),
            KeyringOutcome::PromptUnsupported {
                operation: KeyringPromptOperation::Delete,
                completed: 1,
                ..
            }
        ));
        assert!(matches!(
            client.unlock(vec![object_path(ITEM_ONE_PATH)]).unwrap(),
            KeyringOutcome::PromptUnsupported {
                operation: KeyringPromptOperation::Unlock,
                ..
            }
        ));
        assert_eq!(dismissals.load(Ordering::Relaxed), 3);
    }

    struct UnlockPrompt {
        dismissed: bool,
        complete: bool,
        dismissals: Arc<AtomicUsize>,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
    impl UnlockPrompt {
        async fn prompt(
            &self,
            _window: &str,
            #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
        ) -> zbus::fdo::Result<()> {
            if self.complete {
                let value = zvariant::Value::new(vec![object_path(COLLECTION_PATH)]);
                Self::completed(&emitter, self.dismissed, value).await?;
            }
            Ok(())
        }
        fn dismiss(&self) {
            self.dismissals.fetch_add(1, Ordering::Relaxed);
        }
        #[zbus(signal)]
        async fn completed(
            emitter: &zbus::object_server::SignalEmitter<'_>,
            dismissed: bool,
            result: zvariant::Value<'_>,
        ) -> zbus::Result<()>;
    }

    #[test]
    fn interactive_unlock_handles_immediate_completion_cancel_and_timeout() -> anyhow::Result<()> {
        for (dismissed, complete) in [(false, true), (true, true), (false, false)] {
            let peer = TestPeer::new(":1.0", ":1.1");
            let dismissals = Arc::new(AtomicUsize::new(0));
            peer.server.object_server().at(
                PROMPT_PATH,
                UnlockPrompt {
                    dismissed,
                    complete,
                    dismissals: dismissals.clone(),
                },
            )?;
            let client = SecretServiceClient {
                interactive: true,
                connection: peer.client.clone(),
                destination: ":1.0".into(),
                session: object_path("/session/test"),
            };
            let result = client.complete_prompt(
                &object_path(PROMPT_PATH),
                std::time::Duration::from_millis(100),
            );
            if complete && !dismissed {
                assert_eq!(
                    Vec::<OwnedObjectPath>::try_from(result?)?,
                    vec![object_path(COLLECTION_PATH)]
                );
            } else {
                assert!(result.is_err());
            }
            assert_eq!(dismissals.load(Ordering::Relaxed), usize::from(!complete));
        }
        Ok(())
    }

    fn object_path(path: &str) -> OwnedObjectPath {
        OwnedObjectPath::try_from(path).expect("valid fake Secret Service object path")
    }
}
