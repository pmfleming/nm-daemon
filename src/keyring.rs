use std::collections::HashMap;

mod prompts;
#[cfg(test)]
mod real_provider;

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

    /// Explicit saves may open the desktop's unlock dialog. Credential delivery
    /// and background reads remain noninteractive.
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
        let attrs = primary_secret_attributes(connection_path, settings, setting_name, key);
        self.client.lookup(&attrs)
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
        let attrs = primary_secret_attributes(connection_path, settings, setting_name, key);
        self.client.delete(&attrs)
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
        // Activate through OpenSession, then pin calls to this provider.
        let service = service_proxy(&connection, SECRET_DEST)?;
        let reply = service
            .call_method("OpenSession", &("plain", Value::new("")))
            .context("open Secret Service session")?;
        let (_output, session): (OwnedValue, OwnedObjectPath) = reply.body().deserialize()?;
        let destination = reply
            .header()
            .sender()
            .context("Secret Service reply has no owner")?
            .to_string();
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
        // Re-read Locked after the unlock reply; a cached property can still
        // contain the pre-prompt value until PropertiesChanged is dispatched.
        let collection_proxy: Proxy<'_> = zbus::blocking::proxy::Builder::new(&self.connection)
            .destination(self.destination.as_str())?
            .path(collection.as_str())?
            .interface(SECRET_COLLECTION_IFACE)?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
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
            self.unsupported_prompt(prompt, KeyringPromptOperation::Create, ())
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
                return self.unsupported_prompt(prompt, KeyringPromptOperation::Delete, deleted);
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
        if !self.interactive {
            // Do not even allocate a provider prompt on the delivery path.
            return Ok(KeyringOutcome::PromptUnsupported {
                operation: KeyringPromptOperation::Unlock,
                prompt: OwnedObjectPath::try_from(NULL_PROMPT)?,
                completed: Vec::new(),
            });
        }
        prompts::unlock(
            &self.connection,
            &self.destination,
            locked,
            std::time::Duration::from_secs(45),
        )
        .map(KeyringOutcome::Completed)
    }

    fn unsupported_prompt<T>(
        &self,
        prompt: OwnedObjectPath,
        operation: KeyringPromptOperation,
        completed: T,
    ) -> Result<KeyringOutcome<T>> {
        // Never presented: let the provider release these with the connection.
        // Do not Dismiss while another unlock may be active in the provider.
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
    // NM reuses settings paths after restart. A UUID is authoritative: do not
    // search a legacy path entry when this profile's UUID has no stored secret.
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

        assert_eq!(
            searches.lock().unwrap().len(),
            8,
            "one search per key or delete"
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
    fn fake_secret_service_prompts_are_never_counted_as_success() -> anyhow::Result<()> {
        crate::test_support::workflows::isolated(
            concat!(
                module_path!(),
                "::fake_secret_service_prompts_are_never_counted_as_success"
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
        assert_eq!(dismissals.load(Ordering::Relaxed), 0);
    }

    struct UnlockPrompt {
        lock: Option<Arc<AtomicBool>>,
        targets: Option<Arc<std::sync::Mutex<Vec<OwnedObjectPath>>>>,
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
                if !self.dismissed
                    && let Some(lock) = &self.lock
                {
                    lock.store(false, Ordering::Relaxed);
                }
                let unlocked = self
                    .targets
                    .as_ref()
                    .map(|targets| targets.lock().unwrap().clone())
                    .unwrap_or_else(|| vec![object_path(COLLECTION_PATH)]);
                let value = zvariant::Value::new(unlocked);
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
                    lock: None,
                    targets: None,
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
            peer.server
                .object_server()
                .at(SECRET_SERVICE_PATH, FakeSecretService)?;
            let result = super::prompts::unlock(
                &client.connection,
                &client.destination,
                vec![object_path(COLLECTION_PATH)],
                std::time::Duration::from_millis(100),
            );
            if complete && !dismissed {
                assert_eq!(result?, vec![object_path(COLLECTION_PATH)]);
            } else {
                assert!(result.is_err());
            }
            assert_eq!(dismissals.load(Ordering::Relaxed), 0);
            if !complete {
                let retry = std::time::Instant::now();
                assert!(
                    super::prompts::unlock(
                        &client.connection,
                        &client.destination,
                        vec![object_path(COLLECTION_PATH)],
                        std::time::Duration::from_secs(1)
                    )
                    .is_err()
                );
                assert!(retry.elapsed() < std::time::Duration::from_millis(100));
            }
        }
        Ok(())
    }

    type StoredItem = (HashMap<String, String>, Vec<u8>);

    #[derive(Default)]
    struct StoredCollection {
        locked: Arc<AtomicBool>,
        unlock_targets: Arc<std::sync::Mutex<Vec<OwnedObjectPath>>>,
        item: std::sync::Mutex<Option<StoredItem>>,
    }
    struct PersistenceService(Arc<StoredCollection>);
    #[zbus::interface(name = "org.freedesktop.Secret.Service")]
    impl PersistenceService {
        fn read_alias(&self, _alias: &str) -> OwnedObjectPath {
            object_path(COLLECTION_PATH)
        }
        fn search_items(
            &self,
            attrs: HashMap<String, String>,
        ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
            let found = self
                .0
                .item
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|(stored, _)| {
                    attrs
                        .iter()
                        .all(|(key, value)| stored.get(key) == Some(value))
                });
            let items = if found {
                vec![object_path(ITEM_ONE_PATH)]
            } else {
                vec![]
            };
            if self.0.locked.load(Ordering::Relaxed) {
                (vec![], items)
            } else {
                (items, vec![])
            }
        }
        fn unlock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
            *self.0.unlock_targets.lock().unwrap() = objects.clone();
            if self.0.locked.load(Ordering::Relaxed) {
                (vec![], object_path(PROMPT_PATH))
            } else {
                (objects, object_path("/"))
            }
        }
        fn get_secrets(
            &self,
            items: Vec<OwnedObjectPath>,
            session: OwnedObjectPath,
        ) -> HashMap<OwnedObjectPath, Secret> {
            assert!(!self.0.locked.load(Ordering::Relaxed));
            assert!(items.iter().all(|item| item.as_str() == ITEM_ONE_PATH));
            let item = self.0.item.lock().unwrap();
            items
                .into_iter()
                .map(|path| {
                    (
                        path,
                        (
                            session.clone(),
                            vec![],
                            item.as_ref().unwrap().1.clone(),
                            "text/plain".into(),
                        ),
                    )
                })
                .collect()
        }
    }
    struct PersistenceCollection(Arc<StoredCollection>);
    #[zbus::interface(name = "org.freedesktop.Secret.Collection")]
    impl PersistenceCollection {
        #[zbus(property)]
        fn locked(&self) -> bool {
            self.0.locked.load(Ordering::Relaxed)
        }
        fn create_item(
            &self,
            mut props: HashMap<String, OwnedValue>,
            secret: Secret,
            _replace: bool,
        ) -> (OwnedObjectPath, OwnedObjectPath) {
            assert!(!self.locked(), "must unlock before CreateItem");
            let attrs = HashMap::<String, String>::try_from(
                props.remove(super::ITEM_ATTRIBUTES_KEY).unwrap(),
            )
            .unwrap();
            *self.0.item.lock().unwrap() = Some((attrs, secret.2));
            (object_path(ITEM_ONE_PATH), object_path("/"))
        }
    }
    #[test]
    fn locked_save_survives_new_agent_session_and_relocked_lookup() -> anyhow::Result<()> {
        let peer = TestPeer::new(":1.0", ":1.1");
        let state = Arc::new(StoredCollection::default());
        state.locked.store(true, Ordering::Relaxed);
        peer.server
            .object_server()
            .at(SECRET_SERVICE_PATH, PersistenceService(state.clone()))?;
        peer.server
            .object_server()
            .at(COLLECTION_PATH, PersistenceCollection(state.clone()))?;
        peer.server.object_server().at(
            PROMPT_PATH,
            UnlockPrompt {
                lock: Some(state.locked.clone()),
                targets: Some(state.unlock_targets.clone()),
                dismissed: false,
                complete: true,
                dismissals: Arc::new(AtomicUsize::new(0)),
            },
        )?;
        let settings = crate::nm::ConnectionSettings::from([(
            "connection".into(),
            crate::variant::value_map([("uuid", "stable-profile".into())])?,
        )]);
        let make_client = |interactive, session| super::Keyring {
            client: SecretServiceClient {
                interactive,
                connection: peer.client.clone(),
                destination: ":1.0".into(),
                session: object_path(session),
            },
        };
        let first = make_client(true, "/session/one");
        assert!(matches!(
            first.store_secret(
                "/old/path",
                &settings,
                "802-11-wireless-security",
                "psk",
                "synthetic-secret"
            )?,
            KeyringOutcome::Completed(())
        ));
        drop(first);
        let second = make_client(false, "/session/two");
        let keys = vec!["psk".into()];
        let KeyringOutcome::Completed(secrets) =
            second.lookup_secrets("/new/path", &settings, "802-11-wireless-security", &keys)?
        else {
            panic!("saved UUID must survive a new agent session")
        };
        assert_eq!(secrets[0].password, "synthetic-secret");
        state.locked.store(true, Ordering::Relaxed);
        assert!(matches!(
            second.lookup_secrets("/new/path", &settings, "802-11-wireless-security", &keys)?,
            KeyringOutcome::PromptUnsupported { .. }
        ));
        assert!(
            state.locked.load(Ordering::Relaxed),
            "background lookup cannot unlock"
        );
        let third = make_client(true, "/session/three");
        let KeyringOutcome::Completed(secrets) =
            third.lookup_secrets("/new/path", &settings, "802-11-wireless-security", &keys)?
        else {
            panic!("interactive unlock must recover the saved password")
        };
        assert_eq!(secrets[0].password, "synthetic-secret");
        Ok(())
    }

    fn object_path(path: &str) -> OwnedObjectPath {
        OwnedObjectPath::try_from(path).expect("valid fake Secret Service object path")
    }
}
