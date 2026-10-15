use super::{
    ALLOW_INTERACTION, ConnectionSettings, HashMap, PendingSecretRequest, REQUEST_NEW,
    SecretPersistenceOutcome, SecretResponse, apply_password, apply_secret_response,
    apply_stored_values, persistence, request_values_complete, resolve_secret_request, session,
    value_string,
};
use crate::test_support::{TestPeer, workflows::isolated};
use anyhow::Result;
use std::sync::{
    Arc, Mutex, Weak,
    mpsc::{self, Receiver, Sender},
};
use std::time::Duration;
use std::time::Instant;
use zvariant::OwnedObjectPath;

fn request() -> PendingSecretRequest {
    PendingSecretRequest::new(
        OwnedObjectPath::try_from("/test/profile").unwrap(),
        "802-11-wireless-security",
        vec!["psk".into()],
        ALLOW_INTERACTION,
    )
}
fn settings(uuid: &str, password: bool) -> ConnectionSettings {
    let mut settings = ConnectionSettings::from([(
        "connection".into(),
        crate::variant::value_map([("uuid", uuid.into())]).unwrap(),
    )]);
    if password {
        apply_password(
            &mut settings,
            "802-11-wireless-security",
            "psk",
            "synthetic-password".into(),
        )
        .unwrap();
    }
    settings
}

#[test]
fn credentials_are_prepared_without_attempting_keyring_io() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::credentials_are_prepared_without_attempting_keyring_io"
        ),
        || {
            for (save, supported) in [(true, true), (true, false), (false, true)] {
                let mut request = request();
                request.save_supported = supported;
                let request = Arc::new(request);
                let mut connection = settings("prepared", false);
                let started = Instant::now();
                let deferred = apply_secret_response(
                    &mut connection,
                    &request,
                    SecretResponse {
                        password: Some("synthetic-password".into()),
                        values: HashMap::new(),
                        save,
                        cancelled: false,
                    },
                )
                .map_err(|_| anyhow::anyhow!("response preparation failed"))?;
                assert!(started.elapsed() < Duration::from_millis(100));
                assert!(request_values_complete(&request, &connection));
                assert_eq!(deferred.is_some(), save);
                // Storage failures happen only when the separate save is actually run.
                if save && !supported {
                    assert!(matches!(
                        deferred.unwrap()(),
                        SecretPersistenceOutcome::Failed(_)
                    ));
                }
            }
            Ok(())
        },
    )
}

#[test]
fn partial_native_credentials_are_not_overwritten_by_old_stored_values() -> Result<()> {
    let mut request = request();
    request.setting_name = "802-1x".into();
    request.secret_keys = vec!["password".into(), "pin".into()];
    let mut connection = settings("partial", false);
    apply_password(
        &mut connection,
        "802-1x",
        "password",
        "fresh-synthetic-password".into(),
    )?;
    let stored = vec![
        crate::keyring::KeyringSecret {
            key: "password".into(),
            password: "old-synthetic-password".into(),
        },
        crate::keyring::KeyringSecret {
            key: "pin".into(),
            password: "1234".into(),
        },
    ];
    assert!(apply_stored_values(&request, &mut connection, stored)?);
    assert_eq!(
        value_string(&connection["802-1x"]["password"]).as_deref(),
        Some("fresh-synthetic-password")
    );
    Ok(())
}

struct DeferredReply {
    entered: Sender<()>,
    release: Arc<Mutex<Receiver<()>>>,
}
#[zbus::interface(name = "org.example.DeferredSecrets")]
impl DeferredReply {
    async fn get(&self) -> zbus::object_server::ResponseDispatchNotifier<String> {
        let entered = self.entered.clone();
        let release = self.release.clone();
        persistence::after_reply(
            "synthetic-password".into(),
            Weak::new(),
            "test-dispatch".into(),
            "/test/profile".into(),
            None,
            true,
            Some(Box::new(move || {
                entered.send(()).unwrap();
                release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
                SecretPersistenceOutcome::Failed("synthetic save failure".into())
            })),
        )
    }
}
#[test]
fn dbus_reply_arrives_while_persistence_is_still_blocked() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::dbus_reply_arrives_while_persistence_is_still_blocked"
        ),
        || {
            let peer = TestPeer::new(":1.0", ":1.1");
            let (entered, started) = mpsc::channel();
            let (release, wait) = mpsc::channel();
            peer.server.object_server().at(
                "/test",
                DeferredReply {
                    entered,
                    release: Arc::new(Mutex::new(wait)),
                },
            )?;
            let proxy = zbus::blocking::Proxy::new(
                &peer.client,
                ":1.0",
                "/test",
                "org.example.DeferredSecrets",
            )?;
            let begin = Instant::now();
            let reply: String = proxy.call("Get", &())?;
            assert_eq!(reply, "synthetic-password");
            assert!(begin.elapsed() < Duration::from_secs(1));
            started.recv_timeout(Duration::from_secs(1))?;
            release.send(())?;
            Ok(())
        },
    )
}

#[test]
fn native_password_handoff_is_one_shot_owner_uuid_scoped_and_never_reuses_rejected_values()
-> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::native_password_handoff_is_one_shot_owner_uuid_scoped_and_never_reuses_rejected_values"
        ),
        || {
            let mut request = request();
            let full = settings("handoff", true);
            session::stage("", &request.connection_path, &full);
            request.nm_owner = Some(":1.other".into());
            assert!(session::take(&request, &full).is_empty());
            request.nm_owner = None;
            assert!(session::take(&request, &settings("different", false)).is_empty());
            let mut reply = settings("handoff", false);
            let supplied = session::take(&request, &reply);
            assert!(apply_stored_values(&request, &mut reply, supplied)?);
            assert!(session::take(&request, &full).is_empty());
            session::stage("", &request.connection_path, &full);
            request.flags = REQUEST_NEW;
            let request = Arc::new(request);
            assert!(
                resolve_secret_request(
                    &request,
                    settings("handoff", false),
                    |_, _| panic!("rejected password was looked up"),
                    |_, _| panic!("noninteractive request prompted")
                )
                .is_err()
            );
            assert!(session::take(&request, &full).is_empty());
            session::stage("", &request.connection_path, &full);
            session::clear(Some(&request.connection_path));
            assert!(session::take(&request, &full).is_empty());
            Ok(())
        },
    )
}
