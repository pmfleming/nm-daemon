use super::{
    ALLOW_INTERACTION, ConnectionSettings, PendingSecretRequest, REQUEST_NEW,
    SecretPersistenceOutcome, apply_password, apply_stored_values, persistence,
    resolve_secret_request, session,
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
            let mut temporary = settings("handoff", true);
            temporary
                .get_mut("802-11-wireless-security")
                .unwrap()
                .insert("psk-flags".into(), crate::variant::owned_value(2_u32)?);
            session::stage("", &request.connection_path, &temporary);
            assert!(
                session::take(&request, &temporary).is_empty(),
                "NOT_SAVED must not stage credentials"
            );
            Ok(())
        },
    )
}
