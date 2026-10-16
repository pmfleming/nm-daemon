use super::*;
use crate::test_support::{bus::TestBus, workflows::isolated};
use crate::variant::value_map;
use std::sync::Mutex;

const PATH: &str = "/test/profile";
const ACTIVATION: &str = "/test/active";
struct State {
    public: ConnectionSettings,
    version: u64,
    active: u32,
    dirty: bool,
    permission: bool,
    mode: &'static str,
    reads: usize,
    writes: usize,
    cancelled: Arc<AtomicBool>,
}
struct Manager(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Manager {
    #[zbus(property)]
    fn version(&self) -> &str {
        "1.56.0"
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn active_connections(&self) -> Vec<OwnedObjectPath> {
        vec![ACTIVATION.try_into().unwrap()]
    }
    fn get_permissions(&self) -> HashMap<String, String> {
        HashMap::from([(
            "org.freedesktop.NetworkManager.settings.modify.system".into(),
            if self.0.lock().unwrap().permission {
                "yes"
            } else {
                "auth"
            }
            .into(),
        )])
    }
}
struct Active(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Connection.Active")]
impl Active {
    #[zbus(property(emits_changed_signal = "false"))]
    fn connection(&self) -> OwnedObjectPath {
        PATH.try_into().unwrap()
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn state(&self) -> u32 {
        self.0.lock().unwrap().active
    }
}
struct Profile(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl Profile {
    #[zbus(property(emits_changed_signal = "false"))]
    fn version_id(&self) -> u64 {
        self.0.lock().unwrap().version
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn unsaved(&self) -> bool {
        self.0.lock().unwrap().dirty
    }
    #[zbus(property)]
    fn filename(&self) -> &str {
        "/etc/NetworkManager/system-connections/fixture"
    }
    fn get_settings(&self) -> ConnectionSettings {
        self.0.lock().unwrap().public.clone()
    }
    fn get_secrets(&self, section: &str) -> zbus::fdo::Result<ConnectionSettings> {
        let mut state = self.0.lock().unwrap();
        assert_eq!(
            state.active, 2,
            "GetSecrets before terminal activation is forbidden"
        );
        assert_eq!(section, "802-1x");
        state.reads += 1;
        if state.mode == "read-error" {
            return Err(zbus::fdo::Error::AccessDenied(
                "do-not-log-synthetic-secret".into(),
            ));
        }
        state.version += if state.mode == "concurrent-read" {
            2
        } else {
            1
        };
        if state.mode == "cancel-read" {
            state.cancelled.store(true, Ordering::Release);
        }
        let password = if state.mode == "different-password" {
            "different"
        } else {
            "synthetic-password"
        };
        Ok(ConnectionSettings::from([(
            "802-1x".into(),
            value_map([
                ("password", password.into()),
                ("pin", "synthetic-otp".into()),
                ("private-key-password", "unrelated-password".into()),
            ])
            .unwrap(),
        )]))
    }
    fn update2(
        &self,
        settings: ConnectionSettings,
        flags: u32,
        args: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<HashMap<String, OwnedValue>> {
        let mut state = self.0.lock().unwrap();
        assert_eq!(state.active, 2);
        assert!(
            settings.is_empty(),
            "never overlay credentials or an old profile snapshot"
        );
        assert_eq!(flags, 1);
        assert_eq!(u64::try_from(&args["version-id"]).unwrap(), state.version);
        state.writes += 1;
        if state.mode == "write-error" {
            return Err(zbus::fdo::Error::AccessDenied(
                "do-not-log-synthetic-secret".into(),
            ));
        }
        state.version += if state.mode == "concurrent-after-write" {
            2
        } else {
            1
        };
        Ok(HashMap::new())
    }
}

#[test]
fn confirmation_fences_lifecycle_permissions_concurrency_and_multisecret_policy() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::confirmation_fences_lifecycle_permissions_concurrency_and_multisecret_policy"
        ),
        || {
            for mode in [
                "success",
                "cancelled",
                "owner-replaced",
                "deleted",
                "dirty",
                "permission",
                "policy",
                "ended",
                "read-error",
                "concurrent-read",
                "cancel-read",
                "different-password",
                "write-error",
                "concurrent-after-write",
            ] {
                let bus = TestBus::new()?;
                let server = bus.connect()?;
                let client = bus.connect()?;
                let public = ConnectionSettings::from([
                    (
                        "connection".into(),
                        value_map([("uuid", "fixture-uuid".into())])?,
                    ),
                    (
                        "802-1x".into(),
                        value_map([("password-flags", 0u32.into()), ("pin-flags", 2u32.into())])?,
                    ),
                ]);
                let cancelled = Arc::new(AtomicBool::new(false));
                let state = Arc::new(Mutex::new(State {
                    public: public.clone(),
                    version: 7,
                    active: 1,
                    dirty: false,
                    permission: true,
                    mode,
                    reads: 0,
                    writes: 0,
                    cancelled: cancelled.clone(),
                }));
                server.object_server().at(ROOT, Manager(state.clone()))?;
                server.object_server().at(PATH, Profile(state.clone()))?;
                server
                    .object_server()
                    .at(ACTIVATION, Active(state.clone()))?;
                server.request_name(NM)?;
                let owner = server.unique_name().unwrap().to_string();
                crate::daemon_secret::with_pending_registry(|registry| {
                    registry.nm_owner = Some(owner.clone())
                });
                let mut request = PendingSecretRequest::new(
                    PATH.try_into()?,
                    "802-1x",
                    vec!["password".into(), "pin".into()],
                    1,
                );
                request.nm_owner = Some(owner);
                request.nm_connection = Some(client);
                request.cancelled = cancelled;
                request.policy = Policy::from_request(&public, "802-1x", &request.secret_keys)?;
                let request = Arc::new(request);
                let executor = tokio::runtime::Runtime::new()?;
                let state_for_worker = state.clone();
                let server_for_worker = server.clone();
                let replacement = bus.connect()?;
                let outcome = executor.block_on(tokio::task::spawn_blocking(
                    move || -> Result<SecretPersistenceOutcome> {
                        let save = prepare(
                            &request,
                            &public,
                            HashMap::from([
                                ("password".into(), "synthetic-password".into()),
                                ("pin".into(), "synthetic-otp".into()),
                            ]),
                        );
                        {
                            let mut state = state_for_worker.lock().unwrap();
                            assert_eq!(
                                state.reads, 0,
                                "pre-dispatch capture is public metadata only"
                            );
                            state.active = if mode == "ended" { 4 } else { 2 };
                            state.dirty = mode == "dirty";
                            state.permission = mode != "permission";
                            if mode == "cancelled" {
                                state.cancelled.store(true, Ordering::Release);
                            }
                            if mode == "policy" {
                                state
                                    .public
                                    .get_mut("802-1x")
                                    .unwrap()
                                    .insert("password-flags".into(), owned_value(2u32)?);
                            }
                        }
                        if mode == "owner-replaced" {
                            server_for_worker.release_name(NM)?;
                            replacement.request_name(NM)?;
                        }
                        if mode == "deleted" {
                            server_for_worker
                                .object_server()
                                .remove::<Profile, _>(PATH)?;
                        }
                        Ok(save(&AtomicBool::new(false)))
                    },
                ))??;
                match outcome {
                    SecretPersistenceOutcome::Stored => assert_eq!(mode, "success"),
                    SecretPersistenceOutcome::Failed(message) => {
                        assert_ne!(mode, "success", "{message}");
                        assert!(!message.contains("do-not-log-synthetic-secret"));
                    }
                }
                assert_eq!(
                    state.lock().unwrap().writes,
                    usize::from(matches!(
                        mode,
                        "success" | "write-error" | "concurrent-after-write"
                    )),
                    "{mode}"
                );
            }
            Ok(())
        },
    )
}
