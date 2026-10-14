//! Actual ActivateConnection -> exported SecretAgent callbacks on a private bus.
//! Synthetic credentials only; the workflow runner disables the desktop keyring.
use super::*;
use crate::activation::{AUTHENTICATION_RESERVE, Guard};
use crate::application::{Application, ConnectOutcome};
use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
use crate::test_support::bus::TestBus;
use crate::test_support::workflows::{ACTIVE, FakeNm, Outcome, PROFILE, isolated};
use zbus::blocking::Proxy;

const SECURITY: &str = "802-11-wireless-security";

fn settings() -> Result<ConnectionSettings> {
    use crate::variant::value_map;
    Ok(ConnectionSettings::from([
        (
            "connection".into(),
            value_map([
                ("id", "Example".into()),
                ("uuid", "activation-test".into()),
                ("type", "802-11-wireless".into()),
            ])?,
        ),
        (
            "802-11-wireless".into(),
            value_map([
                ("ssid", b"Example".to_vec().into()),
                ("mode", "infrastructure".into()),
            ])?,
        ),
        (
            SECURITY.into(),
            value_map([("key-mgmt", "wpa-psk".into()), ("psk-flags", 1u32.into())])?,
        ),
    ]))
}

struct Harness {
    fake: FakeNm,
    runtime: Arc<DaemonRuntime>,
    executor: tokio::runtime::Runtime,
    _bus: TestBus,
}
impl Harness {
    fn new(subscribe: bool) -> Result<Self> {
        let bus = TestBus::new()?;
        let fake = FakeNm::on_bus(&bus, [Outcome::AwaitingSecrets])?;
        fake.state.lock().unwrap().settings = settings()?;
        let executor = tokio::runtime::Runtime::new()?;
        let nm = crate::nm::Nm::with_connection_runner_destination_and_telemetry(
            fake.peer.client.clone(),
            crate::command::default_runner(),
            NM_DEST,
            Arc::new(crate::nl80211::UnavailableWirelessTelemetry),
        )?;
        let runtime = DaemonRuntime::start(nm, executor.handle().clone())?;
        export_secret_agent(&fake.peer.client, &runtime)?;
        change_network_manager_owner(
            &runtime,
            Some(fake.peer.server.unique_name().unwrap().to_string()),
        );
        if subscribe {
            runtime.subscribe(
                "frontend".into(),
                Some(fake.peer.client.unique_name().unwrap().to_string()),
                vec![Stream::WifiSecret],
                zbus::object_server::SignalEmitter::new(fake.peer.client.inner(), "/test")?
                    .into_owned(),
            )?;
        }
        Ok(Self {
            fake,
            runtime,
            executor,
            _bus: bus,
        })
    }
    fn agent(&self) -> Result<Proxy<'_>> {
        Ok(Proxy::new(
            &self.fake.peer.server,
            self.fake.peer.client.unique_name().unwrap().as_str(),
            SECRET_AGENT_OBJECT_PATH,
            "org.freedesktop.NetworkManager.SecretAgent",
        )?)
    }
    fn native_handoff(&self) -> Result<()> {
        let mut native = settings()?;
        native
            .get_mut(SECURITY)
            .unwrap()
            .insert("psk".into(), crate::variant::owned_value("synthetic-old")?);
        self.agent()?.call::<_, _, ()>(
            "SaveSecrets",
            &(native, OwnedObjectPath::try_from(PROFILE)?),
        )?;
        Ok(())
    }
    fn callback(
        &self,
        flags: u32,
        reject: bool,
        other_agent: bool,
    ) -> Result<mpsc::Receiver<zbus::Result<ConnectionSettings>>> {
        let caller = self.fake.peer.server.clone();
        let agent = self.fake.peer.client.unique_name().unwrap().to_string();
        let state = Arc::clone(&self.fake.state);
        let nm = self.fake.nm.scoped()?;
        let (sender, receiver) = mpsc::channel();
        self.fake.state.lock().unwrap().on_activate = Some(Arc::new(move |settings| {
            let result = get(&caller, &agent, settings, flags);
            state.lock().unwrap().current = Some(if (result.is_ok() || other_agent) && !reject {
                Outcome::Connected
            } else {
                Outcome::NoSecrets
            });
            nm.wake_waiters();
            sender.send(result).unwrap();
        }));
        Ok(receiver)
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.fake.state.lock().unwrap().on_activate = None;
        self.executor.block_on(self.runtime.shutdown());
    }
}
fn get(
    caller: &zbus::blocking::Connection,
    agent: &str,
    settings: ConnectionSettings,
    flags: u32,
) -> zbus::Result<ConnectionSettings> {
    Proxy::new(
        caller,
        agent,
        SECRET_AGENT_OBJECT_PATH,
        "org.freedesktop.NetworkManager.SecretAgent",
    )?
    .call(
        "GetSecrets",
        &(
            settings,
            OwnedObjectPath::try_from(PROFILE).unwrap(),
            SECURITY,
            Vec::<String>::new(),
            flags,
        ),
    )
}
fn pending() -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(id) = with_pending_registry(|registry| registry.requests.keys().next().cloned())
        {
            return id;
        }
        assert!(
            Instant::now() < deadline,
            "expected a live credential request"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn submit(owner: &str, id: &str, cancel: bool) -> Result<Value> {
    provide(
        Some(owner),
        SecretProvideParams {
            request_id: id.into(),
            save: false,
            password: None,
            values: HashMap::from([("psk".into(), "synthetic-fresh".into())]),
            cancel,
        },
    )
}

#[test]
fn manual_saved_activation_uses_real_agent_callbacks_without_speculative_forms_or_retries()
-> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::manual_saved_activation_uses_real_agent_callbacks_without_speculative_forms_or_retries"
        ),
        || {
            for case in [
                "available",
                "provided",
                "cancelled",
                "no-frontend",
                "other-agent",
                "rejected",
            ] {
                let harness = Harness::new(!matches!(case, "no-frontend" | "other-agent"))?;
                if matches!(case, "available" | "rejected") {
                    harness.native_handoff()?;
                }
                // REQUEST_NEW must bypass the available native credential on rejection.
                let returned = harness.callback(
                    if case == "rejected" { 3 } else { 1 },
                    case == "rejected",
                    case == "other-agent",
                )?;
                let frontend = harness.fake.peer.client.unique_name().unwrap().to_string();
                let reply = matches!(case, "provided" | "cancelled" | "rejected").then(|| {
                    std::thread::spawn(move || {
                        let id = pending();
                        assert_eq!(
                            submit(":9.999", &id, false).unwrap()["data"]["result"]["accepted"],
                            false
                        );
                        assert_eq!(
                            submit(&frontend, &id, case == "cancelled").unwrap()["data"]["result"]
                                ["accepted"],
                            true
                        );
                    })
                });
                let app = Application::new(&harness.fake.nm);
                let entries = harness
                    .fake
                    .nm
                    .network_entries_for_access_points(harness.fake.nm.list_all_access_points()?)?;
                let request = app.connect_request_for_key(&entries[0].key, None, None, None)?;
                let result = app.connect(&request, None, |_| Ok(()))?;
                let secrets = returned.recv_timeout(Duration::from_secs(5))?;
                match case {
                    "available" | "provided" => {
                        assert!(matches!(result, ConnectOutcome::Succeeded(_)), "{case}");
                        let secrets = secrets?;
                        assert_eq!(
                            crate::variant::setting::<&str>(&secrets[SECURITY], "psk"),
                            Some(if case == "available" {
                                "synthetic-old"
                            } else {
                                "synthetic-fresh"
                            })
                        );
                    }
                    "other-agent" => {
                        assert!(
                            matches!(result, ConnectOutcome::Succeeded(_)),
                            "our agent declining must not preempt another agent"
                        );
                        assert!(secrets.is_err());
                        assert!(harness.fake.state.lock().unwrap().deactivated.is_empty());
                    }
                    "cancelled" => {
                        assert!(matches!(result, ConnectOutcome::Cancelled { .. }));
                        assert!(secrets.is_err());
                    }
                    "no-frontend" => {
                        let ConnectOutcome::Failed { error, .. } = result else {
                            panic!("expected missing frontend failure")
                        };
                        assert_eq!(error.details["credential_outcome"], "agent-unavailable");
                        assert!(secrets.is_err());
                    }
                    "rejected" => {
                        assert!(matches!(result, ConnectOutcome::Failed { .. }));
                        assert_eq!(
                            crate::variant::setting::<&str>(&secrets?[SECURITY], "psk"),
                            Some("synthetic-fresh")
                        );
                    }
                    _ => unreachable!(),
                }
                if let Some(reply) = reply {
                    reply.join().unwrap();
                }
                let state = harness.fake.state.lock().unwrap();
                assert_eq!(
                    state.activations.len(),
                    1,
                    "{case}: no authentication retry on another AP"
                );
                assert_eq!(state.deleted, 0);
                assert_eq!(
                    crate::variant::setting::<&str>(&state.settings["connection"], "uuid"),
                    Some("activation-test")
                );
                assert!(
                    !state.settings[SECURITY].contains_key("psk"),
                    "manual Connect does not rewrite credentials"
                );
                if matches!(case, "cancelled" | "no-frontend") {
                    assert_eq!(state.deactivated, [ACTIVE]);
                }
                assert!(with_pending_registry(|registry| registry
                    .requests
                    .is_empty()));
            }
            Ok(())
        },
    )
}

#[test]
fn expired_or_finished_activation_retires_exported_request_and_rejects_late_submission()
-> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::expired_or_finished_activation_retires_exported_request_and_rejects_late_submission"
        ),
        || {
            for expire in [false, true] {
                let harness = Harness::new(true)?;
                let owner = harness.fake.peer.server.unique_name().unwrap().to_string();
                let guard = Guard::new(
                    owner,
                    crate::activation::identity(&settings()?, PROFILE),
                    Instant::now() + AUTHENTICATION_RESERVE + Duration::from_millis(800),
                    || {},
                );
                let state = Arc::clone(&guard.state);
                let caller = harness.fake.peer.server.clone();
                let agent = harness.fake.peer.client.unique_name().unwrap().to_string();
                let thread =
                    std::thread::spawn(move || get(&caller, &agent, settings().unwrap(), 3));
                let id = pending();
                if !expire {
                    drop(guard);
                }
                assert!(thread.join().unwrap().is_err());
                assert_eq!(
                    submit(
                        harness.fake.peer.client.unique_name().unwrap().as_str(),
                        &id,
                        false
                    )?["data"]["result"]["accepted"],
                    false
                );
                assert!(with_pending_registry(|registry| registry
                    .requests
                    .is_empty()));
                if expire {
                    let report =
                        ErrorReport::from_error(&state.error().unwrap(), ErrorOperation::Connect);
                    assert_eq!(report.code, ErrorCode::Timeout);
                    assert_eq!(report.details["credential_outcome"], "expired");
                    assert!(
                        Instant::now() < state.deadline,
                        "authentication reserve remains intact"
                    );
                }
            }
            Ok(())
        },
    )
}
