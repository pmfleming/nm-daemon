//! Scripted NetworkManager boundary: real D-Bus, no host networking or subprocesses.
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::Value;
use zbus::blocking::Proxy;
use zbus::object_server::SignalEmitter;
use zvariant::{OwnedObjectPath, OwnedValue};

use super::TestPeer;
use crate::command::{CommandFailure, CommandOutput, CommandRequest, CommandRunner};
use crate::nm::{ConnectionSettings, NM_PATH, Nm, SETTINGS_PATH};
use crate::variant::value_map;

pub(crate) const DEVICE: &str = "/org/freedesktop/NetworkManager/Devices/1";
pub(crate) const PROFILE: &str = "/org/freedesktop/NetworkManager/Settings/1";
pub(crate) const ACTIVE: &str = "/org/freedesktop/NetworkManager/ActiveConnection/1";
const AP1: &str = "/org/freedesktop/NetworkManager/AccessPoint/1";
const AP2: &str = "/org/freedesktop/NetworkManager/AccessPoint/2";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Connected,
    DhcpFailed,
    NoSecrets,
    CancelBeforeWait,
    CancelOnSuccess,
}

pub(crate) struct State {
    script: VecDeque<Outcome>,
    current: Option<Outcome>,
    ap: String,
    hotspot: bool,
    vpn: bool,
    settings: ConnectionSettings,
    pub(crate) activations: Vec<String>,
    pub(crate) deactivated: Vec<String>,
    pub(crate) deleted: usize,
    pub(crate) cancellation: Arc<AtomicBool>,
}

impl State {
    fn activate(&mut self, specific: &str) -> OwnedObjectPath {
        self.activations.push(specific.to_string());
        self.ap = specific.to_string();
        self.current = Some(
            self.script
                .pop_front()
                .expect("unexpected extra activation"),
        );
        if self.current == Some(Outcome::CancelBeforeWait) {
            self.cancellation.store(true, Ordering::Release);
        }
        path(ACTIVE)
    }

    fn active_state(&self) -> u32 {
        match self.current {
            Some(Outcome::Connected) => 2,
            Some(Outcome::CancelOnSuccess) => {
                self.cancellation.store(true, Ordering::Release);
                2
            }
            Some(Outcome::CancelBeforeWait) => 1,
            _ => 4,
        }
    }
}

pub(crate) struct FakeNm {
    pub(crate) nm: Nm,
    pub(crate) state: Arc<Mutex<State>>,
    peer: TestPeer,
}

impl FakeNm {
    pub(crate) fn new(script: impl IntoIterator<Item = Outcome>, vpn: bool) -> Result<Self> {
        let peer = TestPeer::new(":1.0", ":1.1");
        let settings = if vpn {
            ConnectionSettings::from([(
                "connection".into(),
                value_map([
                    ("id", "Test VPN".into()),
                    ("uuid", "test-vpn".into()),
                    ("type", "vpn".into()),
                ])?,
            )])
        } else {
            ConnectionSettings::new()
        };
        let state = Arc::new(Mutex::new(State {
            script: script.into_iter().collect(),
            current: None,
            ap: AP1.into(),
            hotspot: false,
            vpn,
            settings,
            activations: Vec::new(),
            deactivated: Vec::new(),
            deleted: 0,
            cancellation: Arc::new(AtomicBool::new(false)),
        }));
        let server = peer.server.object_server();
        server.at(NM_PATH, Manager(state.clone()))?;
        server.at(SETTINGS_PATH, Settings(state.clone()))?;
        server.at(PROFILE, Profile(state.clone()))?;
        server.at(DEVICE, Device(state.clone()))?;
        server.at(DEVICE, Wireless(state.clone()))?;
        server.at(AP1, AccessPoint(5180, "00:11:22:33:44:55"))?;
        server.at(AP2, AccessPoint(2412, "00:11:22:33:44:66"))?;
        server.at(ACTIVE, Active(state.clone()))?;
        server.at(ACTIVE, Vpn(state.clone()))?;
        let nm = Nm::with_connection_runner_destination_and_telemetry(
            peer.client.clone(),
            Arc::new(FakeCommands),
            ":1.0",
            Arc::new(crate::nl80211::UnavailableWirelessTelemetry),
        )?;
        drop(server);
        Ok(Self { nm, state, peer })
    }

    pub(crate) fn cancellation(&self) -> Arc<AtomicBool> {
        self.state.lock().unwrap().cancellation.clone()
    }

    pub(crate) fn terminal_event(&self, run: impl FnOnce(SignalEmitter<'static>)) -> Result<Value> {
        let proxy = Proxy::new(
            &self.peer.client,
            ":1.0",
            "/test",
            crate::protocol::DBUS_INTERFACE,
        )?;
        let events = proxy.receive_signal("Event")?;
        let emitter = SignalEmitter::new(self.peer.server.inner(), "/test")?.into_owned();
        run(emitter.clone());
        // Same-connection fence: inspect every event emitted by the worker,
        // rather than accepting its first terminal signal and missing duplicates.
        crate::daemon::emit_event_signal(
            &emitter,
            crate::protocol::Stream::Hotspot,
            r#"{"event":"test-complete"}"#.into(),
        )?;
        let mut terminal = None;
        for message in events {
            let (_, json): (String, String) = message.body().deserialize()?;
            let event: Value = serde_json::from_str(&json)?;
            if event["event"] == "test-complete" {
                break;
            }
            if matches!(
                event["event"].as_str(),
                Some("cancelled" | "failed" | "succeeded")
            ) {
                anyhow::ensure!(
                    terminal.replace(event).is_none(),
                    "duplicate terminal events"
                );
            }
        }
        terminal.ok_or_else(|| anyhow::anyhow!("operation emitted no terminal event"))
    }
}

fn path(value: &str) -> OwnedObjectPath {
    value.try_into().unwrap()
}

struct FakeCommands;
impl CommandRunner for FakeCommands {
    fn run(
        &self,
        _: &CommandRequest,
        _: Option<&AtomicBool>,
    ) -> Result<CommandOutput, CommandFailure> {
        Ok(CommandOutput {
            stdout: "IP4.ADDRESS[1]:192.0.2.2/24\n".into(),
            stderr: String::new(),
        })
    }
}

struct Manager(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Manager {
    fn get_devices(&self) -> Vec<OwnedObjectPath> {
        vec![path(DEVICE)]
    }
    fn check_connectivity(&self) -> u32 {
        4
    }
    #[zbus(property)]
    fn wireless_enabled(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn active_connections(&self) -> Vec<OwnedObjectPath> {
        if self.0.lock().unwrap().current.is_some() {
            vec![path(ACTIVE)]
        } else {
            vec![]
        }
    }
    async fn add_and_activate_connection(
        &self,
        settings: ConnectionSettings,
        device: OwnedObjectPath,
        specific: OwnedObjectPath,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> (OwnedObjectPath, OwnedObjectPath) {
        assert_eq!(device.as_str(), DEVICE);
        let active = {
            let mut state = self.0.lock().unwrap();
            state.settings = settings;
            state.activate(specific.as_str())
        };
        self.active_connections_changed(&emitter).await.unwrap();
        (path(PROFILE), active)
    }
    async fn add_and_activate_connection2(
        &self,
        settings: ConnectionSettings,
        device: OwnedObjectPath,
        specific: OwnedObjectPath,
        options: HashMap<String, OwnedValue>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> (
        OwnedObjectPath,
        OwnedObjectPath,
        HashMap<String, OwnedValue>,
    ) {
        assert_eq!(
            crate::variant::value_string(&options["persist"]).as_deref(),
            Some("volatile")
        );
        self.0.lock().unwrap().hotspot = true;
        let (profile, active) = self
            .add_and_activate_connection(settings, device, specific, emitter)
            .await;
        (profile, active, HashMap::new())
    }
    async fn activate_connection(
        &self,
        profile: OwnedObjectPath,
        _device: OwnedObjectPath,
        specific: OwnedObjectPath,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> OwnedObjectPath {
        assert_eq!(profile.as_str(), PROFILE);
        let active = self.0.lock().unwrap().activate(specific.as_str());
        self.active_connections_changed(&emitter).await.unwrap();
        active
    }
    async fn deactivate_connection(
        &self,
        active: OwnedObjectPath,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) {
        {
            let mut state = self.0.lock().unwrap();
            state.deactivated.push(active.to_string());
            state.current = None;
        }
        self.active_connections_changed(&emitter).await.unwrap();
    }
}

struct Settings(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings")]
impl Settings {
    fn list_connections(&self) -> Vec<OwnedObjectPath> {
        if self.0.lock().unwrap().settings.is_empty() {
            vec![]
        } else {
            vec![path(PROFILE)]
        }
    }
}
struct Profile(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl Profile {
    fn get_settings(&self) -> ConnectionSettings {
        self.0.lock().unwrap().settings.clone()
    }
    fn update(&self, settings: ConnectionSettings) {
        self.0.lock().unwrap().settings = settings;
    }
    fn delete(&self) {
        let mut state = self.0.lock().unwrap();
        state.deleted += 1;
        state.settings.clear();
    }
}
struct Device(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
impl Device {
    #[zbus(property)]
    fn device_type(&self) -> u32 {
        2
    }
    #[zbus(property)]
    fn interface(&self) -> &str {
        "test-wifi"
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn active_connection(&self) -> OwnedObjectPath {
        if self.0.lock().unwrap().current.is_some() {
            path(ACTIVE)
        } else {
            path("/")
        }
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn available_connections(&self) -> Vec<OwnedObjectPath> {
        Settings(self.0.clone()).list_connections()
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn state(&self) -> u32 {
        if matches!(
            self.0.lock().unwrap().current,
            Some(Outcome::Connected | Outcome::CancelOnSuccess)
        ) {
            100
        } else {
            30
        }
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn state_reason(&self) -> (u32, u32) {
        let reason = match self.0.lock().unwrap().current {
            Some(Outcome::DhcpFailed) => 17,
            Some(Outcome::NoSecrets) => 7,
            _ => 0,
        };
        (self.state(), reason)
    }
}
struct Wireless(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Device.Wireless")]
impl Wireless {
    fn get_access_points(&self) -> Vec<OwnedObjectPath> {
        vec![path(AP1), path(AP2)]
    }
    #[zbus(property)]
    fn wireless_capabilities(&self) -> u32 {
        0x640
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn mode(&self) -> u32 {
        if self.0.lock().unwrap().hotspot { 3 } else { 2 }
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn active_access_point(&self) -> OwnedObjectPath {
        let state = self.0.lock().unwrap();
        if matches!(
            state.current,
            Some(Outcome::Connected | Outcome::CancelOnSuccess)
        ) {
            path(&state.ap)
        } else {
            path("/")
        }
    }
}
struct AccessPoint(u32, &'static str);
#[zbus::interface(name = "org.freedesktop.NetworkManager.AccessPoint")]
impl AccessPoint {
    #[zbus(property)]
    fn ssid(&self) -> Vec<u8> {
        b"Example".to_vec()
    }
    #[zbus(property)]
    fn frequency(&self) -> u32 {
        self.0
    }
    #[zbus(property)]
    fn hw_address(&self) -> &str {
        self.1
    }
}
struct Active(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.Connection.Active")]
impl Active {
    #[zbus(property)]
    fn id(&self) -> &str {
        "Example"
    }
    #[zbus(property)]
    fn uuid(&self) -> &str {
        "test-vpn"
    }
    #[zbus(property)]
    fn connection(&self) -> OwnedObjectPath {
        path(PROFILE)
    }
    #[zbus(property)]
    fn devices(&self) -> Vec<OwnedObjectPath> {
        vec![path(DEVICE)]
    }
    #[zbus(property)]
    fn vpn(&self) -> bool {
        self.0.lock().unwrap().vpn
    }
    #[zbus(property, name = "Type")]
    fn connection_type(&self) -> &str {
        if self.vpn() { "vpn" } else { "802-11-wireless" }
    }
    #[zbus(property(emits_changed_signal = "false"))]
    fn state(&self) -> u32 {
        self.0.lock().unwrap().active_state()
    }
}
struct Vpn(Arc<Mutex<State>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.VPN.Connection")]
impl Vpn {
    #[zbus(property(emits_changed_signal = "false"))]
    fn vpn_state(&self) -> u32 {
        if self.0.lock().unwrap().active_state() == 2 {
            5
        } else {
            6
        }
    }
}

#[test]
fn candidate_retry_is_bounded_and_authentication_failure_is_not_retried() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::candidate_retry_is_bounded_and_authentication_failure_is_not_retried"
        ),
        || {
            use crate::application::{
                Application, ConnectCandidate, ConnectEvent, ConnectOutcome, ConnectRequest,
            };
            use crate::model::{ConnectFailureReason, NmObjectPath};
            for (script, attempts, reason) in [
                (vec![Outcome::DhcpFailed, Outcome::Connected], 2, None),
                (
                    vec![Outcome::NoSecrets],
                    1,
                    Some(ConnectFailureReason::PasswordUnavailable),
                ),
                (
                    vec![Outcome::DhcpFailed, Outcome::DhcpFailed],
                    2,
                    Some(ConnectFailureReason::DhcpFailed),
                ),
            ] {
                let fake = FakeNm::new(script, false)?;
                let mut target = crate::model::example_connect_target(false);
                target.ap_path = Some(NmObjectPath::parse(AP1.into())?);
                let mut request = ConnectRequest::single(target.clone(), None, None);
                target.ap_path = Some(NmObjectPath::parse(AP2.into())?);
                let alternate = ConnectCandidate {
                    target,
                    band: Some("2.4 GHz".into()),
                    channel: Some(1),
                    strength: Some(70),
                };
                request.alternatives = vec![alternate.clone(), alternate];
                let mut events = Vec::new();
                let outcome = Application::new(&fake.nm).connect(&request, None, |event| {
                    events.push(event.clone());
                    Ok(())
                })?;
                let result = match outcome {
                    ConnectOutcome::Succeeded(result) => {
                        assert!(reason.is_none());
                        assert!(result.fallback_used);
                        result
                    }
                    ConnectOutcome::Failed { result, .. } => {
                        assert_eq!(result.reason, reason);
                        result
                    }
                    other => panic!("unexpected outcome: {other:?}"),
                };
                assert_eq!(result.attempts.len(), attempts);
                let state = fake.state.lock().unwrap();
                assert_eq!(
                    state.activations,
                    if attempts == 2 {
                        vec![AP1, AP2]
                    } else {
                        vec![AP1]
                    }
                );
                assert_eq!(state.deleted, attempts - usize::from(reason.is_none()));
                assert_eq!(
                    events
                        .iter()
                        .filter(|event| matches!(event, ConnectEvent::Finished { .. }))
                        .count(),
                    1
                );
            }
            Ok(())
        },
    )
}

#[test]
fn activation_failure_and_early_cancellation_roll_back_hotspot_and_vpn() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::activation_failure_and_early_cancellation_roll_back_hotspot_and_vpn"
        ),
        || {
            use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
            use crate::model::{HotspotSecurity, WifiBand};
            use crate::nm::{HotspotRequest, VpnSelector};
            for outcome in [Outcome::DhcpFailed, Outcome::CancelBeforeWait] {
                for vpn in [false, true] {
                    let fake = FakeNm::new([outcome], vpn)?;
                    let cancellation = fake.cancellation();
                    let error = if vpn {
                        fake.nm
                            .activate_vpn(
                                &VpnSelector {
                                    uuid: Some("test-vpn".into()),
                                    path: None,
                                },
                                Duration::from_secs(1),
                                Some(&cancellation),
                            )
                            .unwrap_err()
                    } else {
                        fake.nm
                            .start_hotspot(
                                &HotspotRequest {
                                    ssid: Some("Test".into()),
                                    passphrase: Some("test password".into()),
                                    security: HotspotSecurity::WpaPsk,
                                    band: WifiBand::Auto,
                                    channel: None,
                                    hidden: false,
                                    device: None,
                                },
                                Some(&cancellation),
                            )
                            .unwrap_err()
                    };
                    assert_eq!(
                        ErrorReport::from_error(&error, ErrorOperation::Unknown).code,
                        if outcome == Outcome::CancelBeforeWait {
                            ErrorCode::Cancelled
                        } else {
                            ErrorCode::ActivationFailed
                        }
                    );
                    let state = fake.state.lock().unwrap();
                    assert_eq!(state.deactivated, [ACTIVE]);
                    assert_eq!(
                        state.deleted,
                        usize::from(!vpn),
                        "saved VPN profiles must survive failure"
                    );
                }
            }
            Ok(())
        },
    )
}

/// Bound hangs and isolate real cache/history writes without unsafe process-global
/// environment changes. Never retry a failing child (which could hide flakiness).
pub(crate) fn isolated(name: &str, run: impl FnOnce() -> Result<()>) -> Result<()> {
    let name = name
        .strip_prefix(concat!(env!("CARGO_CRATE_NAME"), "::"))
        .unwrap_or(name);
    if std::env::var("NM_WORKFLOW_TEST").as_deref() == Ok(name) {
        let runtime = tokio::runtime::Runtime::new()?;
        let _entered = runtime.enter();
        run()?;
        std::fs::write(std::env::var("NM_WORKFLOW_COMPLETED")?, "ok")?;
        return Ok(());
    }
    let directory = std::env::temp_dir().join(format!(
        "nm-workflow-{}-{name}-{}",
        std::process::id(),
        crate::cache::now_ms()
    ));
    std::fs::create_dir(&directory)?;
    let completed = directory.join("completed");
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", name, "--nocapture"])
        .env("NM_WORKFLOW_TEST", name)
        .env("NM_WORKFLOW_COMPLETED", &completed)
        // Keep fixtures runnable on small builders and expose dispatch-startup
        // races that extra worker threads can otherwise conceal.
        .env("TOKIO_WORKER_THREADS", "1")
        .env("XDG_RUNTIME_DIR", &directory)
        .env("XDG_STATE_HOME", &directory)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(45);
    let result = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let completed = completed.is_file();
    std::fs::remove_dir_all(directory)?;
    let status =
        result.ok_or_else(|| anyhow::anyhow!("workflow child timed out after 45s: {name}"))?;
    anyhow::ensure!(
        status.success(),
        "workflow child exited with {status}: {name}"
    );
    anyhow::ensure!(
        completed,
        "workflow child did not complete the test body: {name}"
    );
    Ok(())
}
