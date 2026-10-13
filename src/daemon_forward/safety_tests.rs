//! Real private-bus faults, without host NetworkManager access or direct effects.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use serde_json::{Value, json};
use zbus::{
    blocking::{Connection, Proxy, connection::Builder},
    message::Header,
    object_server::SignalEmitter,
};

use super::{ForwardOutcome, dispatch_forward, forward_connect, safety};
use crate::cli::{Cli, Command, WifiCommand};
use crate::error::{ErrorOperation, ErrorReport};
use crate::protocol::{DBUS_BUS_NAME, DBUS_INTERFACE, DBUS_OBJECT_PATH, Method, Stream};
use crate::test_support::{bus::TestBus, workflows::isolated};

#[derive(Clone, Copy)]
enum Reply {
    Stall,
    Disconnect,
    ServiceUnknown,
    Malformed,
    Rejected,
    Success,
    Recoverable,
}

struct Service {
    reply: Reply,
    effects: Arc<AtomicUsize>,
    owners: Arc<Mutex<Vec<String>>>,
    status: Arc<Mutex<String>>,
}

fn terminal_status() -> Value {
    json!({
        "protocol": "nm-api", "version": 2, "ok": true,
        "data": {"result": {
            "request_id": "connect-example", "status": "finished",
            "stream": Stream::WifiConnect,
            "event": {
                "protocol": "nm-api", "version": 2,
                "stream": Stream::WifiConnect, "request_id": "connect-example",
                "event": "succeeded", "data": {"result": {"status": "connected"}}
            }
        }}
    })
}

#[zbus::interface(name = "org.laufan.NmDaemon2")]
impl Service {
    async fn call(
        &self,
        method: &str,
        _params: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<String> {
        self.owners
            .lock()
            .unwrap()
            .push(header.sender().unwrap().to_string());
        if method == Method::OperationStatus.as_str() {
            return Ok(self.status.lock().unwrap().clone());
        }
        // Model an effect accepted before the reply is lost. Never touch NM.
        self.effects.fetch_add(1, Ordering::SeqCst);
        match self.reply {
            Reply::Stall => std::future::pending().await,
            Reply::Disconnect => {
                connection.clone().close().await?;
                std::future::pending().await
            }
            Reply::ServiceUnknown => Err(zbus::fdo::Error::ServiceUnknown(
                "applied, reply failed".into(),
            )),
            Reply::Malformed => Ok("not JSON".into()),
            Reply::Rejected => Ok(json!({
                "protocol": "nm-api", "version": 2, "ok": false,
                "error": {"code": "validation-error", "message": "Rejected"}
            })
            .to_string()),
            Reply::Success => Ok(json!({
                "protocol": "nm-api", "version": 2, "ok": true, "data": {"result": {}}
            })
            .to_string()),
            Reply::Recoverable => {
                // A bad event makes observation fail after admission; the same
                // owner's status read can recover the cached terminal result.
                emitter
                    .emit(
                        DBUS_INTERFACE,
                        "Event",
                        &(Stream::WifiConnect.as_str(), "not JSON"),
                    )
                    .await?;
                Ok(json!({
                    "protocol": "nm-api", "version": 2, "ok": true,
                    "data": {"result": {"request_id": "connect-example"}}
                })
                .to_string())
            }
        }
    }
}

struct Fixture {
    client: Connection,
    _server: Connection,
    effects: Arc<AtomicUsize>,
    owners: Arc<Mutex<Vec<String>>>,
    status: Arc<Mutex<String>>,
    _bus: TestBus,
}

impl Fixture {
    fn new(reply: Reply) -> Result<Self> {
        let bus = TestBus::new()?;
        let effects = Arc::new(AtomicUsize::new(0));
        let owners = Arc::new(Mutex::new(Vec::new()));
        let status = Arc::new(Mutex::new(terminal_status().to_string()));
        let server = Builder::address(bus.address())?
            .serve_at(
                DBUS_OBJECT_PATH,
                Service {
                    reply,
                    effects: effects.clone(),
                    owners: owners.clone(),
                    status: status.clone(),
                },
            )?
            .name(DBUS_BUS_NAME)?
            .build()?;
        let client = Builder::address(bus.address())?
            .method_timeout(Duration::from_millis(500))
            .build()?;
        Ok(Self {
            client,
            _server: server,
            effects,
            owners,
            status,
            _bus: bus,
        })
    }

    fn proxy(&self) -> Result<Proxy<'_>> {
        Ok(Proxy::new(
            &self.client,
            DBUS_BUS_NAME,
            DBUS_OBJECT_PATH,
            DBUS_INTERFACE,
        )?)
    }
}

fn command(args: &[&str]) -> Command {
    Cli::try_parse_from(std::iter::once("nm-daemon").chain(args.iter().copied()))
        .unwrap()
        .command
}

fn assert_unknown(result: Result<ForwardOutcome>, method: &str) -> ErrorReport {
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("uncertain {method} was allowed to fall back or reported as successful"),
    };
    let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
    let envelope = crate::output::api_error_value_for(&report);
    assert_eq!(envelope["error"]["code"], "outcome-unknown");
    assert_eq!(envelope["error"]["details"]["method"], method);
    assert_eq!(envelope["error"]["details"]["retryable"], false);
    assert!(report.message.contains("not retried"));
    report
}

#[test]
fn applied_but_unanswered_calls_never_fall_back() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::applied_but_unanswered_calls_never_fall_back"
        ),
        || {
            for (args, method) in [
                (vec!["wifi", "disconnect"], Method::WifiDisconnect),
                (
                    vec![
                        "wifi",
                        "profile",
                        "delete",
                        "/org/freedesktop/NetworkManager/Settings/1",
                    ],
                    Method::WifiProfileOperation,
                ),
                (
                    vec!["network", "activate", "--uuid", "example"],
                    Method::NetworkActivateProfile,
                ),
                (
                    vec!["network", "deactivate", "--uuid", "example"],
                    Method::NetworkDeactivate,
                ),
                (
                    vec!["wifi", "connect", "Example"],
                    Method::WifiConnectTarget,
                ),
                (vec!["hotspot", "start"], Method::HotspotStart),
                (
                    vec!["vpn", "connect", "--uuid", "example"],
                    Method::VpnConnect,
                ),
            ] {
                for reply in [
                    Reply::Stall,
                    Reply::Disconnect,
                    Reply::ServiceUnknown,
                    Reply::Malformed,
                ] {
                    let fixture = Fixture::new(reply)?;
                    assert_unknown(
                        dispatch_forward(&fixture.proxy()?, &command(&args)),
                        method.as_str(),
                    );
                    assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
                    assert_eq!(
                        fixture.owners.lock().unwrap().len(),
                        1,
                        "No ID: do not guess a recovery request"
                    );
                }
            }
            Ok(())
        },
    )
}

#[test]
fn absent_service_allows_direct_fallback_without_dispatch() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::absent_service_allows_direct_fallback_without_dispatch"
        ),
        || {
            let bus = TestBus::new()?;
            let connection = bus.connect()?;
            let proxy = Proxy::new(&connection, DBUS_BUS_NAME, DBUS_OBJECT_PATH, DBUS_INTERFACE)?;
            assert!(matches!(
                dispatch_forward(&proxy, &command(&["wifi", "disconnect"]))?,
                ForwardOutcome::Unavailable
            ));
            let Command::Wifi {
                command: WifiCommand::Connect(options),
            } = command(&["wifi", "connect", "Example"])
            else {
                unreachable!()
            };
            let mut request = crate::actions::connect_ssid_request(options)?;
            request.password = Some("test-secret-already-read-from-stdin".into());
            let ForwardOutcome::DirectConnect(request) = forward_connect(&proxy, request)? else {
                panic!("missing preserved direct-connect request")
            };
            assert_eq!(request.candidate.target.ssid.as_str(), "Example");
            assert_eq!(
                request.password.as_deref(),
                Some("test-secret-already-read-from-stdin")
            );
            Ok(())
        },
    )
}

#[test]
fn authoritative_success_and_api_rejection_do_not_fall_back() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::authoritative_success_and_api_rejection_do_not_fall_back"
        ),
        || {
            let fixture = Fixture::new(Reply::Success)?;
            assert!(matches!(
                dispatch_forward(&fixture.proxy()?, &command(&["wifi", "disconnect"]))?,
                ForwardOutcome::Handled
            ));
            for args in [
                vec!["wifi", "disconnect"],
                vec!["wifi", "connect", "Example"],
            ] {
                let fixture = Fixture::new(Reply::Rejected)?;
                let result = dispatch_forward(&fixture.proxy()?, &command(&args));
                assert!(result.is_err_and(|error| crate::output::is_reported_error(&error)));
                assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
            }
            Ok(())
        },
    )
}

#[test]
fn known_operation_recovers_with_same_owner_status_read() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::known_operation_recovers_with_same_owner_status_read"
        ),
        || {
            for terminal in ["succeeded", "failed", "cancelled"] {
                let fixture = Fixture::new(Reply::Recoverable)?;
                let mut status = terminal_status();
                status["data"]["result"]["event"]["event"] = json!(terminal);
                *fixture.status.lock().unwrap() = status.to_string();
                let result =
                    dispatch_forward(&fixture.proxy()?, &command(&["wifi", "connect", "Example"]));
                if terminal == "succeeded" {
                    assert!(matches!(result?, ForwardOutcome::Handled));
                } else {
                    assert!(result.is_err_and(|error| crate::output::is_reported_error(&error)));
                }
                assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
                let owners = fixture.owners.lock().unwrap();
                assert_eq!(owners.len(), 2);
                assert_eq!(owners[0], owners[1], "Recovery must not change bus owner");
            }
            Ok(())
        },
    )
}

#[test]
fn incomplete_or_foreign_status_keeps_outcome_unknown() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::incomplete_or_foreign_status_keeps_outcome_unknown"
        ),
        || {
            let mut replies = vec!["not JSON".to_string()];
            for (path, replacement) in [
                ("/ok", json!(false)),
                ("/data/result/status", json!("running")),
                ("/data/result/status", json!("unknown")),
                ("/data/result/request_id", json!("foreign")),
                ("/data/result/stream", json!(Stream::Vpn)),
                ("/data/result/event/request_id", json!("foreign")),
                ("/data/result/event/stream", json!(Stream::Vpn)),
                ("/data/result/event/version", json!(1)),
                ("/data/result/event/event", json!("progress")),
            ] {
                let mut status = terminal_status();
                *status.pointer_mut(path).unwrap() = replacement;
                replies.push(status.to_string());
            }
            for reply in replies {
                let fixture = Fixture::new(Reply::Recoverable)?;
                *fixture.status.lock().unwrap() = reply;
                let report = assert_unknown(
                    dispatch_forward(&fixture.proxy()?, &command(&["wifi", "connect", "Example"])),
                    Method::WifiConnectTarget.as_str(),
                );
                assert_eq!(report.details["request_id"], "connect-example");
                assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
                assert_eq!(
                    fixture.owners.lock().unwrap().len(),
                    2,
                    "Only one recovery read is attempted"
                );
            }
            Ok(())
        },
    )
}

#[test]
fn recovery_is_pinned_to_acknowledging_daemon_not_replacement() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::recovery_is_pinned_to_acknowledging_daemon_not_replacement"
        ),
        || {
            let fixture = Fixture::new(Reply::Success)?;
            let proxy = fixture.proxy()?;
            let reply = safety::call(&proxy, Method::WifiConnectTarget, "{}")?.unwrap();
            fixture._server.release_name(DBUS_BUS_NAME)?;
            let replacement_owners = Arc::new(Mutex::new(Vec::new()));
            let _replacement = Builder::address(fixture._bus.address())?
                .serve_at(
                    DBUS_OBJECT_PATH,
                    Service {
                        reply: Reply::Success,
                        effects: Arc::new(AtomicUsize::new(0)),
                        owners: replacement_owners.clone(),
                        status: Arc::new(Mutex::new(terminal_status().to_string())),
                    },
                )?
                .name(DBUS_BUS_NAME)?
                .build()?;
            let recovered = safety::recover_terminal(
                &proxy,
                Method::WifiConnectTarget,
                Stream::WifiConnect,
                "connect-example",
                reply.owner.as_ref(),
            );
            assert!(recovered.is_some());
            assert!(
                replacement_owners.lock().unwrap().is_empty(),
                "Replacement must not receive a reused request ID"
            );
            assert_eq!(fixture.owners.lock().unwrap().len(), 2);
            assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
            Ok(())
        },
    )
}
