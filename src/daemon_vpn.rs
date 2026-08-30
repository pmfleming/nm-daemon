use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::Application;
use crate::daemon_event::{OperationEvents, started_response};
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::{DomainError, ErrorOperation};
use crate::nm::VpnSelector;
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};

const STREAM: Stream = Stream::Vpn;
const DEFAULT_TIMEOUT_SECS: u64 = 45;
const MAX_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct VpnSelectParams {
    uuid: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct VpnConnectParams {
    uuid: Option<String>,
    path: Option<String>,
    timeout: Option<u64>,
}

impl VpnSelectParams {
    fn into_selector(self) -> VpnSelector {
        VpnSelector {
            uuid: nonempty(self.uuid),
            path: nonempty(self.path),
        }
    }
}

impl VpnConnectParams {
    fn split(self) -> Result<(VpnSelector, Duration)> {
        let selector = VpnSelector {
            uuid: nonempty(self.uuid),
            path: nonempty(self.path),
        };
        if selector.uuid.is_none() && selector.path.is_none() {
            return Err(DomainError::validation(
                ErrorOperation::VpnOperation,
                "vpn.connect requires uuid or path",
            )
            .into());
        }
        let timeout = self.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if timeout == 0 || timeout > MAX_TIMEOUT_SECS {
            return Err(DomainError::validation(
                ErrorOperation::VpnOperation,
                format!("timeout must be between 1 and {MAX_TIMEOUT_SECS} seconds"),
            )
            .with_detail("timeout", timeout)
            .into());
        }
        Ok((selector, Duration::from_secs(timeout)))
    }
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

pub(crate) fn call_list(runtime: &Arc<DaemonRuntime>) -> Result<Value> {
    runtime.call(ErrorOperation::VpnOperation, |nm| {
        api_data_value(
            Method::VpnList.spec().response_key,
            &Application::new(nm).vpn_profiles()?,
            "serialize VPN list response JSON",
        )
    })
}

pub(crate) fn call_status(runtime: &Arc<DaemonRuntime>) -> Result<Value> {
    runtime.call(ErrorOperation::VpnOperation, |nm| {
        api_data_value(
            Method::VpnStatus.spec().response_key,
            &Application::new(nm).vpn_status()?,
            "serialize VPN status response JSON",
        )
    })
}

pub(crate) fn call_disconnect(
    runtime: &Arc<DaemonRuntime>,
    params: VpnSelectParams,
) -> Result<Value> {
    let selector = params.into_selector();
    runtime.call(ErrorOperation::VpnOperation, move |nm| {
        api_data_value(
            Method::VpnDisconnect.spec().response_key,
            &Application::new(nm).disconnect_vpn(&selector)?,
            "serialize VPN disconnect response JSON",
        )
    })
}

pub(crate) fn start_connect(
    runtime: &Arc<DaemonRuntime>,
    params: VpnConnectParams,
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let (selector, timeout) = params.split()?;
    let request_id = runtime.start_cancellable(
        "vpn",
        TaskKind::Vpn,
        owner,
        None,
        move |nm, cancellation, request_id| {
            run_vpn_worker(nm, request_id, &selector, timeout, cancellation, &emitter);
        },
    )?;
    started_response(
        Method::VpnConnect,
        STREAM,
        &request_id,
        "VPN activation started; listen for Event('vpn', event_json) signals",
        json!({}),
    )
}

fn run_vpn_worker(
    nm: &crate::nm::Nm,
    request_id: &str,
    selector: &VpnSelector,
    timeout: Duration,
    cancellation: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) {
    let events = OperationEvents::new(emitter, STREAM, request_id);
    events.event(
        "started",
        json!({
            "request_id": request_id,
            "phase": "preparing",
            "uuid": selector.uuid,
            "path": selector.path,
        }),
    );
    events.phase("progress", "activating");

    match Application::new(nm).connect_vpn(selector, timeout, Some(cancellation)) {
        Ok(result) if cancellation.load(Ordering::Relaxed) => {
            let _ = Application::new(nm).disconnect_vpn(selector);
            tracing::info!(%request_id, id = %result.vpn.id, "disconnected VPN that connected after cancellation");
            events.cancelled("VPN activation was cancelled");
        }
        Ok(result) => events.succeeded(&result),
        Err(error) => events.error(
            &error,
            ErrorOperation::VpnOperation,
            "VPN activation was cancelled",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DEFAULT_TIMEOUT_SECS, VpnConnectParams, VpnSelectParams};
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};

    fn connect(json: &str) -> VpnConnectParams {
        serde_json::from_str(json).expect("connect params")
    }

    #[test]
    fn connect_requires_an_identifier_and_defaults_the_timeout() {
        let (selector, timeout) = connect(r#"{"uuid":"uuid-1"}"#).split().expect("selector");
        assert_eq!(selector.uuid.as_deref(), Some("uuid-1"));
        assert_eq!(timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        let error = connect("{}").split().unwrap_err();
        let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::ValidationError);
        assert_eq!(report.operation, ErrorOperation::VpnOperation);
    }

    #[test]
    fn out_of_range_timeouts_are_rejected_before_activation_starts() {
        for rejected in [
            r#"{"uuid":"u","timeout":0}"#,
            r#"{"uuid":"u","timeout":301}"#,
        ] {
            assert!(connect(rejected).split().is_err(), "{rejected}");
        }
        assert!(connect(r#"{"uuid":"u","timeout":300}"#).split().is_ok());
    }

    #[test]
    fn disconnect_without_a_selector_targets_the_only_active_connection() {
        let selector = serde_json::from_str::<VpnSelectParams>("{}")
            .expect("select params")
            .into_selector();
        assert!(selector.uuid.is_none() && selector.path.is_none());

        let selector = serde_json::from_str::<VpnSelectParams>(r#"{"uuid":"  "}"#)
            .expect("select params")
            .into_selector();
        assert!(
            selector.uuid.is_none(),
            "blank identifiers are not selectors"
        );
    }
}
