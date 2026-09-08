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

pub(crate) fn call_disconnect(
    runtime: &Arc<DaemonRuntime>,
    params: VpnSelectParams,
) -> Result<Value> {
    let selector = params.into_selector();
    runtime.call_application(Method::VpnDisconnect, move |application| {
        application.disconnect_vpn(&selector)
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

    use super::VpnConnectParams;

    fn connect(json: &str) -> VpnConnectParams {
        serde_json::from_str(json).expect("connect params")
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
}
