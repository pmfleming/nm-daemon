use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::{Application, ConnectEvent, ConnectOutcome, ConnectRequest};
use crate::daemon::{emit_json_event, emit_json_event_nonfatal};
use crate::daemon_event::next_request_id;
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::{ErrorOperation, ErrorReport};
use crate::model::{EnterpriseAuth, WepKeyType, WifiConnectTarget, ssid_for_network_key};
use crate::nm::Nm;
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};

const STREAM: Stream = Stream::WifiConnect;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DbusConnectTargetParams {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    target: Option<WifiConnectTarget>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    wep_key_type: Option<WepKeyType>,
    #[serde(default)]
    enterprise_identity: Option<String>,
    #[serde(default)]
    enterprise: Option<EnterpriseAuth>,
}

impl DbusConnectTargetParams {
    fn validate(&self) -> Result<()> {
        match (&self.key, &self.target) {
            (Some(key), None) => {
                ssid_for_network_key(key)?;
                Ok(())
            }
            (None, Some(target)) => target.validate(),
            (Some(_), Some(_)) => {
                bail!("connect request must provide either key or target, not both")
            }
            (None, None) => bail!("connect request must provide key or target"),
        }
    }

    fn target_ssid(&self) -> Result<Vec<u8>> {
        match (&self.key, &self.target) {
            (Some(key), None) => Ok(ssid_for_network_key(key)?.as_bytes().to_vec()),
            (None, Some(target)) => Ok(target.ssid_bytes().to_vec()),
            _ => bail!("invalid connect target selector"),
        }
    }

    fn into_request(self, nm: &Nm) -> Result<ConnectRequest> {
        if let Some(target) = self.target {
            return Ok(ConnectRequest {
                target,
                password: self.password,
                wep_key_type: self.wep_key_type,
            });
        }
        let enterprise_identity = self.enterprise_identity.or_else(|| {
            self.enterprise
                .as_ref()
                .and_then(|enterprise| enterprise.identity.clone())
        });
        let mut request = Application::new(nm).connect_request_for_key(
            self.key.as_deref().unwrap_or_default(),
            self.password,
            self.wep_key_type,
            enterprise_identity,
        )?;
        if let Some(mut enterprise) = self.enterprise {
            if enterprise.key_mgmt.is_none() {
                enterprise.key_mgmt = request
                    .target
                    .enterprise
                    .as_ref()
                    .and_then(|defaults| defaults.key_mgmt.clone());
            }
            request.target.enterprise = Some(enterprise);
        }
        Ok(request)
    }
}

pub(crate) fn start_connect_target(
    runtime: &Arc<DaemonRuntime>,
    params: DbusConnectTargetParams,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    params.validate()?;
    let target_ssid = params.target_ssid()?;
    let request_id = next_request_id("connect");
    tracing::info!(
        request_id = %request_id,
        network_key = ?params.key,
        ssid = %crate::model::display_ssid(&target_ssid),
        "accepted correlated Wi-Fi connection request"
    );
    let worker_request_id = request_id.clone();
    runtime.start_cancellable(
        request_id.clone(),
        TaskKind::Connect,
        Some(target_ssid),
        move |nm, cancel_flag| {
            if let Err(err) =
                run_connect_worker(nm, &worker_request_id, params, cancel_flag, &emitter)
            {
                let report = ErrorReport::from_error(&err, ErrorOperation::Connect);
                emit_connect_failure(&emitter, &worker_request_id, &report);
            }
        },
    )?;
    api_data_value(
        Method::WifiConnectTarget.spec().response_key,
        &json!({
            "status": "started",
            "request_id": request_id,
            "stream": STREAM,
            "message": "Wi-Fi connection started; listen for Event('wifi.connect', event_json) signals",
        }),
        "serialize connect start response JSON",
    )
}

fn run_connect_worker(
    nm: &Nm,
    request_id: &str,
    params: DbusConnectTargetParams,
    cancel_flag: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) -> Result<()> {
    let request = params.into_request(nm)?;
    Application::new(nm)
        .connect(&request, Some(cancel_flag), |event| {
            emit_connect_event(emitter, request_id, event)
        })
        .map(|_| ())
}

fn emit_connect_event(
    emitter: &SignalEmitter<'static>,
    request_id: &str,
    event: &ConnectEvent,
) -> Result<()> {
    let (name, data) = match event {
        ConnectEvent::Started { message } => (
            "started",
            json!({ "request_id": request_id, "message": message }),
        ),
        ConnectEvent::Progress { message } => (
            "progress",
            json!({ "request_id": request_id, "message": message }),
        ),
        ConnectEvent::Finished(ConnectOutcome::Succeeded(result)) => {
            let connectivity_state = result
                .connectivity
                .as_ref()
                .map(|status| status.state)
                .unwrap_or("unavailable");
            let connectivity_code = result.connectivity.as_ref().map(|status| status.code);
            tracing::info!(
                %request_id,
                ssid = %result.ssid,
                connectivity_state,
                ?connectivity_code,
                suggest_open_portal = result.suggest_open_portal,
                "emitting correlated Wi-Fi connection success"
            );
            (
                "succeeded",
                json!({ "request_id": request_id, "result": result }),
            )
        }
        ConnectEvent::Finished(ConnectOutcome::Failed { result, error }) => {
            tracing::warn!(
                %request_id,
                ssid = %result.ssid,
                reason = ?result.reason,
                code = ?error.code,
                "emitting correlated Wi-Fi connection failure"
            );
            (
                "failed",
                json!({
                    "request_id": request_id,
                    "result": result.clone(),
                    "reason": result.reason,
                    "message": result.message,
                    "code": error.code,
                    "details": error.api_details(),
                }),
            )
        }
        ConnectEvent::Cancelled { message }
        | ConnectEvent::Finished(ConnectOutcome::Cancelled { message }) => {
            tracing::info!(%request_id, "emitting correlated Wi-Fi connection cancellation");
            (
                "cancelled",
                json!({ "request_id": request_id, "message": message }),
            )
        }
    };
    emit_json_event(emitter, STREAM, Some(request_id), name, data)
}

fn emit_connect_failure(emitter: &SignalEmitter<'static>, request_id: &str, report: &ErrorReport) {
    emit_json_event_nonfatal(
        emitter,
        STREAM,
        Some(request_id),
        "failed",
        json!({
            "request_id": request_id,
            "reason": report.code.connect_reason(),
            "code": report.code,
            "message": report.message,
            "details": report.api_details(),
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::DbusConnectTargetParams;

    #[test]
    fn opaque_key_and_legacy_target_requests_are_both_supported() {
        let keyed: DbusConnectTargetParams =
            serde_json::from_str(r#"{"key":"ssid-hex:4578616d706c65","password":"secret"}"#)
                .unwrap();
        keyed.validate().unwrap();
        assert_eq!(keyed.target_ssid().unwrap(), b"Example");

        let legacy: DbusConnectTargetParams =
            serde_json::from_str(r#"{"target":{"ssid":"Example"}}"#).unwrap();
        legacy.validate().unwrap();

        let ambiguous: DbusConnectTargetParams = serde_json::from_str(
            r#"{"key":"ssid-hex:4578616d706c65","target":{"ssid":"Example"}}"#,
        )
        .unwrap();
        assert!(ambiguous.validate().is_err());
    }
}
