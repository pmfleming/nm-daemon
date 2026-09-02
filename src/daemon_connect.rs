use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::{Application, ConnectEvent, ConnectOutcome, ConnectRequest};
use crate::daemon_event::{emit_json_event, emit_json_event_nonfatal, started_response};
use crate::daemon_runtime::{ConnectAttemptKey, DaemonRuntime, TaskKind};
use crate::error::{DomainError, ErrorOperation, ErrorReport};
use crate::model::{
    ConnectPhase, ConnectTargetIdentity, EnterpriseAuth, WepKeyType, WifiConnectTarget,
    connect_target_for_network_key, ssid_for_network_key,
};
use crate::nm::Nm;
use crate::protocol::{Method, Stream};

const STREAM: Stream = Stream::WifiConnect;

#[derive(Deserialize, Serialize)]
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
    /// Builds a request around an exact target, for callers that resolved the
    /// network themselves rather than through an opaque network key.
    pub(crate) fn for_target(
        target: WifiConnectTarget,
        password: Option<String>,
        wep_key_type: Option<WepKeyType>,
    ) -> Self {
        Self {
            key: None,
            target: Some(target),
            password,
            wep_key_type,
            enterprise_identity: None,
            enterprise: None,
        }
    }

    pub(crate) fn requested_identity(&self) -> Result<ConnectTargetIdentity> {
        match (&self.key, &self.target) {
            (Some(key), None) => {
                let target = connect_target_for_network_key(key, None)?;
                Ok(ConnectTargetIdentity::from_target(&target, Some(key)))
            }
            (None, Some(target)) => Ok(ConnectTargetIdentity::from_target(target, None)),
            (Some(_), Some(_)) => {
                bail!("connect request must provide either key or target, not both")
            }
            (None, None) => bail!("connect request must provide key or target"),
        }
    }

    fn attempt_key(&self) -> Result<ConnectAttemptKey> {
        let identity = self.requested_identity()?;
        let identity = identity.network_key.unwrap_or_else(|| {
            format!(
                "{}:{}:{}",
                identity.ssid_hex,
                identity.device_iface.unwrap_or_default(),
                identity.bssid.unwrap_or_default()
            )
        });
        let supplied_credentials = self.password.is_some() || self.enterprise.is_some();
        let credential_material = serde_json::to_vec(self)?;
        Ok(ConnectAttemptKey::new(
            identity,
            &credential_material,
            supplied_credentials,
        ))
    }

    fn validated_ssid(&self) -> Result<Vec<u8>> {
        match (&self.key, &self.target) {
            (Some(key), None) => Ok(ssid_for_network_key(key)?.as_bytes().to_vec()),
            (None, Some(target)) => {
                target.validate()?;
                Ok(target.ssid_bytes().to_vec())
            }
            (Some(_), Some(_)) => {
                bail!("connect request must provide either key or target, not both")
            }
            (None, None) => bail!("connect request must provide key or target"),
        }
    }

    fn into_request(self, nm: &Nm) -> Result<ConnectRequest> {
        if let Some(target) = self.target {
            return Ok(ConnectRequest {
                target,
                network_key: None,
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
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let target_ssid = params.validated_ssid().map_err(connect_validation_error)?;
    let attempt =
        runtime.begin_connect_attempt(params.attempt_key().map_err(connect_validation_error)?)?;
    let requested_identity = params
        .requested_identity()
        .map_err(connect_validation_error)?;
    let target_display = crate::model::display_ssid(&target_ssid);
    let network_key = params.key.clone();
    let request_id = runtime.start_cancellable(
        "connect",
        TaskKind::Connect,
        owner,
        Some(target_ssid),
        move |nm, cancel_flag, request_id| match run_connect_worker(
            nm,
            request_id,
            params,
            cancel_flag,
            &emitter,
        ) {
            Ok(outcome) => {
                let (reason, succeeded) = match &outcome {
                    ConnectOutcome::Succeeded(_) => (None, true),
                    ConnectOutcome::Failed { result, .. } => (result.reason, false),
                    ConnectOutcome::Cancelled { .. } => (None, false),
                };
                attempt.finish(reason, succeeded);
            }
            Err(error) => {
                let report = ErrorReport::from_error(&error, ErrorOperation::Connect);
                attempt.finish(report.code.connect_reason(), false);
                emit_connect_failure(&emitter, request_id, &requested_identity, &report);
            }
        },
    )?;
    tracing::info!(
        %request_id,
        ?network_key,
        ssid = %target_display,
        "accepted correlated Wi-Fi connection request"
    );
    started_response(
        Method::WifiConnectTarget,
        STREAM,
        &request_id,
        "Wi-Fi connection started; listen for Event('wifi.connect', event_json) signals",
        json!({}),
    )
}

fn connect_validation_error(error: anyhow::Error) -> anyhow::Error {
    DomainError::validation(ErrorOperation::Connect, &error)
        .with_cause(error)
        .into()
}

fn run_connect_worker(
    nm: &Nm,
    request_id: &str,
    params: DbusConnectTargetParams,
    cancel_flag: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) -> Result<ConnectOutcome> {
    let request = params.into_request(nm)?;
    Application::new(nm).connect(&request, Some(cancel_flag), |event| {
        emit_connect_event(emitter, request_id, event)
    })
}

fn emit_connect_event(
    emitter: &SignalEmitter<'static>,
    request_id: &str,
    event: &ConnectEvent,
) -> Result<()> {
    let (name, data) = match event {
        ConnectEvent::Started {
            phase,
            target,
            message,
        } => (
            "started",
            json!({
                "request_id": request_id,
                "phase": phase,
                "target": target,
                "message": message,
            }),
        ),
        ConnectEvent::Progress {
            phase,
            target,
            message,
        } => (
            "progress",
            json!({
                "request_id": request_id,
                "phase": phase,
                "target": target,
                "message": message,
            }),
        ),
        ConnectEvent::Finished {
            phase,
            target,
            outcome: ConnectOutcome::Succeeded(result),
        } => {
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
                json!({
                    "request_id": request_id,
                    "phase": phase,
                    "target": target,
                    "result": result,
                }),
            )
        }
        ConnectEvent::Finished {
            phase,
            target,
            outcome: ConnectOutcome::Failed { result, error },
        } => {
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
                    "phase": phase,
                    "target": target,
                    "result": result,
                    "reason": result.reason,
                    "message": result.message,
                    "code": error.code,
                    "details": error.api_details(),
                }),
            )
        }
        ConnectEvent::Cancelled {
            phase,
            target,
            message,
        }
        | ConnectEvent::Finished {
            phase,
            target,
            outcome: ConnectOutcome::Cancelled { message },
        } => {
            tracing::info!(%request_id, "emitting correlated Wi-Fi connection cancellation");
            (
                "cancelled",
                json!({
                    "request_id": request_id,
                    "phase": phase,
                    "target": target,
                    "message": message,
                }),
            )
        }
    };
    emit_json_event(emitter, STREAM, Some(request_id), name, data)
}

fn emit_connect_failure(
    emitter: &SignalEmitter<'static>,
    request_id: &str,
    target: &ConnectTargetIdentity,
    report: &ErrorReport,
) {
    emit_json_event_nonfatal(
        emitter,
        STREAM,
        Some(request_id),
        "failed",
        json!({
            "request_id": request_id,
            "phase": ConnectPhase::Failed,
            "target": target,
            "reason": report.code.connect_reason(),
            "code": report.code,
            "message": report.message,
            "details": report.api_details(),
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::{DbusConnectTargetParams, connect_validation_error};
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};

    #[test]
    fn opaque_key_and_legacy_target_requests_are_both_supported() {
        let keyed: DbusConnectTargetParams =
            serde_json::from_str(r#"{"key":"ssid-hex:4578616d706c65","password":"secret"}"#)
                .unwrap();
        assert_eq!(keyed.validated_ssid().unwrap(), b"Example");

        let legacy: DbusConnectTargetParams =
            serde_json::from_str(r#"{"target":{"ssid":"Example"}}"#).unwrap();
        legacy.validated_ssid().unwrap();

        let ambiguous: DbusConnectTargetParams = serde_json::from_str(
            r#"{"key":"ssid-hex:4578616d706c65","target":{"ssid":"Example"}}"#,
        )
        .unwrap();
        let error = ambiguous
            .validated_ssid()
            .map_err(connect_validation_error)
            .unwrap_err();
        let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::ValidationError);
    }
}
