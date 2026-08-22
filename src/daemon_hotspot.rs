use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::Application;
use crate::daemon_event::{
    emit_cancelled_operation, emit_json_event, emit_json_event_nonfatal, next_request_id,
};
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
use crate::model::{HotspotSecurity, WifiBand};
use crate::nm::HotspotRequest;
use crate::output::api_data_value;
use crate::protocol::{Method, Stream};

const STREAM: Stream = Stream::Hotspot;

/// Hotspot start parameters. `passphrase` only ever arrives over the protected
/// D-Bus/JSON transport and is never logged or echoed into events.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct HotspotStartParams {
    ssid: Option<String>,
    passphrase: Option<String>,
    security: Option<HotspotSecurity>,
    band: Option<WifiBand>,
    channel: Option<u32>,
    hidden: bool,
    device: Option<String>,
}

impl From<HotspotStartParams> for HotspotRequest {
    fn from(params: HotspotStartParams) -> Self {
        Self {
            ssid: params.ssid.filter(|ssid| !ssid.is_empty()),
            passphrase: params.passphrase.filter(|value| !value.is_empty()),
            security: params.security.unwrap_or(HotspotSecurity::WpaPsk),
            band: params.band.unwrap_or(WifiBand::Auto),
            channel: params.channel.filter(|channel| *channel > 0),
            hidden: params.hidden,
            device: params.device.filter(|device| !device.is_empty()),
        }
    }
}

pub(crate) fn call_capabilities(runtime: &Arc<DaemonRuntime>) -> Result<Value> {
    call_hotspot(runtime, Method::HotspotCapabilities, |application| {
        application.hotspot_capabilities()
    })
}

pub(crate) fn call_status(runtime: &Arc<DaemonRuntime>) -> Result<Value> {
    call_hotspot(runtime, Method::HotspotStatus, |application| {
        application.hotspot_status()
    })
}

pub(crate) fn call_stop(runtime: &Arc<DaemonRuntime>) -> Result<Value> {
    call_hotspot(runtime, Method::HotspotStop, |application| {
        application.stop_hotspot()
    })
}

pub(crate) fn start(
    runtime: &Arc<DaemonRuntime>,
    params: HotspotStartParams,
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let request = HotspotRequest::from(params);
    let request_id = next_request_id("hotspot");
    let worker_request_id = request_id.clone();
    runtime.start_cancellable(
        request_id.clone(),
        TaskKind::Hotspot,
        owner,
        None,
        move |nm, cancellation| {
            run_hotspot_worker(nm, &worker_request_id, &request, cancellation, &emitter);
        },
    )?;
    api_data_value(
        Method::HotspotStart.spec().response_key,
        &json!({
            "status": "started",
            "request_id": request_id,
            "stream": STREAM,
            "message": "Hotspot start requested; listen for Event('hotspot', event_json) signals",
        }),
        "serialize hotspot start response JSON",
    )
}

fn call_hotspot<T>(
    runtime: &Arc<DaemonRuntime>,
    method: Method,
    operation: impl FnOnce(&Application<'_>) -> Result<T> + Send + 'static,
) -> Result<Value>
where
    T: serde::Serialize + Send + 'static,
{
    runtime.call(method.spec().operation, move |nm| {
        api_data_value(
            method.spec().response_key,
            &operation(&Application::new(nm))?,
            "serialize hotspot response JSON",
        )
    })
}

fn run_hotspot_worker(
    nm: &crate::nm::Nm,
    request_id: &str,
    request: &HotspotRequest,
    cancellation: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) {
    emit_json_event_nonfatal(
        emitter,
        STREAM,
        Some(request_id),
        "started",
        json!({ "request_id": request_id, "phase": "preparing" }),
    );
    emit_json_event_nonfatal(
        emitter,
        STREAM,
        Some(request_id),
        "progress",
        json!({ "request_id": request_id, "phase": "activating" }),
    );

    match Application::new(nm).start_hotspot(request, Some(cancellation)) {
        Ok(result) if cancellation.load(Ordering::Relaxed) => {
            // The hotspot came up after cancellation was requested; take it back
            // down so a cancelled request never leaves a radio broadcasting.
            let stopped = Application::new(nm).stop_hotspot();
            tracing::info!(
                %request_id,
                ssid = result.hotspot.ssid.as_deref().unwrap_or("unknown"),
                stopped = stopped.is_ok(),
                "stopped hotspot that activated after cancellation"
            );
            emit_cancelled(emitter, request_id);
        }
        Ok(result) => emit_json_event_nonfatal(
            emitter,
            STREAM,
            Some(request_id),
            "succeeded",
            json!({ "request_id": request_id, "phase": "complete", "result": result }),
        ),
        Err(error) => {
            let report = ErrorReport::from_error(&error, ErrorOperation::HotspotOperation);
            if report.code == ErrorCode::Cancelled {
                emit_cancelled(emitter, request_id);
                return;
            }
            let data = json!({
                "request_id": request_id,
                "phase": "failed",
                "code": report.code,
                "message": report.message,
                "details": report.api_details(),
            });
            if let Err(emit_error) =
                emit_json_event(emitter, STREAM, Some(request_id), "failed", data)
            {
                tracing::warn!(error = %crate::error::err_chain(&emit_error), "failed to emit hotspot failure");
            }
        }
    }
}

fn emit_cancelled(emitter: &SignalEmitter<'_>, request_id: &str) {
    emit_cancelled_operation(emitter, STREAM, request_id, "Hotspot start was cancelled");
}

#[cfg(test)]
mod tests {
    use super::HotspotStartParams;
    use crate::model::{HotspotSecurity, WifiBand};
    use crate::nm::HotspotRequest;

    #[test]
    fn start_params_default_to_wpa_personal_on_an_automatic_band() {
        let request = HotspotRequest::from(
            serde_json::from_str::<HotspotStartParams>("{}").expect("empty params"),
        );
        assert_eq!(request.security, HotspotSecurity::WpaPsk);
        assert_eq!(request.band, WifiBand::Auto);
        assert!(!request.hidden);
        assert!(request.ssid.is_none() && request.passphrase.is_none());
    }

    #[test]
    fn blank_strings_are_treated_as_omitted_rather_than_empty_credentials() {
        let request = HotspotRequest::from(
            serde_json::from_str::<HotspotStartParams>(
                r#"{"ssid":"","passphrase":"","device":"","channel":0}"#,
            )
            .expect("blank params"),
        );
        assert!(request.ssid.is_none());
        assert!(request.passphrase.is_none());
        assert!(request.device.is_none());
        assert!(request.channel.is_none());
    }

    #[test]
    fn insecure_security_choices_are_rejected_at_the_parameter_boundary() {
        for rejected in [
            r#"{"security":"wep"}"#,
            r#"{"security":"none"}"#,
            r#"{"security":"adhoc"}"#,
        ] {
            assert!(
                serde_json::from_str::<HotspotStartParams>(rejected).is_err(),
                "{rejected}"
            );
        }
        assert!(serde_json::from_str::<HotspotStartParams>(r#"{"security":"sae"}"#).is_ok());
    }
}
