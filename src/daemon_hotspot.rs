use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use zbus::object_server::SignalEmitter;

use crate::application::Application;
use crate::daemon_event::{OperationEvents, started_response};
use crate::daemon_runtime::{DaemonRuntime, TaskKind};
use crate::error::ErrorOperation;
use crate::model::{HotspotSecurity, WifiBand};
use crate::nm::HotspotRequest;
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

pub(crate) fn start(
    runtime: &Arc<DaemonRuntime>,
    params: HotspotStartParams,
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let request = HotspotRequest::from(params);
    let request_id = runtime.start_cancellable(
        "hotspot",
        TaskKind::Hotspot,
        owner,
        None,
        move |nm, cancellation, request_id| {
            run_hotspot_worker(nm, request_id, &request, cancellation, &emitter);
        },
    )?;
    started_response(
        Method::HotspotStart,
        STREAM,
        &request_id,
        "Hotspot start requested; listen for Event('hotspot', event_json) signals",
        json!({}),
    )
}

fn run_hotspot_worker(
    nm: &crate::nm::Nm,
    request_id: &str,
    request: &HotspotRequest,
    cancellation: &AtomicBool,
    emitter: &SignalEmitter<'static>,
) {
    let events = OperationEvents::new(emitter, STREAM, request_id);
    events.phase("started", "preparing");
    events.phase("progress", "activating");

    match Application::new(nm).start_hotspot(request, Some(cancellation)) {
        Ok(result) if cancellation.load(Ordering::Relaxed) => {
            // A late success must not leave a cancelled hotspot broadcasting.
            let stopped = Application::new(nm).stop_hotspot();
            tracing::info!(
                %request_id,
                ssid = result.hotspot.ssid.as_deref().unwrap_or("unknown"),
                stopped = stopped.is_ok(),
                "stopped hotspot that activated after cancellation"
            );
            events.cancelled("Hotspot start was cancelled");
        }
        Ok(result) => events.succeeded(&result),
        Err(error) => events.error(
            &error,
            ErrorOperation::HotspotOperation,
            "Hotspot start was cancelled",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::HotspotStartParams;

    #[test]
    fn late_cancellation_stops_the_hotspot_and_emits_only_cancelled() -> anyhow::Result<()> {
        use crate::test_support::workflows::{ACTIVE, FakeNm, Outcome, isolated};
        isolated(
            concat!(
                module_path!(),
                "::late_cancellation_stops_the_hotspot_and_emits_only_cancelled"
            ),
            || {
                let fake = FakeNm::new([Outcome::CancelOnSuccess], false)?;
                let cancellation = fake.cancellation();
                let request = serde_json::from_str::<HotspotStartParams>(
                    r#"{"ssid":"Test","passphrase":"test password"}"#,
                )?
                .into();
                let event = fake.terminal_event(|emitter| {
                    super::run_hotspot_worker(
                        &fake.nm,
                        "late-hotspot",
                        &request,
                        &cancellation,
                        &emitter,
                    )
                })?;
                assert_eq!(event["event"], "cancelled");
                assert_eq!(event["request_id"], "late-hotspot");
                let state = fake.state.lock().unwrap();
                assert_eq!(state.deactivated, [ACTIVE]);
                assert_eq!(state.deleted, 1);
                Ok(())
            },
        )
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
