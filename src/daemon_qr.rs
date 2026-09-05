use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use zbus::object_server::SignalEmitter;

use crate::daemon_connect::DbusConnectTargetParams;
use crate::daemon_runtime::DaemonRuntime;
use crate::model::{InterfaceName, Ssid, WifiConnectTarget};
use crate::output::api_data_value;
use crate::protocol::Method;
use crate::qr::{ParsedWifiQr, parse_wifi_qr};

/// A scanned QR payload. It carries a passphrase, so it is never logged and
/// never echoed back in a response or error.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QrPayloadParams {
    payload: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QrConnectParams {
    payload: String,
    #[serde(default)]
    ifname: Option<InterfaceName>,
}

pub(crate) fn call_parse(params: QrPayloadParams) -> Result<Value> {
    let parsed = parse_wifi_qr(&params.payload)?;
    tracing::info!(
        ssid_hex = %parsed.ssid_hex,
        auth = ?parsed.auth,
        hidden = parsed.hidden,
        has_password = parsed.has_password,
        "parsed a scanned Wi-Fi QR payload"
    );
    api_data_value(
        Method::WifiQrParse.spec().response_key,
        &parsed,
        "serialize Wi-Fi QR parse response JSON",
    )
}

pub(crate) fn start_connect(
    runtime: &Arc<DaemonRuntime>,
    params: QrConnectParams,
    owner: Option<String>,
    emitter: SignalEmitter<'static>,
) -> Result<Value> {
    let parsed = parse_wifi_qr(&params.payload)?;
    let connect = connect_params(&parsed, params.ifname)?;
    tracing::info!(
        ssid_hex = %parsed.ssid_hex,
        auth = ?parsed.auth,
        hidden = parsed.hidden,
        "connecting from a scanned Wi-Fi QR payload"
    );
    crate::daemon_connect::start_connect_target(runtime, connect, owner, emitter)
}

/// Builds an exact connect target from the payload. QR codes identify a network
/// by SSID rather than by an access point, so a hidden payload is marked hidden
/// and the payload's authentication becomes the key-management hint.
fn connect_params(
    parsed: &ParsedWifiQr,
    ifname: Option<InterfaceName>,
) -> Result<DbusConnectTargetParams> {
    let target = WifiConnectTarget {
        ssid: Ssid::from_display(parsed.ssid.clone())?,
        ap_path: None,
        bssid: None,
        ifname,
        device_path: None,
        connection_name: None,
        private: false,
        hidden: parsed.hidden,
        security: None,
        key_mgmt: parsed.auth.key_management_hint().map(ToString::to_string),
        enterprise: None,
        profile: Default::default(),
    };
    Ok(DbusConnectTargetParams::for_target(
        target,
        parsed.password.clone(),
        parsed.wep_key_type,
    ))
}
