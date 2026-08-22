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

#[cfg(test)]
mod tests {
    use super::{QrConnectParams, QrPayloadParams, connect_params};
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
    use crate::model::WepKeyType;
    use crate::qr::parse_wifi_qr;

    #[test]
    fn a_scanned_payload_becomes_an_exact_connect_target() {
        let parsed = parse_wifi_qr("WIFI:T:WPA;S:Cafe;P:correcthorse;H:true;;").expect("payload");
        let params = connect_params(&parsed, None).expect("connect params");
        let identity = params.requested_identity().expect("identity");
        assert_eq!(identity.ssid, "Cafe");
        assert_eq!(identity.ssid_bytes, b"Cafe".to_vec());
        assert!(identity.access_point_path.is_none());
    }

    #[test]
    fn authentication_becomes_the_key_management_hint() {
        for (payload, hint) in [
            ("WIFI:T:WPA;S:Home;P:correcthorse;;", Some("wpa-psk")),
            ("WIFI:T:SAE;S:Home;P:correcthorse;;", Some("sae")),
            ("WIFI:T:WEP;S:Home;P:abcdef0123;;", Some("wep")),
            ("WIFI:T:nopass;S:Guest;;", None),
        ] {
            let parsed = parse_wifi_qr(payload).expect(payload);
            assert_eq!(parsed.auth.key_management_hint(), hint, "{payload}");
        }
    }

    #[test]
    fn wep_payloads_carry_the_detected_key_type_through_to_the_connect_request() {
        let parsed = parse_wifi_qr("WIFI:T:WEP;S:Old;P:abcdef0123;;").expect("payload");
        assert_eq!(parsed.wep_key_type, Some(WepKeyType::Key));
        assert!(connect_params(&parsed, None).is_ok());
    }

    #[test]
    fn malformed_payloads_are_rejected_before_any_connect_work_starts() {
        let error = parse_wifi_qr("not-a-qr-code").expect_err("rejected");
        let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::ValidationError);
        assert_eq!(report.operation, ErrorOperation::QrOperation);
    }

    #[test]
    fn params_reject_unknown_fields_so_a_typo_is_not_silently_ignored() {
        assert!(serde_json::from_str::<QrPayloadParams>(r#"{"payload":"WIFI:;"}"#).is_ok());
        assert!(serde_json::from_str::<QrPayloadParams>(r#"{"paylaod":"x"}"#).is_err());
        assert!(
            serde_json::from_str::<QrConnectParams>(r#"{"payload":"WIFI:;","ifname":"wlan0"}"#)
                .is_ok()
        );
        assert!(
            serde_json::from_str::<QrConnectParams>(r#"{"payload":"WIFI:;","bssid":"x"}"#).is_err()
        );
    }
}
