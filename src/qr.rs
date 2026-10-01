//! Wi-Fi QR payload generation and intake.
//!
//! Intake never logs the payload: a scanned code carries a passphrase.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;

use crate::error::{DomainError, ErrorOperation};
use crate::model::{WepKeyType, validate_ssid_bytes};

/// Maximum WPA passphrase length; longer values are a 64-character raw PSK.
const MAX_PASSPHRASE_CHARS: usize = 63;
const RAW_PSK_CHARS: usize = 64;
const MAX_WEP_KEY_CHARS: usize = 58;

pub(crate) fn wifi_qr_payload(
    auth_type: &str,
    ssid: &str,
    password: Option<&str>,
    hidden: bool,
) -> String {
    let password = password
        .map(|password| format!(";P:{}", wifi_qr_value(password)))
        .unwrap_or_default();
    let hidden = if hidden { ";H:true" } else { "" };
    format!(
        "WIFI:T:{};S:{}{}{};;",
        auth_type,
        wifi_qr_value(ssid),
        password,
        hidden
    )
}

/// Render only bounded, validated Wi-Fi payloads. No subprocesses, files or logs.
pub(crate) fn render_share(payload: &str) -> Result<String> {
    anyhow::ensure!(payload.len() <= 1024, "Wi-Fi QR payload is too large");
    parse_wifi_qr(payload)?;
    let code = qrcode::QrCode::new(payload.as_bytes())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(320, 320)
        .build())
}

#[cfg(test)]
mod render_tests {
    #[test]
    fn renders_validated_payloads_without_embedding_plaintext() {
        let payload = super::wifi_qr_payload("WPA", "Cafe;Guest", Some("pass:word1"), true);
        let svg = super::render_share(&payload).unwrap();
        assert!(svg.contains("<svg"));
        assert!(!svg.contains("pass:word1"));
        assert!(svg.len() < 200_000);
        assert!(super::render_share(&"x".repeat(1025)).is_err());
        assert!(super::render_share("not a Wi-Fi code").is_err());
        assert!(super::render_share("WIFI:T:nopass;S:Guest;;").is_ok());
    }
}

fn wifi_qr_value(value: &str) -> String {
    let escaped: String = value
        .chars()
        .flat_map(|ch| match ch {
            '\\' | ';' | ',' | ':' | '"' => [Some('\\'), Some(ch)],
            ch => [None, Some(ch)],
        })
        .flatten()
        .collect();
    if !value.is_empty() && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        format!("\"{escaped}\"")
    } else {
        escaped
    }
}

/// A validated `WIFI:` payload, ready to hand to a connect request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ParsedWifiQr {
    pub(crate) ssid: String,
    pub(crate) ssid_bytes: Vec<u8>,
    pub(crate) ssid_hex: String,
    /// Typed authentication: `open`, `wpa`, `sae`, or `wep`.
    pub(crate) auth: WifiQrAuth,
    /// Raw `T:` token as written in the payload.
    pub(crate) auth_token: String,
    pub(crate) hidden: bool,
    pub(crate) has_password: bool,
    /// Present only when the payload carried one; excluded from logs.
    #[serde(skip_serializing)]
    pub(crate) password: Option<String>,
    /// Set when the WEP secret is a raw key rather than a passphrase.
    pub(crate) wep_key_type: Option<WepKeyType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WifiQrAuth {
    Open,
    Wpa,
    Sae,
    Wep,
}

impl WifiQrAuth {
    pub(crate) fn key_management_hint(self) -> Option<&'static str> {
        match self {
            Self::Open => None,
            Self::Wpa => Some("wpa-psk"),
            Self::Sae => Some("sae"),
            Self::Wep => Some("wep"),
        }
    }
}

/// Parses and validates a scanned `WIFI:` payload.
///
/// The payload is never included in errors or logs, because it carries a
/// passphrase; failures name the offending field instead.
pub(crate) fn parse_wifi_qr(payload: &str) -> Result<ParsedWifiQr> {
    let body = payload
        .strip_prefix("WIFI:")
        .or_else(|| payload.strip_prefix("wifi:"))
        .ok_or_else(|| qr_error("payload is not a WIFI: code", "payload"))?;
    let mut fields = split_fields(body)?;
    let ssid = fields
        .remove("S")
        .filter(|ssid| !ssid.is_empty())
        .ok_or_else(|| qr_error("payload has no SSID", "S"))?;
    let ssid_bytes = ssid.as_bytes().to_vec();
    // The SSID validation message names the constraint, not the payload.
    validate_ssid_bytes(&ssid_bytes).map_err(|error| qr_error(format!("{error}"), "S"))?;
    let auth_token = fields.remove("T").unwrap_or_default();
    let auth = parse_auth(&auth_token)?;
    let password = fields.remove("P").filter(|value| !value.is_empty());
    validate_password(auth, password.as_deref())?;
    let wep_key_type = (auth == WifiQrAuth::Wep)
        .then(|| wep_key_type_for(password.as_deref().unwrap_or_default()));
    Ok(ParsedWifiQr {
        ssid_hex: crate::model::ssid_hex(&ssid_bytes),
        ssid,
        ssid_bytes,
        auth,
        auth_token,
        hidden: matches!(
            fields.get("H").map(String::as_str),
            Some("true") | Some("TRUE") | Some("True") | Some("1")
        ),
        has_password: password.is_some(),
        password,
        wep_key_type,
    })
}

/// Splits `key:value;` fields, honouring MECARD backslash escapes and the
/// optional quoting NetworkManager uses for hex-looking values.
fn split_fields(body: &str) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in body.chars() {
        match character {
            _ if escaped => {
                current.push(character);
                escaped = false;
            }
            '\\' => {
                // Keep escapes until after removing optional wrapper quotes, so
                // escaped literal quotes cannot be mistaken for wrappers.
                current.push(character);
                escaped = true;
            }
            ';' => {
                insert_field(&mut fields, std::mem::take(&mut current))?;
            }
            _ => current.push(character),
        }
    }
    if escaped {
        return Err(qr_error("payload ends with a dangling escape", "payload"));
    }
    insert_field(&mut fields, current)?;
    Ok(fields)
}

fn insert_field(fields: &mut BTreeMap<String, String>, field: String) -> Result<()> {
    if field.is_empty() {
        return Ok(());
    }
    let (key, value) = field
        .split_once(':')
        .ok_or_else(|| qr_error("payload contains a field without a key", "payload"))?;
    fields.insert(unescape(key), unescape(unquote(value)));
    Ok(())
}

/// NetworkManager wraps values that are entirely hex digits in quotes so they
/// are not mistaken for a raw key.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| value.chars().rev().take_while(|&ch| ch == '\\').count() % 2 == 0)
        .unwrap_or(value)
}

/// Decode escapes only after splitting fields and identifying wrapper quotes.
/// `split_fields` has already rejected dangling escapes.
fn unescape(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut escaped = false;
    for character in value.chars() {
        if character == '\\' && !escaped {
            escaped = true;
        } else {
            decoded.push(character);
            escaped = false;
        }
    }
    decoded
}

fn parse_auth(token: &str) -> Result<WifiQrAuth> {
    match token.to_ascii_uppercase().as_str() {
        "" | "NOPASS" => Ok(WifiQrAuth::Open),
        "WPA2-EAP" => Err(qr_error(
            "enterprise Wi-Fi cannot be joined from a QR code",
            "T",
        )),
        "WPA" | "WPA2" => Ok(WifiQrAuth::Wpa),
        "SAE" | "WPA3" => Ok(WifiQrAuth::Sae),
        "WEP" => Ok(WifiQrAuth::Wep),
        _ => Err(qr_error("unsupported QR authentication type", "T")),
    }
}

fn validate_password(auth: WifiQrAuth, password: Option<&str>) -> Result<()> {
    let length = password.map_or(0, |password| password.chars().count());
    let message = match (auth, password) {
        (WifiQrAuth::Open, None) => return Ok(()),
        (WifiQrAuth::Open, Some(_)) => "an open network payload must not carry a password",
        (_, None) => "payload has no password",
        (WifiQrAuth::Wpa | WifiQrAuth::Sae, Some(password))
            if (8..=MAX_PASSPHRASE_CHARS).contains(&length)
                || (length == RAW_PSK_CHARS && password.chars().all(|c| c.is_ascii_hexdigit())) =>
        {
            return Ok(());
        }
        (WifiQrAuth::Wpa | WifiQrAuth::Sae, Some(_)) => {
            "WPA passphrase must be 8-63 characters or a 64-character key"
        }
        (WifiQrAuth::Wep, Some(_)) if (1..=MAX_WEP_KEY_CHARS).contains(&length) => return Ok(()),
        (WifiQrAuth::Wep, Some(_)) => "WEP key length is not valid",
    };
    Err(qr_error(message, "P"))
}

/// WEP secrets are raw keys at the standard hex key lengths, and passphrases
/// otherwise.
fn wep_key_type_for(password: &str) -> WepKeyType {
    let length = password.chars().count();
    let hex = password.chars().all(|c| c.is_ascii_hexdigit());
    if (hex && matches!(length, 10 | 26 | 32 | 58)) || matches!(length, 5 | 13 | 16) {
        WepKeyType::Key
    } else {
        WepKeyType::Phrase
    }
}

fn qr_error(message: impl Into<String>, field: &str) -> anyhow::Error {
    DomainError::validation(ErrorOperation::QrOperation, message.into())
        .with_detail("field", field)
        .into()
}

#[cfg(test)]
mod tests {
    use super::{WifiQrAuth, parse_wifi_qr, wifi_qr_payload};
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
    use crate::model::WepKeyType;
    fn parse_error(payload: &str) -> ErrorReport {
        let error = parse_wifi_qr(payload).expect_err("rejected payload");
        ErrorReport::from_error(&error, ErrorOperation::Unknown)
    }

    #[test]
    fn generated_payloads_round_trip_through_the_parser() {
        for (ssid, password) in [
            ("Cafe;Guest", r#"pass:word1\,\""#),
            (r#""Cafe""#, r#""password""#),
            ("deadbeef", "0123456789abcdef"),
            (r#"Cafe\"#, r#"password\"#),
        ] {
            let payload = wifi_qr_payload("WPA", ssid, Some(password), true);
            let parsed = parse_wifi_qr(&payload).expect("round trip");
            assert_eq!(parsed.ssid, ssid);
            assert_eq!(parsed.password.as_deref(), Some(password));
            assert_eq!(parsed.auth, WifiQrAuth::Wpa);
            assert!(parsed.hidden);
            assert!(parsed.has_password);
        }
    }

    #[test]
    fn wrapper_quotes_are_distinct_from_escaped_literal_quotes() {
        for (payload, ssid) in [
            (r#"WIFI:S:"Cafe";;"#, "Cafe"),
            (r#"WIFI:S:"Cafe\\";;"#, r#"Cafe\"#),
            (r#"WIFI:S:"Cafe\";;"#, r#""Cafe""#),
            (r#"WIFI:S:\"Cafe";;"#, r#""Cafe""#),
        ] {
            assert_eq!(parse_wifi_qr(payload).unwrap().ssid, ssid);
        }
    }

    #[test]
    fn password_validation_preserves_length_and_encoding_boundaries() {
        for (auth, password, valid) in [
            ("nopass", String::new(), true),
            ("WPA", "a".repeat(7), false),
            ("WPA", "a".repeat(8), true),
            ("WPA", "a".repeat(63), true),
            ("WPA", "a".repeat(64), true),
            ("WPA", "g".repeat(64), false),
            ("WPA", "a".repeat(65), false),
            ("SAE", "é".repeat(8), true),
            ("WEP", "a".repeat(58), true),
            ("WEP", "a".repeat(59), false),
        ] {
            let payload = wifi_qr_payload(auth, "Cafe", Some(&password), false);
            assert_eq!(
                parse_wifi_qr(&payload).is_ok(),
                valid,
                "{auth}, {} characters",
                password.chars().count()
            );
        }
    }

    #[test]
    fn wpa3_and_wep_authentication_map_to_key_management_hints() {
        assert_eq!(
            parse_wifi_qr("WIFI:T:SAE;S:Home;P:correcthorse;;")
                .expect("sae payload")
                .auth
                .key_management_hint(),
            Some("sae")
        );
        let wep = parse_wifi_qr("WIFI:T:WEP;S:Old;P:abcdef0123;;").expect("wep payload");
        assert_eq!(wep.auth.key_management_hint(), Some("wep"));
        assert_eq!(wep.wep_key_type, Some(WepKeyType::Key));

        let phrase = parse_wifi_qr("WIFI:T:WEP;S:Old;P:a longer phrase;;").expect("wep phrase");
        assert_eq!(phrase.wep_key_type, Some(WepKeyType::Phrase));
    }

    #[test]
    fn malformed_and_unsupported_payloads_are_typed_validation_errors() {
        for (payload, field) in [
            ("not-a-qr-code", "payload"),
            ("WIFI:T:WPA;P:correcthorse;;", "S"),
            ("WIFI:T:WPA-EAP;S:Campus;P:correcthorse;;", "T"),
            ("WIFI:T:WPA2-EAP;S:Campus;P:correcthorse;;", "T"),
            ("WIFI:T:WPA;S:Home;;", "P"),
            ("WIFI:T:nopass;S:Guest;P:unexpected;;", "P"),
            ("WIFI:T:WPA;S:Home;P:short;;", "P"),
            ("WIFI:S:Home;nokey;;", "payload"),
            ("WIFI:T:WPA;S:Home;P:correcthorse;\\", "payload"),
        ] {
            let report = parse_error(payload);
            assert_eq!(report.code, ErrorCode::ValidationError, "{payload}");
            assert_eq!(report.operation, ErrorOperation::QrOperation, "{payload}");
            assert_eq!(report.details["field"], field, "{payload}");
        }
    }

    #[test]
    fn rejected_payloads_never_echo_the_secret_back() {
        let report = parse_error("WIFI:T:WPA;S:Home;P:hunter2;;");
        assert!(!report.message.contains("hunter2"));
        assert!(!format!("{:?}", report.details).contains("hunter2"));
    }

    #[test]
    fn parsed_payloads_do_not_serialize_the_password() {
        let parsed = parse_wifi_qr("WIFI:T:WPA;S:Home;P:correcthorse;;").expect("payload");
        let value = serde_json::to_value(&parsed).expect("serialize");
        assert_eq!(value["has_password"], true);
        assert!(value.get("password").is_none());
    }
}
