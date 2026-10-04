//! Captive-portal decisions only. Browser execution and compositor intent belong to the UI.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    daemon_runtime::DaemonRuntime,
    error::{DomainError, ErrorOperation},
    model::ConnectivityStatus,
    output::api_data_value,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Mode {
    Automatic,
    Manual,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrepareParams {
    pub mode: Mode,
    #[serde(default)]
    pub connect_request_id: Option<String>,
    #[serde(default)]
    pub fallback: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Intent {
    pub launch_id: String,
    pub episode: String,
    pub url: String,
    pub reason: Mode,
    pub expires_at_ms: u64,
}

pub(crate) fn invalid(message: &str) -> anyhow::Error {
    DomainError::validation(ErrorOperation::Connectivity, message).into()
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// Reject credentials, control characters, browser pseudo-schemes and parser repairs.
// NetworkManager's configured URL is not inherently safe to pass to a browser.
fn safe_url(value: &str) -> Option<String> {
    if value.len() > 4096
        || value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return None;
    }
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return None;
    }
    let parsed = url::Url::parse(value).ok()?;
    if parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    Some(parsed.into())
}

pub(crate) fn episode(nm_owner: &str, status: &ConnectivityStatus) -> Result<String> {
    let primary = status
        .primary_connection
        .as_ref()
        .ok_or_else(|| invalid("no primary connection"))?;
    if nm_owner.is_empty() || primary.path == "/" || primary.uuid.is_empty() {
        return Err(invalid("primary connection identity is unavailable"));
    }
    // NM's unique bus owner fences restarts; the active-object path fences reconnects.
    Ok(serde_json::to_string(&(
        nm_owner,
        &primary.path,
        &primary.uuid,
    ))?)
}

pub(crate) fn validate(
    params: &PrepareParams,
    nm_owner: &str,
    status: &ConnectivityStatus,
    proof: &Value,
    now: u64,
) -> Result<Intent> {
    let episode = episode(nm_owner, status)?;
    if params.mode == Mode::Automatic {
        let current = status
            .primary_connection
            .as_ref()
            .expect("validated primary");
        let result = &proof["event"]["result"];
        let previous = &result["connectivity"]["primary_connection"];
        if params.fallback
            || !status.captive_portal
            || proof["status"] != "finished"
            || proof["stream"] != "wifi.connect"
            || proof["event"]["event"] != "succeeded"
            || result["suggest_open_portal"] != true
            || previous["path"] != current.path
            || previous["uuid"] != current.uuid
        {
            return Err(invalid(
                "automatic portal launch requires this caller's successful connect on the current captive connection",
            ));
        }
    } else if params.connect_request_id.is_some() {
        return Err(invalid(
            "manual portal launch does not take a connect request",
        ));
    }
    Ok(Intent {
        launch_id: crate::random::random_uuid_v4()?,
        episode,
        url: status
            .check_uri
            .as_deref()
            .and_then(safe_url)
            .unwrap_or_else(|| "http://neverssl.com/".into()),
        reason: params.mode,
        expires_at_ms: now.saturating_add(10_000),
    })
}

pub(crate) fn prepare(
    runtime: &DaemonRuntime,
    owner: Option<&str>,
    params: PrepareParams,
) -> Result<Value> {
    let owner = owner.ok_or_else(|| invalid("portal launch requires a transport owner"))?;
    let proof = match (&params.mode, &params.connect_request_id) {
        (Mode::Automatic, Some(id)) if !id.is_empty() && id.len() <= 256 => {
            runtime.request_status(id, Some(owner))
        }
        (Mode::Automatic, _) => {
            return Err(invalid(
                "automatic portal launch requires a connect request",
            ));
        }
        _ => Value::Null,
    };
    let (nm_owner, status) =
        runtime.call_read(ErrorOperation::Connectivity, |nm| nm.portal_snapshot())?;
    let intent = validate(&params, &nm_owner, &status, &proof, now_ms())?;
    api_data_value(
        "portal",
        &serde_json::json!({"decision": "launch", "intent": intent}),
        "serialize portal intent",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PrimaryConnectionIdentity;
    use serde_json::json;

    pub(super) fn status() -> ConnectivityStatus {
        ConnectivityStatus::from_nm_code(2).with_portal_context(
            Some("http://probe.example/check".into()),
            true,
            true,
            Some(PrimaryConnectionIdentity {
                path: "/active/1".into(),
                uuid: "profile-one".into(),
                id: "Cafe".into(),
                connection_type: "802-11-wireless".into(),
                type_name: None,
                device_iface: Some("wlan0".into()),
            }),
        )
    }
    fn params(mode: Mode) -> PrepareParams {
        PrepareParams {
            mode,
            connect_request_id: (mode == Mode::Automatic).then(|| "connect-1".into()),
            fallback: false,
        }
    }
    fn proof(status: &ConnectivityStatus) -> Value {
        json!({"status":"finished", "stream":"wifi.connect", "event":{"event":"succeeded", "result":{"suggest_open_portal":true, "connectivity":status}}})
    }
    #[test]
    fn automatic_uses_authoritative_connect_proof_and_current_network() {
        let status = status();
        let p = params(Mode::Automatic);
        assert!(validate(&p, ":1.4", &status, &proof(&status), 100).is_ok());
        assert!(validate(&p, ":1.4", &status, &Value::Null, 100).is_err());
        let mut stale = proof(&status);
        stale["event"]["result"]["connectivity"]["primary_connection"]["path"] = json!("/active/2");
        assert!(validate(&p, ":1.4", &status, &stale, 100).is_err());
        let mut full = status.clone();
        full.captive_portal = false;
        assert!(validate(&p, ":1.4", &full, &proof(&status), 100).is_err());
    }
    #[test]
    fn reconnects_and_nm_restarts_change_episode_but_names_do_not() {
        let mut status = status();
        let first = episode(":1.4", &status).unwrap();
        status.primary_connection.as_mut().unwrap().id = "Renamed".into();
        assert_eq!(first, episode(":1.4", &status).unwrap());
        assert_ne!(first, episode(":1.5", &status).unwrap());
        status.primary_connection.as_mut().unwrap().path = "/active/2".into();
        assert_ne!(first, episode(":1.4", &status).unwrap());
    }
    #[test]
    fn url_policy_never_forwards_browser_pseudo_schemes_or_credentials() {
        for value in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "--app=x",
            "http://u:p@host/",
            "http://a\\b/",
            "http://host/\n",
            "data:text/plain,a",
        ] {
            assert!(safe_url(value).is_none(), "{value}");
        }
        assert_eq!(
            safe_url("https://example.org/a?b=c").unwrap(),
            "https://example.org/a?b=c"
        );
        let mut status = status();
        status.check_uri = Some("file:///etc/passwd".into());
        let intent = validate(&params(Mode::Manual), ":1.4", &status, &Value::Null, 100).unwrap();
        assert_eq!(intent.url, "http://neverssl.com/");
        assert_eq!(intent.expires_at_ms, 10_100);
    }
    #[test]
    fn request_cannot_supply_identity_url_or_episode() {
        for extra in ["url", "identity", "episode"] {
            assert!(
                serde_json::from_value::<PrepareParams>(json!({"mode":"manual",extra:"forged"}))
                    .is_err()
            );
        }
        assert!(serde_json::from_value::<PrepareParams>(json!({"mode":"other"})).is_err());
    }
}
