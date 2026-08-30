//! VPN and WireGuard activation.
//!
//! Activation itself is type-neutral and shared with `network.activateProfile`;
//! what this module adds is the VPN-specific view a frontend needs: which saved
//! profiles are VPNs, which plugin serves them, whether activation will prompt
//! for secrets, and the plugin's own state, banner, and typed failure reason.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use super::{
    ACTIVE_CONNECTION_IFACE, DEVICE_IFACE, HealthSubject, Nm,
    inventory::active_connection_state_name,
};
use crate::error::{DomainError, ErrorOperation, check_cancellation};
use crate::model::{
    NetworkConnectionSummary, TypedReason, VpnActivationResult, VpnActiveStatus,
    VpnDisconnectResult, VpnProfileSummary, VpnStatus, active_connection_state_reason,
    device_state_reason, vpn_state_name, vpn_state_reason,
};
use crate::variant::value_string;

const VPN_CONNECTION_IFACE: &str = "org.freedesktop.NetworkManager.VPN.Connection";
const NM_VPN_STATE_ACTIVATED: u32 = 5;
const NM_VPN_STATE_FAILED: u32 = 6;
const NM_VPN_STATE_DISCONNECTED: u32 = 7;
const NM_ACTIVE_STATE_DEACTIVATING: u32 = 3;
const ACTIVATION_POLL: Duration = Duration::from_millis(200);

/// Selects one saved VPN or WireGuard profile.
#[derive(Debug, Clone, Default)]
pub(crate) struct VpnSelector {
    pub(crate) uuid: Option<String>,
    pub(crate) path: Option<String>,
}

impl Nm {
    pub(crate) fn vpn_profiles(&self) -> Result<Vec<VpnProfileSummary>> {
        let connections = self.network_connections()?;
        connections
            .iter()
            .filter(|profile| is_vpn_like(&profile.connection_type))
            .map(|profile| self.vpn_profile_summary(profile))
            .collect()
    }

    pub(crate) fn vpn_status(&self) -> Result<VpnStatus> {
        let active = self
            .network_active_connections()?
            .into_iter()
            .filter(|active| active.vpn || is_vpn_like(&active.connection_type))
            .map(|active| self.vpn_active_status(&active))
            .collect::<Result<Vec<_>>>()?;
        Ok(VpnStatus { active })
    }

    /// Activates a saved VPN/WireGuard profile and waits for the plugin to
    /// report a terminal state, so callers learn *why* a VPN failed rather than
    /// only that activation was requested.
    pub(crate) fn activate_vpn(
        &self,
        selector: &VpnSelector,
        timeout: Duration,
        cancellation: Option<&AtomicBool>,
    ) -> Result<VpnActivationResult> {
        let profile = self.select_vpn_profile(selector)?;
        let profile_path =
            OwnedObjectPath::try_from(profile.path.as_str()).context("parse VPN profile path")?;
        let root = object_path("/")?;
        tracing::info!(
            id = %profile.id,
            uuid = %profile.uuid,
            connection_type = %profile.connection_type,
            "activating saved VPN profile"
        );
        let active_path: OwnedObjectPath = self
            .root_proxy()
            .call("ActivateConnection", &(profile_path, root.clone(), root))
            .with_context(|| format!("ActivateConnection for VPN profile {}", profile.id))?;
        match self.await_vpn_activation(&active_path, &profile.id, timeout, cancellation) {
            Ok(status) => Ok(VpnActivationResult {
                status: "connected",
                message: format!("{} is connected", profile.id),
                vpn: status,
            }),
            Err(error) => {
                self.deactivate_quietly(&active_path);
                Err(error)
            }
        }
    }

    pub(crate) fn deactivate_vpn(&self, selector: &VpnSelector) -> Result<VpnDisconnectResult> {
        let active = self.vpn_status()?.active.into_iter().find(|active| {
            match (&selector.uuid, &selector.path) {
                (Some(uuid), _) => &active.uuid == uuid,
                (None, Some(path)) => {
                    &active.path == path || active.profile_path.as_ref() == Some(path)
                }
                (None, None) => true,
            }
        });
        let Some(active) = active else {
            return Ok(VpnDisconnectResult {
                status: "noop",
                message: "No matching VPN connection is active".to_string(),
                id: None,
                uuid: None,
                path: None,
            });
        };
        let path = object_path(&active.path)?;
        tracing::info!(id = %active.id, "deactivating VPN connection");
        self.root_proxy()
            .call::<_, _, ()>("DeactivateConnection", &(path,))
            .with_context(|| format!("DeactivateConnection for VPN {}", active.id))?;
        Ok(VpnDisconnectResult {
            status: "disconnected",
            message: format!("{} disconnected", active.id),
            id: Some(active.id),
            uuid: Some(active.uuid),
            path: Some(active.path),
        })
    }

    fn select_vpn_profile(&self, selector: &VpnSelector) -> Result<VpnProfileSummary> {
        let profiles = self.vpn_profiles()?;
        let matched = match (&selector.uuid, &selector.path) {
            (Some(uuid), _) => profiles.into_iter().find(|profile| &profile.uuid == uuid),
            (None, Some(path)) => profiles.into_iter().find(|profile| &profile.path == path),
            (None, None) => {
                return Err(DomainError::validation(
                    ErrorOperation::VpnOperation,
                    "vpn.connect requires uuid or path",
                )
                .into());
            }
        };
        matched.ok_or_else(|| {
            DomainError::not_found(
                ErrorOperation::VpnOperation,
                "no saved VPN or WireGuard profile matched the request",
            )
            .with_detail("uuid", selector.uuid.clone().unwrap_or_default())
            .with_detail("path", selector.path.clone().unwrap_or_default())
            .into()
        })
    }

    fn await_vpn_activation(
        &self,
        active_path: &OwnedObjectPath,
        profile_id: &str,
        timeout: Duration,
        cancellation: Option<&AtomicBool>,
    ) -> Result<VpnActiveStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            check_cancellation(
                cancellation,
                ErrorOperation::VpnOperation,
                "VPN activation was cancelled",
            )?;
            let status = self.vpn_status_for_active_path(active_path, profile_id)?;
            if let Some(error) = vpn_failure(&status) {
                return Err(error);
            }
            if vpn_is_connected(&status) {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(DomainError::timeout(
                    ErrorOperation::VpnOperation,
                    "timed out waiting for the VPN to connect",
                )
                .with_detail(
                    "vpn_state",
                    status.vpn_state_name.unwrap_or(status.active_state_name),
                )
                .into());
            }
            std::thread::sleep(ACTIVATION_POLL);
        }
    }

    fn vpn_status_for_active_path(
        &self,
        active_path: &OwnedObjectPath,
        profile_id: &str,
    ) -> Result<VpnActiveStatus> {
        let active = self
            .network_active_connections()?
            .into_iter()
            .find(|active| active.path == active_path.as_str());
        if let Some(active) = active {
            return self.vpn_active_status(&active);
        }
        if let Some(signal) = self.latest_health_signal(HealthSubject::Vpn, active_path.as_str()) {
            return Err(vpn_activation_error(
                profile_id,
                vpn_state_reason(signal.reason),
                vpn_state_name(signal.state),
            ));
        }
        Err(DomainError::new(
            crate::error::ErrorCode::ActivationFailed,
            ErrorOperation::VpnOperation,
            crate::error::ErrorSource::NetworkManager,
            "NetworkManager removed the VPN connection during activation",
        )
        .into())
    }

    fn vpn_active_status(
        &self,
        active: &crate::model::ActiveConnectionSummary,
    ) -> Result<VpnActiveStatus> {
        let settings = active
            .profile_path
            .as_deref()
            .and_then(|path| OwnedObjectPath::try_from(path).ok())
            .and_then(|path| self.connection_settings(&path).ok());
        let service_type = settings
            .as_ref()
            .and_then(|settings| settings.get("vpn"))
            .and_then(|vpn| vpn.get("service-type"))
            .and_then(value_string);
        let activated_at_ms = settings
            .as_ref()
            .and_then(|settings| settings.get("connection"))
            .and_then(|connection| connection.get("timestamp"))
            .and_then(|value| u64::try_from(value.clone()).ok())
            .map(|seconds| seconds.saturating_mul(1000));
        let (vpn_state, banner) = self.vpn_plugin_state(&active.path);
        Ok(VpnActiveStatus {
            path: active.path.clone(),
            id: active.id.clone(),
            uuid: active.uuid.clone(),
            connection_type: active.connection_type.clone(),
            plugin: plugin_name(&active.connection_type, service_type.as_deref()),
            service_type,
            banner,
            vpn_state,
            vpn_state_name: vpn_state.map(vpn_state_name),
            reason: Some(self.vpn_reason(&active.path, &active.devices, vpn_state)),
            active_state: active.state,
            active_state_name: active.state_name,
            profile_path: active.profile_path.clone(),
            specific_object: active.specific_object.clone(),
            devices: active.devices.clone(),
            activated_at_ms,
            duration_ms: activated_at_ms
                .map(|at| crate::cache::now_ms().saturating_sub(u128::from(at)) as u64),
            default4: active.default4,
            default6: active.default6,
        })
    }

    fn vpn_plugin_state(&self, active_path: &str) -> (Option<u32>, Option<String>) {
        let Ok(proxy) = self.proxy(active_path, VPN_CONNECTION_IFACE) else {
            return (None, None);
        };
        let state = proxy.get_property::<u32>("VpnState").ok();
        let banner = proxy
            .get_property::<String>("Banner")
            .ok()
            .filter(|banner| !banner.is_empty());
        (state, banner)
    }

    /// VPN plugin reason numbers belong to `VpnStateChanged`, not to the
    /// device `StateReason` enum. WireGuard has no plugin signal, so only its
    /// type-neutral fallback uses the underlying device reason.
    fn vpn_reason(
        &self,
        active_path: &str,
        devices: &[String],
        vpn_state: Option<u32>,
    ) -> TypedReason {
        if vpn_state.is_some() {
            return self
                .latest_health_signal(HealthSubject::Vpn, active_path)
                .map(|signal| vpn_state_reason(signal.reason))
                .unwrap_or_else(|| vpn_state_reason(0));
        }
        let Some(device) = devices.first() else {
            return active_connection_state_reason(0);
        };
        self.proxy(device, DEVICE_IFACE)
            .ok()
            .and_then(|proxy| proxy.get_property::<(u32, u32)>("StateReason").ok())
            .map(|(_, reason)| device_state_reason(reason))
            .unwrap_or_else(|| active_connection_state_reason(0))
    }

    fn vpn_profile_summary(&self, profile: &NetworkConnectionSummary) -> Result<VpnProfileSummary> {
        let path =
            OwnedObjectPath::try_from(profile.path.as_str()).context("parse VPN profile path")?;
        let settings = self.connection_settings(&path)?;
        let service_type = settings
            .get("vpn")
            .and_then(|vpn| vpn.get("service-type"))
            .and_then(value_string);
        let secret_names = vpn_secret_names(&settings);
        let state = profile
            .active_connection
            .as_deref()
            .and_then(|active| self.proxy(active, ACTIVE_CONNECTION_IFACE).ok())
            .and_then(|proxy| proxy.get_property::<u32>("State").ok());
        Ok(VpnProfileSummary {
            path: profile.path.clone(),
            id: profile.id.clone(),
            uuid: profile.uuid.clone(),
            connection_type: profile.connection_type.clone(),
            type_name: profile.type_name,
            plugin: plugin_name(&profile.connection_type, service_type.as_deref()),
            service_type,
            autoconnect: profile.autoconnect,
            timestamp_ms: profile.timestamp_ms,
            permissions: profile.permissions.clone(),
            requires_secrets: profile_requires_secrets(&settings),
            secret_names,
            active_connection: profile.active_connection.clone(),
            state,
            state_name: state.map(active_connection_state_name),
        })
    }

    fn deactivate_quietly(&self, active_path: &OwnedObjectPath) {
        if let Err(error) = self
            .root_proxy()
            .call::<_, _, ()>("DeactivateConnection", &(active_path.clone(),))
        {
            tracing::debug!(%error, "VPN activation was already inactive during rollback");
        }
    }
}

fn vpn_is_connected(status: &VpnActiveStatus) -> bool {
    match status.vpn_state {
        Some(state) => state == NM_VPN_STATE_ACTIVATED,
        // WireGuard has no VPN plugin; its active-connection state is the truth.
        None => status.active_state == 2,
    }
}

fn vpn_failure(status: &VpnActiveStatus) -> Option<anyhow::Error> {
    let failed = match status.vpn_state {
        Some(state) => state == NM_VPN_STATE_FAILED || state == NM_VPN_STATE_DISCONNECTED,
        None => status.active_state >= NM_ACTIVE_STATE_DEACTIVATING,
    };
    let reason = status
        .reason
        .unwrap_or_else(|| active_connection_state_reason(0));
    // A disconnect the user asked for is not an activation failure.
    if !failed || (status.vpn_state == Some(NM_VPN_STATE_DISCONNECTED) && reason.expected()) {
        return None;
    }
    Some(vpn_activation_error(
        &status.id,
        reason,
        status.vpn_state_name.unwrap_or(status.active_state_name),
    ))
}

fn vpn_activation_error(id: &str, reason: TypedReason, state_name: &str) -> anyhow::Error {
    let code = match reason.name {
        "no-secrets" => crate::error::ErrorCode::SecretRequired,
        "login-failed" => crate::error::ErrorCode::WrongPassword,
        _ => crate::error::ErrorCode::ActivationFailed,
    };
    DomainError::new(
        code,
        ErrorOperation::VpnOperation,
        crate::error::ErrorSource::NetworkManager,
        format!("{id} failed to connect"),
    )
    .with_detail("reason", reason.name)
    .with_detail("reason_category", serde_json::json!(reason.category))
    .with_detail("reason_code", reason.code)
    .with_detail("vpn_state", state_name)
    .into()
}

pub(crate) fn is_vpn_like(connection_type: &str) -> bool {
    matches!(connection_type, "vpn" | "wireguard")
}

/// Short plugin name for prompt labelling, derived from the plugin's D-Bus
/// service name so new plugins work without a table entry.
fn plugin_name(connection_type: &str, service_type: Option<&str>) -> Option<String> {
    if connection_type == "wireguard" {
        return Some("wireguard".to_string());
    }
    let service_type = service_type?;
    service_type
        .rsplit('.')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

/// Secret names a profile references, taken from the plugin's own
/// `vpn.secrets` map and `*-flags` data keys rather than a fixed list, so
/// arbitrary plugin secrets are surfaced.
fn vpn_secret_names(settings: &super::ConnectionSettings) -> Vec<String> {
    let Some(vpn) = settings.get("vpn") else {
        return wireguard_secret_names(settings);
    };
    let mut names = vpn
        .get("secrets")
        .and_then(|value| HashMap::<String, String>::try_from(value.clone()).ok())
        .map(|secrets| secrets.into_keys().collect::<Vec<_>>())
        .unwrap_or_default();
    if let Some(data) = vpn
        .get("data")
        .and_then(|value| HashMap::<String, String>::try_from(value.clone()).ok())
    {
        names.extend(
            data.keys()
                .filter_map(|key| key.strip_suffix("-flags"))
                .map(str::to_string),
        );
    }
    names.sort();
    names.dedup();
    names
}

fn wireguard_secret_names(settings: &super::ConnectionSettings) -> Vec<String> {
    let Some(wireguard) = settings.get("wireguard") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    if wireguard.contains_key("private-key") || wireguard.contains_key("private-key-flags") {
        names.push("private-key".to_string());
    }
    if wireguard.contains_key("peers") {
        names.push("preshared-key".to_string());
    }
    names
}

/// True when activating will need a SecretAgent prompt: a referenced secret is
/// agent-owned or explicitly not saved.
fn profile_requires_secrets(settings: &super::ConnectionSettings) -> bool {
    const AGENT_OWNED_OR_NOT_SAVED: u32 = 0x1 | 0x2;
    settings
        .iter()
        .filter(|(section, _)| matches!(section.as_str(), "vpn" | "wireguard"))
        .flat_map(|(_, values)| values.iter())
        .any(|(key, value)| {
            key.ends_with("-flags")
                && u32::try_from(value.clone())
                    .is_ok_and(|flags| flags & AGENT_OWNED_OR_NOT_SAVED != 0)
        })
        || settings
            .get("vpn")
            .and_then(|vpn| vpn.get("data"))
            .and_then(|value| HashMap::<String, String>::try_from(value.clone()).ok())
            .is_some_and(|data| {
                data.iter().any(|(key, value)| {
                    key.ends_with("-flags")
                        && value
                            .parse::<u32>()
                            .is_ok_and(|flags| flags & AGENT_OWNED_OR_NOT_SAVED != 0)
                })
            })
}

fn object_path(value: &str) -> Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(value.to_string())
        .with_context(|| format!("parse NetworkManager object path {value}"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use zvariant::OwnedValue;

    use super::super::{ConnectionSettings, owned_value};
    use super::{
        VpnActiveStatus, is_vpn_like, plugin_name, profile_requires_secrets, vpn_failure,
        vpn_is_connected, vpn_secret_names,
    };
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
    use crate::model::vpn_state_reason;

    fn status(vpn_state: Option<u32>, active_state: u32, reason: u32) -> VpnActiveStatus {
        VpnActiveStatus {
            path: "/active/1".to_string(),
            id: "Work VPN".to_string(),
            uuid: "uuid-1".to_string(),
            connection_type: "vpn".to_string(),
            service_type: Some("org.freedesktop.NetworkManager.openvpn".to_string()),
            plugin: Some("openvpn".to_string()),
            banner: None,
            vpn_state,
            vpn_state_name: vpn_state.map(crate::model::vpn_state_name),
            reason: Some(vpn_state_reason(reason)),
            active_state,
            active_state_name: "activating",
            profile_path: Some("/settings/2".to_string()),
            specific_object: None,
            devices: Vec::new(),
            activated_at_ms: None,
            duration_ms: None,
            default4: false,
            default6: false,
        }
    }

    fn string_map(entries: &[(&str, &str)]) -> OwnedValue {
        let map = entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<HashMap<String, String>>();
        owned_value(map).expect("string map variant")
    }

    #[test]
    fn vpn_and_wireguard_profiles_are_both_recognized() {
        assert!(is_vpn_like("vpn"));
        assert!(is_vpn_like("wireguard"));
        assert!(!is_vpn_like("802-11-wireless"));
    }

    #[test]
    fn plugin_names_come_from_the_service_name_so_new_plugins_need_no_table() {
        assert_eq!(
            plugin_name("vpn", Some("org.freedesktop.NetworkManager.openconnect")).as_deref(),
            Some("openconnect")
        );
        assert_eq!(plugin_name("wireguard", None).as_deref(), Some("wireguard"));
        assert_eq!(plugin_name("vpn", None), None);
    }

    #[test]
    fn connection_completes_on_plugin_state_and_falls_back_to_active_state() {
        assert!(vpn_is_connected(&status(Some(5), 1, 1)));
        assert!(!vpn_is_connected(&status(Some(3), 1, 1)));
        // WireGuard has no plugin state.
        assert!(vpn_is_connected(&status(None, 2, 1)));
        assert!(!vpn_is_connected(&status(None, 1, 1)));
    }

    #[test]
    fn terminal_vpn_states_map_to_typed_failure_codes() {
        // NM_VPN_CONNECTION_STATE_REASON_NO_SECRETS
        let missing_secrets = vpn_failure(&status(Some(6), 1, 9)).expect("failure");
        let report = ErrorReport::from_error(&missing_secrets, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::SecretRequired);
        assert_eq!(report.details["reason"], "no-secrets");
        assert_eq!(report.details["reason_category"], "authentication");

        let login_failed = vpn_failure(&status(Some(6), 1, 10)).expect("failure");
        assert_eq!(
            ErrorReport::from_error(&login_failed, ErrorOperation::Unknown).code,
            ErrorCode::WrongPassword
        );

        // A user-requested disconnect is not an activation failure.
        assert!(vpn_failure(&status(Some(7), 1, 2)).is_none());
        // An unexpected disconnect still is.
        assert!(vpn_failure(&status(Some(7), 1, 3)).is_some());

        assert!(vpn_failure(&status(Some(3), 1, 1)).is_none());
        assert!(vpn_failure(&status(None, 1, 1)).is_none());
    }

    #[test]
    fn secret_names_come_from_the_plugin_rather_than_a_fixed_list() {
        let mut settings = ConnectionSettings::new();
        settings.insert(
            "vpn".to_string(),
            HashMap::from([
                (
                    "secrets".to_string(),
                    string_map(&[("cookie", ""), ("gwcert", "")]),
                ),
                (
                    "data".to_string(),
                    string_map(&[("password-flags", "1"), ("service-type", "openconnect")]),
                ),
            ]),
        );
        assert_eq!(
            vpn_secret_names(&settings),
            vec![
                "cookie".to_string(),
                "gwcert".to_string(),
                "password".to_string()
            ]
        );
        assert!(profile_requires_secrets(&settings));
    }

    #[test]
    fn wireguard_keys_are_reported_as_secret_names() {
        let mut settings = ConnectionSettings::new();
        settings.insert(
            "wireguard".to_string(),
            HashMap::from([
                ("private-key-flags".to_string(), owned_value(1_u32).unwrap()),
                (
                    "peers".to_string(),
                    owned_value(Vec::<String>::new()).unwrap(),
                ),
            ]),
        );
        assert_eq!(
            vpn_secret_names(&settings),
            vec!["private-key".to_string(), "preshared-key".to_string()]
        );
        assert!(profile_requires_secrets(&settings));
    }

    #[test]
    fn a_profile_with_saved_secrets_does_not_claim_it_will_prompt() {
        let mut settings = ConnectionSettings::new();
        settings.insert(
            "vpn".to_string(),
            HashMap::from([("data".to_string(), string_map(&[("password-flags", "0")]))]),
        );
        assert!(!profile_requires_secrets(&settings));
    }
}
