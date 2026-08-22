//! Turns one NetworkManager state transition into a typed health event.
//!
//! NetworkManager reports the reason for a transition only on the signal, so
//! the reason arrives with the signal and the surrounding identity — which
//! device, which profile — is resolved here.

use anyhow::Result;
use serde::Serialize;
use zvariant::OwnedObjectPath;

use super::inventory::{active_connection_state_name, device_state_name};
use super::{ACTIVE_CONNECTION_IFACE, DEVICE_IFACE, HealthSignal, HealthSubject, Nm};
use crate::model::{
    TypedReason, active_connection_state_reason, device_state_reason, vpn_state_name,
    vpn_state_reason,
};
use crate::variant::value_string;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NetworkHealthEvent {
    /// `device`, `connection`, or `vpn`.
    pub(crate) subject: &'static str,
    pub(crate) state: u32,
    pub(crate) state_name: &'static str,
    pub(crate) previous_state: Option<u32>,
    pub(crate) previous_state_name: Option<&'static str>,
    pub(crate) reason: TypedReason,
    /// True when the transition was explicitly requested rather than a failure.
    pub(crate) user_requested: bool,
    /// True when the transition was neither requested nor an ordinary step.
    pub(crate) unexpected: bool,
    pub(crate) device_path: Option<String>,
    pub(crate) device_iface: Option<String>,
    pub(crate) device_type: Option<u32>,
    pub(crate) active_connection_path: Option<String>,
    pub(crate) profile_path: Option<String>,
    pub(crate) id: Option<String>,
    pub(crate) uuid: Option<String>,
    pub(crate) connection_type: Option<String>,
    pub(crate) at_ms: u128,
}

impl Nm {
    pub(crate) fn network_health_event(&self, signal: &HealthSignal) -> Result<NetworkHealthEvent> {
        let (state_name, previous_state_name, reason) = describe(signal);
        let mut event = NetworkHealthEvent {
            subject: signal.subject.as_str(),
            state: signal.state,
            state_name,
            previous_state: signal.previous_state,
            previous_state_name,
            reason,
            user_requested: reason.expected() && reason.name == "user-requested"
                || reason.name == "user-disconnected",
            unexpected: !reason.expected(),
            device_path: None,
            device_iface: None,
            device_type: None,
            active_connection_path: None,
            profile_path: None,
            id: None,
            uuid: None,
            connection_type: None,
            at_ms: crate::cache::now_ms(),
        };
        match signal.subject {
            HealthSubject::Device => self.describe_device(&signal.path, &mut event),
            HealthSubject::ActiveConnection | HealthSubject::Vpn => {
                self.describe_active_connection(&signal.path, &mut event)
            }
        }
        Ok(event)
    }

    fn describe_device(&self, path: &str, event: &mut NetworkHealthEvent) {
        event.device_path = Some(path.to_string());
        let Ok(device) = self.proxy(path, DEVICE_IFACE) else {
            return;
        };
        event.device_iface = device
            .get_property::<String>("Interface")
            .ok()
            .filter(|iface| !iface.is_empty());
        event.device_type = device.get_property::<u32>("DeviceType").ok();
        let active = device
            .get_property::<OwnedObjectPath>("ActiveConnection")
            .ok()
            .filter(|path| path.as_str() != "/");
        drop(device);
        if let Some(active) = active {
            self.describe_active_connection(active.as_str(), event);
        }
    }

    fn describe_active_connection(&self, path: &str, event: &mut NetworkHealthEvent) {
        event.active_connection_path = Some(path.to_string());
        let Ok(active) = self.proxy(path, ACTIVE_CONNECTION_IFACE) else {
            return;
        };
        event.id = active
            .get_property::<String>("Id")
            .ok()
            .filter(|id| !id.is_empty());
        event.uuid = active
            .get_property::<String>("Uuid")
            .ok()
            .filter(|uuid| !uuid.is_empty());
        event.connection_type = active
            .get_property::<String>("Type")
            .ok()
            .filter(|value| !value.is_empty());
        let profile = active
            .get_property::<OwnedObjectPath>("Connection")
            .ok()
            .filter(|path| path.as_str() != "/");
        let devices = active
            .get_property::<Vec<OwnedObjectPath>>("Devices")
            .unwrap_or_default();
        drop(active);
        event.profile_path = profile.as_ref().map(ToString::to_string);
        if event.device_path.is_none()
            && let Some(device) = devices.first()
        {
            event.device_path = Some(device.to_string());
            event.device_iface = self
                .proxy(device.as_str(), DEVICE_IFACE)
                .ok()
                .and_then(|proxy| proxy.get_property::<String>("Interface").ok());
        }
        if event.id.is_none()
            && let Some(profile) = profile
            && let Ok(settings) = self.connection_settings(&profile)
            && let Some(connection) = settings.get("connection")
        {
            event.id = connection.get("id").and_then(value_string);
            event.uuid = connection.get("uuid").and_then(value_string);
            event.connection_type = connection.get("type").and_then(value_string);
        }
    }
}

fn describe(signal: &HealthSignal) -> (&'static str, Option<&'static str>, TypedReason) {
    match signal.subject {
        HealthSubject::Device => (
            device_state_name(signal.state),
            signal.previous_state.map(device_state_name),
            device_state_reason(signal.reason),
        ),
        HealthSubject::ActiveConnection => (
            active_connection_state_name(signal.state),
            signal.previous_state.map(active_connection_state_name),
            active_connection_state_reason(signal.reason),
        ),
        HealthSubject::Vpn => (
            vpn_state_name(signal.state),
            signal.previous_state.map(vpn_state_name),
            vpn_state_reason(signal.reason),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::describe;
    use crate::model::reason::ReasonCategory;
    use crate::nm::{HealthSignal, HealthSubject};

    fn signal(subject: HealthSubject, state: u32, reason: u32) -> HealthSignal {
        HealthSignal {
            subject,
            path: "/object/1".to_string(),
            state,
            previous_state: Some(70),
            reason,
        }
    }

    #[test]
    fn each_subject_uses_its_own_state_and_reason_vocabulary() {
        let (state, previous, reason) = describe(&signal(HealthSubject::Device, 120, 7));
        assert_eq!(state, "failed");
        assert_eq!(previous, Some("ip-config"));
        assert_eq!(reason.name, "no-secrets");
        assert_eq!(reason.category, ReasonCategory::Authentication);

        let (state, _, reason) = describe(&signal(HealthSubject::ActiveConnection, 4, 2));
        assert_eq!(state, "deactivated");
        assert_eq!(reason.name, "user-disconnected");

        let (state, _, reason) = describe(&signal(HealthSubject::Vpn, 6, 9));
        assert_eq!(state, "failed");
        assert_eq!(reason.name, "no-secrets");
    }

    #[test]
    fn unmapped_codes_stay_typed_instead_of_being_dropped() {
        let (state, _, reason) = describe(&signal(HealthSubject::Device, 9_999, 9_999));
        assert_eq!(state, "unknown");
        assert_eq!(reason.name, "unknown");
        assert_eq!(reason.code, 9_999);
    }
}
