//! Turns one NetworkManager state transition into a typed health event.
//!
//! NetworkManager reports the reason for a transition only on the signal, so
//! the reason arrives with the signal and the surrounding identity — which
//! device, which profile — is resolved here.

use std::time::Duration;

use anyhow::Result;
use serde::Serialize;
use zvariant::OwnedObjectPath;

use super::inventory::{active_connection_state_name, device_state_name};
use super::{ACTIVE_CONNECTION_IFACE, DEVICE_IFACE, HealthSignal, HealthSubject, Nm};
use crate::model::reason::ReasonCategory;
use crate::model::{
    TypedReason, active_connection_state_reason, device_state_reason, vpn_state_name,
    vpn_state_reason,
};
use crate::variant::value_string;

const HEALTH_FAILURE_CORRELATION_WINDOW: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HealthTransitionKind {
    Informational,
    Progress,
    Success,
    ExpectedLifecycle,
    Failure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HealthSeverity {
    Info,
    Warning,
    Error,
}

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
    pub(crate) transition_kind: HealthTransitionKind,
    pub(crate) notification_recommended: bool,
    pub(crate) severity: HealthSeverity,
    /// Ready-to-render summary for unexpected transitions. Frontends should
    /// prefer this over translating NetworkManager's numeric state themselves.
    pub(crate) message: Option<String>,
    pub(crate) suggested_actions: Vec<&'static str>,
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
        let transition_kind = classify_transition(signal, reason);
        let mut event = NetworkHealthEvent {
            subject: signal.subject.as_str(),
            state: signal.state,
            state_name,
            previous_state: signal.previous_state,
            previous_state_name,
            reason,
            user_requested: reason.expected() && reason.name == "user-requested"
                || reason.name == "user-disconnected",
            unexpected: transition_kind == HealthTransitionKind::Failure,
            transition_kind,
            notification_recommended: transition_kind == HealthTransitionKind::Failure,
            severity: transition_severity(signal, transition_kind),
            message: None,
            suggested_actions: Vec::new(),
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
        if event.notification_recommended
            && signal.subject == HealthSubject::ActiveConnection
            && event.device_path.as_deref().is_some_and(|device_path| {
                recent_detailed_device_failure(
                    self.latest_health_signal(HealthSubject::Device, device_path)
                        .as_ref(),
                )
            })
        {
            event.notification_recommended = false;
            tracing::debug!(
                active_connection = %signal.path,
                device_path = ?event.device_path,
                "deprioritized generic active-connection failure in favor of recent device failure"
            );
        }
        if event.notification_recommended {
            event.message = Some(health_message(&event));
            event.suggested_actions = suggested_actions(event.reason.category);
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

fn classify_transition(signal: &HealthSignal, reason: TypedReason) -> HealthTransitionKind {
    let expected_lifecycle =
        reason.category == ReasonCategory::UserRequested || benign_lifecycle_reason(reason.name);
    let explicit_failure = !matches!(
        reason.category,
        ReasonCategory::None | ReasonCategory::Unknown | ReasonCategory::UserRequested
    ) && !benign_lifecycle_reason(reason.name);
    match signal.subject {
        HealthSubject::Device => match signal.state {
            40..=90 => HealthTransitionKind::Progress,
            100 => HealthTransitionKind::Success,
            110 => HealthTransitionKind::Progress,
            120 if expected_lifecycle => HealthTransitionKind::ExpectedLifecycle,
            120 => HealthTransitionKind::Failure,
            10 | 20 | 30 if expected_lifecycle => HealthTransitionKind::ExpectedLifecycle,
            10 | 20 | 30 if explicit_failure => HealthTransitionKind::Failure,
            10 | 20 | 30 => HealthTransitionKind::Informational,
            _ if explicit_failure => HealthTransitionKind::Failure,
            _ => HealthTransitionKind::Informational,
        },
        HealthSubject::ActiveConnection => match signal.state {
            1 => HealthTransitionKind::Progress,
            2 => HealthTransitionKind::Success,
            3 => HealthTransitionKind::Progress,
            4 if expected_lifecycle => HealthTransitionKind::ExpectedLifecycle,
            4 if explicit_failure => HealthTransitionKind::Failure,
            4 => HealthTransitionKind::Informational,
            _ if explicit_failure => HealthTransitionKind::Failure,
            _ => HealthTransitionKind::Informational,
        },
        HealthSubject::Vpn => match signal.state {
            1..=4 => HealthTransitionKind::Progress,
            5 => HealthTransitionKind::Success,
            6 | 7 if expected_lifecycle => HealthTransitionKind::ExpectedLifecycle,
            6 | 7 => HealthTransitionKind::Failure,
            _ if explicit_failure => HealthTransitionKind::Failure,
            _ => HealthTransitionKind::Informational,
        },
    }
}

fn transition_severity(
    signal: &HealthSignal,
    transition_kind: HealthTransitionKind,
) -> HealthSeverity {
    match (transition_kind, signal.subject, signal.state) {
        (HealthTransitionKind::Failure, HealthSubject::Device, 120)
        | (HealthTransitionKind::Failure, HealthSubject::Vpn, 6) => HealthSeverity::Error,
        (HealthTransitionKind::Failure, _, _) => HealthSeverity::Warning,
        _ => HealthSeverity::Info,
    }
}

fn benign_lifecycle_reason(name: &str) -> bool {
    matches!(
        name,
        "now-managed"
            | "now-unmanaged"
            | "sleeping"
            | "new-activation"
            | "unmanaged-by-default"
            | "unmanaged-external-down"
            | "unmanaged-link-not-init"
            | "unmanaged-quitting"
            | "unmanaged-sleeping"
            | "unmanaged-user-conf"
            | "unmanaged-user-explicit"
            | "unmanaged-user-settings"
            | "unmanaged-user-udev"
    )
}

fn recent_detailed_device_failure(signal: Option<&HealthSignal>) -> bool {
    let Some(signal) = signal else {
        return false;
    };
    if signal.subject != HealthSubject::Device
        || signal.observed_at.elapsed() > HEALTH_FAILURE_CORRELATION_WINDOW
    {
        return false;
    }
    let (_, _, reason) = describe(signal);
    classify_transition(signal, reason) == HealthTransitionKind::Failure
        && reason.category != ReasonCategory::Unknown
}

fn health_message(event: &NetworkHealthEvent) -> String {
    let subject = event
        .id
        .as_deref()
        .or(event.device_iface.as_deref())
        .unwrap_or("Network connection");
    match event.reason.category {
        ReasonCategory::AddressAssignment => {
            format!("{subject} connected to Wi-Fi, but IP address assignment failed")
        }
        ReasonCategory::Authentication => {
            format!("{subject} could not authenticate with the Wi-Fi access point")
        }
        ReasonCategory::Carrier => format!("{subject} lost its wireless link"),
        ReasonCategory::Hardware => format!("{subject} failed because the radio is unavailable"),
        ReasonCategory::Configuration if event.reason.name == "ssid-not-found" => {
            format!("{subject} could not find or reach the selected Wi-Fi access point")
        }
        ReasonCategory::Configuration => {
            format!("{subject} failed because its network configuration is incompatible")
        }
        _ => format!(
            "{subject} changed to {} because of {}",
            event.state_name, event.reason.name
        ),
    }
}

fn suggested_actions(category: ReasonCategory) -> Vec<&'static str> {
    match category {
        ReasonCategory::AddressAssignment => {
            vec!["retry", "try-alternate-band", "restart-access-point"]
        }
        ReasonCategory::Authentication => vec!["check-credentials", "retry"],
        ReasonCategory::Carrier => vec!["retry", "move-closer", "try-alternate-band"],
        ReasonCategory::Hardware => vec!["enable-wifi", "check-firmware"],
        ReasonCategory::Configuration => vec!["refresh-networks", "retry"],
        _ => vec!["retry"],
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
    use std::time::{Duration, Instant};

    use super::{
        HEALTH_FAILURE_CORRELATION_WINDOW, HealthSeverity, HealthTransitionKind,
        classify_transition, describe, recent_detailed_device_failure, transition_severity,
    };
    use crate::model::reason::ReasonCategory;
    use crate::nm::{HealthSignal, HealthSubject};

    fn signal(subject: HealthSubject, state: u32, reason: u32) -> HealthSignal {
        HealthSignal {
            subject,
            path: "/object/1".to_string(),
            state,
            previous_state: Some(70),
            reason,
            observed_at: Instant::now(),
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
    fn ordinary_active_connection_progress_is_not_unexpected_with_reason_zero() {
        for state in [1, 2, 3] {
            let signal = signal(HealthSubject::ActiveConnection, state, 0);
            let (_, _, reason) = describe(&signal);
            assert_ne!(
                classify_transition(&signal, reason),
                HealthTransitionKind::Failure
            );
        }
    }

    #[test]
    fn recent_detailed_device_failures_can_own_the_notification() {
        let recent = signal(HealthSubject::Device, 120, 17);
        assert!(recent_detailed_device_failure(Some(&recent)));

        let mut stale = recent.clone();
        stale.observed_at =
            Instant::now() - HEALTH_FAILURE_CORRELATION_WINDOW - Duration::from_millis(1);
        assert!(!recent_detailed_device_failure(Some(&stale)));

        let generic = signal(HealthSubject::Device, 120, 1);
        assert!(!recent_detailed_device_failure(Some(&generic)));
        assert!(!recent_detailed_device_failure(None));
    }

    #[test]
    fn transitions_have_presentation_kind_and_severity() {
        let activated = signal(HealthSubject::ActiveConnection, 2, 0);
        let (_, _, reason) = describe(&activated);
        let kind = classify_transition(&activated, reason);
        assert_eq!(kind, HealthTransitionKind::Success);
        assert_eq!(transition_severity(&activated, kind), HealthSeverity::Info);

        let failed = signal(HealthSubject::Device, 120, 17);
        let (_, _, reason) = describe(&failed);
        let kind = classify_transition(&failed, reason);
        assert_eq!(kind, HealthTransitionKind::Failure);
        assert_eq!(transition_severity(&failed, kind), HealthSeverity::Error);
    }

    #[test]
    fn sleep_and_management_lifecycle_transitions_are_expected() {
        for (state, reason_code) in [(110, 37), (30, 37), (10, 73), (20, 2)] {
            let signal = signal(HealthSubject::Device, state, reason_code);
            let (_, _, reason) = describe(&signal);
            assert_ne!(
                classify_transition(&signal, reason),
                HealthTransitionKind::Failure,
                "{reason:?}"
            );
        }

        let removed = signal(HealthSubject::Device, 10, 36);
        let (_, _, reason) = describe(&removed);
        assert_eq!(
            classify_transition(&removed, reason),
            HealthTransitionKind::Failure
        );
    }

    #[test]
    fn terminal_states_still_use_their_failure_reason() {
        let device = signal(HealthSubject::Device, 120, 7);
        let (_, _, device_reason) = describe(&device);
        assert_eq!(
            classify_transition(&device, device_reason),
            HealthTransitionKind::Failure
        );

        let vpn = signal(HealthSubject::Vpn, 6, 9);
        let (_, _, vpn_reason) = describe(&vpn);
        assert_eq!(
            classify_transition(&vpn, vpn_reason),
            HealthTransitionKind::Failure
        );

        let connection = signal(HealthSubject::ActiveConnection, 4, 0);
        let (_, _, connection_reason) = describe(&connection);
        assert_ne!(
            classify_transition(&connection, connection_reason),
            HealthTransitionKind::Failure
        );
    }

    #[test]
    fn unmapped_codes_stay_typed_instead_of_being_dropped() {
        let (state, _, reason) = describe(&signal(HealthSubject::Device, 9_999, 9_999));
        assert_eq!(state, "unknown");
        assert_eq!(reason.name, "unknown");
        assert_eq!(reason.code, 9_999);
    }
}
