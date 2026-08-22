//! Stable frontend names and categories for NetworkManager's numeric reason
//! codes. NetworkManager keeps the numbers stable, so clients get a typed name
//! and a coarse category instead of parsing rendered English messages.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReasonCategory {
    /// No failure: an ordinary or successful transition.
    None,
    /// The user or a client explicitly requested the transition.
    UserRequested,
    /// Wrong, missing, or rejected credentials.
    Authentication,
    /// The saved profile is invalid or incompatible with the device.
    Configuration,
    /// Radio, firmware, driver, or hardware availability.
    Hardware,
    /// Physical link/carrier availability.
    Carrier,
    /// DHCP, autoip, or address assignment.
    AddressAssignment,
    /// Shared-connection, PPP, modem, or plugin-specific service failures.
    Service,
    /// Another connection, device, or dependency went away.
    Dependency,
    /// The device or profile was removed, or NetworkManager slept.
    Lifecycle,
    /// NetworkManager reported a reason this build does not name.
    Unknown,
}

/// Stable name and category for one NetworkManager reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct TypedReason {
    pub(crate) code: u32,
    pub(crate) name: &'static str,
    pub(crate) category: ReasonCategory,
}

type ReasonSpec = (&'static str, ReasonCategory);
use ReasonCategory as C;

const DEVICE_REASONS: &[ReasonSpec] = &[
    ("none", C::None),
    ("unknown", C::Unknown),
    ("now-managed", C::Lifecycle),
    ("now-unmanaged", C::Lifecycle),
    ("config-failed", C::Configuration),
    ("ip-config-unavailable", C::AddressAssignment),
    ("ip-config-expired", C::AddressAssignment),
    ("no-secrets", C::Authentication),
    ("supplicant-disconnect", C::Authentication),
    ("supplicant-config-failed", C::Configuration),
    ("supplicant-failed", C::Authentication),
    ("supplicant-timeout", C::Authentication),
    ("ppp-start-failed", C::Service),
    ("ppp-disconnect", C::Service),
    ("ppp-failed", C::Service),
    ("dhcp-start-failed", C::AddressAssignment),
    ("dhcp-error", C::AddressAssignment),
    ("dhcp-failed", C::AddressAssignment),
    ("shared-start-failed", C::Service),
    ("shared-failed", C::Service),
    ("autoip-start-failed", C::AddressAssignment),
    ("autoip-error", C::AddressAssignment),
    ("autoip-failed", C::AddressAssignment),
    ("modem-busy", C::Service),
    ("modem-no-dial-tone", C::Service),
    ("modem-no-carrier", C::Carrier),
    ("modem-dial-timeout", C::Service),
    ("modem-dial-failed", C::Service),
    ("modem-init-failed", C::Service),
    ("gsm-apn-failed", C::Configuration),
    ("gsm-registration-not-searching", C::Service),
    ("gsm-registration-denied", C::Authentication),
    ("gsm-registration-timeout", C::Service),
    ("gsm-registration-failed", C::Service),
    ("gsm-pin-check-failed", C::Authentication),
    ("firmware-missing", C::Hardware),
    ("removed", C::Lifecycle),
    ("sleeping", C::Lifecycle),
    ("connection-removed", C::Lifecycle),
    ("user-requested", C::UserRequested),
    ("carrier", C::Carrier),
    ("connection-assumed", C::None),
    ("supplicant-available", C::None),
    ("modem-not-found", C::Hardware),
    ("bluetooth-failed", C::Service),
    ("gsm-sim-not-inserted", C::Hardware),
    ("gsm-sim-pin-required", C::Authentication),
    ("gsm-sim-puk-required", C::Authentication),
    ("gsm-sim-wrong", C::Authentication),
    ("infiniband-mode", C::Configuration),
    ("dependency-failed", C::Dependency),
    ("br2684-failed", C::Service),
    ("modem-manager-unavailable", C::Service),
    ("ssid-not-found", C::Configuration),
    ("secondary-connection-failed", C::Dependency),
    ("dcb-fcoe-failed", C::Service),
    ("teamd-control-failed", C::Service),
    ("modem-failed", C::Hardware),
    ("modem-available", C::None),
    ("sim-pin-incorrect", C::Authentication),
    ("new-activation", C::Lifecycle),
    ("parent-changed", C::Dependency),
    ("parent-managed-changed", C::Dependency),
    ("ovsdb-failed", C::Service),
    ("ip-address-duplicate", C::AddressAssignment),
    ("ip-method-unsupported", C::Configuration),
    ("sriov-configuration-failed", C::Configuration),
    ("peer-not-found", C::Dependency),
    ("device-handler-failed", C::Service),
    ("unmanaged-by-default", C::Lifecycle),
    ("unmanaged-external-down", C::Lifecycle),
    ("unmanaged-link-not-init", C::Lifecycle),
    ("unmanaged-quitting", C::Lifecycle),
    ("unmanaged-sleeping", C::Lifecycle),
    ("unmanaged-user-conf", C::Lifecycle),
    ("unmanaged-user-explicit", C::Lifecycle),
    ("unmanaged-user-settings", C::Lifecycle),
    ("unmanaged-user-udev", C::Lifecycle),
];

// VPN reasons 0..=11 intentionally share NetworkManager's active-connection
// vocabulary. Active connections add three device-realization reasons.
const ACTIVE_CONNECTION_REASONS: &[ReasonSpec] = &[
    ("unknown", C::Unknown),
    ("none", C::None),
    ("user-disconnected", C::UserRequested),
    ("device-disconnected", C::Dependency),
    ("service-stopped", C::Service),
    ("ip-config-invalid", C::AddressAssignment),
    ("connect-timeout", C::Service),
    ("service-start-timeout", C::Service),
    ("service-start-failed", C::Service),
    ("no-secrets", C::Authentication),
    ("login-failed", C::Authentication),
    ("connection-removed", C::Lifecycle),
    ("dependency-failed", C::Dependency),
    ("device-realize-failed", C::Hardware),
    ("device-removed", C::Lifecycle),
];

const VPN_REASON_COUNT: usize = 12;
const VPN_STATE_NAMES: &[&str] = &[
    "unknown",
    "prepare",
    "need-auth",
    "connect",
    "ip-config-get",
    "activated",
    "failed",
    "disconnected",
];

pub(crate) fn device_state_reason(code: u32) -> TypedReason {
    typed_reason(code, DEVICE_REASONS)
}

pub(crate) fn active_connection_state_reason(code: u32) -> TypedReason {
    typed_reason(code, ACTIVE_CONNECTION_REASONS)
}

pub(crate) fn vpn_state_reason(code: u32) -> TypedReason {
    typed_reason(code, &ACTIVE_CONNECTION_REASONS[..VPN_REASON_COUNT])
}

fn typed_reason(code: u32, specs: &[ReasonSpec]) -> TypedReason {
    let (name, category) = usize::try_from(code)
        .ok()
        .and_then(|index| specs.get(index))
        .copied()
        .unwrap_or(("unknown", C::Unknown));
    TypedReason {
        code,
        name,
        category,
    }
}

pub(crate) fn vpn_state_name(code: u32) -> &'static str {
    usize::try_from(code)
        .ok()
        .and_then(|index| VPN_STATE_NAMES.get(index))
        .copied()
        .unwrap_or("unknown")
}

impl TypedReason {
    /// True when the transition was expected rather than a failure.
    pub(crate) fn expected(self) -> bool {
        matches!(self.category, C::None | C::UserRequested)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEVICE_REASONS, ReasonCategory, active_connection_state_reason, device_state_reason,
        vpn_state_name, vpn_state_reason,
    };

    #[test]
    fn known_reason_codes_carry_stable_names_and_categories() {
        assert_eq!(device_state_reason(7).name, "no-secrets");
        assert_eq!(
            device_state_reason(7).category,
            ReasonCategory::Authentication
        );
        assert_eq!(device_state_reason(39).name, "user-requested");
        assert_eq!(
            device_state_reason(39).category,
            ReasonCategory::UserRequested
        );
        assert_eq!(device_state_reason(40).name, "carrier");
        assert!(device_state_reason(39).expected());
        assert!(!device_state_reason(7).expected());
        assert_eq!(
            active_connection_state_reason(10).category,
            ReasonCategory::Authentication
        );
        assert_eq!(vpn_state_reason(2).name, "user-disconnected");
        assert_eq!(vpn_state_name(5), "activated");
    }

    #[test]
    fn every_device_reason_table_index_preserves_its_code() {
        for (code, expected) in DEVICE_REASONS.iter().enumerate() {
            let reason = device_state_reason(code as u32);
            assert_eq!(reason.code, code as u32);
            assert_eq!((reason.name, reason.category), *expected);
        }
    }

    #[test]
    fn unmapped_codes_stay_typed_instead_of_panicking() {
        let reason = device_state_reason(9_999);
        assert_eq!(reason.code, 9_999);
        assert_eq!(reason.name, "unknown");
        assert_eq!(reason.category, ReasonCategory::Unknown);
    }
}
