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

pub(crate) fn device_state_reason(code: u32) -> TypedReason {
    use ReasonCategory as C;
    let (name, category) = match code {
        0 => ("none", C::None),
        1 => ("unknown", C::Unknown),
        2 => ("now-managed", C::Lifecycle),
        3 => ("now-unmanaged", C::Lifecycle),
        4 => ("config-failed", C::Configuration),
        5 => ("ip-config-unavailable", C::AddressAssignment),
        6 => ("ip-config-expired", C::AddressAssignment),
        7 => ("no-secrets", C::Authentication),
        8 => ("supplicant-disconnect", C::Authentication),
        9 => ("supplicant-config-failed", C::Configuration),
        10 => ("supplicant-failed", C::Authentication),
        11 => ("supplicant-timeout", C::Authentication),
        12 => ("ppp-start-failed", C::Service),
        13 => ("ppp-disconnect", C::Service),
        14 => ("ppp-failed", C::Service),
        15 => ("dhcp-start-failed", C::AddressAssignment),
        16 => ("dhcp-error", C::AddressAssignment),
        17 => ("dhcp-failed", C::AddressAssignment),
        18 => ("shared-start-failed", C::Service),
        19 => ("shared-failed", C::Service),
        20 => ("autoip-start-failed", C::AddressAssignment),
        21 => ("autoip-error", C::AddressAssignment),
        22 => ("autoip-failed", C::AddressAssignment),
        23 => ("modem-busy", C::Service),
        24 => ("modem-no-dial-tone", C::Service),
        25 => ("modem-no-carrier", C::Carrier),
        26 => ("modem-dial-timeout", C::Service),
        27 => ("modem-dial-failed", C::Service),
        28 => ("modem-init-failed", C::Service),
        29 => ("gsm-apn-failed", C::Configuration),
        30 => ("gsm-registration-not-searching", C::Service),
        31 => ("gsm-registration-denied", C::Authentication),
        32 => ("gsm-registration-timeout", C::Service),
        33 => ("gsm-registration-failed", C::Service),
        34 => ("gsm-pin-check-failed", C::Authentication),
        35 => ("firmware-missing", C::Hardware),
        36 => ("removed", C::Lifecycle),
        37 => ("sleeping", C::Lifecycle),
        38 => ("connection-removed", C::Lifecycle),
        39 => ("user-requested", C::UserRequested),
        40 => ("carrier", C::Carrier),
        41 => ("connection-assumed", C::None),
        42 => ("supplicant-available", C::None),
        43 => ("modem-not-found", C::Hardware),
        44 => ("bluetooth-failed", C::Service),
        45 => ("gsm-sim-not-inserted", C::Hardware),
        46 => ("gsm-sim-pin-required", C::Authentication),
        47 => ("gsm-sim-puk-required", C::Authentication),
        48 => ("gsm-sim-wrong", C::Authentication),
        49 => ("infiniband-mode", C::Configuration),
        50 => ("dependency-failed", C::Dependency),
        51 => ("br2684-failed", C::Service),
        52 => ("modem-manager-unavailable", C::Service),
        53 => ("ssid-not-found", C::Configuration),
        54 => ("secondary-connection-failed", C::Dependency),
        55 => ("dcb-fcoe-failed", C::Service),
        56 => ("teamd-control-failed", C::Service),
        57 => ("modem-failed", C::Hardware),
        58 => ("modem-available", C::None),
        59 => ("sim-pin-incorrect", C::Authentication),
        60 => ("new-activation", C::Lifecycle),
        61 => ("parent-changed", C::Dependency),
        62 => ("parent-managed-changed", C::Dependency),
        63 => ("ovsdb-failed", C::Service),
        64 => ("ip-address-duplicate", C::AddressAssignment),
        65 => ("ip-method-unsupported", C::Configuration),
        66 => ("sriov-configuration-failed", C::Configuration),
        67 => ("peer-not-found", C::Dependency),
        68 => ("device-handler-failed", C::Service),
        69 => ("unmanaged-by-default", C::Lifecycle),
        70 => ("unmanaged-external-down", C::Lifecycle),
        71 => ("unmanaged-link-not-init", C::Lifecycle),
        72 => ("unmanaged-quitting", C::Lifecycle),
        73 => ("unmanaged-sleeping", C::Lifecycle),
        74 => ("unmanaged-user-conf", C::Lifecycle),
        75 => ("unmanaged-user-explicit", C::Lifecycle),
        76 => ("unmanaged-user-settings", C::Lifecycle),
        77 => ("unmanaged-user-udev", C::Lifecycle),
        _ => ("unknown", C::Unknown),
    };
    TypedReason {
        code,
        name,
        category,
    }
}

pub(crate) fn active_connection_state_reason(code: u32) -> TypedReason {
    use ReasonCategory as C;
    let (name, category) = match code {
        0 => ("unknown", C::Unknown),
        1 => ("none", C::None),
        2 => ("user-disconnected", C::UserRequested),
        3 => ("device-disconnected", C::Dependency),
        4 => ("service-stopped", C::Service),
        5 => ("ip-config-invalid", C::AddressAssignment),
        6 => ("connect-timeout", C::Service),
        7 => ("service-start-timeout", C::Service),
        8 => ("service-start-failed", C::Service),
        9 => ("no-secrets", C::Authentication),
        10 => ("login-failed", C::Authentication),
        11 => ("connection-removed", C::Lifecycle),
        12 => ("dependency-failed", C::Dependency),
        13 => ("device-realize-failed", C::Hardware),
        14 => ("device-removed", C::Lifecycle),
        _ => ("unknown", C::Unknown),
    };
    TypedReason {
        code,
        name,
        category,
    }
}

pub(crate) fn vpn_state_reason(code: u32) -> TypedReason {
    use ReasonCategory as C;
    let (name, category) = match code {
        0 => ("unknown", C::Unknown),
        1 => ("none", C::None),
        2 => ("user-disconnected", C::UserRequested),
        3 => ("device-disconnected", C::Dependency),
        4 => ("service-stopped", C::Service),
        5 => ("ip-config-invalid", C::AddressAssignment),
        6 => ("connect-timeout", C::Service),
        7 => ("service-start-timeout", C::Service),
        8 => ("service-start-failed", C::Service),
        9 => ("no-secrets", C::Authentication),
        10 => ("login-failed", C::Authentication),
        11 => ("connection-removed", C::Lifecycle),
        _ => ("unknown", C::Unknown),
    };
    TypedReason {
        code,
        name,
        category,
    }
}

pub(crate) fn vpn_state_name(code: u32) -> &'static str {
    match code {
        0 => "unknown",
        1 => "prepare",
        2 => "need-auth",
        3 => "connect",
        4 => "ip-config-get",
        5 => "activated",
        6 => "failed",
        7 => "disconnected",
        _ => "unknown",
    }
}

impl TypedReason {
    /// True when the transition was expected rather than a failure.
    pub(crate) fn expected(self) -> bool {
        matches!(
            self.category,
            ReasonCategory::None | ReasonCategory::UserRequested
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ReasonCategory, active_connection_state_reason, device_state_reason, vpn_state_name,
        vpn_state_reason,
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
    fn unmapped_reason_codes_stay_typed_instead_of_panicking() {
        let reason = device_state_reason(9_999);
        assert_eq!(reason.code, 9_999);
        assert_eq!(reason.name, "unknown");
        assert_eq!(reason.category, ReasonCategory::Unknown);
    }
}
