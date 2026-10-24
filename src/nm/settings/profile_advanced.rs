//! Advanced Wi-Fi profile fields: reading them back for the editor, writing
//! them without disturbing settings the frontend did not send, and the
//! optimistic-concurrency token that stops a stale editor overwriting a
//! profile someone else changed.

use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use zvariant::{DynamicType, OwnedValue, Value};

use crate::error::{DomainError, ErrorOperation};
use crate::model::{
    ProfileEnterpriseSettings, ProfileEnterpriseUpdate, SecretFlags, WifiBand,
    WifiProfileAdvancedUpdate,
};
use crate::variant::{
    ConnectionSettings, insert_optional_value, insert_optional_values, owned_value, setting,
    setting_strings as strings, setting_text,
};

const WIRELESS: &str = "802-11-wireless";
const ENTERPRISE: &str = "802-1x";
const CONNECTION: &str = "connection";

/// Settings that change on their own and must not invalidate a version token.
const VOLATILE_CONNECTION_KEYS: [&str; 1] = ["timestamp"];

/// Derives a stable optimistic-concurrency token from the saved settings.
///
/// Secrets are never included: `GetSettings` already elides them, and a token
/// that changed when a secret changed would leak that a secret changed.
pub(super) fn profile_version(settings: &ConnectionSettings) -> String {
    let canonical = settings
        .iter()
        .map(|(section, values)| {
            let values = values
                .iter()
                .filter(|(key, _)| {
                    section != CONNECTION || !VOLATILE_CONNECTION_KEYS.contains(&key.as_str())
                })
                .map(|(key, value)| (key, format!("{value:?}")))
                .collect::<BTreeMap<_, _>>();
            (section, values)
        })
        .collect::<BTreeMap<_, _>>();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (section, values) in canonical {
        hash = section.bytes().fold(hash, fnv1a);
        for (key, value) in values {
            hash = key.bytes().chain(value.bytes()).fold(hash, fnv1a);
        }
    }
    format!("{hash:016x}")
}

fn fnv1a(hash: u64, byte: u8) -> u64 {
    (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
}

/// Fails the update when the profile changed since the frontend read it.
pub(super) fn check_expected_version(
    settings: &ConnectionSettings,
    expected: Option<&str>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let current = profile_version(settings);
    if current == expected {
        return Ok(());
    }
    Err(DomainError::conflict(
        ErrorOperation::ProfileOperation,
        "the saved profile changed since it was read; reload it and retry",
    )
    .with_detail("expected_version", expected)
    .with_detail("current_version", current)
    .into())
}

pub(super) fn read_enterprise(settings: &ConnectionSettings) -> Option<ProfileEnterpriseSettings> {
    let section = settings.get(ENTERPRISE)?;
    Some(ProfileEnterpriseSettings {
        eap: strings(section, "eap"),
        identity: text(section, "identity"),
        anonymous_identity: text(section, "anonymous-identity"),
        domain_suffix_match: text(section, "domain-suffix-match"),
        domain_match: text(section, "domain-match"),
        subject_match: text(section, "subject-match"),
        altsubject_matches: strings(section, "altsubject-matches"),
        ca_cert: blob(section, "ca-cert"),
        ca_path: text(section, "ca-path"),
        phase2_ca_path: text(section, "phase2-ca-path"),
        system_ca_certs: setting(section, "system-ca-certs").unwrap_or(false),
        client_cert: blob(section, "client-cert"),
        private_key: blob(section, "private-key"),
        phase1_peapver: text(section, "phase1-peapver"),
        phase1_peaplabel: text(section, "phase1-peaplabel"),
        phase1_fast_provisioning: text(section, "phase1-fast-provisioning"),
        phase1_auth_flags: setting(section, "phase1-auth-flags"),
        phase2_auth: text(section, "phase2-auth"),
        phase2_autheap: text(section, "phase2-autheap"),
        phase2_ca_cert: blob(section, "phase2-ca-cert"),
        phase2_client_cert: blob(section, "phase2-client-cert"),
        phase2_private_key: blob(section, "phase2-private-key"),
        phase2_domain_suffix_match: text(section, "phase2-domain-suffix-match"),
        phase2_subject_match: text(section, "phase2-subject-match"),
        phase2_altsubject_matches: strings(section, "phase2-altsubject-matches"),
        pac_file: text(section, "pac-file"),
        password_flags: secret_flags(section, "password-flags"),
        private_key_password_flags: secret_flags(section, "private-key-password-flags"),
        phase2_private_key_password_flags: secret_flags(
            section,
            "phase2-private-key-password-flags",
        ),
        ca_cert_password_flags: secret_flags(section, "ca-cert-password-flags"),
        client_cert_password_flags: secret_flags(section, "client-cert-password-flags"),
        pin_flags: secret_flags(section, "pin-flags"),
    })
}

pub(super) fn apply_advanced(
    settings: &mut ConnectionSettings,
    update: &WifiProfileAdvancedUpdate,
) -> Result<()> {
    apply_connection_fields(settings, update)?;
    apply_wireless_fields(settings, update)?;
    apply_ip_fields(settings, update)?;
    if let Some(enterprise) = &update.enterprise {
        apply_enterprise(settings, enterprise)?;
    }
    crate::nm::profile_policy::validate_private_ca_paths(settings, ErrorOperation::ProfileOperation)
}

fn apply_connection_fields(
    settings: &mut ConnectionSettings,
    update: &WifiProfileAdvancedUpdate,
) -> Result<()> {
    let connection = settings.entry(CONNECTION.to_string()).or_default();
    insert_optional_value(
        connection,
        "autoconnect-priority",
        update.autoconnect_priority,
    )?;
    set_clearable(connection, "zone", update.firewall_zone.as_deref())?;
    set_clearable(connection, "permissions", update.permissions.as_deref())?;
    set_clearable(connection, "secondaries", update.secondaries.as_deref())?;
    if let Some(enabled) = update.casting_enabled {
        super::set_casting_enabled(settings, enabled)?;
    }
    Ok(())
}

fn apply_wireless_fields(
    settings: &mut ConnectionSettings,
    update: &WifiProfileAdvancedUpdate,
) -> Result<()> {
    validate_wireless_update(update)?;
    let wireless = settings.entry(WIRELESS.to_string()).or_default();
    set_clearable(wireless, "bssid", update.bssid.as_deref())?;
    set_clearable(wireless, "mac-address", update.mac_address.as_deref())?;
    set_clearable(wireless, "mode", update.mode.as_deref())?;
    apply_cloned_address(wireless, update.cloned_mac_address.as_deref())?;
    insert_optional_value(wireless, "mtu", update.mtu)?;
    apply_band(wireless, update.band)?;
    set_clearable(wireless, "channel", update.channel)
}

fn validate_wireless_update(update: &WifiProfileAdvancedUpdate) -> Result<()> {
    if let Some(mode) = &update.mode {
        validate_mode(mode)?;
    }
    let Some((band, channel)) = update.band.zip(update.channel) else {
        return Ok(());
    };
    if band == WifiBand::Auto || channel == 0 || crate::model::channel_is_in_band(channel, band) {
        return Ok(());
    }
    Err(DomainError::validation(
        ErrorOperation::ProfileOperation,
        "channel does not belong to the selected band",
    )
    .with_detail("field", "advanced.channel")
    .into())
}

fn apply_cloned_address(
    wireless: &mut HashMap<String, OwnedValue>,
    cloned: Option<&str>,
) -> Result<()> {
    let Some(cloned) = cloned else {
        return Ok(());
    };
    // A literal cloned MAC and its keyword policy occupy the same property.
    wireless.remove("cloned-mac-address");
    wireless.remove("mac-address-randomization");
    set_clearable(wireless, "assigned-mac-address", Some(cloned))
}

fn apply_band(wireless: &mut HashMap<String, OwnedValue>, band: Option<WifiBand>) -> Result<()> {
    let Some(band) = band else {
        return Ok(());
    };
    if let Some(value) = band.nm_value() {
        wireless.insert("band".to_string(), owned_value(value)?);
    } else {
        wireless.remove("band");
        wireless.remove("channel");
    }
    Ok(())
}

fn apply_ip_fields(
    settings: &mut ConnectionSettings,
    update: &WifiProfileAdvancedUpdate,
) -> Result<()> {
    let ipv4 = settings.entry("ipv4".to_string()).or_default();
    set_clearable(
        ipv4,
        "dhcp-client-id",
        update.ipv4_dhcp_client_id.as_deref(),
    )?;
    set_clearable(ipv4, "dhcp-hostname", update.ipv4_dhcp_hostname.as_deref())?;
    insert_optional_values(
        ipv4,
        [
            ("never-default", update.ipv4_never_default),
            ("ignore-auto-routes", update.ipv4_ignore_auto_routes),
            ("may-fail", update.ipv4_may_fail),
        ],
    )?;
    insert_optional_value(ipv4, "dad-timeout", update.ipv4_dad_timeout)?;

    let ipv6 = settings.entry("ipv6".to_string()).or_default();
    insert_optional_values(
        ipv6,
        [
            ("never-default", update.ipv6_never_default),
            ("ignore-auto-routes", update.ipv6_ignore_auto_routes),
            ("may-fail", update.ipv6_may_fail),
        ],
    )?;
    if let Some(privacy) = update.ipv6_privacy {
        if !(-1..=2).contains(&privacy) {
            return Err(DomainError::validation(
                ErrorOperation::ProfileOperation,
                "ipv6_privacy must be -1, 0, 1, or 2",
            )
            .with_detail("field", "advanced.ipv6_privacy")
            .into());
        }
        insert_optional_value(ipv6, "ip6-privacy", Some(privacy))?;
    }
    Ok(())
}

fn apply_enterprise(
    settings: &mut ConnectionSettings,
    update: &ProfileEnterpriseUpdate,
) -> Result<()> {
    validate_eap_methods(update.eap.as_deref())?;
    crate::nm::profile_policy::validate_peaplabel(
        update.phase1_peaplabel.as_deref(),
        ErrorOperation::ProfileOperation,
    )?;
    let section = settings.entry(ENTERPRISE.to_string()).or_default();
    set_clearable(section, "eap", update.eap.as_deref())?;
    set_clearable(
        section,
        "altsubject-matches",
        update.altsubject_matches.as_deref(),
    )?;
    set_clearable(
        section,
        "phase2-altsubject-matches",
        update.phase2_altsubject_matches.as_deref(),
    )?;
    for (key, value) in [
        ("identity", &update.identity),
        ("anonymous-identity", &update.anonymous_identity),
        ("domain-suffix-match", &update.domain_suffix_match),
        ("domain-match", &update.domain_match),
        ("subject-match", &update.subject_match),
        ("ca-path", &update.ca_path),
        ("phase2-ca-path", &update.phase2_ca_path),
        ("phase1-peapver", &update.phase1_peapver),
        ("phase1-peaplabel", &update.phase1_peaplabel),
        ("phase1-fast-provisioning", &update.phase1_fast_provisioning),
        ("phase2-auth", &update.phase2_auth),
        ("phase2-autheap", &update.phase2_autheap),
        (
            "phase2-domain-suffix-match",
            &update.phase2_domain_suffix_match,
        ),
        ("phase2-subject-match", &update.phase2_subject_match),
        ("pac-file", &update.pac_file),
    ] {
        set_clearable(section, key, value.as_deref())?;
    }
    for (key, value) in [
        ("ca-cert", &update.ca_cert),
        ("client-cert", &update.client_cert),
        ("private-key", &update.private_key),
        ("phase2-ca-cert", &update.phase2_ca_cert),
        ("phase2-client-cert", &update.phase2_client_cert),
        ("phase2-private-key", &update.phase2_private_key),
    ] {
        crate::nm::profile_policy::set_certificate_reference(
            section,
            key,
            value.as_deref(),
            ErrorOperation::ProfileOperation,
        )?;
    }
    insert_optional_value(section, "system-ca-certs", update.system_ca_certs)?;
    insert_optional_values(
        section,
        [
            ("phase1-auth-flags", update.phase1_auth_flags),
            ("password-flags", update.password_flags),
            (
                "private-key-password-flags",
                update.private_key_password_flags,
            ),
            (
                "phase2-private-key-password-flags",
                update.phase2_private_key_password_flags,
            ),
            ("ca-cert-password-flags", update.ca_cert_password_flags),
            (
                "client-cert-password-flags",
                update.client_cert_password_flags,
            ),
            ("pin-flags", update.pin_flags),
        ],
    )
}

fn validate_mode(mode: &str) -> Result<()> {
    if matches!(mode, "" | "infrastructure" | "ap" | "mesh") {
        return Ok(());
    }
    // Ad-hoc is deliberately excluded: it has no modern secure ciphersuite.
    Err(DomainError::validation(
        ErrorOperation::ProfileOperation,
        "Wi-Fi mode must be infrastructure, ap, or mesh",
    )
    .with_detail("field", "advanced.mode")
    .with_detail("value", mode)
    .into())
}

fn validate_eap_methods(eap: Option<&[String]>) -> Result<()> {
    const SUPPORTED: [&str; 7] = ["tls", "peap", "ttls", "pwd", "leap", "fast", "md5"];
    let Some(eap) = eap else {
        return Ok(());
    };
    if let Some(unsupported) = eap
        .iter()
        .find(|method| !SUPPORTED.contains(&method.as_str()))
    {
        return Err(DomainError::validation(
            ErrorOperation::ProfileOperation,
            "unsupported 802.1X EAP method",
        )
        .with_detail("field", "advanced.enterprise.eap")
        .with_detail("value", unsupported.as_str())
        .into());
    }
    Ok(())
}

/// For editor fields whose default means clear (empty text/list, channel zero).
/// Absent preserves. Other scalars use `insert_optional_value`: zero/false are values.
fn set_clearable<'a, T>(
    section: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<T>,
) -> Result<()>
where
    T: Into<Value<'a>> + DynamicType + Default + PartialEq,
{
    let Some(value) = value else {
        return Ok(());
    };
    if value == T::default() {
        section.remove(key);
    } else {
        section.insert(key.to_string(), owned_value(value)?);
    }
    Ok(())
}

fn text(section: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    setting_text(section, key).filter(|value| !value.is_empty())
}

/// Certificate and key properties are byte arrays; NetworkManager stores URIs
/// NUL-terminated, and DER blobs that are not valid UTF-8 are reported as a
/// stable marker instead of mangled text.
fn blob(section: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    let bytes: Vec<u8> = crate::variant::value_list(section.get(key)?)?;
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(&bytes);
    if bytes.is_empty() {
        return None;
    }
    match std::str::from_utf8(bytes) {
        Ok(value) => Some(value.to_string()),
        Err(_) => Some(format!("blob:{} bytes", bytes.len())),
    }
}

fn secret_flags(section: &HashMap<String, OwnedValue>, key: &str) -> SecretFlags {
    SecretFlags::from_code(setting(section, key).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::{apply_advanced, check_expected_version, profile_version, validate_mode};
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
    use crate::model::{ProfileEnterpriseUpdate, WifiBand, WifiProfileAdvancedUpdate};
    use crate::variant::{ConnectionSettings, owned_value, setting, value_map};
    use serde_json::json;

    fn settings() -> ConnectionSettings {
        ConnectionSettings::from([(
            "connection".to_string(),
            value_map([
                ("id", "Example".into()),
                ("timestamp", 1_762_000_000_u64.into()),
            ])
            .unwrap(),
        )])
    }
    #[test]
    fn security_policy_rejects_unsafe_modes_eap_and_ca_settings_and_allows_explicit_repair() {
        assert!(validate_mode("infrastructure").is_ok());
        assert!(validate_mode("ap").is_ok());
        assert!(validate_mode("adhoc").is_err());
        for update in [
            json!({"enterprise": {"eap": ["tls", "not-a-method"]}}),
            json!({"enterprise": {"ca_cert": "/etc/ssl/ca.pem"}}),
            json!({"enterprise": {"phase1_peaplabel": "2"}}),
            json!({"mode": "adhoc"}),
            json!({"ipv6_privacy": 3}),
            json!({"band": "2.4", "channel": 36}),
        ] {
            let update = serde_json::from_value(update).unwrap();
            let error = apply_advanced(&mut settings(), &update).unwrap_err();
            assert_eq!(
                ErrorReport::from_error(&error, ErrorOperation::Unknown).code,
                ErrorCode::ValidationError
            );
        }
        let mut peap = settings();
        for (label, expected) in [(Some("0"), Some("0")), (None, Some("0")), (Some(""), None)] {
            apply_advanced(
                &mut peap,
                &WifiProfileAdvancedUpdate {
                    enterprise: Some(ProfileEnterpriseUpdate {
                        phase1_peaplabel: label.map(str::to_owned),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
            let enterprise = super::read_enterprise(&peap).unwrap();
            assert_eq!(enterprise.phase1_peaplabel.as_deref(), expected);
        }
        for (nm_key, api_key) in [("ca-path", "ca_path"), ("phase2-ca-path", "phase2_ca_path")] {
            let mut original = settings();
            original.insert(
                "802-1x".into(),
                value_map([(nm_key, "/home/user/custom-ca".into())]).unwrap(),
            );
            apply_advanced(&mut original, &WifiProfileAdvancedUpdate::default()).unwrap();
            let permissions = vec!["user:alice:".to_string()];
            let private = WifiProfileAdvancedUpdate {
                permissions: Some(permissions.clone()),
                ..Default::default()
            };
            let mut changed = original.clone();
            let error = apply_advanced(&mut changed, &private).unwrap_err();
            let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
            assert_eq!(report.code, ErrorCode::ValidationError);
            assert_eq!(report.details["field"], format!("802-1x.{nm_key}"));

            // Turning on system CA trust alone is not a portable directory
            // override: NM can be built with a CA bundle instead of a directory.
            changed
                .get_mut("802-1x")
                .unwrap()
                .insert("system-ca-certs".into(), owned_value(true).unwrap());
            assert!(apply_advanced(&mut changed, &WifiProfileAdvancedUpdate::default()).is_err());
            assert!(
                crate::nm::wifi_settings::apply_target_connection_metadata(
                    &mut changed,
                    &crate::model::example_connect_target(false),
                )
                .is_err(),
                "activation validates effective saved privacy too"
            );

            let update: WifiProfileAdvancedUpdate = serde_json::from_value(serde_json::json!({
                "permissions": permissions,
                "enterprise": { (api_key): "", "system_ca_certs": true }
            }))
            .unwrap();
            apply_advanced(&mut original, &update).unwrap();
            let enterprise = super::read_enterprise(&original).unwrap();
            assert!(enterprise.ca_path.is_none() && enterprise.phase2_ca_path.is_none());
            assert!(enterprise.system_ca_certs);
        }
    }

    #[test]
    fn advanced_updates_preserve_unsent_fields_and_can_clear_restrictions() {
        let mut settings = settings();
        let version = profile_version(&settings);
        assert!(check_expected_version(&settings, Some(&version)).is_ok());
        let update = serde_json::from_value(json!({
            "autoconnect_priority": 30, "casting_enabled": true,
            "permissions": ["user:alice:"], "firewall_zone": "home",
            "bssid": "00:11:22:33:44:55", "mtu": 1400,
            "band": "5", "channel": 36, "ipv6_privacy": 2, "ipv4_may_fail": false
        }))
        .unwrap();
        apply_advanced(&mut settings, &update).expect("advanced update");
        let conflict = check_expected_version(&settings, Some(&version)).unwrap_err();
        let report = ErrorReport::from_error(&conflict, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::Conflict);
        assert_eq!(
            report.details["current_version"],
            profile_version(&settings)
        );

        let connection = &settings["connection"];
        assert_eq!(setting::<i32>(connection, "autoconnect-priority"), Some(30));
        assert!(connection.contains_key("id"), "unsent fields are preserved");
        assert!(
            !connection.contains_key("secondaries"),
            "unsent fields are not created"
        );
        assert_eq!(i32::try_from(&connection["mdns"]).unwrap(), 1);
        assert_eq!(super::strings(connection, "permissions"), ["user:alice:"]);
        assert_eq!(super::text(connection, "zone").as_deref(), Some("home"));
        let wireless = &settings["802-11-wireless"];
        assert_eq!(
            setting::<&str>(wireless, "bssid"),
            Some("00:11:22:33:44:55")
        );
        assert_eq!(<&str>::try_from(&wireless["band"]).unwrap(), "a");
        assert_eq!(u32::try_from(&wireless["channel"]).unwrap(), 36);
        assert!(!bool::try_from(&settings["ipv4"]["may-fail"]).unwrap());
        assert_eq!(i32::try_from(&settings["ipv6"]["ip6-privacy"]).unwrap(), 2);

        let version = profile_version(&settings);
        apply_advanced(&mut settings, &WifiProfileAdvancedUpdate::default()).unwrap();
        assert_eq!(
            profile_version(&settings),
            version,
            "unsent fields must survive"
        );
        for (band, channel) in [(WifiBand::Ghz5, Some(0)), (WifiBand::Auto, None)] {
            apply_advanced(&mut settings, &update).unwrap();
            let update = serde_json::from_value(json!({
                "bssid": "", "firewall_zone": "", "permissions": [], "band": band, "channel": channel
            }))
            .unwrap();
            apply_advanced(&mut settings, &update).expect("clearing update");
            let wireless = &settings["802-11-wireless"];
            assert_eq!(super::text(wireless, "band").as_deref(), band.nm_value());
            assert!(!wireless.contains_key("bssid"));
            assert!(!wireless.contains_key("channel"));
            assert!(!settings["connection"].contains_key("permissions"));
            assert!(!settings["connection"].contains_key("zone"));
        }
    }
}
