//! Advanced Wi-Fi profile fields: reading them back for the editor, writing
//! them without disturbing settings the frontend did not send, and the
//! optimistic-concurrency token that stops a stale editor overwriting a
//! profile someone else changed.

use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use zvariant::OwnedValue;

use super::super::{ConnectionSettings, owned_value};
use crate::error::{DomainError, ErrorOperation};
use crate::model::{
    ProfileEnterpriseSettings, ProfileEnterpriseUpdate, SecretFlags, WifiBand,
    WifiProfileAdvancedUpdate,
};
use crate::variant::insert_optional_value;

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
                .map(|(key, value)| (key.clone(), format!("{value:?}")))
                .collect::<BTreeMap<_, _>>();
            (section.clone(), values)
        })
        .collect::<BTreeMap<_, _>>();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (section, values) in &canonical {
        for byte in section.as_bytes() {
            hash = fnv1a(hash, *byte);
        }
        for (key, value) in values {
            for byte in key.as_bytes().iter().chain(value.as_bytes()) {
                hash = fnv1a(hash, *byte);
            }
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
        system_ca_certs: flag(section, "system-ca-certs"),
        client_cert: blob(section, "client-cert"),
        private_key: blob(section, "private-key"),
        phase1_peapver: text(section, "phase1-peapver"),
        phase1_peaplabel: text(section, "phase1-peaplabel"),
        phase1_fast_provisioning: text(section, "phase1-fast-provisioning"),
        phase1_auth_flags: number(section, "phase1-auth-flags"),
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
    match &update.enterprise {
        Some(enterprise) => apply_enterprise(settings, enterprise),
        None => Ok(()),
    }
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
    set_clearable_text(connection, "zone", update.firewall_zone.as_deref())?;
    set_list(connection, "permissions", update.permissions.as_deref())?;
    set_list(connection, "secondaries", update.secondaries.as_deref())?;
    Ok(())
}

fn apply_wireless_fields(
    settings: &mut ConnectionSettings,
    update: &WifiProfileAdvancedUpdate,
) -> Result<()> {
    if let Some(mode) = &update.mode {
        validate_mode(mode)?;
    }
    if let Some(band) = update.band
        && band != WifiBand::Auto
        && update.channel.is_some_and(|channel| channel > 0)
        && !crate::model::channel_is_in_band(update.channel.unwrap_or(0), band)
    {
        return Err(DomainError::validation(
            ErrorOperation::ProfileOperation,
            "channel does not belong to the selected band",
        )
        .with_detail("field", "advanced.channel")
        .into());
    }
    let wireless = settings.entry(WIRELESS.to_string()).or_default();
    set_clearable_text(wireless, "bssid", update.bssid.as_deref())?;
    set_clearable_text(wireless, "mac-address", update.mac_address.as_deref())?;
    set_clearable_text(wireless, "mode", update.mode.as_deref())?;
    // A literal cloned MAC and the keyword policy occupy the same property, so
    // an exact address written here has to win over the policy applied earlier.
    if let Some(cloned) = update.cloned_mac_address.as_deref() {
        wireless.remove("cloned-mac-address");
        wireless.remove("mac-address-randomization");
        set_clearable_text(wireless, "assigned-mac-address", Some(cloned))?;
    }
    insert_optional_value(wireless, "mtu", update.mtu)?;
    if let Some(band) = update.band {
        match band.nm_value() {
            Some(value) => {
                wireless.insert("band".to_string(), owned_value(value.to_string())?);
            }
            None => {
                wireless.remove("band");
                wireless.remove("channel");
            }
        }
    }
    if let Some(channel) = update.channel {
        if channel == 0 {
            wireless.remove("channel");
        } else {
            wireless.insert("channel".to_string(), owned_value(channel)?);
        }
    }
    Ok(())
}

fn apply_ip_fields(
    settings: &mut ConnectionSettings,
    update: &WifiProfileAdvancedUpdate,
) -> Result<()> {
    let ipv4 = settings.entry("ipv4".to_string()).or_default();
    set_clearable_text(
        ipv4,
        "dhcp-client-id",
        update.ipv4_dhcp_client_id.as_deref(),
    )?;
    set_clearable_text(ipv4, "dhcp-hostname", update.ipv4_dhcp_hostname.as_deref())?;
    insert_optional_value(ipv4, "never-default", update.ipv4_never_default)?;
    insert_optional_value(ipv4, "ignore-auto-routes", update.ipv4_ignore_auto_routes)?;
    insert_optional_value(ipv4, "may-fail", update.ipv4_may_fail)?;
    insert_optional_value(ipv4, "dad-timeout", update.ipv4_dad_timeout)?;

    let ipv6 = settings.entry("ipv6".to_string()).or_default();
    insert_optional_value(ipv6, "never-default", update.ipv6_never_default)?;
    insert_optional_value(ipv6, "ignore-auto-routes", update.ipv6_ignore_auto_routes)?;
    insert_optional_value(ipv6, "may-fail", update.ipv6_may_fail)?;
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
    let section = settings.entry(ENTERPRISE.to_string()).or_default();
    set_list(section, "eap", update.eap.as_deref())?;
    set_list(
        section,
        "altsubject-matches",
        update.altsubject_matches.as_deref(),
    )?;
    set_list(
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
        set_clearable_text(section, key, value.as_deref())?;
    }
    for (key, value) in [
        ("ca-cert", &update.ca_cert),
        ("client-cert", &update.client_cert),
        ("private-key", &update.private_key),
        ("phase2-ca-cert", &update.phase2_ca_cert),
        ("phase2-client-cert", &update.phase2_client_cert),
        ("phase2-private-key", &update.phase2_private_key),
    ] {
        set_certificate(section, key, value.as_deref())?;
    }
    insert_optional_value(section, "system-ca-certs", update.system_ca_certs)?;
    for (key, value) in [
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
    ] {
        insert_optional_value(section, key, value)?;
    }
    Ok(())
}

/// NetworkManager stores certificates as bytes; a `file://`/`pkcs11:` URI is
/// written as a NUL-terminated byte string exactly as `nmcli` does.
fn set_certificate(
    section: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<&str>,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty() {
        section.remove(key);
        return Ok(());
    }
    if !(value.starts_with("file://") || value.starts_with("pkcs11:")) {
        return Err(DomainError::validation(
            ErrorOperation::ProfileOperation,
            "certificate references must be a file:// or pkcs11: URI",
        )
        .with_detail("field", format!("advanced.enterprise.{key}"))
        .into());
    }
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    section.insert(key.to_string(), owned_value(bytes)?);
    Ok(())
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

fn set_clearable_text(
    section: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<&str>,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty() {
        section.remove(key);
    } else {
        section.insert(key.to_string(), owned_value(value.to_string())?);
    }
    Ok(())
}

fn set_list(
    section: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<&[String]>,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty() {
        section.remove(key);
    } else {
        section.insert(key.to_string(), owned_value(value.to_vec())?);
    }
    Ok(())
}

fn text(section: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    super::setting_string(section, key).filter(|value| !value.is_empty())
}

/// Certificate and key properties are byte arrays; NetworkManager stores URIs
/// NUL-terminated, and DER blobs that are not valid UTF-8 are reported as a
/// stable marker instead of mangled text.
fn blob(section: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    let bytes = Vec::<u8>::try_from(section.get(key)?.clone()).ok()?;
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(&bytes);
    if bytes.is_empty() {
        return None;
    }
    match std::str::from_utf8(bytes) {
        Ok(value) => Some(value.to_string()),
        Err(_) => Some(format!("blob:{} bytes", bytes.len())),
    }
}

fn strings(section: &HashMap<String, OwnedValue>, key: &str) -> Vec<String> {
    section
        .get(key)
        .and_then(|value| Vec::<String>::try_from(value.clone()).ok())
        .unwrap_or_default()
}

fn flag(section: &HashMap<String, OwnedValue>, key: &str) -> bool {
    section
        .get(key)
        .and_then(|value| bool::try_from(value.clone()).ok())
        .unwrap_or(false)
}

fn number(section: &HashMap<String, OwnedValue>, key: &str) -> Option<u32> {
    section
        .get(key)
        .and_then(|value| u32::try_from(value.clone()).ok())
}

fn secret_flags(section: &HashMap<String, OwnedValue>, key: &str) -> SecretFlags {
    SecretFlags::from_code(number(section, key).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::super::super::{ConnectionSettings, owned_value};
    use super::{
        apply_advanced, check_expected_version, profile_version, read_enterprise, validate_mode,
    };
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
    use crate::model::{ProfileEnterpriseUpdate, WifiBand, WifiProfileAdvancedUpdate};

    fn settings() -> ConnectionSettings {
        ConnectionSettings::from([(
            "connection".to_string(),
            HashMap::from([
                (
                    "id".to_string(),
                    owned_value("Example".to_string()).unwrap(),
                ),
                (
                    "timestamp".to_string(),
                    owned_value(1_762_000_000_u64).unwrap(),
                ),
            ]),
        )])
    }

    #[test]
    fn version_ignores_the_self_updating_activation_timestamp() {
        let mut later = settings();
        later.get_mut("connection").unwrap().insert(
            "timestamp".to_string(),
            owned_value(1_763_000_000_u64).unwrap(),
        );
        assert_eq!(profile_version(&settings()), profile_version(&later));
    }

    #[test]
    fn version_changes_when_a_real_setting_changes() {
        let mut renamed = settings();
        renamed.get_mut("connection").unwrap().insert(
            "id".to_string(),
            owned_value("Renamed".to_string()).unwrap(),
        );
        assert_ne!(profile_version(&settings()), profile_version(&renamed));
    }

    #[test]
    fn a_stale_expected_version_is_a_typed_conflict() {
        let settings = settings();
        let current = profile_version(&settings);
        assert!(check_expected_version(&settings, None).is_ok());
        assert!(check_expected_version(&settings, Some(&current)).is_ok());

        let error = check_expected_version(&settings, Some("0000000000000000")).unwrap_err();
        let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::Conflict);
        assert_eq!(report.details["current_version"], current);
    }

    #[test]
    fn advanced_updates_write_only_the_fields_that_were_sent() {
        let mut settings = settings();
        let update = WifiProfileAdvancedUpdate {
            autoconnect_priority: Some(30),
            bssid: Some("00:11:22:33:44:55".to_string()),
            mtu: Some(1400),
            band: Some(WifiBand::Ghz5),
            channel: Some(36),
            ipv6_privacy: Some(2),
            ipv4_may_fail: Some(false),
            ..WifiProfileAdvancedUpdate::default()
        };
        apply_advanced(&mut settings, &update).expect("advanced update");

        let connection = &settings["connection"];
        assert_eq!(
            i32::try_from(connection["autoconnect-priority"].clone()).unwrap(),
            30
        );
        assert!(connection.contains_key("id"), "unsent fields are preserved");
        assert!(
            !connection.contains_key("zone"),
            "unsent fields are not created"
        );
        let wireless = &settings["802-11-wireless"];
        assert_eq!(
            String::try_from(wireless["bssid"].clone()).unwrap(),
            "00:11:22:33:44:55"
        );
        assert_eq!(String::try_from(wireless["band"].clone()).unwrap(), "a");
        assert_eq!(u32::try_from(wireless["channel"].clone()).unwrap(), 36);
        assert!(!bool::try_from(settings["ipv4"]["may-fail"].clone()).unwrap());
        assert_eq!(
            i32::try_from(settings["ipv6"]["ip6-privacy"].clone()).unwrap(),
            2
        );
    }

    #[test]
    fn empty_strings_clear_a_restriction_and_automatic_band_clears_the_channel() {
        let mut settings = settings();
        apply_advanced(
            &mut settings,
            &WifiProfileAdvancedUpdate {
                bssid: Some("00:11:22:33:44:55".to_string()),
                band: Some(WifiBand::Ghz5),
                channel: Some(36),
                ..WifiProfileAdvancedUpdate::default()
            },
        )
        .expect("initial update");
        apply_advanced(
            &mut settings,
            &WifiProfileAdvancedUpdate {
                bssid: Some(String::new()),
                band: Some(WifiBand::Auto),
                ..WifiProfileAdvancedUpdate::default()
            },
        )
        .expect("clearing update");

        let wireless = &settings["802-11-wireless"];
        assert!(!wireless.contains_key("bssid"));
        assert!(!wireless.contains_key("band"));
        assert!(!wireless.contains_key("channel"));
    }

    #[test]
    fn an_exact_cloned_mac_replaces_the_keyword_policy() {
        let mut settings = settings();
        settings
            .entry("802-11-wireless".to_string())
            .or_default()
            .insert(
                "assigned-mac-address".to_string(),
                owned_value("random".to_string()).unwrap(),
            );
        apply_advanced(
            &mut settings,
            &WifiProfileAdvancedUpdate {
                cloned_mac_address: Some("02:00:00:00:00:99".to_string()),
                ..WifiProfileAdvancedUpdate::default()
            },
        )
        .expect("cloned mac update");
        assert_eq!(
            String::try_from(settings["802-11-wireless"]["assigned-mac-address"].clone()).unwrap(),
            "02:00:00:00:00:99"
        );
    }

    #[test]
    fn insecure_or_unknown_modes_and_eap_methods_are_rejected() {
        assert!(validate_mode("infrastructure").is_ok());
        assert!(validate_mode("ap").is_ok());
        assert!(validate_mode("adhoc").is_err());

        let mut settings = settings();
        let error = apply_advanced(
            &mut settings,
            &WifiProfileAdvancedUpdate {
                enterprise: Some(ProfileEnterpriseUpdate {
                    eap: Some(vec!["tls".to_string(), "not-a-method".to_string()]),
                    ..ProfileEnterpriseUpdate::default()
                }),
                ..WifiProfileAdvancedUpdate::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&error, ErrorOperation::Unknown).code,
            ErrorCode::ValidationError
        );
    }

    #[test]
    fn certificate_references_round_trip_as_nul_terminated_uris() {
        let mut settings = settings();
        apply_advanced(
            &mut settings,
            &WifiProfileAdvancedUpdate {
                enterprise: Some(ProfileEnterpriseUpdate {
                    eap: Some(vec!["tls".to_string()]),
                    ca_cert: Some("file:///etc/ssl/ca.pem".to_string()),
                    identity: Some("laufan".to_string()),
                    password_flags: Some(1),
                    ..ProfileEnterpriseUpdate::default()
                }),
                ..WifiProfileAdvancedUpdate::default()
            },
        )
        .expect("enterprise update");

        let enterprise = read_enterprise(&settings).expect("enterprise settings");
        assert_eq!(enterprise.eap, vec!["tls".to_string()]);
        assert_eq!(
            enterprise.ca_cert.as_deref(),
            Some("file:///etc/ssl/ca.pem")
        );
        assert_eq!(enterprise.identity.as_deref(), Some("laufan"));
        assert!(enterprise.password_flags.agent_owned);
        assert!(!enterprise.password_flags.not_saved);
    }

    #[test]
    fn certificate_references_must_be_a_supported_uri() {
        let mut settings = settings();
        let error = apply_advanced(
            &mut settings,
            &WifiProfileAdvancedUpdate {
                enterprise: Some(ProfileEnterpriseUpdate {
                    ca_cert: Some("/etc/ssl/ca.pem".to_string()),
                    ..ProfileEnterpriseUpdate::default()
                }),
                ..WifiProfileAdvancedUpdate::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&error, ErrorOperation::Unknown).code,
            ErrorCode::ValidationError
        );
    }
}
