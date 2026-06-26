use std::collections::HashMap;

use anyhow::{Result, bail};
use zvariant::OwnedValue;

use super::{ConnectionSettings, owned_value};
use crate::model::{
    AccessPoint, EnterpriseAuth, NM_AP_SEC_KEY_MGMT_PSK, NM_AP_SEC_KEY_MGMT_SAE, WepKeyType,
    WifiConnectTarget, enterprise_key_mgmt,
};

pub(super) fn psk_wifi_connection_settings(
    ap: &AccessPoint,
    password: &str,
) -> Result<ConnectionSettings> {
    let key_mgmt = psk_key_mgmt(ap);
    if key_mgmt == "wpa-psk" {
        validate_wpa_psk(password)?;
    }
    Ok(security_connection_settings(wireless_security_section(
        key_mgmt, password,
    )?))
}

pub(super) fn hidden_wifi_connection_settings(
    target: &WifiConnectTarget,
    password: Option<&str>,
    wep_key_type: Option<WepKeyType>,
) -> Result<ConnectionSettings> {
    let mut settings =
        base_wifi_connection_settings(&target.ssid, target.ssid_bytes().as_ref(), true)?;
    if let Some(enterprise) = &target.enterprise {
        let key_mgmt = enterprise.key_mgmt.as_deref().unwrap_or("wpa-eap");
        settings.extend(enterprise_wifi_connection_settings_with_key_mgmt(
            enterprise, password, key_mgmt,
        )?);
    } else if let Some(password) = password {
        let security = if let Some(wep_key_type) = wep_key_type {
            wep_security_section(password, wep_key_type)?
        } else {
            validate_wpa_psk(password)?;
            wireless_security_section("wpa-psk", password)?
        };
        settings.insert("802-11-wireless-security".to_string(), security);
    }
    Ok(settings)
}

pub(super) fn enterprise_wifi_connection_settings(
    ap: &AccessPoint,
    enterprise: &EnterpriseAuth,
    password: Option<&str>,
) -> Result<ConnectionSettings> {
    enterprise_wifi_connection_settings_with_key_mgmt(
        enterprise,
        password,
        enterprise_key_mgmt(ap.wpa_flags, ap.rsn_flags),
    )
}

fn enterprise_wifi_connection_settings_with_key_mgmt(
    enterprise: &EnterpriseAuth,
    password: Option<&str>,
    key_mgmt: &str,
) -> Result<ConnectionSettings> {
    let mut security = HashMap::new();
    security.insert("key-mgmt".to_string(), owned_value(key_mgmt.to_string())?);

    let mut dot1x = HashMap::new();
    let eap = if enterprise.eap.is_empty() {
        vec!["peap".to_string()]
    } else {
        enterprise.eap.clone()
    };
    dot1x.insert("eap".to_string(), owned_value(eap)?);
    insert_required_string(&mut dot1x, "identity", enterprise.identity.as_deref())?;
    insert_optional_string(
        &mut dot1x,
        "anonymous-identity",
        enterprise.anonymous_identity.as_deref(),
    )?;
    insert_optional_string(
        &mut dot1x,
        "password",
        enterprise.password.as_deref().or(password),
    )?;
    insert_optional_string(&mut dot1x, "phase2-auth", enterprise.phase2_auth.as_deref())?;
    insert_optional_string(&mut dot1x, "ca-cert", enterprise.ca_cert.as_deref())?;
    insert_optional_string(
        &mut dot1x,
        "domain-suffix-match",
        enterprise.domain_suffix_match.as_deref(),
    )?;
    if !enterprise.altsubject_matches.is_empty() {
        dot1x.insert(
            "altsubject-matches".to_string(),
            owned_value(enterprise.altsubject_matches.clone())?,
        );
    }
    insert_optional_string(&mut dot1x, "client-cert", enterprise.client_cert.as_deref())?;
    insert_optional_string(&mut dot1x, "private-key", enterprise.private_key.as_deref())?;
    insert_optional_string(
        &mut dot1x,
        "private-key-password",
        enterprise.private_key_password.as_deref(),
    )?;
    insert_optional_string(&mut dot1x, "pin", enterprise.pin.as_deref())?;
    insert_optional_string(&mut dot1x, "pac-file", enterprise.pac_file.as_deref())?;
    if let Some(system_ca_certs) = enterprise.system_ca_certs {
        dot1x.insert("system-ca-certs".to_string(), owned_value(system_ca_certs)?);
    }

    Ok(ConnectionSettings::from([
        ("802-11-wireless-security".to_string(), security),
        ("802-1x".to_string(), dot1x),
    ]))
}

pub(super) fn wep_wifi_connection_settings(
    password: &str,
    wep_key_type: WepKeyType,
) -> Result<ConnectionSettings> {
    Ok(security_connection_settings(wep_security_section(
        password,
        wep_key_type,
    )?))
}

fn base_wifi_connection_settings(
    ssid: &str,
    ssid_bytes: &[u8],
    hidden: bool,
) -> Result<ConnectionSettings> {
    Ok(ConnectionSettings::from([
        (
            "connection".to_string(),
            HashMap::from([
                ("id".to_string(), owned_value(ssid.to_string())?),
                (
                    "type".to_string(),
                    owned_value("802-11-wireless".to_string())?,
                ),
            ]),
        ),
        (
            "802-11-wireless".to_string(),
            HashMap::from([
                ("ssid".to_string(), owned_value(ssid_bytes.to_vec())?),
                (
                    "mode".to_string(),
                    owned_value("infrastructure".to_string())?,
                ),
                ("hidden".to_string(), owned_value(hidden)?),
            ]),
        ),
        (
            "ipv4".to_string(),
            HashMap::from([("method".to_string(), owned_value("auto".to_string())?)]),
        ),
        (
            "ipv6".to_string(),
            HashMap::from([("method".to_string(), owned_value("auto".to_string())?)]),
        ),
    ]))
}

fn security_connection_settings(section: HashMap<String, OwnedValue>) -> ConnectionSettings {
    ConnectionSettings::from([("802-11-wireless-security".to_string(), section)])
}

fn wireless_security_section(
    key_mgmt: &str,
    password: &str,
) -> Result<HashMap<String, OwnedValue>> {
    Ok(HashMap::from([
        ("key-mgmt".to_string(), owned_value(key_mgmt.to_string())?),
        ("psk".to_string(), owned_value(password.to_string())?),
    ]))
}

fn wep_security_section(
    password: &str,
    wep_key_type: WepKeyType,
) -> Result<HashMap<String, OwnedValue>> {
    validate_wep_key(password, wep_key_type)?;
    Ok(HashMap::from([
        ("key-mgmt".to_string(), owned_value("none".to_string())?),
        ("wep-key0".to_string(), owned_value(password.to_string())?),
        (
            "wep-key-type".to_string(),
            owned_value(wep_key_type.nm_value())?,
        ),
    ]))
}

fn insert_required_string(
    settings: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<&str>,
) -> Result<()> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        bail!("enterprise Wi-Fi field '{key}' is required")
    };
    settings.insert(key.to_string(), owned_value(value.to_string())?);
    Ok(())
}

fn insert_optional_string(
    settings: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<&str>,
) -> Result<()> {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        settings.insert(key.to_string(), owned_value(value.to_string())?);
    }
    Ok(())
}

pub(super) fn psk_key_mgmt(ap: &AccessPoint) -> &'static str {
    let flags = ap.wpa_flags | ap.rsn_flags;
    if flags & NM_AP_SEC_KEY_MGMT_SAE != 0 && flags & NM_AP_SEC_KEY_MGMT_PSK == 0 {
        "sae"
    } else {
        "wpa-psk"
    }
}

fn validate_wpa_psk(password: &str) -> Result<()> {
    let len = password.len();
    if (8..=63).contains(&len) || (len == 64 && password.chars().all(|ch| ch.is_ascii_hexdigit())) {
        return Ok(());
    }
    bail!("WPA-PSK password must be 8-63 characters, or 64 hexadecimal characters")
}

fn validate_wep_key(password: &str, wep_key_type: WepKeyType) -> Result<()> {
    match wep_key_type {
        WepKeyType::Key if wep_key_is_valid(password) => Ok(()),
        WepKeyType::Key => {
            bail!("WEP key must be 5 or 13 ASCII characters, or 10 or 26 hexadecimal characters")
        }
        WepKeyType::Phrase if (8..=64).contains(&password.len()) => Ok(()),
        WepKeyType::Phrase => bail!("WEP passphrase must be 8-64 characters"),
    }
}

fn wep_key_is_valid(password: &str) -> bool {
    (matches!(password.len(), 5 | 13) && password.is_ascii())
        || (matches!(password.len(), 10 | 26) && password.chars().all(|ch| ch.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::{
        enterprise_wifi_connection_settings, psk_key_mgmt, psk_wifi_connection_settings,
        validate_wep_key, validate_wpa_psk,
    };
    use crate::model::{
        AccessPoint, EnterpriseAuth, NM_AP_SEC_KEY_MGMT_802_1X, NM_AP_SEC_KEY_MGMT_PSK,
        NM_AP_SEC_KEY_MGMT_SAE, WepKeyType,
    };

    #[test]
    fn psk_wifi_settings_include_password_and_key_mgmt() {
        let ap = test_ap(NM_AP_SEC_KEY_MGMT_PSK);
        let settings = psk_wifi_connection_settings(&ap, "secret123").expect("settings");

        assert_eq!(
            settings
                .get("802-11-wireless-security")
                .and_then(|section| setting_string(section, "key-mgmt"))
                .as_deref(),
            Some("wpa-psk")
        );
        assert_eq!(
            settings
                .get("802-11-wireless-security")
                .and_then(|section| setting_string(section, "psk"))
                .as_deref(),
            Some("secret123")
        );
    }

    #[test]
    fn sae_only_networks_use_sae_key_mgmt() {
        assert_eq!(psk_key_mgmt(&test_ap(NM_AP_SEC_KEY_MGMT_SAE)), "sae");
        assert_eq!(
            psk_key_mgmt(&test_ap(NM_AP_SEC_KEY_MGMT_SAE | NM_AP_SEC_KEY_MGMT_PSK)),
            "wpa-psk"
        );
    }

    #[test]
    fn enterprise_wifi_settings_include_8021x_credentials() {
        let auth = EnterpriseAuth {
            eap: vec!["peap".to_string()],
            identity: Some("laufan".to_string()),
            anonymous_identity: None,
            password: None,
            phase2_auth: Some("mschapv2".to_string()),
            ca_cert: None,
            domain_suffix_match: None,
            altsubject_matches: Vec::new(),
            client_cert: None,
            private_key: None,
            private_key_password: None,
            pin: None,
            pac_file: None,
            key_mgmt: None,
            system_ca_certs: None,
        };
        let settings = enterprise_wifi_connection_settings(
            &test_ap(NM_AP_SEC_KEY_MGMT_802_1X),
            &auth,
            Some("secret123"),
        )
        .expect("settings");

        assert_eq!(
            settings
                .get("802-11-wireless-security")
                .and_then(|section| setting_string(section, "key-mgmt"))
                .as_deref(),
            Some("wpa-eap")
        );
        assert_eq!(
            settings
                .get("802-1x")
                .and_then(|section| setting_string(section, "identity"))
                .as_deref(),
            Some("laufan")
        );
        assert_eq!(
            settings
                .get("802-1x")
                .and_then(|section| setting_string(section, "password"))
                .as_deref(),
            Some("secret123")
        );
        assert_eq!(
            settings
                .get("802-1x")
                .and_then(|section| setting_string(section, "phase2-auth"))
                .as_deref(),
            Some("mschapv2")
        );
    }

    #[test]
    fn wpa_psk_validation_matches_nmcli_shape() {
        assert!(validate_wpa_psk("12345678").is_ok());
        assert!(validate_wpa_psk(&"a".repeat(63)).is_ok());
        assert!(validate_wpa_psk(&"a".repeat(64)).is_ok());
        assert!(validate_wpa_psk("short").is_err());
        assert!(validate_wpa_psk(&"g".repeat(64)).is_err());
        assert!(validate_wpa_psk(&"a".repeat(65)).is_err());
    }

    #[test]
    fn wep_validation_matches_nmcli_shape() {
        assert!(validate_wep_key("abcde", WepKeyType::Key).is_ok());
        assert!(validate_wep_key("0011223344", WepKeyType::Key).is_ok());
        assert!(validate_wep_key("abc", WepKeyType::Key).is_err());
        assert!(validate_wep_key("éabc", WepKeyType::Key).is_err());
        assert!(validate_wep_key("not-hex-10", WepKeyType::Key).is_err());
        assert!(validate_wep_key("passphrase", WepKeyType::Phrase).is_ok());
        assert!(validate_wep_key("short", WepKeyType::Phrase).is_err());
    }

    fn test_ap(rsn_flags: u32) -> AccessPoint {
        AccessPoint {
            ssid: "Example".to_string(),
            ssid_bytes: b"Example".to_vec(),
            active: false,
            security: "WPA2/3".to_string(),
            strength: 50,
            frequency: 2412,
            channel: 1,
            band: "2.4 GHz".to_string(),
            mode: "Infra".to_string(),
            max_bitrate_mbps: 0,
            bandwidth_mhz: 0,
            ssid_hex: "4578616d706c65".to_string(),
            wpa_flags_label: "(none)".to_string(),
            rsn_flags_label: "(none)".to_string(),
            bssid: "00:11:22:33:44:55".to_string(),
            last_seen: 0,
            last_seen_age_ms: None,
            path: "/ap".to_string(),
            device_path: "/device".to_string(),
            device_iface: "wlan0".to_string(),
            flags: 0,
            wpa_flags: 0,
            rsn_flags,
        }
    }

    fn setting_string(
        settings: &std::collections::HashMap<String, zvariant::OwnedValue>,
        key: &str,
    ) -> Option<String> {
        settings.get(key)?.try_clone().ok()?.try_into().ok()
    }
}
