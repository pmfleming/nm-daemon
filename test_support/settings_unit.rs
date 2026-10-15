use super::{
    ConnectionSettings, profile_ip_settings, profile_secret_spec, profile_secret_values,
    setting_text, update_profile_secrets, validate_profile_update, wifi_settings_need_secret_agent,
};
use crate::model::{TargetIpAddress, TargetIpSettings, WifiProfileUpdate};
use crate::nm::ip_settings::replace as replace_ip_settings;
use crate::variant::{owned_value, setting, value_map};
use std::collections::BTreeMap;

#[test]
fn profile_matching_obeys_identity_and_radio_restrictions_in_both_paths() -> anyhow::Result<()> {
    for (band, channel, frequency, ssid, bssid, expected) in [
        (Some("a"), 36, 5180, "Example", "00:11:22:33:44:FF", true),
        (Some("a"), 36, 5200, "Example", "00:11:22:33:44:FF", false),
        (Some("a"), 0, 2412, "Example", "00:11:22:33:44:FF", false),
        (Some("a"), 0, 0, "Example", "00:11:22:33:44:FF", false),
        (None, 1, 0, "Example", "00:11:22:33:44:FF", false),
        (None, 0, 0, "Example", "00-11-22-33-44-ff", true),
        (Some("6GHz"), 1, 5955, "Example", "00:11:22:33:44:FF", true),
        (None, 0, 0, "example", "00:11:22:33:44:FF", false),
        (None, 0, 0, "Example", "00:11:22:33:44:55", false),
        (None, 0, 0, "Example", "invalid", false),
    ] {
        let mut settings = wifi_settings("Example", "802-11-wireless")?;
        let wireless = settings.get_mut("802-11-wireless").unwrap();
        if let Some(band) = band {
            wireless.insert("band".into(), owned_value(band)?);
        }
        wireless.insert("channel".into(), owned_value(channel as u32)?);
        wireless.insert(
            "bssid".into(),
            owned_value(vec![0_u8, 17, 34, 51, 68, 255])?,
        );
        let ap = crate::model::AccessPoint {
            ssid: ssid.into(),
            bssid: bssid.into(),
            frequency,
            ..Default::default()
        };
        let path = zvariant::OwnedObjectPath::try_from("/settings/1")?;
        let candidate =
            super::saved_wifi_profile_candidate_from_settings(&path, &settings).unwrap();
        assert_eq!(
            super::settings_match_access_point(&settings, &ap),
            expected,
            "{band:?}/{channel}/{frequency}/{ssid}/{bssid}"
        );
        assert_eq!(
            candidate.matcher.matches_access_point(&ap),
            expected,
            "inventory and activation must agree"
        );
    }
    Ok(())
}

#[test]
fn ip_profiles_preserve_defaults_signed_values_and_family_boundaries() -> anyhow::Result<()> {
    let mut settings = ConnectionSettings::new();
    let defaults = profile_ip_settings(&settings, "ipv4");
    assert_eq!(defaults.method, "auto");
    assert!(defaults.may_fail && !defaults.ignore_auto_routes);
    for family in ["ipv4", "ipv6"] {
        settings.insert(
            family.into(),
            value_map([
                ("dhcp-client-id", "client".into()),
                ("dad-timeout", (-1_i32).into()),
                ("ip6-privacy", (-1_i32).into()),
                ("route-metric", 99_u32.into()),
                ("may-fail", false.into()),
            ])?,
        );
        let parsed = profile_ip_settings(&settings, family);
        assert_eq!(
            parsed.dhcp_client_id.as_deref(),
            (family == "ipv4").then_some("client")
        );
        assert_eq!(parsed.dad_timeout, (family == "ipv4").then_some(-1));
        assert_eq!(parsed.ip6_privacy, (family == "ipv6").then_some(-1));
        assert_eq!(parsed.route_metric, Some(99));
        assert!(!parsed.may_fail);
    }
    let ipv4 = TargetIpSettings {
        method: Some("manual".into()),
        addresses: vec![TargetIpAddress {
            address: "192.0.2.20".into(),
            prefix: 24,
        }],
        gateway: Some("192.0.2.1".into()),
        dns: vec!["1.1.1.1".into()],
        ignore_auto_dns: Some(true),
        ..Default::default()
    };
    let mut update = WifiProfileUpdate {
        mac_address_policy: "stable".into(),
        metered: "no".into(),
        ipv4: ipv4.clone(),
        ..Default::default()
    };
    validate_profile_update(&update)?;
    replace_ip_settings(&mut settings, "ipv4", &ipv4)?;
    let parsed = profile_ip_settings(&settings, "ipv4");
    assert_eq!(parsed.method, "manual");
    assert_eq!(parsed.addresses[0].address, "192.0.2.20");
    assert_eq!(parsed.addresses[0].prefix, 24);
    assert_eq!(parsed.gateway.as_deref(), Some("192.0.2.1"));
    assert_eq!(parsed.dns, ["1.1.1.1"]);
    assert!(parsed.ignore_auto_dns);
    update.ipv4.dns = vec!["2001:db8::53".into()];
    assert!(validate_profile_update(&update).is_err());
    Ok(())
}

#[test]
fn profile_secrets_use_the_security_specific_section_key_and_validation() -> anyhow::Result<()> {
    for (management, section, key, password, foreign_key) in [
        (
            "wpa-psk",
            "802-11-wireless-security",
            "psk",
            "new-password",
            "pin",
        ),
        ("wpa-eap", "802-1x", "password", "new-password", "psk"),
        (
            "none",
            "802-11-wireless-security",
            "wep-key2",
            "abcde",
            "pin",
        ),
    ] {
        let mut settings = wifi_settings("Example", "802-11-wireless")?;
        settings.insert(
            "802-11-wireless-security".into(),
            value_map([
                ("key-mgmt", management.into()),
                ("wep-tx-keyidx", 2_u32.into()),
                ("wep-key-type", 1_u32.into()),
            ])?,
        );
        settings.insert(
            "802-1x".into(),
            value_map([("password-flags", 1_u32.into())])?,
        );
        if management == "wpa-psk" {
            let mut optional = settings.clone();
            optional
                .get_mut(section)
                .unwrap()
                .insert("psk-flags".into(), owned_value(4_u32)?);
            assert!(!wifi_settings_need_secret_agent(&optional, None, None));
        }
        let spec = profile_secret_spec(&settings);
        assert_eq!(spec.setting_name, Some(section));
        assert_eq!(spec.primary_secret_key, Some(key));
        let readable = ConnectionSettings::from([(
            section.into(),
            value_map([(key, "old-password".into()), ("pin", "1234".into())])?,
        )]);
        let values = profile_secret_values(&settings, Some(&readable), &spec);
        assert_eq!(values.get(key).map(String::as_str), Some("old-password"));
        let mut update = WifiProfileUpdate {
            password: Some(password.into()),
            ..Default::default()
        };
        if management == "wpa-eap" {
            assert_eq!(values.get("pin").map(String::as_str), Some("1234"));
            assert!(wifi_settings_need_secret_agent(
                &settings,
                Some(&readable),
                None
            ));
            update
                .secrets
                .insert("private-key-password".into(), "private-secret".into());
        }
        update_profile_secrets(&mut settings, &update)?;
        assert_eq!(
            setting_text(&settings[section], key).as_deref(),
            Some(password)
        );
        if management == "wpa-eap" {
            assert_eq!(
                setting_text(&settings[section], "private-key-password").as_deref(),
                Some("private-secret")
            );
            assert_eq!(
                setting::<u32>(&settings[section], "private-key-password-flags"),
                Some(0)
            );
        }
        update.secrets = BTreeMap::from([(foreign_key.into(), "1234".into())]);
        assert!(update_profile_secrets(&mut settings, &update).is_err());
        if management == "none" {
            update.secrets = BTreeMap::from([("wep-key0".into(), "bad".into())]);
            assert!(update_profile_secrets(&mut settings, &update).is_err());
            for (index, expected) in [
                (u32::MAX, "wep-key3"),
                (0, "wep-key0"),
                (1, "wep-key1"),
                (2, "wep-key2"),
            ] {
                settings
                    .get_mut(section)
                    .unwrap()
                    .insert("wep-tx-keyidx".into(), owned_value(index)?);
                assert_eq!(
                    profile_secret_spec(&settings).primary_secret_key,
                    Some(expected)
                );
            }
            settings
                .get_mut(section)
                .unwrap()
                .insert("wep-tx-keyidx".into(), owned_value(2_i32)?);
            assert_eq!(
                profile_secret_spec(&settings).primary_secret_key,
                Some("wep-key0")
            );
        }
    }
    Ok(())
}

fn wifi_settings(ssid: &str, connection_type: &str) -> anyhow::Result<ConnectionSettings> {
    Ok(ConnectionSettings::from([
        (
            "connection".into(),
            value_map([("type", connection_type.into())])?,
        ),
        (
            "802-11-wireless".into(),
            value_map([("ssid", ssid.as_bytes().into())])?,
        ),
    ]))
}
