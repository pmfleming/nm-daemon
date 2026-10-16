//! NetworkManager secret schema. No storage backend or keyring access.
use std::collections::HashMap;

use anyhow::{Result, bail, ensure};
use zvariant::OwnedValue;

use crate::nm::ConnectionSettings;
use crate::variant::{owned_value, setting, value_string_map};

pub(crate) const AGENT_OWNED: u32 = 1;
pub(crate) const NOT_SAVED: u32 = 2;
pub(crate) fn known_keys(section: &str) -> &'static [&'static str] {
    match section {
        "802-11-wireless-security" => &[
            "psk",
            "wep-key0",
            "wep-key1",
            "wep-key2",
            "wep-key3",
            "leap-password",
        ],
        "802-1x" => &[
            "password",
            "password-raw",
            "private-key-password",
            "phase2-private-key-password",
            "ca-cert-password",
            "client-cert-password",
            "phase2-ca-cert-password",
            "phase2-client-cert-password",
            "pin",
        ],
        "gsm" => &["password", "pin"],
        "cdma" | "ppp" | "adsl" => &["password"],
        "macsec" => &["mka-cak"],
        "wifi-p2p" => &["wps-pin"],
        "wireguard" => &["private-key"],
        _ => &[],
    }
}

pub(crate) fn flags_key(key: &str) -> String {
    if matches!(key, "wep-key0" | "wep-key1" | "wep-key2" | "wep-key3") {
        "wep-key-flags".into()
    } else {
        format!("{key}-flags")
    }
}

fn peer_key(key: &str) -> Option<&str> {
    key.strip_prefix("peers.")?.strip_suffix(".preshared-key")
}

fn peers(section: &HashMap<String, OwnedValue>) -> Result<Vec<HashMap<String, OwnedValue>>> {
    match section.get("peers") {
        Some(value) => Ok(value.try_clone()?.try_into()?),
        None => Ok(Vec::new()),
    }
}

pub(crate) fn flags(settings: &ConnectionSettings, section: &str, key: &str) -> Result<u32> {
    let values = settings
        .get(section)
        .ok_or_else(|| anyhow::anyhow!("secret setting missing"))?;
    let value = if section == "vpn" {
        let map = values
            .get("data")
            .and_then(value_string_map)
            .ok_or_else(|| anyhow::anyhow!("VPN secret policy missing"))?;
        let value = map.get(flags_key(key).as_str()).ok_or_else(|| {
            anyhow::anyhow!("VPN secret policy unspecified; refusing automatic persistence")
        })?;
        value.parse::<u32>()?
    } else if section == "wireguard"
        && let Some(public_key) = peer_key(key)
    {
        let peers = peers(values)?;
        let matches = peers
            .iter()
            .filter(|p| setting::<&str>(p, "public-key") == Some(public_key))
            .collect::<Vec<_>>();
        ensure!(matches.len() == 1, "WireGuard peer missing or ambiguous");
        flag_value(matches[0], "preshared-key-flags")?
    } else {
        ensure!(
            known_keys(section).contains(&key),
            "unsupported secret schema"
        );
        flag_value(values, &flags_key(key))?
    };
    ensure!(value & !7 == 0, "unknown secret flags");
    Ok(value)
}

fn flag_value(values: &HashMap<String, OwnedValue>, key: &str) -> Result<u32> {
    values
        .get(key)
        .map(u32::try_from)
        .transpose()
        .map(|v| v.unwrap_or(0))
        .map_err(Into::into)
}

pub(crate) fn set_system_owned(
    settings: &mut ConnectionSettings,
    section: &str,
    key: &str,
) -> Result<()> {
    let flags = flags(settings, section, key)?;
    ensure!(
        flags & NOT_SAVED == 0,
        "temporary credentials must not be persisted"
    );
    ensure!(section != "wifi-p2p", "WPS credentials are temporary");
    let flags = flags & !AGENT_OWNED;
    let values = settings.get_mut(section).unwrap();
    if section == "vpn" {
        let mut data: HashMap<String, String> = values
            .get("data")
            .and_then(value_string_map)
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        data.insert(flags_key(key), flags.to_string());
        values.insert("data".into(), owned_value(data)?);
    } else if section == "wireguard"
        && let Some(public_key) = peer_key(key)
    {
        let mut peers = peers(values)?;
        let peer = peers
            .iter_mut()
            .find(|p| setting::<&str>(p, "public-key") == Some(public_key))
            .unwrap();
        peer.insert("preshared-key-flags".into(), owned_value(flags)?);
        values.insert("peers".into(), owned_value(peers)?);
    } else {
        values.insert(flags_key(key), owned_value(flags)?);
    }
    Ok(())
}

pub(crate) fn set_text(
    settings: &mut ConnectionSettings,
    section: &str,
    key: &str,
    value: String,
) -> Result<()> {
    if section == "vpn" {
        let values = settings.entry(section.into()).or_default();
        let mut secrets: HashMap<String, String> = values
            .get("secrets")
            .and_then(value_string_map)
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        secrets.insert(key.into(), value);
        values.insert("secrets".into(), owned_value(secrets)?);
    } else if section == "wireguard"
        && let Some(public_key) = peer_key(key)
    {
        let values = settings
            .get_mut(section)
            .ok_or_else(|| anyhow::anyhow!("WireGuard setting missing"))?;
        let mut peers = peers(values)?;
        ensure!(
            peers
                .iter()
                .filter(|p| setting::<&str>(p, "public-key") == Some(public_key))
                .count()
                == 1,
            "WireGuard peer missing or ambiguous"
        );
        let peer = peers
            .iter_mut()
            .find(|p| setting::<&str>(p, "public-key") == Some(public_key))
            .unwrap();
        peer.insert("preshared-key".into(), owned_value(value)?);
        values.insert("peers".into(), owned_value(peers)?);
    } else {
        ensure!(
            known_keys(section).contains(&key),
            "unsupported secret schema"
        );
        let value = if key == "password-raw" {
            owned_value(value.into_bytes())?
        } else {
            owned_value(value)?
        };
        settings
            .entry(section.into())
            .or_default()
            .insert(key.into(), value);
    }
    Ok(())
}

pub(crate) fn text(settings: &ConnectionSettings, section: &str, key: &str) -> Option<String> {
    let values = settings.get(section)?;
    if section == "vpn" {
        return values
            .get("secrets")
            .and_then(value_string_map)?
            .get(key)
            .map(|v| (*v).to_string());
    }
    if section == "wireguard"
        && let Some(public_key) = peer_key(key)
    {
        let peers = peers(values).ok()?;
        return peers
            .iter()
            .find(|p| setting::<&str>(p, "public-key") == Some(public_key))
            .and_then(|p| setting::<&str>(p, "preshared-key"))
            .map(str::to_string);
    }
    crate::variant::setting_text(values, key)
}

/// Preserve only secret fields from GetSecrets, never overwrite public settings
/// or replace the peers array. Unknown peer identities abort rather than drop data.
pub(crate) fn merge_secrets(
    target: &mut ConnectionSettings,
    source: &ConnectionSettings,
) -> Result<()> {
    for (section, values) in source {
        let Some(dest) = target.get_mut(section) else {
            continue;
        };
        for key in known_keys(section) {
            if let Some(value) = values.get(*key) {
                dest.insert((*key).into(), value.try_clone()?);
            }
        }
        if section == "vpn"
            && let Some(value) = values.get("secrets")
        {
            let incoming =
                value_string_map(value).ok_or_else(|| anyhow::anyhow!("invalid VPN secrets"))?;
            let mut map: HashMap<String, String> = dest
                .get("secrets")
                .and_then(value_string_map)
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect();
            map.extend(incoming.into_iter().map(|(k, v)| (k.into(), v.into())));
            dest.insert("secrets".into(), owned_value(map)?);
        }
        if section == "wireguard" && values.contains_key("peers") {
            let mut target_peers = peers(dest)?;
            for peer in peers(values)? {
                let Some(secret) = peer.get("preshared-key") else {
                    continue;
                };
                let public = setting::<&str>(&peer, "public-key")
                    .ok_or_else(|| anyhow::anyhow!("peer identity missing"))?;
                let matches = target_peers
                    .iter()
                    .filter(|p| setting::<&str>(p, "public-key") == Some(public))
                    .count();
                if matches != 1 {
                    bail!("cannot preserve ambiguous WireGuard peer secret");
                }
                let dest = target_peers
                    .iter_mut()
                    .find(|p| setting::<&str>(p, "public-key") == Some(public))
                    .unwrap();
                dest.insert("preshared-key".into(), secret.try_clone()?);
            }
            dest.insert("peers".into(), owned_value(target_peers)?);
        }
    }
    Ok(())
}

pub(crate) fn has_secrets(settings: &ConnectionSettings) -> bool {
    settings.iter().any(|(section, values)| {
        known_keys(section).iter().any(|k| values.contains_key(*k))
            || (section == "vpn"
                && values
                    .get("secrets")
                    .and_then(value_string_map)
                    .is_some_and(|s| !s.is_empty()))
            || (section == "wireguard"
                && peers(values).is_ok_and(|p| p.iter().any(|p| p.contains_key("preshared-key"))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variant::value_map;

    #[test]
    fn schema_handles_shared_nested_and_temporary_flags() -> Result<()> {
        let mut s = ConnectionSettings::from([
            (
                "802-11-wireless-security".into(),
                value_map([("wep-key-flags", 1u32.into())])?,
            ),
            (
                "vpn".into(),
                HashMap::from([(
                    "data".into(),
                    owned_value(HashMap::from([("password-flags", "1"), ("otp-flags", "2")]))?,
                )]),
            ),
            (
                "wireguard".into(),
                HashMap::from([(
                    "peers".into(),
                    owned_value(vec![value_map([
                        ("public-key", "peer".into()),
                        ("preshared-key-flags", 1u32.into()),
                    ])?])?,
                )]),
            ),
        ]);
        for (section, key) in [
            ("802-11-wireless-security", "wep-key2"),
            ("vpn", "password"),
            ("wireguard", "peers.peer.preshared-key"),
        ] {
            assert_eq!(flags(&s, section, key)?, 1);
            set_system_owned(&mut s, section, key)?;
            set_text(&mut s, section, key, "synthetic".into())?;
            assert_eq!(flags(&s, section, key)?, 0);
            assert_eq!(text(&s, section, key).as_deref(), Some("synthetic"));
        }
        assert!(set_system_owned(&mut s, "vpn", "otp").is_err());
        assert!(flags(&s, "vpn", "unspecified").is_err());
        assert!(!s["802-11-wireless-security"].contains_key("wep-key2-flags"));
        Ok(())
    }

    #[test]
    fn merging_peer_secrets_preserves_configuration_and_other_credentials() -> Result<()> {
        let mut target = ConnectionSettings::from([(
            "wireguard".into(),
            HashMap::from([
                ("private-key".into(), owned_value("keep-private")?),
                (
                    "peers".into(),
                    owned_value(vec![value_map([
                        ("public-key", "peer".into()),
                        ("endpoint", "keep-endpoint".into()),
                    ])?])?,
                ),
            ]),
        )]);
        let source = ConnectionSettings::from([(
            "wireguard".into(),
            HashMap::from([(
                "peers".into(),
                owned_value(vec![value_map([
                    ("public-key", "peer".into()),
                    ("preshared-key", "incoming".into()),
                    ("endpoint", "wrong".into()),
                ])?])?,
            )]),
        )]);
        merge_secrets(&mut target, &source)?;
        assert_eq!(
            text(&target, "wireguard", "private-key").as_deref(),
            Some("keep-private")
        );
        let p = peers(&target["wireguard"])?;
        assert_eq!(setting::<&str>(&p[0], "endpoint"), Some("keep-endpoint"));
        assert_eq!(
            text(&target, "wireguard", "peers.peer.preshared-key").as_deref(),
            Some("incoming")
        );
        Ok(())
    }
}
