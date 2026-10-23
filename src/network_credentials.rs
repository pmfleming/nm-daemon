//! NetworkManager secret schema. No storage backend or keyring access.
use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result, ensure};
use zvariant::OwnedValue;

use crate::variant::{ConnectionSettings, owned_value, setting, setting_text, value_string_map};

pub(crate) const AGENT_OWNED: u32 = 1;
pub(crate) const NOT_SAVED: u32 = 2;

/// Bounded transient handoff only; deliberately not Debug/Serialize.
pub(crate) struct SecretValue {
    pub(crate) key: String,
    pub(crate) password: String,
}

/// Values for explicitly supported schemas, never a generic password fallback.
pub(crate) fn values(settings: &ConnectionSettings) -> Result<Vec<(String, String, String)>> {
    let mut result = Vec::new();
    for (section, data) in settings {
        let mut secrets: Vec<(String, String)> = known_keys(section)
            .iter()
            .filter_map(|key| Some(((*key).into(), setting_text(data, key)?)))
            .collect();
        match section.as_str() {
            "vpn" => secrets.extend(
                data.get("secrets")
                    .and_then(value_string_map)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(key, value)| (key.into(), value.into())),
            ),
            "wireguard" => secrets.extend(peers(data)?.iter().filter_map(|peer| {
                let public = setting::<&str>(peer, "public-key")?;
                Some((
                    format!("peers.{public}.preshared-key"),
                    setting::<&str>(peer, "preshared-key")?.into(),
                ))
            })),
            _ => {}
        }
        result.extend(
            secrets
                .into_iter()
                .filter(|(_, value)| !value.is_empty())
                .map(|(key, value)| (section.clone(), key, value)),
        );
    }
    Ok(result)
}

/// Canonical public policy snapshot. Exclude only credentials and NM-maintained
/// observation metadata, not ACLs, certificate policy, addresses or user data.
pub(crate) fn public_settings(settings: &ConnectionSettings) -> Result<ConnectionSettings> {
    let mut public = settings.clone();
    for (section, data) in &mut public {
        for key in known_keys(section) {
            data.remove(*key);
        }
        match section.as_str() {
            "wireguard" if data.contains_key("peers") => {
                let mut peers = peers(data)?;
                for peer in &mut peers {
                    peer.remove("preshared-key");
                }
                data.insert("peers".into(), owned_value(peers)?);
            }
            "vpn" => {
                data.remove("secrets");
            }
            "connection" => {
                data.remove("timestamp");
            }
            "802-11-wireless" => {
                data.remove("seen-bssids");
            }
            _ => {}
        }
    }
    Ok(public)
}
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

/// Settings whose credentials must be preserved before a durable profile edit.
pub(crate) fn requires_secrets(section: &str, data: &HashMap<String, OwnedValue>) -> bool {
    if section == "802-11-wireless-security" {
        matches!(
            setting::<&str>(data, "key-mgmt"),
            Some("wpa-psk" | "sae" | "none")
        ) || setting::<&str>(data, "auth-alg") == Some("leap")
    } else {
        !known_keys(section).is_empty() || section == "vpn"
    }
}

/// Serialize only policy flags, never credentials or arbitrary plugin data.
pub(crate) fn flag_inventory(settings: &ConnectionSettings) -> Result<BTreeMap<String, u32>> {
    let mut flags = BTreeMap::new();
    for (name, section) in settings {
        flags.extend(
            section
                .iter()
                .filter(|(key, _)| key.ends_with("-flags"))
                .filter_map(|(key, value)| {
                    Some((format!("{name}.{key}"), u32::try_from(value).ok()?))
                }),
        );
    }
    if let Some(data) = settings
        .get("vpn")
        .and_then(|s| s.get("data"))
        .and_then(value_string_map)
    {
        flags.extend(
            data.into_iter()
                .filter(|(key, _)| key.ends_with("-flags"))
                .filter_map(|(key, value)| Some((format!("vpn.data.{key}"), value.parse().ok()?))),
        );
    }
    if let Some(section) = settings.get("wireguard") {
        flags.extend(
            peers(section)?
                .iter()
                .enumerate()
                .filter_map(|(index, peer)| {
                    Some((
                        format!("wireguard.peers[{index}].preshared-key-flags"),
                        setting::<u32>(peer, "preshared-key-flags")?,
                    ))
                }),
        );
    }
    Ok(flags)
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

/// Resolve once and reject both missing and duplicate identities before mutation.
fn unique_peer<'a>(
    peers: &'a mut [HashMap<String, OwnedValue>],
    public: &str,
) -> Result<&'a mut HashMap<String, OwnedValue>> {
    let mut matches = peers
        .iter_mut()
        .filter(|p| setting::<&str>(p, "public-key") == Some(public));
    let peer = matches
        .next()
        .context("WireGuard peer missing or ambiguous")?;
    ensure!(
        matches.next().is_none(),
        "WireGuard peer missing or ambiguous"
    );
    Ok(peer)
}

fn extend_vpn_map<'a>(
    values: &mut HashMap<String, OwnedValue>,
    key: &str,
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<()> {
    let mut map = values
        .get(key)
        .and_then(value_string_map)
        .unwrap_or_default();
    for (key, value) in entries {
        map.insert(key, value);
    }
    let encoded = owned_value(map)?;
    values.insert(key.into(), encoded);
    Ok(())
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
        flag_value(
            unique_peer(&mut peers(values)?, public_key)?,
            "preshared-key-flags",
        )?
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
    Ok(values.get(key).map(u32::try_from).transpose()?.unwrap_or(0))
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
    let values = settings
        .get_mut(section)
        .context("secret setting missing")?;
    if section == "vpn" {
        extend_vpn_map(
            values,
            "data",
            [(flags_key(key).as_str(), flags.to_string().as_str())],
        )?;
    } else if section == "wireguard"
        && let Some(public_key) = peer_key(key)
    {
        let mut peers = peers(values)?;
        unique_peer(&mut peers, public_key)?
            .insert("preshared-key-flags".into(), owned_value(flags)?);
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
        extend_vpn_map(
            settings.entry(section.into()).or_default(),
            "secrets",
            [(key, value.as_str())],
        )?;
    } else if section == "wireguard"
        && let Some(public_key) = peer_key(key)
    {
        let values = settings
            .get_mut(section)
            .ok_or_else(|| anyhow::anyhow!("WireGuard setting missing"))?;
        let mut peers = peers(values)?;
        unique_peer(&mut peers, public_key)?.insert("preshared-key".into(), owned_value(value)?);
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
            extend_vpn_map(dest, "secrets", incoming)?;
        }
        if section == "wireguard" && values.contains_key("peers") {
            let mut target_peers = peers(dest)?;
            for peer in peers(values)? {
                let Some(secret) = peer.get("preshared-key") else {
                    continue;
                };
                let public = setting::<&str>(&peer, "public-key")
                    .ok_or_else(|| anyhow::anyhow!("peer identity missing"))?;
                let dest = unique_peer(&mut target_peers, public)?;
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
    use super::{
        flag_inventory, flags, merge_secrets, peers, set_system_owned, set_text, text, values,
    };
    use crate::variant::value_map;
    use crate::variant::{ConnectionSettings, owned_value, setting};
    use anyhow::Result;
    use std::collections::HashMap;

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
        assert_eq!(values(&s)?.len(), 3);
        let inventory = flag_inventory(&s)?;
        assert_eq!(inventory["wireguard.peers[0].preshared-key-flags"], 0);
        assert_eq!(inventory["vpn.data.otp-flags"], 2);
        set_text(&mut s, "vpn", "other", "keep".into())?;
        let mut incoming = ConnectionSettings::new();
        set_text(&mut incoming, "vpn", "password", "replacement".into())?;
        merge_secrets(&mut s, &incoming)?;
        assert_eq!(text(&s, "vpn", "password").as_deref(), Some("replacement"));
        assert_eq!(text(&s, "vpn", "other").as_deref(), Some("keep"));
        assert_eq!(flags(&s, "vpn", "otp")?, 2);
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
        let key = "peers.peer.preshared-key";
        for invalid in [Vec::new(), vec![p[0].clone(), p[0].clone()]] {
            target
                .get_mut("wireguard")
                .unwrap()
                .insert("peers".into(), owned_value(invalid)?);
            let before = target.clone();
            assert!(flags(&target, "wireguard", key).is_err());
            assert!(set_system_owned(&mut target, "wireguard", key).is_err());
            assert!(set_text(&mut target, "wireguard", key, "no".into()).is_err());
            assert!(merge_secrets(&mut target, &source).is_err());
            assert_eq!(
                target, before,
                "invalid peer identity must not mutate settings"
            );
        }
        Ok(())
    }
}
