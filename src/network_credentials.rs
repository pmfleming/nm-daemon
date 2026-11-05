//! NetworkManager secret schema. No storage backend or keyring access.
use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result, ensure};
use zvariant::OwnedValue;

use crate::variant::{
    ConnectionSettings, owned_value, setting, setting_text, value_dicts, value_string_map,
};

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
            "wireguard" => secrets.extend(peer_dicts(data)?.into_iter().filter_map(|peer| {
                let public = peer.get::<_, &str>(&"public-key").ok()??;
                Some((
                    format!("peers.{public}.preshared-key"),
                    peer.get::<_, &str>(&"preshared-key").ok()??.into(),
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
        let metadata = match section.as_str() {
            "vpn" => Some("secrets"),
            "connection" => Some("timestamp"),
            "802-11-wireless" => Some("seen-bssids"),
            _ => None,
        };
        for key in known_keys(section).iter().copied().chain(metadata) {
            data.remove(key);
        }
        if section == "wireguard"
            && let Some(value) = data.remove("peers")
        {
            let mut peers: Vec<HashMap<String, OwnedValue>> = value.try_into()?;
            for peer in &mut peers {
                peer.remove("preshared-key");
            }
            data.insert("peers".into(), owned_value(peers)?);
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

/// Plugin hints name arbitrary credentials; informational VPN messages never
/// authorize a guessed password. Unknown fixed-schema hints survive so policy
/// validation rejects them rather than substituting a persistent password.
pub(crate) fn secret_keys_for(section: &str, hints: &[String]) -> Vec<String> {
    let plugin = accepts_plugin_secret_names(section);
    let mut keys: Vec<String> = hints
        .iter()
        .filter_map(|hint| {
            let hint = if plugin {
                plugin_hint(section, hint)?
            } else {
                hint
            };
            (!hint.is_empty()).then(|| hint.to_string())
        })
        .collect();
    if plugin {
        keys.dedup();
    }
    if hints.is_empty() || (!plugin && keys.is_empty()) {
        keys.push(default_secret_key_for_setting(section).into());
    }
    keys
}

/// Wi-Fi profiles refine the default PSK only when NM supplied no explicit hint.
/// WEP's transmit index wins over LEAP, matching NetworkManager's key selection.
pub(crate) fn wireless_secret_key(
    settings: &ConnectionSettings,
    section: &str,
    hints: &[String],
) -> Option<String> {
    if section != "802-11-wireless-security" || !hints.is_empty() {
        return None;
    }
    let security = settings.get(section)?;
    match (
        setting::<&str>(security, "key-mgmt"),
        setting::<&str>(security, "auth-alg"),
    ) {
        (Some("none"), _) => Some(format!(
            "wep-key{}",
            setting::<u32>(security, "wep-tx-keyidx")
                .unwrap_or(0)
                .min(3)
        )),
        (_, Some("leap")) => Some("leap-password".into()),
        _ => None,
    }
}

pub(crate) fn accepts_plugin_secret_names(section: &str) -> bool {
    matches!(section, "vpn" | "wireguard")
}

fn plugin_hint<'a>(section: &str, hint: &'a str) -> Option<&'a str> {
    if section == "vpn" && hint.starts_with("x-vpn-message:") {
        return None;
    }
    let hint = hint.strip_prefix("vpn.secrets.").unwrap_or(hint);
    Some(
        hint.strip_prefix(section)
            .and_then(|rest| rest.strip_prefix('.'))
            .unwrap_or(hint),
    )
}

pub(crate) fn default_secret_key_for_setting(section: &str) -> &'static str {
    match section {
        "802-11-wireless-security" => "psk",
        "wifi-p2p" => "wps-pin",
        "wireguard" => "private-key",
        _ => "password",
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
            peer_dicts(section)?
                .into_iter()
                .enumerate()
                .filter_map(|(index, peer)| {
                    Some((
                        format!("wireguard.peers[{index}].preshared-key-flags"),
                        peer.get::<_, u32>(&"preshared-key-flags").ok()??,
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

/// Read-only inspection borrows peer dictionaries, including credential values.
/// As with owned decoding, malformed keys or containers reject the entire array.
fn peer_dicts(section: &HashMap<String, OwnedValue>) -> Result<Vec<&zvariant::Dict<'_, '_>>> {
    section.get("peers").map_or_else(
        || Ok(Vec::new()),
        |value| value_dicts(value).context("invalid WireGuard peers"),
    )
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

/// Decode and validate before replacing the array, so invalid identities never
/// change the destination. All peer writes preserve unrelated public fields.
fn set_peer_value(
    values: &mut HashMap<String, OwnedValue>,
    public: &str,
    key: &str,
    value: OwnedValue,
) -> Result<()> {
    let mut peers = peers(values)?;
    unique_peer(&mut peers, public)?.insert(key.into(), value);
    values.insert("peers".into(), owned_value(peers)?);
    Ok(())
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
        set_peer_value(
            values,
            public_key,
            "preshared-key-flags",
            owned_value(flags)?,
        )?;
    } else {
        values.insert(flags_key(key), owned_value(flags)?);
    }
    Ok(())
}

pub(crate) fn set_text(
    settings: &mut ConnectionSettings,
    section: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    if section == "vpn" {
        extend_vpn_map(
            settings.entry(section.into()).or_default(),
            "secrets",
            [(key, value)],
        )?;
    } else if section == "wireguard"
        && let Some(public_key) = peer_key(key)
    {
        let values = settings
            .get_mut(section)
            .ok_or_else(|| anyhow::anyhow!("WireGuard setting missing"))?;
        set_peer_value(values, public_key, "preshared-key", owned_value(value)?)?;
    } else {
        ensure!(
            known_keys(section).contains(&key),
            "unsupported secret schema"
        );
        let value = if key == "password-raw" {
            owned_value(value.as_bytes())?
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
        return peer_dicts(values)
            .ok()?
            .into_iter()
            .find(|peer| peer.get::<_, &str>(&"public-key").ok().flatten() == Some(public_key))?
            .get::<_, &str>(&"preshared-key")
            .ok()?
            .map(str::to_string);
    }
    crate::variant::setting_text(values, key)
}

/// Preserve only secret fields from GetSecrets, never overwrite public settings
/// or replace the peers array. Unknown peer identities abort rather than drop data.
pub(crate) fn merge_secrets(
    target: &mut ConnectionSettings,
    source: ConnectionSettings,
) -> Result<()> {
    for (section, values) in source {
        let Some(dest) = target.get_mut(&section) else {
            continue;
        };
        for (key, value) in values {
            match (section.as_str(), key.as_str()) {
                ("vpn", "secrets") => {
                    let incoming = value_string_map(&value).context("invalid VPN secrets")?;
                    extend_vpn_map(dest, "secrets", incoming)?;
                }
                ("wireguard", "peers") => merge_peer_secrets(dest, value)?,
                (_, name) if known_keys(&section).contains(&name) => {
                    dest.insert(key, value);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn merge_peer_secrets(dest: &mut HashMap<String, OwnedValue>, incoming: OwnedValue) -> Result<()> {
    let mut target_peers = peers(dest)?;
    for mut peer in Vec::<HashMap<String, OwnedValue>>::try_from(incoming)? {
        let Some(secret) = peer.remove("preshared-key") else {
            continue;
        };
        let public = setting::<&str>(&peer, "public-key").context("peer identity missing")?;
        unique_peer(&mut target_peers, public)?.insert("preshared-key".into(), secret);
    }
    dest.insert("peers".into(), owned_value(target_peers)?);
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
                && peer_dicts(values).is_ok_and(|peers| {
                    peers.iter().any(|peer| {
                        peer.get::<_, &zvariant::Value>(&"preshared-key")
                            .is_ok_and(|value| value.is_some())
                    })
                }))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        flag_inventory, flags, merge_secrets, peers, set_system_owned, set_text, text, values,
        wireless_secret_key,
    };
    use crate::variant::value_map;
    use crate::variant::{ConnectionSettings, setting};
    use anyhow::Result;
    use std::collections::HashMap;

    #[test]
    fn wireless_defaults_preserve_explicit_hints_and_wep_precedence() -> Result<()> {
        const WIFI: &str = "802-11-wireless-security";
        assert_eq!(
            wireless_secret_key(&ConnectionSettings::new(), WIFI, &[]),
            None
        );
        for (management, auth, index, expected) in [
            ("none", "leap", None, Some("wep-key0")),
            ("none", "open", Some(2u32), Some("wep-key2")),
            ("none", "open", Some(9), Some("wep-key3")),
            ("ieee8021x", "leap", None, Some("leap-password")),
            ("wpa-psk", "open", None, None),
        ] {
            let mut section =
                value_map([("key-mgmt", management.into()), ("auth-alg", auth.into())])?;
            crate::variant::insert_optional_value(&mut section, "wep-tx-keyidx", index)?;
            let settings = ConnectionSettings::from([(WIFI.into(), section)]);
            assert_eq!(
                wireless_secret_key(&settings, WIFI, &[]).as_deref(),
                expected
            );
            assert_eq!(wireless_secret_key(&settings, WIFI, &["psk".into()]), None);
            assert_eq!(wireless_secret_key(&settings, "vpn", &[]), None);
        }
        Ok(())
    }

    fn peer(public: &str) -> Result<HashMap<String, zvariant::OwnedValue>> {
        value_map([
            ("public-key", public.into()),
            ("endpoint", "keep-endpoint".into()),
            ("preshared-key-flags", 1u32.into()),
        ])
    }

    fn with_peers(peers: Vec<HashMap<String, zvariant::OwnedValue>>) -> Result<ConnectionSettings> {
        Ok(ConnectionSettings::from([(
            "wireguard".into(),
            value_map([("peers", peers.into())])?,
        )]))
    }

    #[test]
    fn credential_updates_preserve_policy_public_fields_and_reject_invalid_peers() -> Result<()> {
        let mut s = ConnectionSettings::from([
            (
                "802-11-wireless-security".into(),
                value_map([("wep-key-flags", 1u32.into())])?,
            ),
            (
                "vpn".into(),
                value_map([(
                    "data",
                    HashMap::from([("password-flags", "1"), ("otp-flags", "2")]).into(),
                )])?,
            ),
        ]);
        s.extend(with_peers(vec![peer("peer")?])?);
        set_text(&mut s, "wireguard", "private-key", "keep-private")?;
        for (section, key) in [
            ("802-11-wireless-security", "wep-key2"),
            ("vpn", "password"),
            ("wireguard", "peers.peer.preshared-key"),
        ] {
            assert_eq!(flags(&s, section, key)?, 1);
            set_system_owned(&mut s, section, key)?;
            set_text(&mut s, section, key, "synthetic")?;
            assert_eq!(flags(&s, section, key)?, 0);
            assert_eq!(text(&s, section, key).as_deref(), Some("synthetic"));
        }
        assert!(set_system_owned(&mut s, "vpn", "otp").is_err());
        assert!(flags(&s, "vpn", "unspecified").is_err());
        assert!(!s["802-11-wireless-security"].contains_key("wep-key2-flags"));
        assert_eq!(values(&s)?.len(), 4);
        let raw = "nul\0é";
        set_text(&mut s, "802-1x", "password-raw", raw)?;
        assert_eq!(
            crate::variant::value_list::<u8>(&s["802-1x"]["password-raw"]),
            Some(raw.as_bytes().to_vec())
        );
        let inventory = flag_inventory(&s)?;
        assert_eq!(inventory["wireguard.peers[0].preshared-key-flags"], 0);
        assert_eq!(inventory["vpn.data.otp-flags"], 2);
        set_text(&mut s, "vpn", "other", "keep")?;
        let mut incoming = with_peers(vec![value_map([
            ("public-key", "peer".into()),
            ("preshared-key", "incoming".into()),
            ("endpoint", "wrong".into()),
        ])?])?;
        set_text(&mut incoming, "vpn", "password", "replacement")?;
        merge_secrets(&mut s, incoming)?;
        for (section, key, expected) in [
            ("vpn", "password", "replacement"),
            ("vpn", "other", "keep"),
            ("wireguard", "private-key", "keep-private"),
            ("wireguard", "peers.peer.preshared-key", "incoming"),
        ] {
            assert_eq!(text(&s, section, key).as_deref(), Some(expected));
        }
        assert_eq!(flags(&s, "vpn", "otp")?, 2);
        let p = peers(&s["wireguard"])?;
        assert_eq!(setting::<&str>(&p[0], "endpoint"), Some("keep-endpoint"));
        let public = super::public_settings(&s)?;
        assert!(!super::has_secrets(&public));
        assert!(values(&public)?.is_empty());
        assert_eq!(flag_inventory(&public)?, flag_inventory(&s)?);
        assert_eq!(
            setting::<&str>(&peers(&public["wireguard"])?[0], "endpoint"),
            Some("keep-endpoint")
        );
        for invalid in [
            Vec::new(),
            vec![peer("peer")?, peer("peer")?],
            vec![peer("other")?],
        ] {
            let mut target = with_peers(invalid)?;
            let before = target.clone();
            let source = with_peers(vec![value_map([
                ("public-key", "peer".into()),
                ("preshared-key", "no".into()),
            ])?])?;
            let key = "peers.peer.preshared-key";
            assert!(flags(&target, "wireguard", key).is_err());
            assert!(set_system_owned(&mut target, "wireguard", key).is_err());
            assert!(set_text(&mut target, "wireguard", key, "no").is_err());
            assert!(merge_secrets(&mut target, source).is_err());
            assert_eq!(
                target, before,
                "invalid peer identity must not mutate settings"
            );
        }
        Ok(())
    }
}
