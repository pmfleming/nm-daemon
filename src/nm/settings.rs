use std::collections::HashMap;

use anyhow::{Context, Result};
use zvariant::{OwnedObjectPath, OwnedValue};

use super::{
    ConnectionSettings, DEVICE_IFACE, Nm, SETTINGS_CONNECTION_IFACE, SETTINGS_IFACE, SETTINGS_PATH,
    owned_value,
};
use crate::error::{DomainError, ErrorOperation};
use crate::model::{
    AccessPoint, NetworkEntry, ProfileIpSettings, ProfilePrivacy, SavedWifiConnection,
    TargetIpAddress, TargetIpRoute, TargetIpSettings, WifiConnectTarget, WifiDevice,
    WifiProfileDetails, WifiProfileSecret, WifiProfileUpdate, WifiSharePayload,
    ap_supports_enterprise, ap_supports_psk, ap_uses_wep, display_ssid,
    network_entries_with_profile_matches,
};

const NM_SECRET_FLAG_AGENT_OWNED: u32 = 0x1;
const NM_SECRET_FLAG_NOT_SAVED: u32 = 0x2;
const NM_SECRET_FLAG_NOT_REQUIRED: u32 = 0x4;

type ActivationTarget = (OwnedObjectPath, OwnedObjectPath, OwnedObjectPath);

impl Nm {
    pub(super) fn saved_wifi_activation_target_for(
        &self,
        target: &WifiConnectTarget,
    ) -> Result<Option<ActivationTarget>> {
        if let Some(activation) = self.visible_saved_activation_target(target)? {
            return Ok(Some(activation));
        }
        if target.has_specific_ap() {
            tracing::info!(ssid = %target.ssid, ap_path = ?target.ap_path, bssid = ?target.bssid, "not using generic saved-profile fallback for specific AP target");
            return Ok(None);
        }

        self.generic_saved_activation_target(target)
    }

    fn visible_saved_activation_target(
        &self,
        target: &WifiConnectTarget,
    ) -> Result<Option<ActivationTarget>> {
        if target.hidden {
            return Ok(None);
        }
        let Some((device, ap_path, ap)) = self.visible_access_point_for(target)? else {
            return Ok(None);
        };
        let Some(connection_path) = self.saved_wifi_connection_for_ap_on_device(&ap, &device)?
        else {
            return Ok(None);
        };
        tracing::info!(ssid = %target.ssid, iface = %device.iface, "using saved Wi-Fi profile for selected access point");
        Ok(Some((connection_path, device.path, ap_path)))
    }

    fn generic_saved_activation_target(
        &self,
        target: &WifiConnectTarget,
    ) -> Result<Option<ActivationTarget>> {
        let target_ssid = target.ssid_bytes();
        let Some(connection_path) = self.saved_wifi_connection_for_ssid(target_ssid.as_ref())?
        else {
            return Ok(None);
        };
        let Some(device) = self.wifi_devices_for_target(target)?.into_iter().next() else {
            return Err(DomainError::not_found(
                ErrorOperation::Connect,
                "no matching Wi-Fi device found",
            )
            .into());
        };
        Ok(Some((connection_path, device.path, root_object_path()?)))
    }

    pub(crate) fn delete_connection(&self, path: &OwnedObjectPath) -> Result<()> {
        let connection = self.proxy_path(path, SETTINGS_CONNECTION_IFACE)?;
        tracing::info!(connection = %path, "deleting saved NetworkManager connection");
        connection
            .call::<_, _, ()>("Delete", &())
            .with_context(|| format!("Delete connection {path}"))
    }

    pub(crate) fn delete_connection_by_path(&self, path: &str) -> Result<()> {
        self.delete_connection(&OwnedObjectPath::try_from(path).context("parse connection path")?)
    }

    pub(crate) fn set_connection_autoconnect_by_path(
        &self,
        path: &str,
        autoconnect: bool,
    ) -> Result<()> {
        self.mutate_connection_settings(path, "autoconnect", |settings| {
            settings
                .entry("connection".to_string())
                .or_default()
                .insert("autoconnect".to_string(), owned_value(autoconnect)?);
            Ok(())
        })
    }

    pub(crate) fn set_connection_mac_randomization_by_path(
        &self,
        path: &str,
        randomized: bool,
    ) -> Result<()> {
        self.mutate_connection_settings(path, "MAC randomization", |settings| {
            settings
                .entry("802-11-wireless".to_string())
                .or_default()
                .insert(
                    "assigned-mac-address".to_string(),
                    owned_value(if randomized { "stable" } else { "permanent" }.to_string())?,
                );
            Ok(())
        })
    }

    pub(crate) fn set_connection_send_hostname_by_path(
        &self,
        path: &str,
        enabled: bool,
    ) -> Result<()> {
        self.mutate_connection_settings(path, "DHCP hostname privacy", |settings| {
            set_dhcp_send_hostname(settings, "ipv4", enabled)?;
            set_dhcp_send_hostname(settings, "ipv6", enabled)
        })
    }

    pub(crate) fn wifi_profile_details_by_path(&self, path: &str) -> Result<WifiProfileDetails> {
        let path = OwnedObjectPath::try_from(path).context("parse connection path")?;
        let settings = self.connection_settings(&path)?;
        let profile = saved_wifi_connection_from_settings(&path, &settings).ok_or_else(|| {
            DomainError::not_found(
                ErrorOperation::ProfileOperation,
                format!("connection is not a saved Wi-Fi profile: {path}"),
            )
        })?;
        let connection = settings.get("connection").cloned().unwrap_or_default();
        let wireless = settings.get("802-11-wireless").cloned().unwrap_or_default();
        Ok(WifiProfileDetails {
            path: profile.path,
            id: profile.id,
            ssid: profile.ssid,
            autoconnect: profile.autoconnect,
            metered: metered_from_settings(&connection),
            hidden: wireless
                .get("hidden")
                .and_then(setting_bool)
                .unwrap_or(false),
            mac_address_policy: profile.privacy.mac_address_policy,
            send_hostname: profile.privacy.send_hostname,
            security_type: security_type_from_settings(&settings),
            ipv4: profile_ip_settings(&settings, "ipv4"),
            ipv6: profile_ip_settings(&settings, "ipv6"),
        })
    }

    pub(crate) fn wifi_profile_secret_by_path(&self, path: &str) -> Result<WifiProfileSecret> {
        let path = OwnedObjectPath::try_from(path).context("parse connection path")?;
        let settings = self.connection_settings(&path)?;
        if saved_wifi_connection_from_settings(&path, &settings).is_none() {
            return Err(DomainError::not_found(
                ErrorOperation::ProfileOperation,
                format!("connection is not a saved Wi-Fi profile: {path}"),
            )
            .into());
        }
        let secrets = self
            .connection_secrets(&path, "802-11-wireless-security")
            .ok();
        let key_mgmt = settings
            .get("802-11-wireless-security")
            .and_then(|section| setting_string(section, "key-mgmt"))
            .unwrap_or_default();
        let (kind, key) = match key_mgmt.as_str() {
            "wpa-psk" | "sae" => ("password", "psk".to_string()),
            "none" | "" if has_wep_settings(&settings, secrets.as_ref()) => {
                let index = settings
                    .get("802-11-wireless-security")
                    .and_then(|section| section.get("wep-tx-keyidx"))
                    .and_then(setting_u32)
                    .unwrap_or(0)
                    .min(3);
                ("wep-key", format!("wep-key{index}"))
            }
            value if value.contains("eap") => ("enterprise", "password".to_string()),
            _ => ("none", String::new()),
        };
        let password = (!key.is_empty())
            .then(|| secret_string(&settings, secrets.as_ref(), &key))
            .flatten();
        Ok(WifiProfileSecret {
            path: path.to_string(),
            available: password.is_some(),
            kind: kind.to_string(),
            password,
        })
    }

    pub(crate) fn update_wifi_profile_by_path(
        &self,
        path: &str,
        update: &WifiProfileUpdate,
    ) -> Result<()> {
        validate_profile_update(update)?;
        self.mutate_connection_settings(path, "advanced Wi-Fi profile", |settings| {
            let connection = settings.entry("connection".to_string()).or_default();
            connection.insert("autoconnect".to_string(), owned_value(update.autoconnect)?);
            connection.insert(
                "metered".to_string(),
                owned_value(metered_code(&update.metered)?)?,
            );
            let wireless = settings.entry("802-11-wireless".to_string()).or_default();
            wireless.insert("hidden".to_string(), owned_value(update.hidden)?);
            wireless.insert(
                "assigned-mac-address".to_string(),
                owned_value(update.mac_address_policy.clone())?,
            );
            set_dhcp_send_hostname(settings, "ipv4", update.send_hostname)?;
            set_dhcp_send_hostname(settings, "ipv6", update.send_hostname)?;
            replace_ip_settings(settings, "ipv4", &update.ipv4)?;
            replace_ip_settings(settings, "ipv6", &update.ipv6)?;
            if let Some(password) = update.password.as_deref().filter(|value| !value.is_empty()) {
                update_personal_password(settings, password)?;
            }
            Ok(())
        })
    }

    fn mutate_connection_settings(
        &self,
        path: &str,
        action: &str,
        mutate: impl FnOnce(&mut ConnectionSettings) -> Result<()>,
    ) -> Result<()> {
        let path = OwnedObjectPath::try_from(path).context("parse connection path")?;
        let mut settings = self.connection_settings(&path)?;
        mutate(&mut settings)?;
        self.update_connection_settings(&path, settings, action)
    }

    fn update_connection_settings(
        &self,
        path: &OwnedObjectPath,
        settings: ConnectionSettings,
        action: &str,
    ) -> Result<()> {
        let proxy = self.proxy_path(path, SETTINGS_CONNECTION_IFACE)?;
        tracing::info!(connection = %path, action, "updating saved NetworkManager connection settings");
        proxy
            .call::<_, _, ()>("Update", &(settings,))
            .with_context(|| format!("Update {action} for {path}"))
    }

    pub(crate) fn saved_wifi_connections(&self) -> Result<Vec<SavedWifiConnection>> {
        let mut connections = Vec::new();
        for path in self.saved_connections()? {
            let settings = self.connection_settings(&path)?;
            if let Some(connection) = saved_wifi_connection_from_settings(&path, &settings) {
                connections.push(connection);
            }
        }
        connections.sort_by_key(|connection| connection.id.to_lowercase());
        Ok(connections)
    }

    pub(super) fn saved_wifi_connection_needs_secret_agent(
        &self,
        path: &OwnedObjectPath,
        ap: Option<&AccessPoint>,
    ) -> Result<bool> {
        let settings = self.connection_settings(path)?;
        let secrets = self
            .connection_secrets(path, "802-11-wireless-security")
            .ok();
        Ok(wifi_settings_need_secret_agent(
            &settings,
            secrets.as_ref(),
            ap,
        ))
    }

    pub(crate) fn wifi_share_payload_by_path(&self, path: &str) -> Result<WifiSharePayload> {
        let path = OwnedObjectPath::try_from(path).context("parse connection path")?;
        let settings = self.connection_settings(&path)?;
        let Some(profile) = saved_wifi_connection_from_settings(&path, &settings) else {
            return Err(DomainError::not_found(
                ErrorOperation::ProfileOperation,
                format!("connection is not a saved Wi-Fi profile: {path}"),
            )
            .with_detail("path", path.to_string())
            .into());
        };

        let secrets = self
            .connection_secrets(&path, "802-11-wireless-security")
            .map_err(|err| format!("{err:#}"))
            .ok();

        Ok(wifi_share_payload_for_settings(
            &profile,
            &settings,
            secrets.as_ref(),
        ))
    }

    pub(crate) fn network_entries_for_access_points(
        &self,
        access_points: Vec<AccessPoint>,
    ) -> Result<Vec<NetworkEntry>> {
        let profile_matches = self.compatible_profile_matches_by_ap_path(&access_points)?;
        Ok(network_entries_with_profile_matches(
            access_points,
            &profile_matches,
        ))
    }

    fn compatible_profile_matches_by_ap_path(
        &self,
        access_points: &[AccessPoint],
    ) -> Result<std::collections::BTreeMap<String, Vec<SavedWifiConnection>>> {
        let profiles_by_path = self.saved_wifi_profile_candidates_by_path()?;
        let mut available_by_device_path = HashMap::new();
        let mut matches = std::collections::BTreeMap::new();
        for access_point in access_points {
            self.add_compatible_profile_matches(
                access_point,
                &profiles_by_path,
                &mut available_by_device_path,
                &mut matches,
            );
        }
        Ok(matches)
    }

    fn saved_wifi_profile_candidates_by_path(
        &self,
    ) -> Result<HashMap<String, SavedWifiProfileCandidate>> {
        let mut candidates = HashMap::new();
        for path in self.saved_connections()? {
            let settings = self.connection_settings(&path)?;
            if let Some(candidate) = saved_wifi_profile_candidate_from_settings(&path, &settings) {
                candidates.insert(candidate.profile.path.clone(), candidate);
            }
        }
        Ok(candidates)
    }

    fn add_compatible_profile_matches(
        &self,
        access_point: &AccessPoint,
        profiles_by_path: &HashMap<String, SavedWifiProfileCandidate>,
        available_by_device_path: &mut HashMap<String, Vec<OwnedObjectPath>>,
        matches: &mut std::collections::BTreeMap<String, Vec<SavedWifiConnection>>,
    ) {
        let Some(device) = wifi_device_for_access_point(access_point) else {
            return;
        };
        let Some(available) =
            self.available_connections_cached(access_point, &device, available_by_device_path)
        else {
            return;
        };
        let compatible = available.iter().filter_map(|path| {
            profiles_by_path
                .get(&path.to_string())
                .filter(|candidate| candidate.matches_access_point(access_point))
                .map(|candidate| candidate.profile.clone())
        });
        matches
            .entry(access_point.path.clone())
            .or_default()
            .extend(compatible);
    }

    fn available_connections_cached<'a>(
        &self,
        access_point: &AccessPoint,
        device: &WifiDevice,
        cache: &'a mut HashMap<String, Vec<OwnedObjectPath>>,
    ) -> Option<&'a [OwnedObjectPath]> {
        if !cache.contains_key(&access_point.device_path) {
            let available = self.available_connections(device).map_err(|err| {
                tracing::warn!(iface = %device.iface, error = %crate::error::err_chain(&err), "could not read AvailableConnections for AP profile compatibility");
            }).ok()?;
            cache.insert(access_point.device_path.clone(), available);
        }
        cache.get(&access_point.device_path).map(Vec::as_slice)
    }

    pub(super) fn saved_wifi_connection_settings_for_ap_on_device(
        &self,
        ap: &AccessPoint,
        device: &WifiDevice,
    ) -> Result<Option<ConnectionSettings>> {
        let Some(path) = self.saved_wifi_connection_for_ap_on_device(ap, device)? else {
            return Ok(None);
        };
        self.connection_settings(&path).map(Some)
    }

    fn saved_wifi_connection_for_ap_on_device(
        &self,
        ap: &AccessPoint,
        device: &WifiDevice,
    ) -> Result<Option<OwnedObjectPath>> {
        for path in self.available_connections(device)? {
            if self.connection_matches_access_point(&path, ap)? {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    fn saved_wifi_connection_for_ssid(&self, ssid_bytes: &[u8]) -> Result<Option<OwnedObjectPath>> {
        for path in self.saved_connections()? {
            if self.connection_matches_ssid(&path, ssid_bytes)? {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    fn connection_matches_ssid(&self, path: &OwnedObjectPath, ssid_bytes: &[u8]) -> Result<bool> {
        self.connection_settings_match(path, |settings| {
            settings_match_wifi_ssid(settings, ssid_bytes)
        })
    }

    fn connection_matches_access_point(
        &self,
        path: &OwnedObjectPath,
        ap: &AccessPoint,
    ) -> Result<bool> {
        self.connection_settings_match(path, |settings| settings_match_access_point(settings, ap))
    }

    fn connection_settings_match(
        &self,
        path: &OwnedObjectPath,
        matches: impl FnOnce(&ConnectionSettings) -> bool,
    ) -> Result<bool> {
        Ok(matches(&self.connection_settings(path)?))
    }

    fn saved_connections(&self) -> Result<Vec<OwnedObjectPath>> {
        let settings = self.proxy(SETTINGS_PATH, SETTINGS_IFACE)?;
        settings
            .call("ListConnections", &())
            .context("ListConnections")
    }

    fn connection_settings(&self, path: &OwnedObjectPath) -> Result<ConnectionSettings> {
        let connection = self.proxy_path(path, SETTINGS_CONNECTION_IFACE)?;
        connection
            .call("GetSettings", &())
            .with_context(|| format!("GetSettings for {path}"))
    }

    fn connection_secrets(
        &self,
        path: &OwnedObjectPath,
        setting_name: &str,
    ) -> Result<ConnectionSettings> {
        let connection = self.proxy_path(path, SETTINGS_CONNECTION_IFACE)?;
        connection
            .call("GetSecrets", &(setting_name,))
            .with_context(|| format!("GetSecrets {setting_name} for {path}"))
    }

    fn available_connections(&self, device: &WifiDevice) -> Result<Vec<OwnedObjectPath>> {
        let device_proxy = self.proxy_path(&device.path, DEVICE_IFACE)?;
        device_proxy
            .get_property("AvailableConnections")
            .with_context(|| format!("read AvailableConnections for {}", device.iface))
    }
}

struct SavedWifiProfileCandidate {
    profile: SavedWifiConnection,
    ssid_bytes: Vec<u8>,
    bssid_bytes: Option<Vec<u8>>,
}

impl SavedWifiProfileCandidate {
    fn matches_access_point(&self, ap: &AccessPoint) -> bool {
        ssid_bytes_match(&self.ssid_bytes, ap.ssid_bytes().as_ref())
            && self
                .bssid_bytes
                .as_deref()
                .is_none_or(|saved_bssid| bssid_bytes_match(saved_bssid, &ap.bssid))
    }
}

fn saved_wifi_profile_candidate_from_settings(
    path: &OwnedObjectPath,
    settings: &ConnectionSettings,
) -> Option<SavedWifiProfileCandidate> {
    let profile = saved_wifi_connection_from_settings(path, settings)?;
    let wireless = wifi_settings_section(settings)?;
    let ssid_bytes = wireless.get("ssid").and_then(setting_bytes)?;
    let bssid_bytes = wireless.get("bssid").and_then(setting_bytes);
    Some(SavedWifiProfileCandidate {
        profile,
        ssid_bytes,
        bssid_bytes,
    })
}

fn saved_wifi_connection_from_settings(
    path: &OwnedObjectPath,
    settings: &ConnectionSettings,
) -> Option<SavedWifiConnection> {
    let connection = settings.get("connection")?;
    let wireless = settings.get("802-11-wireless")?;
    if connection
        .get("type")
        .and_then(setting_value_string)
        .is_some_and(|connection_type| connection_type != "802-11-wireless")
    {
        return None;
    }
    let id = setting_string(connection, "id").unwrap_or_else(|| path.to_string());
    let ssid_bytes = wireless
        .get("ssid")
        .and_then(setting_bytes)
        .unwrap_or_default();
    let ssid = display_ssid(&ssid_bytes);
    let autoconnect = connection
        .get("autoconnect")
        .and_then(setting_bool)
        .unwrap_or(true);
    let privacy = privacy_from_settings(settings);
    Some(SavedWifiConnection {
        path: path.to_string(),
        id,
        ssid,
        ssid_bytes,
        autoconnect,
        privacy,
    })
}

fn wifi_share_payload_for_settings(
    profile: &SavedWifiConnection,
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
) -> WifiSharePayload {
    let hidden = hidden_from_settings(settings);
    let security = settings.get("802-11-wireless-security");
    let key_mgmt = security
        .and_then(|section| setting_string(section, "key-mgmt"))
        .unwrap_or_default();
    if security.is_none() || (key_mgmt.is_empty() && !has_wep_settings(settings, secrets)) {
        return shareable_payload(profile, "nopass", None, hidden);
    }

    share_payload_for_key_mgmt(profile, settings, secrets, hidden, security, &key_mgmt)
}

fn share_payload_for_key_mgmt(
    profile: &SavedWifiConnection,
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
    hidden: bool,
    security: Option<&HashMap<String, OwnedValue>>,
    key_mgmt: &str,
) -> WifiSharePayload {
    match key_mgmt {
        "wpa-psk" | "sae" => secret_payload(profile, "WPA", "psk", settings, secrets, hidden),
        "none" | "" if has_wep_settings(settings, secrets) => {
            let key_index = security
                .and_then(|section| setting_u32(section.get("wep-tx-keyidx")?))
                .unwrap_or(0)
                .min(3);
            let key = format!("wep-key{key_index}");
            secret_payload(profile, "WEP", &key, settings, secrets, hidden)
        }
        "none" | "" => shareable_payload(profile, "nopass", None, hidden),
        "owe" => unshareable_payload(
            profile,
            "OWE/enhanced-open QR sharing is not supported by the standard Wi-Fi QR format",
        ),
        value if value.contains("eap") => {
            unshareable_payload(profile, "enterprise Wi-Fi QR sharing is not supported")
        }
        value => unshareable_payload(
            profile,
            &format!("unsupported Wi-Fi security type: {value}"),
        ),
    }
}

fn hidden_from_settings(settings: &ConnectionSettings) -> bool {
    settings
        .get("802-11-wireless")
        .and_then(|wireless| wireless.get("hidden"))
        .and_then(setting_bool)
        .unwrap_or(false)
}

fn has_wep_settings(settings: &ConnectionSettings, secrets: Option<&ConnectionSettings>) -> bool {
    (0..=3).any(|index| {
        let key = format!("wep-key{index}");
        secret_string(settings, secrets, &key).is_some()
            || section_has_key(
                settings,
                "802-11-wireless-security",
                &format!("{key}-flags"),
            )
    }) || section_has_key(settings, "802-11-wireless-security", "wep-tx-keyidx")
        || section_has_key(settings, "802-11-wireless-security", "auth-alg")
}

fn secret_payload(
    profile: &SavedWifiConnection,
    auth_type: &str,
    secret_key: &str,
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
    hidden: bool,
) -> WifiSharePayload {
    let Some(password) = secret_string(settings, secrets, secret_key) else {
        return unshareable_payload(
            profile,
            &format!("saved {auth_type} password is not readable from NetworkManager"),
        );
    };
    shareable_payload(profile, auth_type, Some(&password), hidden)
}

fn shareable_payload(
    profile: &SavedWifiConnection,
    auth_type: &str,
    password: Option<&str>,
    hidden: bool,
) -> WifiSharePayload {
    WifiSharePayload::shareable(profile, auth_type, password, hidden)
}

fn unshareable_payload(profile: &SavedWifiConnection, reason: &str) -> WifiSharePayload {
    WifiSharePayload {
        status: "unavailable",
        shareable: false,
        reason: Some(reason.to_string()),
        path: profile.path.clone(),
        id: profile.id.clone(),
        ssid: profile.ssid.clone(),
        auth_type: None,
        qr_payload: None,
    }
}

fn secret_string(
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
    key: &str,
) -> Option<String> {
    secrets
        .and_then(|secrets| secrets.get("802-11-wireless-security"))
        .and_then(|section| setting_string(section, key))
        .or_else(|| {
            settings
                .get("802-11-wireless-security")
                .and_then(|section| setting_string(section, key))
        })
        .filter(|value| !value.is_empty())
}

fn wifi_settings_need_secret_agent(
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
    ap: Option<&AccessPoint>,
) -> bool {
    let Some(security) = settings.get("802-11-wireless-security") else {
        return false;
    };
    let key_mgmt = setting_string(security, "key-mgmt").unwrap_or_default();
    if key_mgmt == "owe" {
        return false;
    }

    if personal_security(&key_mgmt, ap) {
        return required_secret_needs_agent(settings, secrets, "psk", "psk-flags");
    }
    if wep_security(&key_mgmt, ap) {
        return wep_secret_needs_agent(settings, secrets, security);
    }
    if enterprise_security(&key_mgmt, ap) {
        return enterprise_secret_needs_agent(settings, secrets);
    }
    false
}

fn personal_security(key_mgmt: &str, ap: Option<&AccessPoint>) -> bool {
    matches!(key_mgmt, "wpa-psk" | "sae")
        || ap.is_some_and(|ap| ap_supports_psk(ap.wpa_flags, ap.rsn_flags))
}

fn wep_security(key_mgmt: &str, ap: Option<&AccessPoint>) -> bool {
    matches!(key_mgmt, "none" | "")
        || ap.is_some_and(|ap| ap_uses_wep(ap.flags, ap.wpa_flags, ap.rsn_flags))
}

fn enterprise_security(key_mgmt: &str, ap: Option<&AccessPoint>) -> bool {
    key_mgmt.contains("eap")
        || ap.is_some_and(|ap| ap_supports_enterprise(ap.wpa_flags, ap.rsn_flags))
}

fn wep_secret_needs_agent(
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
    security: &HashMap<String, OwnedValue>,
) -> bool {
    let key_index = security
        .get("wep-tx-keyidx")
        .and_then(setting_u32)
        .unwrap_or(0)
        .min(3);
    let key = format!("wep-key{key_index}");
    required_secret_needs_agent(settings, secrets, &key, &format!("{key}-flags"))
}

fn enterprise_secret_needs_agent(
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
) -> bool {
    [
        ("password", "password-flags"),
        ("private-key-password", "private-key-password-flags"),
        ("pin", "pin-flags"),
    ]
    .into_iter()
    .any(|(secret_key, flags_key)| {
        required_secret_needs_agent(settings, secrets, secret_key, flags_key)
    })
}

fn wifi_device_for_access_point(access_point: &AccessPoint) -> Option<WifiDevice> {
    let device_path = OwnedObjectPath::try_from(access_point.device_path.as_str()).map_err(|_| {
        tracing::warn!(device_path = %access_point.device_path, ap_path = %access_point.path, "skipping AP profile compatibility check with invalid device path");
    }).ok()?;
    Some(WifiDevice {
        path: device_path,
        iface: access_point.device_iface.clone(),
    })
}

fn required_secret_needs_agent(
    settings: &ConnectionSettings,
    secrets: Option<&ConnectionSettings>,
    secret_key: &str,
    flags_key: &str,
) -> bool {
    let flags = secret_flags(settings, flags_key);
    if flags & NM_SECRET_FLAG_NOT_REQUIRED != 0 {
        return false;
    }
    if flags & (NM_SECRET_FLAG_AGENT_OWNED | NM_SECRET_FLAG_NOT_SAVED) != 0 {
        return true;
    }
    secrets.is_some() && secret_string(settings, secrets, secret_key).is_none()
}

fn secret_flags(settings: &ConnectionSettings, flags_key: &str) -> u32 {
    settings
        .get("802-11-wireless-security")
        .and_then(|section| section.get(flags_key))
        .and_then(setting_u32)
        .unwrap_or(0)
}

fn section_has_key(settings: &ConnectionSettings, section: &str, key: &str) -> bool {
    settings
        .get(section)
        .is_some_and(|settings| settings.contains_key(key))
}

fn metered_from_settings(connection: &HashMap<String, OwnedValue>) -> String {
    match connection.get("metered").and_then(setting_u32).unwrap_or(0) {
        1 | 3 => "yes",
        2 | 4 => "no",
        _ => "auto",
    }
    .to_string()
}

fn metered_code(value: &str) -> Result<u32> {
    match value {
        "" | "auto" | "unknown" => Ok(0),
        "yes" | "on" | "true" => Ok(1),
        "no" | "off" | "false" => Ok(2),
        _ => Err(DomainError::validation(
            ErrorOperation::ProfileOperation,
            "metered must be auto, yes, or no",
        )
        .with_detail("field", "metered")
        .with_detail("value", value)
        .into()),
    }
}

fn security_type_from_settings(settings: &ConnectionSettings) -> String {
    let Some(security) = settings.get("802-11-wireless-security") else {
        return "Open".to_string();
    };
    match setting_string(security, "key-mgmt")
        .unwrap_or_default()
        .as_str()
    {
        "wpa-psk" => "WPA/WPA2 Personal",
        "sae" => "WPA3 Personal",
        "owe" => "Enhanced Open (OWE)",
        "none" | "" if has_wep_settings(settings, None) => "WEP",
        value if value.contains("eap") => "WPA Enterprise",
        value if !value.is_empty() => value,
        _ => "Open",
    }
    .to_string()
}

fn profile_ip_settings(settings: &ConnectionSettings, section: &str) -> ProfileIpSettings {
    let values = settings.get(section);
    ProfileIpSettings {
        method: values
            .and_then(|values| setting_string(values, "method"))
            .unwrap_or_else(|| "auto".to_string()),
        addresses: values
            .and_then(|values| values.get("address-data"))
            .and_then(setting_address_data)
            .unwrap_or_default(),
        gateway: values
            .and_then(|values| setting_string(values, "gateway"))
            .filter(|value| !value.is_empty()),
        dns: values
            .and_then(|values| values.get("dns-data"))
            .and_then(setting_string_list)
            .unwrap_or_default(),
        routes: values
            .and_then(|values| values.get("route-data"))
            .and_then(setting_route_data)
            .unwrap_or_default(),
        ignore_auto_dns: values
            .and_then(|values| values.get("ignore-auto-dns"))
            .and_then(setting_bool)
            .unwrap_or(false),
        dns_search: values
            .and_then(|values| values.get("dns-search"))
            .and_then(setting_string_list)
            .unwrap_or_default(),
        route_metric: values
            .and_then(|values| values.get("route-metric"))
            .and_then(setting_i64),
    }
}

fn setting_address_data(value: &OwnedValue) -> Option<Vec<TargetIpAddress>> {
    let entries: Vec<HashMap<String, OwnedValue>> = value.try_clone().ok()?.try_into().ok()?;
    Some(
        entries
            .into_iter()
            .filter_map(|entry| {
                Some(TargetIpAddress {
                    address: setting_string(&entry, "address")?,
                    prefix: entry.get("prefix").and_then(setting_u32)?,
                })
            })
            .collect(),
    )
}

fn setting_route_data(value: &OwnedValue) -> Option<Vec<TargetIpRoute>> {
    let entries: Vec<HashMap<String, OwnedValue>> = value.try_clone().ok()?.try_into().ok()?;
    Some(
        entries
            .into_iter()
            .filter_map(|entry| {
                Some(TargetIpRoute {
                    dest: setting_string(&entry, "dest")?,
                    prefix: entry.get("prefix").and_then(setting_u32)?,
                    next_hop: setting_string(&entry, "next-hop").filter(|value| !value.is_empty()),
                    metric: entry.get("metric").and_then(setting_u32),
                    table: entry.get("table").and_then(setting_u32),
                })
            })
            .collect(),
    )
}

fn setting_string_list(value: &OwnedValue) -> Option<Vec<String>> {
    value.try_clone().ok()?.try_into().ok()
}

fn setting_i64(value: &OwnedValue) -> Option<i64> {
    value
        .try_clone()
        .ok()
        .and_then(|value| value.try_into().ok())
        .or_else(|| setting_u32(value).map(i64::from))
}

fn validate_profile_update(update: &WifiProfileUpdate) -> Result<()> {
    if !matches!(
        update.mac_address_policy.as_str(),
        "default" | "stable" | "random" | "permanent"
    ) {
        return Err(DomainError::validation(
            ErrorOperation::ProfileOperation,
            "MAC address policy must be default, stable, random, or permanent",
        )
        .with_detail("field", "mac_address_policy")
        .into());
    }
    metered_code(&update.metered)?;
    validate_ip_settings("ipv4", &update.ipv4, false)?;
    validate_ip_settings("ipv6", &update.ipv6, true)
}

fn validate_ip_settings(section: &str, settings: &TargetIpSettings, ipv6: bool) -> Result<()> {
    let method = settings.method.as_deref().unwrap_or("auto");
    if !matches!(method, "auto" | "manual" | "disabled") {
        return Err(DomainError::validation(
            ErrorOperation::ProfileOperation,
            format!("{section} method must be auto, manual, or disabled"),
        )
        .with_detail("field", format!("{section}.method"))
        .into());
    }
    if method == "manual" && settings.addresses.is_empty() {
        return Err(DomainError::validation(
            ErrorOperation::ProfileOperation,
            format!("{section} manual configuration requires an address"),
        )
        .with_detail("field", format!("{section}.addresses"))
        .into());
    }
    for address in &settings.addresses {
        validate_ip_value(section, "address", &address.address, ipv6)?;
        let max_prefix = if ipv6 { 128 } else { 32 };
        if address.prefix > max_prefix {
            return Err(DomainError::validation(
                ErrorOperation::ProfileOperation,
                format!("{section} prefix must be between 0 and {max_prefix}"),
            )
            .with_detail("field", format!("{section}.prefix"))
            .into());
        }
    }
    if let Some(gateway) = settings
        .gateway
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        validate_ip_value(section, "gateway", gateway, ipv6)?;
    }
    for dns in &settings.dns {
        validate_ip_value(section, "dns", dns, ipv6)?;
    }
    Ok(())
}

fn validate_ip_value(section: &str, field: &str, value: &str, ipv6: bool) -> Result<()> {
    let parsed: std::net::IpAddr = value.parse().map_err(|error| {
        DomainError::validation(
            ErrorOperation::ProfileOperation,
            format!("invalid {section} {field}: {value}"),
        )
        .with_detail("field", format!("{section}.{field}"))
        .with_cause(anyhow::Error::new(error))
    })?;
    if parsed.is_ipv6() != ipv6 {
        return Err(DomainError::validation(
            ErrorOperation::ProfileOperation,
            format!("{section} {field} has the wrong address family"),
        )
        .with_detail("field", format!("{section}.{field}"))
        .into());
    }
    Ok(())
}

fn replace_ip_settings(
    settings: &mut ConnectionSettings,
    section: &str,
    update: &TargetIpSettings,
) -> Result<()> {
    let values = settings.entry(section.to_string()).or_default();
    for key in [
        "address-data",
        "addresses",
        "gateway",
        "dns-data",
        "dns",
        "route-data",
        "route-metric",
        "ignore-auto-dns",
        "dns-search",
    ] {
        values.remove(key);
    }
    let method = update.method.as_deref().unwrap_or("auto");
    values.insert("method".to_string(), owned_value(method.to_string())?);
    if !update.addresses.is_empty() {
        values.insert(
            "address-data".to_string(),
            owned_value(profile_address_data(&update.addresses)?)?,
        );
    }
    if let Some(gateway) = update.gateway.as_deref().filter(|value| !value.is_empty()) {
        values.insert("gateway".to_string(), owned_value(gateway.to_string())?);
    }
    if !update.dns.is_empty() {
        values.insert("dns-data".to_string(), owned_value(update.dns.clone())?);
    }
    if !update.routes.is_empty() {
        values.insert(
            "route-data".to_string(),
            owned_value(profile_route_data(&update.routes)?)?,
        );
    }
    values.insert(
        "ignore-auto-dns".to_string(),
        owned_value(update.ignore_auto_dns.unwrap_or(false))?,
    );
    if !update.dns_search.is_empty() {
        values.insert(
            "dns-search".to_string(),
            owned_value(update.dns_search.clone())?,
        );
    }
    if let Some(route_metric) = update.route_metric {
        values.insert("route-metric".to_string(), owned_value(route_metric)?);
    }
    Ok(())
}

fn profile_address_data(addresses: &[TargetIpAddress]) -> Result<Vec<HashMap<String, OwnedValue>>> {
    addresses
        .iter()
        .map(|address| {
            Ok(HashMap::from([
                ("address".to_string(), owned_value(address.address.clone())?),
                ("prefix".to_string(), owned_value(address.prefix)?),
            ]))
        })
        .collect()
}

fn profile_route_data(routes: &[TargetIpRoute]) -> Result<Vec<HashMap<String, OwnedValue>>> {
    routes
        .iter()
        .map(|route| {
            let mut values = HashMap::from([
                ("dest".to_string(), owned_value(route.dest.clone())?),
                ("prefix".to_string(), owned_value(route.prefix)?),
            ]);
            if let Some(next_hop) = route.next_hop.as_deref().filter(|value| !value.is_empty()) {
                values.insert("next-hop".to_string(), owned_value(next_hop.to_string())?);
            }
            if let Some(metric) = route.metric {
                values.insert("metric".to_string(), owned_value(metric)?);
            }
            if let Some(table) = route.table {
                values.insert("table".to_string(), owned_value(table)?);
            }
            Ok(values)
        })
        .collect()
}

fn update_personal_password(settings: &mut ConnectionSettings, password: &str) -> Result<()> {
    let security = settings
        .get("802-11-wireless-security")
        .and_then(|section| setting_string(section, "key-mgmt"))
        .unwrap_or_default();
    match security.as_str() {
        "wpa-psk" | "sae" => crate::nm::wifi_settings::validate_wpa_psk(password)?,
        _ => {
            return Err(DomainError::validation(
                ErrorOperation::ProfileOperation,
                "password updates are currently supported only for WPA personal profiles",
            )
            .with_detail("field", "password")
            .into());
        }
    }
    let section = settings
        .entry("802-11-wireless-security".to_string())
        .or_default();
    section.insert("psk".to_string(), owned_value(password.to_string())?);
    section.insert("psk-flags".to_string(), owned_value(0_u32)?);
    Ok(())
}

fn privacy_from_settings(settings: &ConnectionSettings) -> ProfilePrivacy {
    let mac_address_policy = settings
        .get("802-11-wireless")
        .and_then(|wireless| {
            setting_string(wireless, "assigned-mac-address")
                .or_else(|| setting_string(wireless, "cloned-mac-address"))
        })
        .unwrap_or_else(|| "default".to_string());
    let randomized_mac = matches!(mac_address_policy.as_str(), "random" | "stable");
    let ipv4_send_hostname = settings
        .get("ipv4")
        .and_then(|ipv4| ipv4.get("dhcp-send-hostname"))
        .and_then(setting_bool)
        .unwrap_or(true);
    let ipv6_send_hostname = settings
        .get("ipv6")
        .and_then(|ipv6| ipv6.get("dhcp-send-hostname"))
        .and_then(setting_bool)
        .unwrap_or(true);
    ProfilePrivacy {
        mac_address_policy,
        randomized_mac,
        send_hostname: ipv4_send_hostname || ipv6_send_hostname,
    }
}

fn set_dhcp_send_hostname(
    settings: &mut ConnectionSettings,
    section: &str,
    enabled: bool,
) -> Result<()> {
    let ip = settings.entry(section.to_string()).or_default();
    ip.entry("method".to_string())
        .or_insert(owned_value("auto".to_string())?);
    ip.insert("dhcp-send-hostname".to_string(), owned_value(enabled)?);
    Ok(())
}

fn settings_match_wifi_ssid(settings: &ConnectionSettings, ssid_bytes: &[u8]) -> bool {
    let Some(wireless) = wifi_settings_section(settings) else {
        return false;
    };
    wireless
        .get("ssid")
        .and_then(setting_bytes)
        .is_some_and(|saved_ssid| ssid_bytes_match(&saved_ssid, ssid_bytes))
}

fn settings_match_access_point(settings: &ConnectionSettings, ap: &AccessPoint) -> bool {
    let Some(wireless) = wifi_settings_section(settings) else {
        return false;
    };
    if !wireless
        .get("ssid")
        .and_then(setting_bytes)
        .is_some_and(|saved_ssid| ssid_bytes_match(&saved_ssid, ap.ssid_bytes().as_ref()))
    {
        return false;
    }
    wireless
        .get("bssid")
        .and_then(setting_bytes)
        .is_none_or(|saved_bssid| bssid_bytes_match(&saved_bssid, &ap.bssid))
}

fn wifi_settings_section(settings: &ConnectionSettings) -> Option<&HashMap<String, OwnedValue>> {
    let wireless = settings.get("802-11-wireless")?;
    if settings
        .get("connection")
        .and_then(|connection| setting_string(connection, "type"))
        .is_some_and(|connection_type| connection_type != "802-11-wireless")
    {
        return None;
    }
    Some(wireless)
}

fn setting_string(settings: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    settings.get(key).and_then(setting_value_string)
}

fn setting_value_string(value: &OwnedValue) -> Option<String> {
    value
        .try_clone()
        .ok()
        .and_then(|value| value.try_into().ok())
        .or_else(|| String::from_utf8(setting_bytes(value)?).ok())
}

fn setting_bool(value: &OwnedValue) -> Option<bool> {
    value.try_clone().ok()?.try_into().ok()
}

fn setting_u32(value: &OwnedValue) -> Option<u32> {
    value.try_clone().ok()?.try_into().ok()
}

fn setting_bytes(value: &OwnedValue) -> Option<Vec<u8>> {
    value.try_clone().ok()?.try_into().ok()
}

fn ssid_bytes_match(saved_ssid: &[u8], ssid_bytes: &[u8]) -> bool {
    saved_ssid == ssid_bytes
}

fn bssid_bytes_match(saved_bssid: &[u8], ap_bssid: &str) -> bool {
    parse_bssid(ap_bssid).is_some_and(|ap_bssid| saved_bssid == ap_bssid)
}

fn parse_bssid(value: &str) -> Option<Vec<u8>> {
    let bytes: Option<Vec<_>> = value
        .split([':', '-'])
        .map(|part| u8::from_str_radix(part, 16).ok())
        .collect();
    bytes.filter(|bytes| bytes.len() == 6)
}

fn root_object_path() -> Result<OwnedObjectPath> {
    OwnedObjectPath::try_from("/").context("create root object path")
}

#[cfg(test)]
mod tests {
    include!("../../test_support/settings_unit.rs");
}
