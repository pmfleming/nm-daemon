use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    AuthKind, Bssid, ConnectionReadiness, EnterpriseAuth, InterfaceName, NetworkAuth,
    NetworkCapabilities, NmObjectPath, Security, Ssid, TargetProfileSettings, WifiConnectTarget,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WifiConnectTargetV1 {
    ssid: String,
    #[serde(default)]
    ssid_bytes: Vec<u8>,
    #[serde(default, alias = "path")]
    ap_path: Option<NmObjectPath>,
    #[serde(default)]
    bssid: Option<Bssid>,
    #[serde(default, alias = "device_iface")]
    ifname: Option<InterfaceName>,
    #[serde(default)]
    device_path: Option<NmObjectPath>,
    #[serde(default, alias = "name")]
    connection_name: Option<String>,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    security: Option<Security>,
    #[serde(default)]
    key_mgmt: Option<String>,
    #[serde(default)]
    enterprise: Option<EnterpriseAuth>,
    #[serde(default)]
    profile: TargetProfileSettings,
}

#[derive(Serialize)]
struct WifiConnectTargetRef<'a> {
    ssid: &'a str,
    ssid_bytes: &'a [u8],
    ap_path: &'a Option<NmObjectPath>,
    bssid: &'a Option<Bssid>,
    ifname: &'a Option<InterfaceName>,
    device_path: &'a Option<NmObjectPath>,
    connection_name: &'a Option<String>,
    private: bool,
    hidden: bool,
    security: &'a Option<Security>,
    key_mgmt: &'a Option<String>,
    enterprise: &'a Option<EnterpriseAuth>,
    profile: &'a TargetProfileSettings,
}

impl<'a> From<&'a WifiConnectTarget> for WifiConnectTargetRef<'a> {
    fn from(target: &'a WifiConnectTarget) -> Self {
        Self {
            ssid: target.ssid.as_str(),
            ssid_bytes: target.ssid.as_bytes(),
            ap_path: &target.ap_path,
            bssid: &target.bssid,
            ifname: &target.ifname,
            device_path: &target.device_path,
            connection_name: &target.connection_name,
            private: target.private,
            hidden: target.hidden,
            security: &target.security,
            key_mgmt: &target.key_mgmt,
            enterprise: &target.enterprise,
            profile: &target.profile,
        }
    }
}

impl Serialize for WifiConnectTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WifiConnectTargetRef::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WifiConnectTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WifiConnectTargetV1::deserialize(deserializer)?;
        let bytes = if wire.ssid_bytes.is_empty() {
            wire.ssid.as_bytes().to_vec()
        } else {
            wire.ssid_bytes
        };
        let ssid = Ssid::from_bytes(bytes).map_err(D::Error::custom)?;
        if ssid.as_str() != wire.ssid {
            return Err(D::Error::custom(
                "ssid display does not match the exact ssid_bytes identity",
            ));
        }
        Ok(Self {
            ssid,
            ap_path: wire.ap_path,
            bssid: wire.bssid,
            ifname: wire.ifname,
            device_path: wire.device_path,
            connection_name: wire.connection_name,
            private: wire.private,
            hidden: wire.hidden,
            security: wire.security,
            key_mgmt: wire.key_mgmt,
            enterprise: wire.enterprise,
            profile: wire.profile,
        })
    }
}

#[derive(Deserialize)]
struct NetworkCapabilitiesV1 {
    can_connect: bool,
    can_connect_now: bool,
    can_connect_with_password: bool,
    needs_password: bool,
    #[serde(default)]
    can_connect_with_credentials: bool,
    #[serde(default)]
    needs_credentials: bool,
    can_forget: bool,
    can_toggle_autoconnect: bool,
    #[serde(default)]
    can_set_mac_randomization: bool,
    #[serde(default)]
    can_set_send_hostname: bool,
    #[serde(default)]
    can_share_qr: bool,
    supported_auth: bool,
    unsupported_reason: Option<String>,
}

#[derive(Serialize)]
struct NetworkCapabilitiesRef<'a> {
    can_connect: bool,
    can_connect_now: bool,
    can_connect_with_password: bool,
    needs_password: bool,
    can_connect_with_credentials: bool,
    needs_credentials: bool,
    can_forget: bool,
    can_toggle_autoconnect: bool,
    can_set_mac_randomization: bool,
    can_set_send_hostname: bool,
    can_share_qr: bool,
    supported_auth: bool,
    unsupported_reason: Option<&'a str>,
}

impl<'a> From<&'a NetworkCapabilities> for NetworkCapabilitiesRef<'a> {
    fn from(capabilities: &'a NetworkCapabilities) -> Self {
        let readiness = capabilities.v1_readiness();
        Self {
            can_connect: readiness.0,
            can_connect_now: readiness.1,
            can_connect_with_password: readiness.2,
            needs_password: readiness.3,
            can_connect_with_credentials: readiness.4,
            needs_credentials: readiness.5,
            supported_auth: readiness.6,
            unsupported_reason: readiness.7,
            can_forget: capabilities.has_profile,
            can_toggle_autoconnect: capabilities.has_profile,
            can_set_mac_randomization: capabilities.has_profile,
            can_set_send_hostname: capabilities.has_profile,
            can_share_qr: capabilities.can_share_qr,
        }
    }
}

impl Serialize for NetworkCapabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        NetworkCapabilitiesRef::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NetworkCapabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = NetworkCapabilitiesV1::deserialize(deserializer)?;
        let profile_flags = [
            wire.can_forget,
            wire.can_toggle_autoconnect,
            wire.can_set_mac_randomization,
            wire.can_set_send_hostname,
        ];
        if profile_flags.iter().any(|flag| *flag != profile_flags[0]) {
            return Err(D::Error::custom(
                "profile mutation capability flags must agree",
            ));
        }
        let readiness = match (
            wire.can_connect,
            wire.can_connect_now,
            wire.can_connect_with_password,
            wire.needs_password,
            wire.can_connect_with_credentials,
            wire.needs_credentials,
            wire.supported_auth,
        ) {
            (true, true, false, false, false, false, true) => ConnectionReadiness::Ready,
            (true, false, true, true, false, false, true) => ConnectionReadiness::NeedsPassword,
            (true, false, false, false, true, true, true) => {
                ConnectionReadiness::NeedsEnterpriseCredentials
            }
            (false, false, false, false, false, false, false) => ConnectionReadiness::Unsupported {
                reason: wire.unsupported_reason,
            },
            _ => {
                return Err(D::Error::custom(
                    "contradictory v1 network readiness capability flags",
                ));
            }
        };
        Ok(Self {
            readiness,
            has_profile: profile_flags[0],
            can_share_qr: wire.can_share_qr,
        })
    }
}

#[derive(Deserialize, Serialize)]
struct NetworkAuthV1 {
    kind: AuthKind,
    key_management: Vec<String>,
    supported: bool,
    required_fields: Vec<String>,
    optional_fields: Vec<String>,
    note: Option<String>,
}

impl Serialize for NetworkAuth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        NetworkAuthV1 {
            kind: self.kind,
            key_management: self.key_management.clone(),
            supported: self.supported(),
            required_fields: self.required_fields.clone(),
            optional_fields: self.optional_fields.clone(),
            note: self.note.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NetworkAuth {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = NetworkAuthV1::deserialize(deserializer)?;
        if wire.supported != (wire.kind != AuthKind::Unsupported) {
            return Err(D::Error::custom(
                "authentication kind contradicts supported flag",
            ));
        }
        Ok(Self::new(
            wire.kind,
            wire.key_management,
            wire.required_fields,
            wire.optional_fields,
            wire.note,
        ))
    }
}
