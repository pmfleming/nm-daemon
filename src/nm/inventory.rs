use std::collections::HashMap;

use anyhow::{Context, Result};
use zvariant::{OwnedObjectPath, OwnedValue};

use super::{ACTIVE_CONNECTION_IFACE, DEVICE_IFACE, Nm};
use crate::error::{DomainError, ErrorOperation};
use crate::model::{
    ActiveConnectionSummary, ConnectivityStatus, NetworkConnectionSummary, NetworkDeactivateResult,
    NetworkDeviceSummary, NetworkInventory, NetworkStateSummary, ProfileActivationResult,
    device_state_reason,
};
use crate::variant::value_string;

/// Selects one saved profile by UUID or settings path, plus an optional device.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProfileSelector {
    pub(crate) uuid: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) device: Option<String>,
}

/// Selects one active connection by active-connection path or profile UUID.
#[derive(Debug, Clone, Default)]
pub(crate) struct ActiveConnectionSelector {
    pub(crate) path: Option<String>,
    pub(crate) uuid: Option<String>,
}

impl Nm {
    pub(crate) fn network_inventory(&self) -> Result<NetworkInventory> {
        let devices = self.network_devices()?;
        let active_connections = self.network_active_connections()?;
        let connections = self.network_connections_with(&devices, &active_connections)?;
        let root = self.root_proxy();
        Ok(NetworkInventory {
            networking_enabled: root.get_property("NetworkingEnabled").unwrap_or(true),
            primary_connection: object_path_property(&root, "PrimaryConnection"),
            activating_connection: object_path_property(&root, "ActivatingConnection"),
            devices,
            connections,
            active_connections,
        })
    }

    pub(crate) fn network_devices(&self) -> Result<Vec<NetworkDeviceSummary>> {
        let device_paths: Vec<OwnedObjectPath> = self
            .root_proxy()
            .call("GetDevices", &())
            .context("GetDevices for network inventory")?;
        device_paths
            .iter()
            .map(|path| self.network_device_summary(path))
            .collect()
    }

    pub(crate) fn network_connections(&self) -> Result<Vec<NetworkConnectionSummary>> {
        let devices = self.network_devices()?;
        let active_connections = self.network_active_connections()?;
        self.network_connections_with(&devices, &active_connections)
    }

    pub(crate) fn network_active_connections(&self) -> Result<Vec<ActiveConnectionSummary>> {
        let active_paths: Vec<OwnedObjectPath> = self
            .root_proxy()
            .get_property("ActiveConnections")
            .unwrap_or_default();
        active_paths
            .iter()
            .filter_map(|path| self.active_connection_summary(path).transpose())
            .collect()
    }

    pub(crate) fn network_state(&self) -> Result<NetworkStateSummary> {
        let root = self.root_proxy();
        let state: u32 = root.get_property("State").unwrap_or(0);
        let connectivity_code: u32 = root.get_property("Connectivity").unwrap_or(0);
        let active_connections = self.network_active_connections()?;
        let by_path = active_connections
            .iter()
            .map(|active| (active.path.as_str(), active))
            .collect::<HashMap<_, _>>();
        let summary_for = |path: Option<String>| {
            path.and_then(|path| by_path.get(path.as_str()).map(|active| (*active).clone()))
        };
        let primary_connection = summary_for(object_path_property(&root, "PrimaryConnection"));
        Ok(NetworkStateSummary {
            state,
            state_name: network_state_name(state),
            networking_enabled: root.get_property("NetworkingEnabled").unwrap_or(true),
            radios: self.radio_status()?,
            connectivity: self
                .with_portal_context(ConnectivityStatus::from_nm_code(connectivity_code)),
            connectivity_check_uri: root
                .get_property::<String>("ConnectivityCheckUri")
                .ok()
                .filter(|uri| !uri.is_empty()),
            connectivity_check_enabled: root
                .get_property("ConnectivityCheckEnabled")
                .unwrap_or(false),
            primary_connection_type: root
                .get_property::<String>("PrimaryConnectionType")
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    primary_connection
                        .as_ref()
                        .map(|active| active.connection_type.clone())
                }),
            primary_connection,
            activating_connection: summary_for(object_path_property(&root, "ActivatingConnection")),
            default4: active_connections
                .iter()
                .find(|active| active.default4)
                .map(|active| active.path.clone()),
            default6: active_connections
                .iter()
                .find(|active| active.default6)
                .map(|active| active.path.clone()),
        })
    }

    pub(crate) fn activate_network_profile(
        &self,
        selector: &ProfileSelector,
    ) -> Result<ProfileActivationResult> {
        let devices = self.network_devices()?;
        let active_connections = self.network_active_connections()?;
        let connections = self.network_connections_with(&devices, &active_connections)?;
        let profile = select_profile(&connections, selector)?;
        let device = activation_device(profile, &devices, selector)?;
        let profile_path = object_path(&profile.path)?;
        let device_path = object_path(device.as_deref().unwrap_or("/"))?;
        let specific_object = object_path("/")?;
        tracing::info!(
            profile = %profile.path,
            uuid = %profile.uuid,
            connection_type = %profile.connection_type,
            device = device.as_deref().unwrap_or("any"),
            "activating saved NetworkManager profile"
        );
        let active_path: OwnedObjectPath = self
            .root_proxy()
            .call(
                "ActivateConnection",
                &(profile_path, device_path, specific_object),
            )
            .with_context(|| format!("ActivateConnection for profile {}", profile.id))?;
        let active = self.active_connection_summary(&active_path)?;
        let state = active.as_ref().map(|active| active.state).unwrap_or(1);
        Ok(ProfileActivationResult {
            status: if state == 2 {
                "activated"
            } else {
                "activating"
            },
            profile_path: profile.path.clone(),
            id: profile.id.clone(),
            uuid: profile.uuid.clone(),
            connection_type: profile.connection_type.clone(),
            type_name: profile.type_name,
            active_connection: Some(active_path.to_string()),
            device: active
                .as_ref()
                .and_then(|active| active.devices.first().cloned())
                .or(device),
            state,
            state_name: active_connection_state_name(state),
            message: format!("Activating saved profile {}", profile.id),
        })
    }

    pub(crate) fn deactivate_network_connection(
        &self,
        selector: &ActiveConnectionSelector,
    ) -> Result<NetworkDeactivateResult> {
        let active_connections = self.network_active_connections()?;
        let active = select_active_connection(&active_connections, selector)?;
        let path = object_path(&active.path)?;
        tracing::info!(active = %active.path, id = %active.id, "deactivating NetworkManager connection");
        self.root_proxy()
            .call::<_, _, ()>("DeactivateConnection", &(path,))
            .with_context(|| format!("DeactivateConnection for {}", active.id))?;
        Ok(NetworkDeactivateResult {
            status: "deactivated",
            path: active.path.clone(),
            id: active.id.clone(),
            uuid: active.uuid.clone(),
            connection_type: active.connection_type.clone(),
            message: format!("Deactivated {}", active.id),
        })
    }

    fn network_connections_with(
        &self,
        devices: &[NetworkDeviceSummary],
        active_connections: &[ActiveConnectionSummary],
    ) -> Result<Vec<NetworkConnectionSummary>> {
        let active_by_profile = active_connections
            .iter()
            .filter_map(|active| Some((active.profile_path.as_deref()?, active.path.as_str())))
            .collect::<HashMap<_, _>>();
        let available_by_profile = available_devices_by_profile(devices);
        let connection_paths: Vec<OwnedObjectPath> = self
            .settings_proxy()
            .call("ListConnections", &())
            .context("ListConnections for network inventory")?;
        connection_paths
            .iter()
            .filter_map(|path| {
                self.network_connection_summary(path, &available_by_profile, &active_by_profile)
                    .transpose()
            })
            .collect()
    }

    fn network_device_summary(&self, path: &OwnedObjectPath) -> Result<NetworkDeviceSummary> {
        let device = self.proxy_path(path, DEVICE_IFACE)?;
        let device_type = device.get_property("DeviceType").unwrap_or(0);
        let state = device.get_property("State").unwrap_or(0);
        let state_reason: (u32, u32) = device.get_property("StateReason").unwrap_or((state, 0));
        Ok(NetworkDeviceSummary {
            path: path.to_string(),
            interface: device.get_property("Interface").unwrap_or_default(),
            ip_interface: nonempty(device.get_property("IpInterface").ok()),
            device_type,
            type_name: device_type_name(device_type),
            state,
            state_name: device_state_name(state),
            state_reason: device_state_reason(state_reason.1),
            managed: device.get_property("Managed").unwrap_or(false),
            autoconnect: device.get_property("Autoconnect").unwrap_or(false),
            driver: nonempty(device.get_property("Driver").ok()),
            firmware_version: nonempty(device.get_property("FirmwareVersion").ok()),
            hw_address: nonempty(device.get_property("HwAddress").ok()),
            mtu: device.get_property("Mtu").ok().filter(|mtu| *mtu > 0),
            carrier: self.device_carrier(path, device_type),
            speed_mbps: self.device_speed_mbps(path, device_type),
            active_connection: object_path_property(&device, "ActiveConnection"),
            available_connections: object_path_list_property(&device, "AvailableConnections"),
        })
    }

    /// Wired-style link presence, read from the device's typed sub-interface.
    fn device_carrier(&self, path: &OwnedObjectPath, device_type: u32) -> Option<bool> {
        let interface = wired_interface(device_type)?;
        self.proxy(path.as_str(), interface)
            .ok()?
            .get_property("Carrier")
            .ok()
    }

    fn device_speed_mbps(&self, path: &OwnedObjectPath, device_type: u32) -> Option<u32> {
        let interface = wired_interface(device_type)?;
        self.proxy(path.as_str(), interface)
            .ok()?
            .get_property::<u32>("Speed")
            .ok()
            .filter(|speed| *speed > 0)
    }

    fn active_connection_summary(
        &self,
        path: &OwnedObjectPath,
    ) -> Result<Option<ActiveConnectionSummary>> {
        if path.as_str() == "/" {
            return Ok(None);
        }
        let active = self.proxy_path(path, ACTIVE_CONNECTION_IFACE)?;
        let id = active.get_property::<String>("Id").unwrap_or_default();
        let uuid = active.get_property::<String>("Uuid").unwrap_or_default();
        if id.is_empty() && uuid.is_empty() {
            return Ok(None);
        }
        let state = active.get_property("State").unwrap_or(0);
        Ok(Some(ActiveConnectionSummary {
            path: path.to_string(),
            id,
            uuid,
            connection_type: active.get_property("Type").unwrap_or_default(),
            state,
            state_name: active_connection_state_name(state),
            state_flags: active.get_property("StateFlags").unwrap_or(0),
            vpn: active.get_property("Vpn").unwrap_or(false),
            default4: active.get_property("Default").unwrap_or(false),
            default6: active.get_property("Default6").unwrap_or(false),
            profile_path: object_path_property(&active, "Connection"),
            specific_object: object_path_property(&active, "SpecificObject"),
            devices: object_path_list_property(&active, "Devices"),
        }))
    }

    fn network_connection_summary(
        &self,
        path: &OwnedObjectPath,
        available_by_profile: &HashMap<String, Vec<String>>,
        active_by_profile: &HashMap<&str, &str>,
    ) -> Result<Option<NetworkConnectionSummary>> {
        let settings = self.connection_settings(path)?;
        let Some(connection) = settings.get("connection") else {
            return Ok(None);
        };
        let id = setting_string(connection, "id").unwrap_or_default();
        let uuid = setting_string(connection, "uuid").unwrap_or_default();
        let connection_type = setting_string(connection, "type").unwrap_or_default();
        if id.is_empty() || uuid.is_empty() || connection_type.is_empty() {
            return Ok(None);
        }
        Ok(Some(NetworkConnectionSummary {
            path: path.to_string(),
            id,
            uuid,
            connection_type: connection_type.clone(),
            type_name: connection_type_name(&connection_type),
            autoconnect: setting_bool(connection, "autoconnect").unwrap_or(true),
            autoconnect_priority: setting_i32(connection, "autoconnect-priority").unwrap_or(0),
            timestamp_ms: setting_u64(connection, "timestamp")
                .map(|seconds| seconds.saturating_mul(1000)),
            interface_name: setting_string(connection, "interface-name").filter(|v| !v.is_empty()),
            permissions: setting_strings(connection, "permissions"),
            available_devices: available_by_profile
                .get(path.as_str())
                .cloned()
                .unwrap_or_default(),
            active_connection: active_by_profile
                .get(path.as_str())
                .map(|value| (*value).to_string()),
        }))
    }
}

fn select_profile<'a>(
    connections: &'a [NetworkConnectionSummary],
    selector: &ProfileSelector,
) -> Result<&'a NetworkConnectionSummary> {
    let matched = match (&selector.uuid, &selector.path) {
        (Some(uuid), _) => connections.iter().find(|profile| &profile.uuid == uuid),
        (None, Some(path)) => connections.iter().find(|profile| &profile.path == path),
        (None, None) => {
            return Err(DomainError::validation(
                ErrorOperation::Connect,
                "network.activateProfile requires uuid or path",
            )
            .into());
        }
    };
    matched.ok_or_else(|| {
        DomainError::not_found(
            ErrorOperation::Connect,
            "no saved profile matched the request",
        )
        .with_detail("uuid", selector.uuid.clone().unwrap_or_default())
        .with_detail("path", selector.path.clone().unwrap_or_default())
        .into()
    })
}

fn activation_device(
    profile: &NetworkConnectionSummary,
    devices: &[NetworkDeviceSummary],
    selector: &ProfileSelector,
) -> Result<Option<String>> {
    let Some(requested) = selector.device.as_deref() else {
        return Ok(profile.available_devices.first().cloned());
    };
    devices
        .iter()
        .find(|device| device.path == requested || device.interface == requested)
        .map(|device| Some(device.path.clone()))
        .ok_or_else(|| {
            DomainError::not_found(ErrorOperation::Connect, "requested device does not exist")
                .with_detail("device", requested)
                .into()
        })
}

fn select_active_connection<'a>(
    active_connections: &'a [ActiveConnectionSummary],
    selector: &ActiveConnectionSelector,
) -> Result<&'a ActiveConnectionSummary> {
    let matched = match (&selector.path, &selector.uuid) {
        (Some(path), _) => active_connections
            .iter()
            .find(|active| &active.path == path),
        (None, Some(uuid)) => active_connections
            .iter()
            .find(|active| &active.uuid == uuid),
        (None, None) => {
            return Err(DomainError::validation(
                ErrorOperation::Disconnect,
                "network.deactivate requires path or uuid",
            )
            .into());
        }
    };
    matched.ok_or_else(|| {
        DomainError::not_found(
            ErrorOperation::Disconnect,
            "no active connection matched the request",
        )
        .with_detail("path", selector.path.clone().unwrap_or_default())
        .with_detail("uuid", selector.uuid.clone().unwrap_or_default())
        .into()
    })
}

fn object_path(value: &str) -> Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(value.to_string())
        .with_context(|| format!("parse NetworkManager object path {value}"))
}

fn available_devices_by_profile(devices: &[NetworkDeviceSummary]) -> HashMap<String, Vec<String>> {
    let mut result = HashMap::<String, Vec<String>>::new();
    for device in devices {
        for profile in &device.available_connections {
            result
                .entry(profile.clone())
                .or_default()
                .push(device.path.clone());
        }
    }
    result
}

fn object_path_property(proxy: &zbus::blocking::Proxy<'_>, name: &str) -> Option<String> {
    proxy
        .get_property::<OwnedObjectPath>(name)
        .ok()
        .filter(|path| path.as_str() != "/")
        .map(|path| path.to_string())
}

fn object_path_list_property(proxy: &zbus::blocking::Proxy<'_>, name: &str) -> Vec<String> {
    proxy
        .get_property::<Vec<OwnedObjectPath>>(name)
        .unwrap_or_default()
        .into_iter()
        .filter(|path| path.as_str() != "/")
        .map(|path| path.to_string())
        .collect()
}

fn setting_string(settings: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    settings.get(key).and_then(value_string)
}

fn setting_bool(settings: &HashMap<String, OwnedValue>, key: &str) -> Option<bool> {
    settings
        .get(key)
        .and_then(|value| bool::try_from(value.clone()).ok())
}

fn setting_i32(settings: &HashMap<String, OwnedValue>, key: &str) -> Option<i32> {
    settings
        .get(key)
        .and_then(|value| i32::try_from(value.clone()).ok())
}

fn setting_u64(settings: &HashMap<String, OwnedValue>, key: &str) -> Option<u64> {
    settings
        .get(key)
        .and_then(|value| u64::try_from(value.clone()).ok())
}

fn setting_strings(settings: &HashMap<String, OwnedValue>, key: &str) -> Vec<String> {
    settings
        .get(key)
        .and_then(|value| Vec::<String>::try_from(value.clone()).ok())
        .unwrap_or_default()
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

/// NetworkManager exposes carrier/speed on the type-specific device interface.
fn wired_interface(device_type: u32) -> Option<&'static str> {
    match device_type {
        1 => Some("org.freedesktop.NetworkManager.Device.Wired"),
        13 => Some("org.freedesktop.NetworkManager.Device.Bridge"),
        10 => Some("org.freedesktop.NetworkManager.Device.Bond"),
        15 => Some("org.freedesktop.NetworkManager.Device.Team"),
        11 => Some("org.freedesktop.NetworkManager.Device.Vlan"),
        _ => None,
    }
}

fn device_type_name(value: u32) -> &'static str {
    match value {
        1 => "ethernet",
        2 => "wifi",
        5 => "bluetooth",
        8 => "modem",
        10 => "bond",
        11 => "vlan",
        13 => "bridge",
        14 => "generic",
        15 => "team",
        16 => "tun",
        17 => "ip-tunnel",
        18 => "macvlan",
        19 => "vxlan",
        20 => "veth",
        21 => "macsec",
        22 => "dummy",
        23 => "ppp",
        29 => "wifi-p2p",
        30 => "vrf",
        31 => "loopback",
        32 => "hsr",
        _ => "unknown",
    }
}

fn connection_type_name(value: &str) -> &'static str {
    match value {
        "802-3-ethernet" => "ethernet",
        "802-11-wireless" => "wifi",
        "bluetooth" => "bluetooth",
        "gsm" | "cdma" => "cellular",
        "vpn" => "vpn",
        "wireguard" => "wireguard",
        "bond" => "bond",
        "bridge" => "bridge",
        "vlan" => "vlan",
        "team" => "team",
        "tun" => "tun",
        "loopback" => "loopback",
        _ => "other",
    }
}

fn network_state_name(value: u32) -> &'static str {
    match value {
        10 => "asleep",
        20 => "disconnected",
        30 => "disconnecting",
        40 => "connecting",
        50 => "connected-local",
        60 => "connected-site",
        70 => "connected-global",
        _ => "unknown",
    }
}

pub(super) fn device_state_name(value: u32) -> &'static str {
    match value {
        10 => "unmanaged",
        20 => "unavailable",
        30 => "disconnected",
        40 => "prepare",
        50 => "config",
        60 => "need-auth",
        70 => "ip-config",
        80 => "ip-check",
        90 => "secondaries",
        100 => "activated",
        110 => "deactivating",
        120 => "failed",
        _ => "unknown",
    }
}

pub(super) fn active_connection_state_name(value: u32) -> &'static str {
    match value {
        1 => "activating",
        2 => "activated",
        3 => "deactivating",
        4 => "deactivated",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActiveConnectionSelector, ProfileSelector, active_connection_state_name,
        connection_type_name, device_state_name, device_type_name, network_state_name,
        select_active_connection, select_profile,
    };
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
    use crate::model::{ActiveConnectionSummary, NetworkConnectionSummary};

    fn profile(path: &str, uuid: &str) -> NetworkConnectionSummary {
        NetworkConnectionSummary {
            path: path.to_string(),
            id: "Example".to_string(),
            uuid: uuid.to_string(),
            connection_type: "802-11-wireless".to_string(),
            type_name: "wifi",
            autoconnect: true,
            autoconnect_priority: 0,
            timestamp_ms: None,
            interface_name: None,
            permissions: Vec::new(),
            available_devices: Vec::new(),
            active_connection: None,
        }
    }

    fn active(path: &str, uuid: &str) -> ActiveConnectionSummary {
        ActiveConnectionSummary {
            path: path.to_string(),
            id: "Example".to_string(),
            uuid: uuid.to_string(),
            connection_type: "802-11-wireless".to_string(),
            state: 2,
            state_name: "activated",
            state_flags: 0,
            vpn: false,
            default4: true,
            default6: false,
            profile_path: Some("/settings/1".to_string()),
            specific_object: None,
            devices: vec!["/devices/1".to_string()],
        }
    }

    #[test]
    fn networkmanager_types_and_states_have_stable_names() {
        assert_eq!(device_type_name(2), "wifi");
        assert_eq!(connection_type_name("wireguard"), "wireguard");
        assert_eq!(device_state_name(100), "activated");
        assert_eq!(active_connection_state_name(1), "activating");
        assert_eq!(network_state_name(70), "connected-global");
    }

    #[test]
    fn profile_selection_prefers_uuid_and_falls_back_to_path() {
        let connections = vec![
            profile("/settings/1", "uuid-1"),
            profile("/settings/2", "uuid-2"),
        ];
        let by_uuid = ProfileSelector {
            uuid: Some("uuid-2".to_string()),
            ..ProfileSelector::default()
        };
        assert_eq!(
            select_profile(&connections, &by_uuid).unwrap().path,
            "/settings/2"
        );

        let by_path = ProfileSelector {
            path: Some("/settings/1".to_string()),
            ..ProfileSelector::default()
        };
        assert_eq!(
            select_profile(&connections, &by_path).unwrap().uuid,
            "uuid-1"
        );
    }

    #[test]
    fn profile_selection_reports_typed_validation_and_not_found_errors() {
        let connections = vec![profile("/settings/1", "uuid-1")];
        let empty = select_profile(&connections, &ProfileSelector::default()).unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&empty, ErrorOperation::Unknown).code,
            ErrorCode::ValidationError
        );

        let missing = select_profile(
            &connections,
            &ProfileSelector {
                uuid: Some("absent".to_string()),
                ..ProfileSelector::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&missing, ErrorOperation::Unknown).code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn active_connection_selection_matches_path_or_uuid() {
        let actives = vec![active("/active/1", "uuid-1")];
        let by_path = ActiveConnectionSelector {
            path: Some("/active/1".to_string()),
            uuid: None,
        };
        assert_eq!(
            select_active_connection(&actives, &by_path).unwrap().uuid,
            "uuid-1"
        );

        let by_uuid = ActiveConnectionSelector {
            path: None,
            uuid: Some("uuid-1".to_string()),
        };
        assert_eq!(
            select_active_connection(&actives, &by_uuid).unwrap().path,
            "/active/1"
        );

        let missing = ActiveConnectionSelector {
            path: None,
            uuid: Some("absent".to_string()),
        };
        let error = select_active_connection(&actives, &missing).unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&error, ErrorOperation::Unknown).code,
            ErrorCode::NotFound
        );
    }
}
