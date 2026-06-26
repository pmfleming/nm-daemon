use std::collections::HashMap;
use std::process::Command;

use anyhow::{Context, Result};
use zvariant::{OwnedObjectPath, OwnedValue};

use super::{
    ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, NM_IFACE, NM_PATH, Nm,
    SETTINGS_CONNECTION_IFACE, WIFI_IFACE,
};
use crate::model::{
    DisconnectResult, Ip4Status, MeteredStatus, SavedWifiConnection, WifiStatus, WirelessStatus,
};

const IP4_CONFIG_IFACE: &str = "org.freedesktop.NetworkManager.IP4Config";

impl Nm {
    pub(crate) fn wifi_status(&self) -> Result<WifiStatus> {
        let profiles = self.saved_wifi_connections()?;
        let connectivity = self.connectivity_check().ok();

        for device in self.wifi_devices()? {
            let Some(active_connection_path) = self.device_active_connection_path(&device.path)?
            else {
                continue;
            };
            let Some(active_ap_path) = self.active_access_point(&device)? else {
                continue;
            };
            let access_point = self.access_point(&device, &active_ap_path, true)?;
            let entry = self
                .network_entries_for_access_points(vec![access_point.clone()])?
                .into_iter()
                .next();
            let active_profile_path = self.active_connection_profile_path(&active_connection_path);
            let profile = active_profile_path
                .as_ref()
                .and_then(|path| active_connection_profile(path, &profiles))
                .or_else(|| {
                    entry
                        .as_ref()
                        .and_then(|entry| entry.primary_profile.clone())
                });
            let active_since_ms = active_profile_path
                .as_ref()
                .and_then(|path| self.connection_timestamp_ms(path));

            return Ok(WifiStatus {
                active: true,
                device_iface: Some(device.iface.clone()),
                active_connection_path: Some(active_connection_path.to_string()),
                access_point: Some(access_point),
                network: entry,
                profile,
                connectivity,
                ip4: self.ip4_status(&device.path).ok().flatten(),
                wireless: self.wireless_status(&device).ok(),
                metered: self.metered_status(&device.path).ok(),
                active_since_ms,
            });
        }

        Ok(WifiStatus {
            active: false,
            device_iface: None,
            active_connection_path: None,
            access_point: None,
            network: None,
            profile: None,
            connectivity,
            ip4: None,
            wireless: None,
            metered: None,
            active_since_ms: None,
        })
    }

    pub(crate) fn disconnect_wifi(&self) -> Result<DisconnectResult> {
        let Some(active_connection_path) = self.active_wifi_connection_path()? else {
            return Ok(DisconnectResult {
                status: "noop",
                message: "No active Wi-Fi connection".to_string(),
            });
        };

        tracing::info!(connection = %active_connection_path, "deactivating active Wi-Fi connection");
        let nm = self.proxy(NM_PATH, NM_IFACE)?;
        nm.call::<_, _, ()>("DeactivateConnection", &(active_connection_path,))
            .context("DeactivateConnection for active Wi-Fi connection")?;
        Ok(DisconnectResult {
            status: "disconnected",
            message: "Disconnected Wi-Fi".to_string(),
        })
    }

    fn active_wifi_connection_path(&self) -> Result<Option<OwnedObjectPath>> {
        for device in self.wifi_devices()? {
            if let Some(path) = self.device_active_connection_path(&device.path)? {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    fn device_active_connection_path(
        &self,
        device_path: &OwnedObjectPath,
    ) -> Result<Option<OwnedObjectPath>> {
        let device = self.proxy_path(device_path, DEVICE_IFACE)?;
        let active_connection_path: OwnedObjectPath = device
            .get_property("ActiveConnection")
            .with_context(|| format!("read ActiveConnection for {device_path}"))?;
        Ok((active_connection_path.as_str() != "/").then_some(active_connection_path))
    }

    fn active_connection_profile_path(
        &self,
        active_connection_path: &OwnedObjectPath,
    ) -> Option<OwnedObjectPath> {
        self.proxy_path(active_connection_path, ACTIVE_CONNECTION_IFACE)
            .and_then(|proxy| {
                proxy
                    .get_property("Connection")
                    .context("read active profile path")
            })
            .ok()
    }

    fn connection_timestamp_ms(&self, connection_path: &OwnedObjectPath) -> Option<u64> {
        let connection = self
            .proxy_path(connection_path, SETTINGS_CONNECTION_IFACE)
            .ok()?;
        let settings: ConnectionSettings = connection.call("GetSettings", &()).ok()?;
        settings
            .get("connection")?
            .get("timestamp")
            .and_then(value_u64)
            .map(|seconds| seconds.saturating_mul(1000))
    }

    fn ip4_status(&self, device_path: &OwnedObjectPath) -> Result<Option<Ip4Status>> {
        let device = self.proxy_path(device_path, DEVICE_IFACE)?;
        let ip4_config_path: OwnedObjectPath = device
            .get_property("Ip4Config")
            .with_context(|| format!("read Ip4Config for {device_path}"))?;
        if ip4_config_path.as_str() == "/" {
            return Ok(None);
        }

        let ip4 = self.proxy_path(&ip4_config_path, IP4_CONFIG_IFACE)?;
        let gateway = ip4.get_property("Gateway").ok();
        let (address, prefix) = ip4
            .get_property::<Vec<HashMap<String, OwnedValue>>>("AddressData")
            .ok()
            .and_then(|entries| first_address_data(&entries))
            .unwrap_or((None, None));
        let dns = ip4
            .get_property::<Vec<HashMap<String, OwnedValue>>>("NameserverData")
            .ok()
            .map(|entries| nameserver_data(&entries))
            .filter(|entries| !entries.is_empty())
            .unwrap_or_default();

        Ok(Some(Ip4Status {
            address,
            prefix,
            gateway,
            dns,
        }))
    }

    fn wireless_status(&self, device: &crate::model::WifiDevice) -> Result<WirelessStatus> {
        let wifi = self.proxy_path(&device.path, WIFI_IFACE)?;
        let bitrate_kbps: Option<u32> = wifi.get_property("Bitrate").ok();
        let directional_bitrates = directional_bitrates(&device.iface).unwrap_or_default();
        Ok(WirelessStatus {
            bitrate_mbps: bitrate_kbps.map(|value| value / 1000),
            tx_bitrate_mbps: directional_bitrates.tx_mbps,
            rx_bitrate_mbps: directional_bitrates.rx_mbps,
            mac_address: wifi.get_property("HwAddress").ok(),
        })
    }

    fn metered_status(&self, device_path: &OwnedObjectPath) -> Result<MeteredStatus> {
        let device = self.proxy_path(device_path, DEVICE_IFACE)?;
        let metered_code = device
            .get_property("Metered")
            .with_context(|| format!("read Metered for {device_path}"))?;
        Ok(MeteredStatus::from_nm_code(metered_code))
    }
}

fn first_address_data(
    entries: &[HashMap<String, OwnedValue>],
) -> Option<(Option<String>, Option<u32>)> {
    let first = entries.first()?;
    Some((
        first.get("address").and_then(value_string),
        first.get("prefix").and_then(value_u32),
    ))
}

fn nameserver_data(entries: &[HashMap<String, OwnedValue>]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| entry.get("address").and_then(value_string))
        .collect()
}

#[derive(Default)]
struct DirectionalBitrates {
    tx_mbps: Option<f64>,
    rx_mbps: Option<f64>,
}

fn directional_bitrates(iface: &str) -> Option<DirectionalBitrates> {
    let output = Command::new("iw")
        .args(["dev", iface, "link"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(parse_iw_link_bitrates(&stdout))
}

fn parse_iw_link_bitrates(output: &str) -> DirectionalBitrates {
    let mut bitrates = DirectionalBitrates::default();
    for line in output.lines().map(str::trim) {
        if let Some(value) = parse_iw_bitrate_line(line, "tx bitrate:") {
            bitrates.tx_mbps = Some(value);
        } else if let Some(value) = parse_iw_bitrate_line(line, "rx bitrate:") {
            bitrates.rx_mbps = Some(value);
        }
    }
    bitrates
}

fn parse_iw_bitrate_line(line: &str, prefix: &str) -> Option<f64> {
    let mut fields = line.strip_prefix(prefix)?.split_whitespace();
    let value = fields.next()?.parse::<f64>().ok()?;
    match fields.next()?.to_ascii_lowercase().as_str() {
        "kbit/s" => Some(value / 1000.0),
        "mbit/s" => Some(value),
        "gbit/s" => Some(value * 1000.0),
        _ => None,
    }
}

fn active_connection_profile(
    connection_path: &OwnedObjectPath,
    profiles: &[SavedWifiConnection],
) -> Option<SavedWifiConnection> {
    profiles
        .iter()
        .find(|profile| profile.path == connection_path.to_string())
        .cloned()
}

fn value_string(value: &OwnedValue) -> Option<String> {
    value.try_clone().ok()?.try_into().ok()
}

fn value_u32(value: &OwnedValue) -> Option<u32> {
    value.try_clone().ok()?.try_into().ok()
}

fn value_u64(value: &OwnedValue) -> Option<u64> {
    value.try_clone().ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::parse_iw_link_bitrates;

    #[test]
    fn parses_directional_iw_link_bitrates() {
        let output = r#"
Connected to 00:11:22:33:44:55 (on wlp2s0)
	SSID: Example
	rx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
	tx bitrate: 780.0 MBit/s VHT-MCS 8 80MHz VHT-NSS 2
"#;

        let bitrates = parse_iw_link_bitrates(output);

        assert_eq!(bitrates.rx_mbps, Some(866.7));
        assert_eq!(bitrates.tx_mbps, Some(780.0));
    }

    #[test]
    fn converts_iw_link_bitrate_units_to_mbps() {
        let output = r#"
	rx bitrate: 54000 KBit/s
	tx bitrate: 1.2 GBit/s
"#;

        let bitrates = parse_iw_link_bitrates(output);

        assert_eq!(bitrates.rx_mbps, Some(54.0));
        assert_eq!(bitrates.tx_mbps, Some(1200.0));
    }
}
