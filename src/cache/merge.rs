use std::collections::BTreeMap;

use crate::model::{AccessPoint, ConnectionDetails, NetworkEntry};

pub(super) fn attach_connection_details(
    networks: &mut [NetworkEntry],
    connections: &BTreeMap<String, ConnectionDetails>,
) -> usize {
    let mut attached = 0;
    for network in networks {
        network.last_connection = connections
            .get(&network_key(&network.access_point))
            .cloned();
        attached += usize::from(network.last_connection.is_some());
    }
    attached
}

pub(super) fn network_key(access_point: &AccessPoint) -> String {
    format!(
        "{}|{}",
        bytes_hex(access_point.ssid_bytes().as_ref()),
        access_point.security
    )
}

pub(super) fn upsert_connected_access_point(
    networks: &mut Vec<AccessPoint>,
    mut access_point: AccessPoint,
) {
    mark_inactive(networks);
    access_point.active = true;

    if let Some(existing) = networks
        .iter_mut()
        .find(|network| same_access_point(network, &access_point))
    {
        *existing = access_point;
    } else {
        networks.insert(0, access_point);
    }
}

pub(super) fn mark_inactive(networks: &mut [AccessPoint]) {
    networks
        .iter_mut()
        .for_each(|network| network.active = false);
}

fn same_access_point(left: &AccessPoint, right: &AccessPoint) -> bool {
    if !left.path.is_empty() && !right.path.is_empty() {
        return left.path == right.path;
    }
    if !left.bssid.is_empty() && !right.bssid.is_empty() {
        return left.bssid.eq_ignore_ascii_case(&right.bssid);
    }
    left.ssid_bytes().as_ref() == right.ssid_bytes().as_ref() && left.security == right.security
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{same_access_point, upsert_connected_access_point};
    use crate::model::AccessPoint;

    #[test]
    fn connected_access_point_replaces_cached_network_and_marks_only_it_active() {
        let mut networks = vec![test_ap("/ap/1", "00:11:22:33:44:55", false)];
        let connected = test_ap("/ap/1", "00:11:22:33:44:55", false);

        upsert_connected_access_point(&mut networks, connected);

        assert_eq!(networks.len(), 1);
        assert!(networks[0].active);
    }

    #[test]
    fn connected_access_point_can_be_matched_by_bssid_without_path() {
        let left = test_ap("", "00:11:22:33:44:55", false);
        let right = test_ap("", "00:11:22:33:44:55", true);

        assert!(same_access_point(&left, &right));
    }

    fn test_ap(path: &str, bssid: &str, active: bool) -> AccessPoint {
        AccessPoint {
            ssid: "Example".to_string(),
            ssid_bytes: b"Example".to_vec(),
            active,
            security: crate::model::Security::Wpa2Or3,
            strength: 80,
            frequency: 2412,
            channel: 1,
            band: "2.4 GHz".to_string(),
            mode: "Infra".to_string(),
            max_bitrate_mbps: 0,
            bandwidth_mhz: 0,
            ssid_hex: "4578616d706c65".to_string(),
            wpa_flags_label: "(none)".to_string(),
            rsn_flags_label: "(none)".to_string(),
            bssid: bssid.to_string(),
            last_seen: 0,
            last_seen_age_ms: None,
            path: path.to_string(),
            device_path: "/device/1".to_string(),
            device_iface: "wlan0".to_string(),
            flags: 0,
            wpa_flags: 0,
            rsn_flags: 0,
        }
    }
}
