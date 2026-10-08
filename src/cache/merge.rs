use std::collections::BTreeMap;

use crate::model::{AccessPoint, ConnectionDetails, NetworkEntry, ssid_hex};

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
        ssid_hex(access_point.ssid_bytes().as_ref()),
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

#[cfg(test)]
mod tests {
    use super::upsert_connected_access_point;
    use crate::model::example_access_point;

    #[test]
    fn connected_access_point_replaces_cached_network_and_marks_only_it_active() {
        let mut networks = vec![example_access_point()];
        let connected = example_access_point();

        upsert_connected_access_point(&mut networks, connected);

        assert_eq!(networks.len(), 1);
        assert!(networks[0].active);
    }
}
