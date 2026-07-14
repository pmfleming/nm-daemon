use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use neli::consts::nl::{NlmF, NlmFFlags, Nlmsg};
use neli::consts::socket::NlFamily;
use neli::genl::{Genlmsghdr, Nlattr};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::NlSocketHandle;
use neli::types::GenlBuffer;
use neli_wifi::{NL_80211_GENL_NAME, NL_80211_GENL_VERSION, Nl80211Attr, Nl80211Cmd, Station};

const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Directional link rates reported by the kernel in megabits per second.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) struct DirectionalBitrates {
    pub(crate) tx_mbps: Option<f64>,
    pub(crate) rx_mbps: Option<f64>,
}

pub(crate) trait WirelessTelemetry: Send + Sync {
    fn link_bitrates(&self, iface: &str) -> Result<DirectionalBitrates>;
}

#[derive(Debug, Default)]
pub(crate) struct KernelWirelessTelemetry;

impl WirelessTelemetry for KernelWirelessTelemetry {
    fn link_bitrates(&self, iface: &str) -> Result<DirectionalBitrates> {
        link_bitrates(iface)
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct UnavailableWirelessTelemetry;

#[cfg(test)]
impl WirelessTelemetry for UnavailableWirelessTelemetry {
    fn link_bitrates(&self, _iface: &str) -> Result<DirectionalBitrates> {
        Ok(DirectionalBitrates::default())
    }
}

fn link_bitrates(iface: &str) -> Result<DirectionalBitrates> {
    let interface_index = interface_index(iface)?;
    let stations = station_info(interface_index)
        .with_context(|| format!("read nl80211 station information for {iface}"))?;

    Ok(stations
        .iter()
        .find(|station| station_has_bitrate(station))
        .or_else(|| stations.first())
        .map(station_bitrates)
        .unwrap_or_default())
}

fn interface_index(iface: &str) -> Result<i32> {
    if iface.is_empty() || iface.contains('/') || iface.as_bytes().contains(&0) {
        bail!("invalid network interface name {iface:?}");
    }
    let path = Path::new("/sys/class/net").join(iface).join("ifindex");
    let value = std::fs::read_to_string(&path)
        .with_context(|| format!("read kernel interface index from {}", path.display()))?;
    value
        .trim()
        .parse()
        .with_context(|| format!("parse kernel interface index for {iface}"))
}

fn station_info(interface_index: i32) -> Result<Vec<Station>> {
    let (mut socket, family_id) = open_nl80211_socket()?;
    send_station_query(&mut socket, family_id, interface_index)?;
    collect_station_info(&mut socket)
}

fn open_nl80211_socket() -> Result<(NlSocketHandle, u16)> {
    let mut socket = NlSocketHandle::connect(NlFamily::Generic, None, &[])
        .context("open generic-netlink socket")?;
    let family_id = socket
        .resolve_genl_family(NL_80211_GENL_NAME)
        .map_err(|error| anyhow!("resolve nl80211 generic-netlink family: {error}"))?;
    socket
        .nonblock()
        .context("set nl80211 socket nonblocking")?;
    Ok((socket, family_id))
}

fn send_station_query(
    socket: &mut NlSocketHandle,
    family_id: u16,
    interface_index: i32,
) -> Result<()> {
    let mut attributes = GenlBuffer::new();
    attributes.push(
        Nlattr::new(false, false, Nl80211Attr::AttrIfindex, interface_index)
            .context("encode nl80211 interface index")?,
    );
    let payload = Genlmsghdr::new(Nl80211Cmd::CmdGetStation, NL_80211_GENL_VERSION, attributes);
    let request = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Dump]),
        None,
        None,
        NlPayload::Payload(payload),
    );
    socket.send(request).context("send nl80211 station query")?;
    Ok(())
}

fn collect_station_info(socket: &mut NlSocketHandle) -> Result<Vec<Station>> {
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let mut stations = Vec::new();
    loop {
        check_query_deadline(deadline)?;
        match receive_station_message(socket)? {
            StationMessage::Complete => return Ok(stations),
            StationMessage::Pending => thread::sleep(POLL_INTERVAL),
            StationMessage::Station(station) => stations.push(station),
        }
    }
}

enum StationMessage {
    Complete,
    Pending,
    Station(Station),
}

fn check_query_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() < deadline {
        return Ok(());
    }
    bail!(
        "nl80211 station query timed out after {} ms",
        QUERY_TIMEOUT.as_millis()
    )
}

fn receive_station_message(socket: &mut NlSocketHandle) -> Result<StationMessage> {
    let response = socket
        .recv::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>()
        .map_err(|error| anyhow!("receive nl80211 station response: {error}"))?;
    response.map_or(Ok(StationMessage::Pending), decode_station_response)
}

fn decode_station_response(
    response: Nlmsghdr<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>,
) -> Result<StationMessage> {
    match response.nl_type {
        Nlmsg::Done => Ok(StationMessage::Complete),
        Nlmsg::Noop => Ok(StationMessage::Pending),
        Nlmsg::Error => bail!("nl80211 station query failed: {:?}", response.nl_payload),
        _ => decode_station_payload(response.nl_payload),
    }
}

fn decode_station_payload(
    payload: NlPayload<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>,
) -> Result<StationMessage> {
    let NlPayload::Payload(payload) = payload else {
        return Ok(StationMessage::Pending);
    };
    let station = payload
        .get_attr_handle()
        .try_into()
        .map_err(|error| anyhow!("decode nl80211 station: {error}"))?;
    Ok(StationMessage::Station(station))
}

fn station_has_bitrate(station: &Station) -> bool {
    station.tx_bitrate.is_some() || station.rx_bitrate.is_some()
}

fn station_bitrates(station: &Station) -> DirectionalBitrates {
    DirectionalBitrates {
        tx_mbps: station.tx_bitrate.map(rate_100kbps_to_mbps),
        rx_mbps: station.rx_bitrate.map(rate_100kbps_to_mbps),
    }
}

fn rate_100kbps_to_mbps(rate: u32) -> f64 {
    f64::from(rate) / 10.0
}

#[cfg(test)]
mod tests {
    use super::{interface_index, rate_100kbps_to_mbps};

    #[test]
    fn converts_kernel_rate_units_to_mbps() {
        assert_eq!(rate_100kbps_to_mbps(8667), 866.7);
        assert_eq!(rate_100kbps_to_mbps(12000), 1200.0);
    }

    #[test]
    fn rejects_interface_names_that_could_escape_sysfs() {
        assert!(interface_index("../wlan0").is_err());
        assert!(interface_index("").is_err());
    }
}
