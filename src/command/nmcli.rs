use anyhow::Result;
use serde::Serialize;

use super::{CommandRequest, CommandRunner};
use crate::error::ErrorOperation;
use crate::generated::NMCLI_QUERY_TIMEOUT;
use crate::model::{Ip4Status, frequency_band};

pub(crate) struct Nmcli<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> Nmcli<'a> {
    pub(crate) fn new(runner: &'a dyn CommandRunner) -> Self {
        Self { runner }
    }

    pub(crate) fn device_ip4(
        &self,
        iface: &str,
        operation: ErrorOperation,
    ) -> Result<Option<Ip4Status>> {
        let request = CommandRequest::new("nmcli", operation, NMCLI_QUERY_TIMEOUT)
            .args(["-t", "device", "show", iface]);
        let output = self
            .runner
            .run(&request, None)
            .map_err(|failure| failure.into_domain())?;
        Ok(parse_device_ip4(&output.stdout))
    }

    pub(crate) fn active_wifi(&self, operation: ErrorOperation) -> Result<Option<NmcliWifiRow>> {
        let request = CommandRequest::new("nmcli", operation, NMCLI_QUERY_TIMEOUT).args([
            "-t",
            "-f",
            "IN-USE,SSID,BSSID,SIGNAL,SECURITY,FREQ",
            "dev",
            "wifi",
            "list",
            "--rescan",
            "no",
        ]);
        let output = self
            .runner
            .run(&request, None)
            .map_err(|failure| failure.into_domain())?;
        Ok(output.stdout.lines().find_map(parse_active_wifi_row))
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NmcliWifiRow {
    pub(crate) ssid: String,
    pub(crate) bssid: String,
    pub(crate) signal: Option<u8>,
    pub(crate) security: String,
    pub(crate) frequency_mhz: Option<u32>,
    pub(crate) band: String,
}

pub(crate) fn parse_device_ip4(output: &str) -> Option<Ip4Status> {
    let mut ip4 = Ip4Status {
        address: None,
        prefix: None,
        addresses: Vec::new(),
        gateway: None,
        dns: Vec::new(),
        domains: Vec::new(),
        searches: Vec::new(),
        routes: Vec::new(),
        dhcp_lease: None,
    };
    output
        .lines()
        .filter_map(split_key_value)
        .for_each(|(key, value)| apply_device_ip4_field(&mut ip4, &key, value));
    (ip4.address.is_some() || ip4.gateway.is_some() || !ip4.dns.is_empty()).then_some(ip4)
}

fn apply_device_ip4_field(ip4: &mut Ip4Status, key: &str, value: String) {
    match key {
        key if key.starts_with("IP4.ADDRESS") => {
            let (address, prefix) = parse_cidr(&value);
            if let (Some(address), Some(prefix)) = (address.clone(), prefix) {
                ip4.addresses
                    .push(crate::model::IpAddressEntry { address, prefix });
            }
            if ip4.address.is_none() {
                (ip4.address, ip4.prefix) = (address, prefix);
            }
        }
        "IP4.GATEWAY" if !value.is_empty() => ip4.gateway = Some(value),
        key if key.starts_with("IP4.DNS") && !value.is_empty() => ip4.dns.push(value),
        _ => {}
    }
}

fn parse_active_wifi_row(line: &str) -> Option<NmcliWifiRow> {
    let [active, ssid, bssid, signal, security, frequency] =
        <[String; 6]>::try_from(split_fields(line)).ok()?;
    (active == "*").then_some(())?;
    let frequency_mhz = frequency
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok());
    Some(NmcliWifiRow {
        ssid,
        bssid,
        signal: signal.parse().ok(),
        security,
        frequency_mhz,
        band: frequency_mhz
            .map(frequency_band)
            .unwrap_or("unknown")
            .to_string(),
    })
}

fn split_key_value(line: &str) -> Option<(String, String)> {
    let mut parts = split_fields(line).into_iter();
    Some((parts.next()?, parts.next().unwrap_or_default()))
}

fn split_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for character in line.chars() {
        match character {
            _ if escaped => {
                current.push(character);
                escaped = false;
            }
            '\\' => escaped = true,
            ':' => fields.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    fields.push(current);
    fields
}

fn parse_cidr(value: &str) -> (Option<String>, Option<u32>) {
    let Some((address, prefix)) = value.split_once('/') else {
        return (Some(value.to_string()), None);
    };
    (Some(address.to_string()), prefix.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::{Nmcli, parse_active_wifi_row};
    use crate::command::tests::FakeRunner;
    use crate::error::ErrorOperation;

    #[test]
    fn parses_escaped_active_wifi_rows() {
        let row = parse_active_wifi_row("*:Cafe:A0\\:55\\:1F\\:D0\\:42\\:8F:84:WPA2:5220 MHz")
            .expect("active row");
        assert_eq!(row.ssid, "Cafe");
        assert_eq!(row.bssid, "A0:55:1F:D0:42:8F");
        assert_eq!(row.frequency_mhz, Some(5220));
        assert_eq!(row.band, "5 GHz");
    }

    #[test]
    fn one_device_parser_serves_status_and_diagnosis() {
        let output = "IP4.ADDRESS[1]:192.168.178.119/24\nIP4.GATEWAY:192.168.178.1\nIP4.DNS[1]:84.116.46.23\nIP4.DNS[2]:84.116.46.22\n";
        let runner = FakeRunner::success(output);
        let ip4 = Nmcli::new(&runner)
            .device_ip4("wlan0", ErrorOperation::Status)
            .unwrap()
            .expect("ip4");
        assert_eq!(ip4.address.as_deref(), Some("192.168.178.119"));
        assert_eq!(ip4.prefix, Some(24));
        assert_eq!(ip4.dns.len(), 2);
    }
}
