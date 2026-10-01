use anyhow::Result;
use serde::Serialize;

use super::{CommandRequest, CommandRunner};
use crate::error::ErrorOperation;
use crate::generated::NMCLI_QUERY_TIMEOUT;
use crate::model::{IpAddressEntry, IpStatus, frequency_band};

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
    ) -> Result<Option<IpStatus>> {
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

pub(crate) fn parse_device_ip4(output: &str) -> Option<IpStatus> {
    let mut ip4 = IpStatus::default();
    output
        .lines()
        .filter_map(split_key_value)
        .for_each(|(key, value)| apply_device_ip4_field(&mut ip4, &key, value));
    (ip4.address.is_some() || ip4.gateway.is_some() || !ip4.dns.is_empty()).then_some(ip4)
}

fn apply_device_ip4_field(ip4: &mut IpStatus, key: &str, value: String) {
    match key {
        key if key.starts_with("IP4.ADDRESS") => {
            let (address, prefix) = parse_cidr(&value);
            if ip4.address.is_none() {
                ip4.address = Some(address.clone());
                ip4.prefix = prefix;
            }
            ip4.addresses
                .extend(prefix.map(|prefix| IpAddressEntry { address, prefix }));
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

fn parse_cidr(value: &str) -> (String, Option<u32>) {
    let (address, prefix) = value.split_once('/').unwrap_or((value, ""));
    (address.to_string(), prefix.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::{parse_active_wifi_row, parse_device_ip4};

    #[test]
    fn ip4_addresses_keep_primary_and_skip_only_invalid_prefix_entries() {
        let status = parse_device_ip4("IP4.ADDRESS[1]:192.0.2.2/bad\nIP4.ADDRESS[2]:192.0.2.3/24\nIP4.ADDRESS[3]:192.0.2.4\nIP4.GATEWAY:192.0.2.1\nIP4.DNS[1]:1.1.1.1").unwrap();
        assert_eq!(status.address.as_deref(), Some("192.0.2.2"));
        assert_eq!(status.prefix, None);
        assert_eq!(status.addresses.len(), 1);
        assert_eq!(status.addresses[0].address, "192.0.2.3");
        assert_eq!(status.addresses[0].prefix, 24);
        assert_eq!(status.gateway.as_deref(), Some("192.0.2.1"));
        assert_eq!(status.dns, ["1.1.1.1"]);
        assert!(parse_device_ip4("IP4.GATEWAY:\nIP4.DNS[1]:").is_none());
    }

    #[test]
    fn parses_escaped_active_wifi_rows() {
        let row = parse_active_wifi_row("*:Cafe:A0\\:55\\:1F\\:D0\\:42\\:8F:84:WPA2:5220 MHz")
            .expect("active row");
        assert_eq!(row.ssid, "Cafe");
        assert_eq!(row.bssid, "A0:55:1F:D0:42:8F");
        assert_eq!(row.frequency_mhz, Some(5220));
        assert_eq!(row.band, "5 GHz");
    }
}
