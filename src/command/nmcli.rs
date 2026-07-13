use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

use super::{CommandFailure, CommandFailureKind, CommandRequest, CommandRunner};
use crate::error::{ErrorCode, ErrorOperation, ErrorSource};
use crate::model::Ip4Status;

const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(95);
const NMCLI_CONNECT_WAIT_SECS: &str = "90";

pub(crate) struct Nmcli<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> Nmcli<'a> {
    pub(crate) fn new(runner: &'a dyn CommandRunner) -> Self {
        Self { runner }
    }

    pub(crate) fn connect(
        &self,
        args: &[&str],
        cancellation: Option<&AtomicBool>,
    ) -> Result<String> {
        let mut request = CommandRequest::new("nmcli", ErrorOperation::RunNmcli, CONNECT_TIMEOUT)
            .args(["--wait", NMCLI_CONNECT_WAIT_SECS]);
        let mut sensitive = false;
        for arg in args {
            request = if sensitive {
                sensitive = false;
                request.sensitive_arg(*arg)
            } else {
                sensitive = *arg == "password";
                request.arg(*arg)
            };
        }
        self.runner
            .run(&request, cancellation)
            .map(|output| output.stdout)
            .map_err(|failure| nmcli_failure(failure).into())
    }

    pub(crate) fn device_ip4(
        &self,
        iface: &str,
        operation: ErrorOperation,
    ) -> Result<Option<Ip4Status>> {
        let request = CommandRequest::new("nmcli", operation, QUERY_TIMEOUT)
            .args(["-t", "device", "show", iface]);
        let output = self
            .runner
            .run(&request, None)
            .map_err(|failure| failure.into_domain())?;
        Ok(parse_device_ip4(&output.stdout))
    }

    pub(crate) fn active_wifi(&self, operation: ErrorOperation) -> Result<Option<NmcliWifiRow>> {
        let request = CommandRequest::new("nmcli", operation, QUERY_TIMEOUT).args([
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
}

pub(crate) fn parse_device_ip4(output: &str) -> Option<Ip4Status> {
    let mut address = None;
    let mut prefix = None;
    let mut gateway = None;
    let mut dns = Vec::new();
    for line in output.lines() {
        let Some((key, value)) = split_key_value(line) else {
            continue;
        };
        if key.starts_with("IP4.ADDRESS") {
            (address, prefix) = parse_cidr(&value);
        } else if key == "IP4.GATEWAY" && !value.is_empty() {
            gateway = Some(value);
        } else if key.starts_with("IP4.DNS") && !value.is_empty() {
            dns.push(value);
        }
    }
    (address.is_some() || gateway.is_some() || !dns.is_empty()).then_some(Ip4Status {
        address,
        prefix,
        gateway,
        dns,
    })
}

fn parse_active_wifi_row(line: &str) -> Option<NmcliWifiRow> {
    let fields = split_fields(line);
    if fields.first().map(String::as_str) != Some("*") || fields.len() < 6 {
        return None;
    }
    Some(NmcliWifiRow {
        ssid: fields[1].clone(),
        bssid: fields[2].clone(),
        signal: fields[3].parse().ok(),
        security: fields[4].clone(),
        frequency_mhz: fields[5]
            .split_whitespace()
            .next()
            .and_then(|value| value.parse().ok()),
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
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(character);
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

fn nmcli_failure(failure: CommandFailure) -> crate::error::DomainError {
    if matches!(
        failure.kind(),
        CommandFailureKind::Timeout | CommandFailureKind::Cancelled
    ) {
        return failure.into_domain();
    }
    let code = match failure.exit_code() {
        Some(3) => ErrorCode::Timeout,
        Some(10) => ErrorCode::NotFound,
        Some(4) => ErrorCode::ActivationFailed,
        _ => ErrorCode::SubprocessFailed,
    };
    failure.into_domain_with_code(code, ErrorSource::Subprocess)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;
    use crate::command::SystemCommandRunner;
    use crate::command::tests::FakeRunner;
    use crate::error::{ErrorCode, ErrorReport};

    #[test]
    fn parses_escaped_active_wifi_rows() {
        let row = parse_active_wifi_row("*:Cafe:A0\\:55\\:1F\\:D0\\:42\\:8F:84:WPA2:5220 MHz")
            .expect("active row");
        assert_eq!(row.ssid, "Cafe");
        assert_eq!(row.bssid, "A0:55:1F:D0:42:8F");
        assert_eq!(row.frequency_mhz, Some(5220));
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

    #[test]
    fn connect_password_is_redacted_by_the_gateway_request() {
        let runner = FakeRunner::success("");
        Nmcli::new(&runner)
            .connect(
                &["device", "wifi", "connect", "Cafe", "password", "secret"],
                None,
            )
            .unwrap();
        assert_eq!(
            runner.redacted_args(),
            [
                "--wait",
                "90",
                "device",
                "wifi",
                "connect",
                "Cafe",
                "password",
                "<redacted>"
            ]
        );
    }

    #[test]
    fn connect_preserves_gateway_cancellation() {
        let cancellation = AtomicBool::new(true);
        let error = Nmcli::new(&SystemCommandRunner)
            .connect(&["connection", "up", "id", "Cafe"], Some(&cancellation))
            .unwrap_err();
        let report = ErrorReport::from_error(&error, ErrorOperation::Connect);
        assert_eq!(report.code, ErrorCode::Cancelled);
    }
}
