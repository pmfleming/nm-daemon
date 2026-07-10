use std::collections::BTreeMap;
use std::process::Command;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::model::{NetworkEntry, WifiStatus};
use crate::nm::{Nm, split_nmcli_fields, split_nmcli_key_value as split_key_value};

#[derive(Serialize)]
struct ParityReport {
    summary: ParitySummary,
    checks: Vec<ParityCheck>,
    nm_api: NmApiSnapshot,
    nmcli: NmcliSnapshot,
}

#[derive(Serialize)]
struct ParitySummary {
    status: &'static str,
    pass: usize,
    warn: usize,
    fail: usize,
    unknown: usize,
}

#[derive(Serialize)]
struct ParityCheck {
    area: &'static str,
    check: &'static str,
    status: &'static str,
    nm_api: Option<String>,
    nmcli: Option<String>,
    detail: String,
}

#[derive(Serialize)]
struct NmApiSnapshot {
    status: WifiStatus,
    network_count: usize,
    active_network: Option<NetworkEntry>,
    remembered_network_count: usize,
}

#[derive(Serialize)]
struct NmcliSnapshot {
    available: bool,
    active_wifi: Option<NmcliWifiRow>,
    ip4: Option<NmcliIp4>,
    errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct NmcliWifiRow {
    ssid: String,
    bssid: String,
    signal: Option<u8>,
    security: String,
    frequency_mhz: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
struct NmcliIp4 {
    address: Option<String>,
    prefix: Option<u32>,
    gateway: Option<String>,
    dns: Vec<String>,
}

pub(crate) fn print_diagnosis(nm: &Nm, json: bool) -> Result<()> {
    let report = build_report(nm)?;
    if json {
        serde_json::to_writer_pretty(std::io::stdout(), &report)
            .context("serialize nmcli parity diagnosis")?;
        println!();
    } else {
        print_text_report(&report);
    }
    Ok(())
}

fn build_report(nm: &Nm) -> Result<ParityReport> {
    let status = nm.wifi_status()?;
    let mut networks = nm.network_entries_for_access_points(nm.list_all_access_points()?)?;
    crate::cache::attach_connection_details(&mut networks);
    let active_network = networks
        .iter()
        .find(|network| network.access_point.active)
        .cloned();
    let remembered_network_count = networks
        .iter()
        .filter(|network| network.last_connection.is_some())
        .count();
    let nmcli = nmcli_snapshot(status.device_iface.as_deref());
    let nm_api = NmApiSnapshot {
        status,
        network_count: networks.len(),
        active_network,
        remembered_network_count,
    };
    let checks = parity_checks(&nm_api, &nmcli);
    let summary = summarize(&checks);
    Ok(ParityReport {
        summary,
        checks,
        nm_api,
        nmcli,
    })
}

fn nmcli_snapshot(iface: Option<&str>) -> NmcliSnapshot {
    let mut errors = Vec::new();
    let active_wifi = match nmcli_active_wifi() {
        Ok(active) => active,
        Err(err) => {
            errors.push(err);
            None
        }
    };
    let ip4 = match iface {
        Some(iface) => match nmcli_ip4_for_device(iface) {
            Ok(ip4) => ip4,
            Err(err) => {
                errors.push(err);
                None
            }
        },
        None => None,
    };
    NmcliSnapshot {
        available: errors.iter().all(|error| !error.starts_with("run nmcli"))
            || active_wifi.is_some()
            || ip4.is_some(),
        active_wifi,
        ip4,
        errors,
    }
}

fn nmcli_active_wifi() -> std::result::Result<Option<NmcliWifiRow>, String> {
    let output = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "IN-USE,SSID,BSSID,SIGNAL,SECURITY,FREQ",
            "dev",
            "wifi",
            "list",
            "--rescan",
            "no",
        ])
        .output()
        .map_err(|err| format!("run nmcli wifi list: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "nmcli wifi list exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().find_map(parse_active_wifi_row))
}

fn parse_active_wifi_row(line: &str) -> Option<NmcliWifiRow> {
    let fields = split_nmcli_fields(line);
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

fn nmcli_ip4_for_device(iface: &str) -> std::result::Result<Option<NmcliIp4>, String> {
    let output = Command::new("nmcli")
        .args(["-t", "device", "show", iface])
        .output()
        .map_err(|err| format!("run nmcli device show: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "nmcli device show {iface} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_nmcli_ip4(&stdout))
}

fn parse_nmcli_ip4(output: &str) -> Option<NmcliIp4> {
    let mut values = BTreeMap::<String, Vec<String>>::new();
    for line in output.lines() {
        let Some((key, value)) = split_key_value(line) else {
            continue;
        };
        values.entry(key).or_default().push(value);
    }
    let (address, prefix) = values
        .iter()
        .find(|(key, _)| key.starts_with("IP4.ADDRESS"))
        .and_then(|(_, values)| values.first())
        .map(|value| parse_cidr(value))
        .unwrap_or((None, None));
    let gateway = values
        .get("IP4.GATEWAY")
        .and_then(|values| values.first())
        .filter(|value| !value.is_empty())
        .cloned();
    let dns = values
        .iter()
        .filter(|(key, _)| key.starts_with("IP4.DNS"))
        .flat_map(|(_, values)| values.iter().filter(|value| !value.is_empty()).cloned())
        .collect::<Vec<_>>();

    if address.is_none() && gateway.is_none() && dns.is_empty() {
        return None;
    }
    Some(NmcliIp4 {
        address,
        prefix,
        gateway,
        dns,
    })
}

fn parity_checks(nm_api: &NmApiSnapshot, nmcli: &NmcliSnapshot) -> Vec<ParityCheck> {
    let mut checks = Vec::new();
    let status = &nm_api.status;
    let nmcli_active = nmcli.active_wifi.as_ref();
    checks.push(compare_optional(
        "active",
        "ssid",
        status.access_point.as_ref().map(|ap| ap.ssid.clone()),
        nmcli_active.map(|active| active.ssid.clone()),
    ));
    checks.push(compare_optional(
        "active",
        "bssid",
        status.access_point.as_ref().map(|ap| ap.bssid.clone()),
        nmcli_active.map(|active| active.bssid.clone()),
    ));
    checks.push(compare_frequency(status, nmcli_active));
    checks.push(compare_signal(status, nmcli_active));
    checks.push(compare_optional(
        "ip4",
        "address",
        status.ip4.as_ref().and_then(|ip4| ip4.address.clone()),
        nmcli.ip4.as_ref().and_then(|ip4| ip4.address.clone()),
    ));
    checks.push(compare_optional(
        "ip4",
        "gateway",
        status.ip4.as_ref().and_then(|ip4| ip4.gateway.clone()),
        nmcli.ip4.as_ref().and_then(|ip4| ip4.gateway.clone()),
    ));
    checks.push(compare_dns(status, nmcli.ip4.as_ref()));
    checks.push(check_bool(
        "cache",
        "active network in enriched list",
        nm_api
            .active_network
            .as_ref()
            .is_some_and(|network| network.access_point.active),
        "active AP should remain selected after SSID grouping",
    ));
    checks.push(check_bool(
        "cache",
        "remembered connection details",
        nm_api.remembered_network_count > 0,
        "at least one network should expose last_connection after status/connect caching",
    ));
    checks
}

fn compare_optional(
    area: &'static str,
    check: &'static str,
    nm_api: Option<String>,
    nmcli: Option<String>,
) -> ParityCheck {
    match (&nm_api, &nmcli) {
        (Some(left), Some(right)) if normalize(left) == normalize(right) => ParityCheck {
            area,
            check,
            status: "pass",
            nm_api,
            nmcli,
            detail: "values match".to_string(),
        },
        (Some(_), Some(_)) => ParityCheck {
            area,
            check,
            status: "fail",
            nm_api,
            nmcli,
            detail: "nm-daemon and nmcli disagree".to_string(),
        },
        (None, None) => ParityCheck {
            area,
            check,
            status: "unknown",
            nm_api,
            nmcli,
            detail: "neither tool reported a value".to_string(),
        },
        _ => ParityCheck {
            area,
            check,
            status: "warn",
            nm_api,
            nmcli,
            detail: "only one tool reported a value".to_string(),
        },
    }
}

fn compare_frequency(status: &WifiStatus, nmcli_active: Option<&NmcliWifiRow>) -> ParityCheck {
    let left = status
        .access_point
        .as_ref()
        .map(|ap| ap.frequency.to_string());
    let right = nmcli_active.and_then(|active| active.frequency_mhz.map(|value| value.to_string()));
    compare_optional("active", "frequency", left, right)
}

fn compare_signal(status: &WifiStatus, nmcli_active: Option<&NmcliWifiRow>) -> ParityCheck {
    let left = status.access_point.as_ref().map(|ap| ap.strength);
    let right = nmcli_active.and_then(|active| active.signal);
    match (left, right) {
        (Some(left), Some(right)) if left.abs_diff(right) <= 15 => ParityCheck {
            area: "active",
            check: "signal",
            status: "pass",
            nm_api: Some(left.to_string()),
            nmcli: Some(right.to_string()),
            detail: "signal is within 15 percentage points".to_string(),
        },
        (Some(left), Some(right)) => ParityCheck {
            area: "active",
            check: "signal",
            status: "warn",
            nm_api: Some(left.to_string()),
            nmcli: Some(right.to_string()),
            detail: "signal differs; scan timing may explain this".to_string(),
        },
        _ => compare_optional(
            "active",
            "signal",
            left.map(|value| value.to_string()),
            right.map(|value| value.to_string()),
        ),
    }
}

fn compare_dns(status: &WifiStatus, nmcli_ip4: Option<&NmcliIp4>) -> ParityCheck {
    let left = status.ip4.as_ref().map(|ip4| ip4.dns.join(","));
    let right = nmcli_ip4.map(|ip4| ip4.dns.join(","));
    compare_optional("ip4", "dns", left, right)
}

fn check_bool(
    area: &'static str,
    check: &'static str,
    passed: bool,
    detail: &'static str,
) -> ParityCheck {
    ParityCheck {
        area,
        check,
        status: if passed { "pass" } else { "warn" },
        nm_api: Some(passed.to_string()),
        nmcli: None,
        detail: detail.to_string(),
    }
}

fn summarize(checks: &[ParityCheck]) -> ParitySummary {
    let count = |status| checks.iter().filter(|check| check.status == status).count();
    let fail = count("fail");
    let warn = count("warn");
    let unknown = count("unknown");
    ParitySummary {
        status: if fail > 0 {
            "fail"
        } else if warn > 0 || unknown > 0 {
            "warn"
        } else {
            "pass"
        },
        pass: count("pass"),
        warn,
        fail,
        unknown,
    }
}

fn print_text_report(report: &ParityReport) {
    println!(
        "nmcli parity: {} ({} pass, {} warn, {} fail, {} unknown)",
        report.summary.status,
        report.summary.pass,
        report.summary.warn,
        report.summary.fail,
        report.summary.unknown
    );
    for check in &report.checks {
        println!(
            "{}\t{}\t{}\tnm-daemon={}\tnmcli={}\t{}",
            check.status,
            check.area,
            check.check,
            check.nm_api.as_deref().unwrap_or("—"),
            check.nmcli.as_deref().unwrap_or("—"),
            check.detail
        );
    }
    if !report.nmcli.errors.is_empty() {
        println!("nmcli errors:");
        for error in &report.nmcli.errors {
            println!("- {error}");
        }
    }
}

fn parse_cidr(value: &str) -> (Option<String>, Option<u32>) {
    let Some((address, prefix)) = value.split_once('/') else {
        return (Some(value.to_string()), None);
    };
    (Some(address.to_string()), prefix.parse().ok())
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{parse_active_wifi_row, parse_nmcli_ip4};

    #[test]
    fn parses_escaped_nmcli_wifi_rows() {
        let row = parse_active_wifi_row("*:Cafe:A0\\:55\\:1F\\:D0\\:42\\:8F:84:WPA2:5220 MHz")
            .expect("active row");

        assert_eq!(row.ssid, "Cafe");
        assert_eq!(row.bssid, "A0:55:1F:D0:42:8F");
        assert_eq!(row.frequency_mhz, Some(5220));
    }

    #[test]
    fn parses_nmcli_device_show_ip4() {
        let ip4 = parse_nmcli_ip4(
            "IP4.ADDRESS[1]:192.168.178.119/24\nIP4.GATEWAY:192.168.178.1\nIP4.DNS[1]:84.116.46.23\nIP4.DNS[2]:84.116.46.22\n",
        )
        .expect("ip4");

        assert_eq!(ip4.address.as_deref(), Some("192.168.178.119"));
        assert_eq!(ip4.prefix, Some(24));
        assert_eq!(ip4.dns.len(), 2);
    }
}
