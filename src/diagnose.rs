use anyhow::{Context, Result};
use serde::Serialize;

use crate::command::nmcli::{Nmcli, NmcliWifiRow};
use crate::error::ErrorOperation;
use crate::model::{Ip4Status, NetworkEntry, WifiStatus};
use crate::nm::Nm;

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
    ip4: Option<Ip4Status>,
    errors: Vec<String>,
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
    match crate::cache::attach_connection_details(&mut networks)? {
        crate::cache::CacheRead::Available(_) | crate::cache::CacheRead::Missing => {}
        state => tracing::warn!(
            message = %state.unavailable_message("known-connections cache").unwrap_or_default(),
            "connection details are unavailable for diagnosis"
        ),
    }
    let active_network = networks
        .iter()
        .find(|network| network.access_point.active)
        .cloned();
    let remembered_network_count = networks
        .iter()
        .filter(|network| network.last_connection.is_some())
        .count();
    let nmcli = nmcli_snapshot(
        &Nmcli::new(nm.command_runner()),
        status.device_iface.as_deref(),
    );
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

fn nmcli_snapshot(nmcli: &Nmcli<'_>, iface: Option<&str>) -> NmcliSnapshot {
    let mut errors = Vec::new();
    let mut available = false;
    let active_wifi = match nmcli.active_wifi(ErrorOperation::Status) {
        Ok(active) => {
            available = true;
            active
        }
        Err(error) => {
            errors.push(format!("{error:#}"));
            None
        }
    };
    let ip4 = match iface {
        Some(iface) => match nmcli.device_ip4(iface, ErrorOperation::Status) {
            Ok(ip4) => {
                available = true;
                ip4
            }
            Err(error) => {
                errors.push(format!("{error:#}"));
                None
            }
        },
        None => None,
    };
    NmcliSnapshot {
        available,
        active_wifi,
        ip4,
        errors,
    }
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

fn compare_dns(status: &WifiStatus, nmcli_ip4: Option<&Ip4Status>) -> ParityCheck {
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

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}
