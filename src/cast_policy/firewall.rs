use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::io::AsyncWriteExt;

// Longer than a normal snapshot + refresh, but bounded on crashes, bus outages
// or failed firewall updates. Disabled interfaces never rely on a lease.
const PERMISSION_LEASE_SECONDS: u32 = 10;

pub(super) fn validate_interface(interface: &str) -> Result<()> {
    // Interface names become nft string literals, not shell arguments. Be stricter
    // than Linux rather than permitting escaping/injection in a root-owned batch.
    ensure!(
        !interface.is_empty()
            && interface.len() <= 15
            && interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)),
        "unsupported Wi-Fi interface name"
    );
    Ok(())
}

fn elements(interfaces: &BTreeSet<String>) -> Result<String> {
    interfaces
        .iter()
        .map(|name| {
            validate_interface(name)?;
            Ok(format!("\"{name}\""))
        })
        .collect::<Result<Vec<_>>>()
        .map(|names| {
            if names.is_empty() {
                String::new()
            } else {
                format!("elements = {{ {} }};", names.join(", "))
            }
        })
}

pub(super) fn rules(wifi: &BTreeSet<String>, enabled: &BTreeSet<String>) -> Result<String> {
    ensure!(enabled.is_subset(wifi), "enabled interface is not Wi-Fi");
    let wifi = elements(wifi)?;
    let enabled = elements(enabled)?;
    // add (non-exclusive) then delete works for both first install and replacement.
    // nft -f commits the whole batch atomically: never a delete/add exposure gap.
    // Drops precede the usual priority-0 established/related accepts. There is no
    // ct-state exemption, so already-established supported Cast flows stop too.
    Ok(format!(
        r#"add table inet nm_cast_policy
delete table inet nm_cast_policy
table inet nm_cast_policy {{
    set wifi {{ type ifname; {wifi} }}
    set enabled {{ type ifname; flags timeout; timeout {PERMISSION_LEASE_SECONDS}s; {enabled} }}
    chain input {{
        type filter hook input priority -10; policy accept;
        iifname @wifi iifname != @enabled udp sport {{ 1900, 5353 }} counter drop
        iifname @wifi iifname != @enabled udp dport {{ 1900, 5353 }} counter drop
        iifname @wifi iifname != @enabled tcp sport {{ 8008, 8009, 8443 }} counter drop
    }}
    chain output {{
        type filter hook output priority -10; policy accept;
        oifname @wifi oifname != @enabled udp sport {{ 1900, 5353 }} counter drop
        oifname @wifi oifname != @enabled udp dport {{ 1900, 5353 }} counter drop
        oifname @wifi oifname != @enabled tcp dport {{ 8008, 8009, 8443 }} counter drop
    }}
}}
"#
    ))
}

pub(super) async fn apply(
    nft: &Path,
    wifi: &BTreeSet<String>,
    enabled: &BTreeSet<String>,
) -> Result<()> {
    ensure!(nft.is_absolute(), "nft executable path must be absolute");
    let batch = rules(wifi, enabled)?;
    let mut child = tokio::process::Command::new(nft)
        .args(["-f", "-"])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("start nft for Cast policy")?;
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut stdin = child.stdin.take().context("nft stdin unavailable")?;
        stdin.write_all(batch.as_bytes()).await?;
        drop(stdin);
        let output = child.wait_with_output().await?;
        if !output.status.success() {
            bail!(
                "nft Cast policy update failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    })
    .await
    .context("nft Cast policy update timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_are_scoped_dual_stack_atomic_and_block_established_cast_flows() {
        let wifi = BTreeSet::from(["wlan0".into(), "wlan1".into()]);
        let on = rules(&wifi, &BTreeSet::from(["wlan1".into()])).unwrap();
        assert!(
            on.starts_with("add table inet nm_cast_policy\ndelete table inet nm_cast_policy\n")
        );
        assert!(on.contains("table inet nm_cast_policy"));
        assert!(on.contains("elements = { \"wlan0\", \"wlan1\" }"));
        assert!(on.contains("timeout 10s; elements = { \"wlan1\" }"));
        assert!(on.contains("hook input priority -10"));
        assert!(on.contains("hook output priority -10"));
        assert_eq!(on.matches("counter drop").count(), 6);
        assert!(!on.contains("ct state"));
        assert!(!on.contains("flush ruleset"));
        let off = rules(&wifi, &BTreeSet::new()).unwrap();
        assert!(off.contains("timeout 10s;  }"));
        assert!(
            !rules(&BTreeSet::new(), &BTreeSet::new())
                .unwrap()
                .contains("elements")
        );
    }

    #[test]
    fn interface_names_cannot_inject_rules_or_enable_an_unmanaged_link() {
        for name in ["", "wlan\"0", "a\nb", "wlan0;", "1234567890123456", "é"] {
            assert!(validate_interface(name).is_err(), "{name:?}");
        }
        for name in ["wlp2s0", "wlan-1", "wl_0.1", "wl:0"] {
            assert!(validate_interface(name).is_ok());
        }
        assert!(rules(&BTreeSet::new(), &BTreeSet::from(["eth0".into()])).is_err());
    }

    // Opt-in kernel test. ALWAYS enter a fresh network namespace before nft;
    // even running this as root cannot modify the host firewall. See docs.
    #[test]
    #[ignore = "opt-in kernel firewall test in an isolated network namespace"]
    fn isolated_kernel_enforcement() -> Result<()> {
        let nft = std::env::var_os("NM_CAST_POLICY_TEST_NFT")
            .context("set NM_CAST_POLICY_TEST_NFT to the absolute nft executable path")?;
        let script = include_str!("../../test_support/cast-policy-netns.py");
        let wifi = BTreeSet::from(["cast0".into(), "cast1".into()]);
        let mut child = std::process::Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--net",
                "python3",
                "-c",
                script,
            ])
            .arg(nft)
            .stdin(Stdio::piped())
            .spawn()
            .context("start isolated firewall test")?;
        use std::io::Write;
        child.stdin.take().unwrap().write_all(
            serde_json::to_string(&[
                rules(&wifi, &BTreeSet::new())?,
                rules(&wifi, &BTreeSet::from(["cast0".into()]))?,
                rules(&wifi, &BTreeSet::from(["cast1".into()]))?,
                rules(&BTreeSet::new(), &BTreeSet::new())?,
            ])?
            .as_bytes(),
        )?;
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait()? {
                ensure!(status.success(), "isolated firewall test failed");
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("isolated firewall test timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
}
