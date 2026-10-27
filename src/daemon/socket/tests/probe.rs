//! Explicit real-Quickshell acceptance, never a live NetworkManager service.
use super::*;
use std::process::Stdio;
use tokio::{io::AsyncReadExt, process::Command};

// Keep each native entrypoint, expected receipt and scripted effect in one
// fixture record. A new scenario cannot silently select an ordinary fallback.
struct Scenario {
    qml: &'static str,
    passed: &'static str,
    outcome: Option<Outcome>,
    quiet_status: bool,
}

const SCENARIOS: [Scenario; 3] = [
    Scenario {
        qml: "tests/e2e/nm-unix-jsonl.qml",
        passed: "NM_SOCKET_PROBE_PASS native-shared-session-renewal",
        outcome: None,
        quiet_status: false,
    },
    Scenario {
        qml: "tests/e2e/nm-connect-recovery.qml",
        passed: "NM_CONNECT_RECOVERY_PASS native-quiet-terminal-status",
        outcome: Some(Outcome::Connected),
        quiet_status: false,
    },
    Scenario {
        qml: "tests/e2e/nm-status-recovery.qml",
        passed: "NM_STATUS_RECOVERY_PASS native-quiet-status-read",
        outcome: None,
        quiet_status: true,
    },
];

async fn bounded(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    quiet_status: Option<Arc<std::sync::Mutex<crate::test_support::workflows::State>>>,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let mut changed = false;
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        ensure!(
            bytes.len() <= 1024 * 1024,
            "native probe log limit exceeded"
        );
        if !changed && let Some(state) = &quiet_status {
            let marker = b"NM_STATUS_RECOVERY_BASELINE";
            if bytes.windows(marker.len()).any(|window| window == marker) {
                // Current synthetic facts only: no activation and no signal.
                state.lock().unwrap().current = Some(Outcome::Connected);
                changed = true;
            }
        }
    }
    Ok(bytes)
}

#[test]
#[ignore = "requires actual Quickshell and SHELLLIST_SOURCE; isolated, no hardware"]
fn native_quickshell_nm_socket_acceptance() -> Result<()> {
    isolated(
        concat!(module_path!(), "::native_quickshell_nm_socket_acceptance"),
        || {
            let root = PathBuf::from(
                std::env::var_os("SHELLLIST_SOURCE").context("set SHELLLIST_SOURCE")?,
            )
            .canonicalize()?;
            for scenario in SCENARIOS {
                let rig = Rig::new(scenario.outcome)?;
                std::fs::create_dir_all(rig.directory.join("home"))?;
                let mut target = crate::model::example_connect_target(false);
                target.ap_path = Some(crate::model::NmObjectPath::parse(
                    "/org/freedesktop/NetworkManager/AccessPoint/1".into(),
                )?);
                target.security = Some(crate::model::Security::Open);
                let executable = std::env::var_os("QUICKSHELL_BIN")
                    .map(PathBuf::from)
                    .or_else(|| {
                        std::env::var_os("PATH").and_then(|paths| {
                            std::env::split_paths(&paths)
                                .map(|path| path.join("quickshell"))
                                .find(|path| path.is_file())
                        })
                    })
                    .context("set QUICKSHELL_BIN or provide Quickshell on PATH")?
                    .canonicalize()?;
                let output = tokio::runtime::Handle::current().block_on(async {
                    // Inherit the isolated test's private process group. Its outer
                    // deadline kills the whole group while its leader is still owned.
                    let mut child = Command::new(executable)
                        .env_clear()
                        // The full Wi-Fi controller may instantiate optional
                        // helper consumers. None may execute an installed host binary.
                        .env("PATH", "/nonexistent/nm-native-probe-programs")
                        .args(["--no-color", "--path"])
                        .arg(root.join(scenario.qml))
                        .env(
                            "SHELLLIST_NM_FIXTURE_TARGET",
                            serde_json::to_string(&target)?,
                        )
                        .env("HOME", rig.directory.join("home"))
                        .env("QML_IMPORT_PATH", root.join("qml"))
                        .env("QML2_IMPORT_PATH", root.join("qml"))
                        .env("QT_QPA_PLATFORM", "offscreen")
                        .env("QT_QUICK_BACKEND", "software")
                        .env("QSG_RHI_BACKEND", "software")
                        .env("QT_QPA_PLATFORMTHEME", "")
                        .env_remove("WAYLAND_DISPLAY")
                        .env_remove("DISPLAY")
                        .env("SHELLLIST_NM_SOCKET", "1")
                        .env("SHELLLIST_THEME_OFFLINE", "1")
                        .env("XDG_RUNTIME_DIR", &rig.directory)
                        .env("XDG_CACHE_HOME", rig.directory.join("cache"))
                        .env("XDG_CONFIG_HOME", rig.directory.join("config"))
                        .env("XDG_STATE_HOME", rig.directory.join("state"))
                        .env("DBUS_SESSION_BUS_ADDRESS", rig.bus.address())
                        .env(
                            "DBUS_SYSTEM_BUS_ADDRESS",
                            "unix:path=/nonexistent/nm-native-probe-system",
                        )
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .kill_on_drop(true)
                        .spawn()
                        .context("start actual Quickshell")?;
                    let stdout = child.stdout.take().context("probe stdout")?;
                    let stderr = child.stderr.take().context("probe stderr")?;
                    let result = tokio::time::timeout(Duration::from_secs(15), async {
                        tokio::try_join!(
                            async { Ok::<_, anyhow::Error>(child.wait().await?) },
                            bounded(
                                stdout,
                                scenario.quiet_status.then(|| rig.fake.state.clone())
                            ),
                            bounded(
                                stderr,
                                scenario.quiet_status.then(|| rig.fake.state.clone())
                            )
                        )
                    })
                    .await;
                    let (status, stdout, stderr) = match result {
                        Ok(Ok(result)) => result,
                        error => {
                            let _ = child.start_kill();
                            let _ =
                                tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
                            anyhow::bail!("native Quickshell did not complete: {error:?}");
                        }
                    };
                    let output = format!(
                        "{}{}",
                        String::from_utf8_lossy(&stdout),
                        String::from_utf8_lossy(&stderr)
                    );
                    ensure!(
                        status.success()
                            && output.contains(scenario.passed)
                            && !output.contains("NM_SOCKET_PROBE_FAIL")
                            && !output.contains("NM_CONNECT_RECOVERY_FAIL")
                            && !output.contains("NM_STATUS_RECOVERY_FAIL"),
                        "native probe failed ({status}):\n{output}"
                    );
                    Ok::<_, anyhow::Error>(output)
                })?;
                println!("{output}");
                let state = rig.fake.state.lock().unwrap();
                assert_eq!(
                    state.activations.len(),
                    usize::from(scenario.outcome.is_some())
                );
                if scenario.quiet_status {
                    assert!(state.deactivated.is_empty());
                    assert_eq!(state.added, 0);
                    assert_eq!(state.updates, 0);
                    assert_eq!(state.secret_probes, 0);
                    assert_eq!(state.connectivity_checks, 0);
                }
                drop(state);
                rig.finish()?;
            }
            Ok(())
        },
    )
}
