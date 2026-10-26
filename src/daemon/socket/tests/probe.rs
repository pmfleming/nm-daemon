//! Explicit real-Quickshell acceptance, never a live NetworkManager service.
use super::*;
use std::process::Stdio;
use tokio::{io::AsyncReadExt, process::Command};

async fn bounded(reader: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(1024 * 1024 + 1).read_to_end(&mut bytes).await?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "native probe log limit exceeded"
    );
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
            for recovery in [false, true] {
                let rig = Rig::new(if recovery {
                    vec![Outcome::Connected]
                } else {
                    vec![]
                })?;
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
                        .arg(root.join(if recovery {
                            "tests/e2e/nm-connect-recovery.qml"
                        } else {
                            "tests/e2e/nm-unix-jsonl.qml"
                        }))
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
                            bounded(stdout),
                            bounded(stderr)
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
                            && output.contains(if recovery {
                                "NM_CONNECT_RECOVERY_PASS native-quiet-terminal-status"
                            } else {
                                "NM_SOCKET_PROBE_PASS native-shared-session-renewal"
                            })
                            && !output.contains("NM_SOCKET_PROBE_FAIL")
                            && !output.contains("NM_CONNECT_RECOVERY_FAIL"),
                        "native probe failed ({status}):\n{output}"
                    );
                    Ok::<_, anyhow::Error>(output)
                })?;
                println!("{output}");
                assert_eq!(
                    rig.fake.state.lock().unwrap().activations.len(),
                    usize::from(recovery)
                );
                rig.finish()?;
            }
            Ok(())
        },
    )
}
