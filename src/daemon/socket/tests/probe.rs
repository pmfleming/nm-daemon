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
            let rig = Rig::new([])?;
            let executable =
                std::env::var_os("QUICKSHELL_BIN").unwrap_or_else(|| "quickshell".into());
            let output = tokio::runtime::Handle::current().block_on(async {
                // Inherit the isolated test's private process group. Its outer
                // deadline kills the whole group while its leader is still owned.
                let mut child = Command::new(executable)
                    .args(["--no-color", "--path"])
                    .arg(root.join("tests/e2e/nm-unix-jsonl.qml"))
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
                        let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
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
                        && output.contains("NM_SOCKET_PROBE_PASS native-shared-session-renewal")
                        && !output.contains("NM_SOCKET_PROBE_FAIL"),
                    "native probe failed ({status}):\n{output}"
                );
                Ok::<_, anyhow::Error>(output)
            })?;
            println!("{output}");
            assert!(rig.fake.state.lock().unwrap().activations.is_empty());
            rig.finish()
        },
    )
}
