//! Private bus for owner replacement tests; never reads host bus configuration.
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use zbus::blocking::{Connection, connection::Builder};

pub(crate) struct TestBus {
    daemon: Option<Child>,
    directory: PathBuf,
    address: String,
}

impl TestBus {
    pub(crate) fn new() -> Result<Self> {
        let directory = std::env::temp_dir().join(format!(
            "nm-test-bus-{}-{}",
            std::process::id(),
            crate::daemon_runtime::next_request_id("bus"),
        ));
        std::fs::create_dir(&directory)?;
        let mut bus = Self {
            daemon: None,
            directory,
            address: String::new(),
        };
        std::fs::set_permissions(&bus.directory, std::fs::Permissions::from_mode(0o700))?;
        // Nix sandboxes lack /etc/dbus-1/session.conf and /etc/machine-id.
        // No service directories: this bus cannot activate any host services.
        let listen = bus
            .directory
            .to_string_lossy()
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let config = bus.directory.join("bus.conf");
        std::fs::write(
            &config,
            format!(
                r#"<busconfig>
          <type>session</type><listen>unix:tmpdir={listen}</listen><auth>EXTERNAL</auth>
          <policy context="default"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy>
        </busconfig>"#
            ),
        )?;
        let mut daemon = Command::new("dbus-daemon")
            .arg("--config-file")
            .arg(config)
            .args(["--nofork", "--print-address=1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("start private test bus (requires dbus-daemon)")?;
        let stdout = daemon.stdout.take().context("test bus address pipe")?;
        bus.daemon = Some(daemon);
        BufReader::new(stdout).read_line(&mut bus.address)?;
        anyhow::ensure!(
            !bus.address.trim().is_empty(),
            "private test bus did not start"
        );
        Ok(bus)
    }

    pub(crate) fn connect(&self) -> Result<Connection> {
        Ok(Builder::address(self.address.trim())?.build()?)
    }
}

impl Drop for TestBus {
    fn drop(&mut self) {
        if let Some(daemon) = self.daemon.as_mut() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
