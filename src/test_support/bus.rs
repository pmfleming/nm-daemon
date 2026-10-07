//! Private bus for owner replacement tests; never connects to the host bus.
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use zbus::blocking::{Connection, connection::Builder};

pub(crate) struct TestBus {
    daemon: Child,
    address: String,
}

impl TestBus {
    pub(crate) fn new() -> Result<Self> {
        let daemon = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("start private test bus (requires dbus-daemon)")?;
        let mut bus = Self {
            daemon,
            address: String::new(),
        };
        let stdout = bus.daemon.stdout.take().context("test bus address pipe")?;
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
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}
