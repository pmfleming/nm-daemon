use std::time::Instant;

use anyhow::{Context, Result};

use zvariant::OwnedObjectPath;

use super::{ACTIVE_CONNECTION_IFACE, DEVICE_IFACE, Nm};
use crate::model::{ConnectivityStatus, PrimaryConnectionIdentity};

impl Nm {
    pub(crate) fn connectivity_check(&self) -> Result<ConnectivityStatus> {
        let started = Instant::now();
        let nm = self.root_proxy();
        let code: u32 = match nm.call("CheckConnectivity", &()) {
            Ok(code) => code,
            Err(error) => {
                tracing::warn!(
                    elapsed_ms = started.elapsed().as_millis(),
                    error = %error,
                    "NetworkManager connectivity check failed"
                );
                return Err(error).context("CheckConnectivity");
            }
        };
        let status = self.with_portal_context(ConnectivityStatus::from_nm_code(code));
        tracing::debug!(
            connectivity_code = status.code,
            connectivity_state = status.state,
            captive_portal = status.captive_portal,
            full = status.full,
            elapsed_ms = started.elapsed().as_millis(),
            "NetworkManager connectivity check completed"
        );
        Ok(status)
    }

    /// Adds NetworkManager's own check URI and the identity of the connection
    /// the verdict applies to, so a captive-portal flow opens the URL
    /// NetworkManager probed on the connection it probed it over.
    pub(crate) fn with_portal_context(&self, status: ConnectivityStatus) -> ConnectivityStatus {
        let root = self.root_proxy();
        status.with_portal_context(
            root.get_property::<String>("ConnectivityCheckUri").ok(),
            root.get_property("ConnectivityCheckEnabled")
                .unwrap_or(false),
            root.get_property("ConnectivityCheckAvailable")
                .unwrap_or(false),
            self.primary_connection_identity(),
        )
    }

    fn primary_connection_identity(&self) -> Option<PrimaryConnectionIdentity> {
        let path = self
            .root_proxy()
            .get_property::<OwnedObjectPath>("PrimaryConnection")
            .ok()
            .filter(|path| path.as_str() != "/")?;
        let active = self.proxy(path.as_str(), ACTIVE_CONNECTION_IFACE).ok()?;
        let connection_type = active.get_property::<String>("Type").unwrap_or_default();
        let device_iface = active
            .get_property::<Vec<OwnedObjectPath>>("Devices")
            .ok()
            .and_then(|devices| devices.into_iter().next())
            .and_then(|device| {
                self.proxy(device.as_str(), DEVICE_IFACE)
                    .ok()?
                    .get_property::<String>("Interface")
                    .ok()
            })
            .filter(|iface| !iface.is_empty());
        Some(PrimaryConnectionIdentity {
            path: path.to_string(),
            id: active.get_property("Id").unwrap_or_default(),
            uuid: active.get_property("Uuid").unwrap_or_default(),
            type_name: self
                .root_proxy()
                .get_property::<String>("PrimaryConnectionType")
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| Some(connection_type.clone()))
                .filter(|value| !value.is_empty()),
            connection_type,
            device_iface,
        })
    }
}
