use std::time::Instant;

use anyhow::{Context, Result};

use zvariant::OwnedObjectPath;

use super::{ACTIVE_CONNECTION_IFACE, DEVICE_IFACE, Nm};
use crate::model::{ConnectivityStatus, PrimaryConnectionIdentity};

impl Nm {
    /// Read a current verdict, fenced against primary changes and NM restarts.
    pub(crate) fn portal_snapshot(&self) -> Result<(String, ConnectivityStatus)> {
        let bus = zbus::blocking::fdo::DBusProxy::new(&self.conn)?;
        let destination = zbus::names::BusName::try_from(self.destination.as_str())?;
        let owner = bus.get_name_owner(destination.clone())?.to_string();
        // Ordinary status proxies cache properties asynchronously. A launch
        // fence must perform real reads against this specific NM owner.
        let root: zbus::blocking::Proxy<'_> = zbus::blocking::proxy::Builder::new(&self.conn)
            .destination(owner.as_str())?
            .path(super::NM_PATH)?
            .interface(super::NM_IFACE)?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()?;
        let before: OwnedObjectPath = root.get_property("PrimaryConnection")?;
        let code: u32 = root.get_property("Connectivity")?;
        let status = self.portal_context_from(&root, ConnectivityStatus::from_nm_code(code));
        let after: OwnedObjectPath = root.get_property("PrimaryConnection")?;
        let final_code: u32 = root.get_property("Connectivity")?;
        anyhow::ensure!(
            before == after
                && code == final_code
                && status
                    .primary_connection
                    .as_ref()
                    .is_some_and(|p| p.path == before.as_str())
                && owner == bus.get_name_owner(destination)?.as_str(),
            "network changed while preparing portal launch"
        );
        Ok((format!("{}:{owner}", self.conn.server_guid()), status))
    }

    /// Passive telemetry must not issue an HTTP probe. NetworkManager owns
    /// periodic checks and publishes Connectivity changes independently of link
    /// activation; an explicit network.connectivity call may still request one.
    pub(crate) fn connectivity_snapshot(&self) -> Result<ConnectivityStatus> {
        let code = self
            .root_proxy()
            .get_property("Connectivity")
            .context("read NetworkManager Connectivity")?;
        Ok(self.with_portal_context(ConnectivityStatus::from_nm_code(code)))
    }

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
        self.portal_context_from(&self.root_proxy(), status)
    }

    fn portal_context_from(
        &self,
        root: &zbus::blocking::Proxy<'_>,
        status: ConnectivityStatus,
    ) -> ConnectivityStatus {
        status.with_portal_context(
            root.get_property::<String>("ConnectivityCheckUri").ok(),
            root.get_property("ConnectivityCheckEnabled")
                .unwrap_or(false),
            root.get_property("ConnectivityCheckAvailable")
                .unwrap_or(false),
            self.primary_connection_identity(root),
        )
    }

    fn primary_connection_identity(
        &self,
        root: &zbus::blocking::Proxy<'_>,
    ) -> Option<PrimaryConnectionIdentity> {
        let path = root
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
            type_name: root
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
