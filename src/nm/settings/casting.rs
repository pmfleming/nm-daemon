use anyhow::{Context, Result};
use zvariant::OwnedObjectPath;

use crate::error::{DomainError, ErrorOperation};
use crate::nm::{ACTIVE_CONNECTION_IFACE, ConnectionSettings, DEVICE_IFACE, Nm, owned_value};

// Match the host's default-off NetworkManager policy. Resolve-only permits
// discovery without registering this machine's hostname on the network.
const NM_MDNS_DISABLED: i32 = 0;
const NM_MDNS_RESOLVE: i32 = 1;
const NM_MDNS_YES: i32 = 2;

#[cfg(test)]
mod tests;

pub(super) fn casting_enabled_from_settings(settings: &ConnectionSettings) -> bool {
    matches!(mdns_policy(settings), Some(NM_MDNS_RESOLVE | NM_MDNS_YES))
}

fn mdns_policy(settings: &ConnectionSettings) -> Option<i32> {
    settings
        .get("connection")?
        .get("mdns")?
        .try_clone()
        .ok()?
        .try_into()
        .ok()
}

pub(super) fn set_casting_enabled(settings: &mut ConnectionSettings, enabled: bool) -> Result<()> {
    settings
        .entry("connection".to_string())
        .or_default()
        .insert(
            "mdns".to_string(),
            owned_value(if enabled {
                NM_MDNS_RESOLVE
            } else {
                NM_MDNS_DISABLED
            })?,
        );
    Ok(())
}

impl Nm {
    pub(super) fn reapply_casting(&self, profile: &OwnedObjectPath, enabled: bool) -> Result<()> {
        // Saved policy is already committed. Close the firewall first on Off;
        // on On it stays closed until the applied resolver policy also agrees.
        // Always attempt both layers, even if one fails, and never claim success
        // when the privileged companion is missing or enforcement failed.
        let before = self.reconcile_cast_firewall();
        let resolver = self.reapply_casting_resolver(profile, enabled);
        let after = self.reconcile_cast_firewall();
        let failures: Vec<String> = [before, resolver, after]
            .into_iter()
            .filter_map(|result| result.err().map(|error| format!("{error:#}")))
            .collect();
        anyhow::ensure!(failures.is_empty(), "{}", failures.join("; "));
        Ok(())
    }

    fn reconcile_cast_firewall(&self) -> Result<()> {
        zbus::blocking::Proxy::new(
            &self.conn,
            crate::cast_policy::DESTINATION,
            crate::cast_policy::PATH,
            crate::cast_policy::INTERFACE,
        )?
        .call::<_, _, ()>("Reconcile", &())
        .context("apply Cast firewall policy (nm-cast-policy system service required)")
    }

    fn reapply_casting_resolver(&self, profile: &OwnedObjectPath, enabled: bool) -> Result<()> {
        let active_paths: Vec<OwnedObjectPath> = self
            .root_proxy()
            .get_property("ActiveConnections")
            .context("read active connections for Cast discovery")?;
        for active_path in active_paths {
            let active = self.proxy_path(&active_path, ACTIVE_CONNECTION_IFACE)?;
            let active_profile: OwnedObjectPath = active.get_property("Connection")?;
            if &active_profile != profile {
                continue;
            }
            let devices: Vec<OwnedObjectPath> = active.get_property("Devices")?;
            for device_path in devices {
                self.reapply_device_casting(&device_path, &active_path, enabled)?;
            }
        }
        Ok(())
    }

    fn reapply_device_casting(
        &self,
        device_path: &OwnedObjectPath,
        active_path: &OwnedObjectPath,
        enabled: bool,
    ) -> Result<()> {
        let device = self.proxy_path(device_path, DEVICE_IFACE)?;
        let (mut applied, version): (ConnectionSettings, u64) = device
            .call("GetAppliedConnection", &(0_u32,))
            .with_context(|| format!("read applied settings for {device_path}"))?;
        let current_active: OwnedObjectPath = device.get_property("ActiveConnection")?;
        if &current_active != active_path || version == 0 {
            return Err(DomainError::conflict(
                ErrorOperation::ProfileOperation,
                "Active connection changed while applying Cast discovery; retry",
            )
            .into());
        }
        let desired = if enabled {
            NM_MDNS_RESOLVE
        } else {
            NM_MDNS_DISABLED
        };
        if mdns_policy(&applied) == Some(desired) {
            return Ok(());
        }
        // Never reapply the saved profile wholesale: MAC/IP/password edits may
        // intentionally be pending a reconnect. Patch only the applied mDNS
        // field and let NM reject a concurrent activation/reapply by version.
        set_casting_enabled(&mut applied, enabled)?;
        const PRESERVE_EXTERNAL_IP: u32 = 1;
        device
            .call::<_, _, ()>("Reapply", &(applied, version, PRESERVE_EXTERNAL_IP))
            .with_context(|| format!("reapply Cast discovery on {device_path}"))
    }
}
