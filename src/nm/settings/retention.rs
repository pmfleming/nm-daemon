//! Profile lifetime is owned by NetworkManager, never by a UI disconnect callback.
use std::collections::HashMap;

use anyhow::{Result, ensure};
use zvariant::{OwnedObjectPath, OwnedValue};

use super::super::{ConnectionSettings, Nm, SETTINGS_CONNECTION_IFACE};
use crate::network_credentials::{AGENT_OWNED, flags, known_keys};
use crate::variant::owned_value;

impl Nm {
    pub(super) fn connection_remembered(&self, path: &OwnedObjectPath) -> Result<bool> {
        let proxy = self.proxy_path(path, SETTINGS_CONNECTION_IFACE)?;
        let unsaved: bool = proxy.get_property("Unsaved")?;
        let flags: u32 = proxy.get_property("Flags")?;
        Ok(!unsaved && flags & 4 == 0) // NM_SETTINGS_CONNECTION_FLAG_VOLATILE
    }

    pub(crate) fn set_connection_remember_by_path(
        &self,
        path: &str,
        remember: bool,
    ) -> Result<&'static str> {
        let _transaction = self.begin_profile_transaction();
        let path = OwnedObjectPath::try_from(path)?;
        let owner = self.current_owner()?;
        ensure!(
            self.destination() == owner,
            "retention writes require a pinned NM owner"
        );
        let proxy = self.proxy_path(&path, SETTINGS_CONNECTION_IFACE)?;
        let version: u64 = proxy.get_property("VersionId")?;
        ensure!(
            version != 0,
            "NetworkManager profile version is unavailable"
        );
        self.saved_wifi_connection_by_path(&path)?; // Reject non-Wi-Fi identities.
        let filename: String = proxy.get_property("Filename")?;
        ensure!(
            filename.is_empty()
                || filename.starts_with("/etc/NetworkManager/system-connections/")
                || filename.starts_with("/run/NetworkManager/system-connections/"),
            "retention is unavailable for externally managed profiles"
        );
        ensure!(
            self.current_owner()? == owner && proxy.get_property::<u64>("VersionId")? == version,
            "profile changed; retry the explicit retention change"
        );

        if remember {
            let edit = self.begin_remember_edit(&path)?;
            for section in edit.settings.keys() {
                for key in known_keys(section) {
                    ensure!(
                        flags(&edit.settings, section, key)? & AGENT_OWNED == 0,
                        "agent-owned credentials require explicit migration before remembering"
                    );
                }
            }
            self.commit_credential_edit(edit, false)?;
            ensure!(
                self.connection_remembered(&path)?,
                "NetworkManager did not confirm saved network details"
            );
            return Ok("Network details saved for future connections.");
        }

        // Empty settings preserve credentials and all public settings natively.
        // IN_MEMORY (not DETACHED) retains the original disk backing until NM
        // deletes BOTH it and the runtime profile on disconnect. VOLATILE also
        // deletes immediately if already inactive, and prevents autoactivation.
        // No certificate/key files are removed by us.
        let update_flags = 0x2u32 | 0x10 | 0x20 | 0x40;
        let args = HashMap::from([("version-id", owned_value(version)?)]);
        let _: HashMap<String, OwnedValue> =
            proxy.call("Update2", &(ConnectionSettings::new(), update_flags, args))?;
        ensure!(
            self.current_owner()? == owner,
            "NetworkManager changed; refresh to verify retention"
        );
        if !self.saved_connections()?.contains(&path) {
            return Ok("Saved network details deleted. Future connections won't be remembered.");
        }
        ensure!(
            proxy.get_property::<u32>("Flags")? & 4 != 0,
            "NetworkManager did not confirm deletion on disconnect"
        );
        Ok("Network details will be deleted when you disconnect.")
    }
}
