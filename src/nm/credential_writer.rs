//! Optimistic, preserving profile edits. Never call from an unresolved
//! SecretAgent callback: GetSecrets can consult agents.
use std::collections::HashMap;

use anyhow::{Result, ensure};
use zvariant::{OwnedObjectPath, OwnedValue};

use super::{ConnectionSettings, Nm, SETTINGS_CONNECTION_IFACE};
use crate::network_credentials::{
    AGENT_OWNED, NOT_SAVED, flags, has_secrets, known_keys, merge_secrets, text,
};
use crate::variant::{owned_value, setting};

/// No Debug/Serialize: this may hold credentials during an explicit edit.
pub(super) struct ProfileEdit {
    pub(super) settings: ConnectionSettings,
    original: ConnectionSettings,
    version: u64,
    uuid: String,
    owner: String,
    path: OwnedObjectPath,
}

impl Nm {
    pub(super) fn begin_credential_edit(&self, path: &OwnedObjectPath) -> Result<ProfileEdit> {
        let owner = self.current_owner()?;
        ensure!(
            self.destination() == owner,
            "profile writes require a pinned NM owner"
        );
        let proxy = self.proxy_path(path, SETTINGS_CONNECTION_IFACE)?;
        let version: u64 = proxy.get_property("VersionId")?;
        ensure!(
            version != 0,
            "NetworkManager profile version is unavailable"
        );
        let settings: ConnectionSettings = proxy.call("GetSettings", &())?;
        let uuid = settings
            .get("connection")
            .and_then(|s| setting::<&str>(s, "uuid"))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("profile UUID missing"))?
            .to_string();
        let unsaved: bool = proxy.get_property("Unsaved")?;
        let filename: String = proxy.get_property("Filename")?;
        ensure!(
            !unsaved && filename.starts_with("/etc/NetworkManager/system-connections/"),
            "refusing implicit persistence of temporary, staged or unsupported-location profiles"
        );
        ensure!(
            proxy.get_property::<u64>("VersionId")? == version && self.current_owner()? == owner,
            "profile changed during snapshot; retry the explicit edit"
        );
        Ok(ProfileEdit {
            original: settings.clone(),
            settings,
            version,
            uuid,
            owner,
            path: path.clone(),
        })
    }

    pub(super) fn commit_credential_edit(
        &self,
        mut edit: ProfileEdit,
        block_autoconnect: bool,
    ) -> Result<()> {
        let proxy = self.proxy_path(&edit.path, SETTINGS_CONNECTION_IFACE)?;
        ensure!(
            self.current_owner()? == edit.owner && self.destination() == edit.owner,
            "NetworkManager changed; edit cancelled"
        );
        ensure!(
            proxy.get_property::<u64>("VersionId")? == edit.version,
            "profile changed; edit cancelled"
        );
        ensure!(
            edit.settings
                .get("connection")
                .and_then(|s| setting::<&str>(s, "uuid"))
                == Some(edit.uuid.as_str()),
            "profile identity changed; edit cancelled"
        );
        validate_policy_changes(&edit.original, &edit.settings)?;
        if has_secrets(&edit.settings) {
            let running: String = self.root_proxy().get_property("Version")?;
            ensure!(
                crate::networkmanager_compatibility::validated_storage_version(&running),
                "credential writes require a validated NetworkManager version"
            );
            // Save the intended secret patch separately. Read *every* supported
            // secret-bearing setting; any authorization/lookup error aborts.
            // Do not reinterpret an error as an empty destination.
            let patch = edit.settings.clone();
            let sections = edit
                .settings
                .keys()
                .filter(|s| {
                    if s.as_str() == "802-11-wireless-security" {
                        let security = &edit.settings[*s];
                        matches!(
                            setting::<&str>(security, "key-mgmt"),
                            Some("wpa-psk" | "sae" | "none")
                        ) || setting::<&str>(security, "auth-alg") == Some("leap")
                    } else {
                        !known_keys(s).is_empty() || s.as_str() == "vpn"
                    }
                })
                .cloned()
                .collect::<Vec<_>>();
            for section in sections {
                let secrets: ConnectionSettings =
                    proxy.call("GetSecrets", &(section,)).map_err(|_| {
                        anyhow::anyhow!("cannot preserve existing credentials; no update attempted")
                    })?;
                // Reviewed NM versions execute exactly one internal settings
                // update for each successful GetSecrets, including cache hits.
                // Never adopt an arbitrary new version: a concurrent external
                // edit adds another increment and must abort this transaction.
                let expected = edit
                    .version
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("profile version exhausted"))?;
                ensure!(
                    proxy.get_property::<u64>("VersionId")? == expected,
                    "profile changed during secret retrieval; no update attempted"
                );
                edit.version = expected;
                validate_secret_reply(&secrets)?;
                merge_secrets(&mut edit.settings, &secrets)?;
            }
            // Only secret fields from the original edit are overlaid, not its
            // public/nested peer settings. Unknown structures fail closed.
            merge_secrets(&mut edit.settings, &patch)?;
        }
        ensure!(
            self.current_owner()? == edit.owner
                && proxy.get_property::<u64>("VersionId")? == edit.version,
            "profile changed while preserving credentials; no update attempted"
        );
        ensure!(
            !proxy.get_property::<bool>("Unsaved")?,
            "profile has staged edits; no update attempted"
        );
        let flags = 1u32 | if block_autoconnect { 0x20 } else { 0 }; // TO_DISK
        let args = HashMap::from([("version-id", owned_value(edit.version)?)]);
        let _: HashMap<String, OwnedValue> = proxy.call("Update2", &(edit.settings, flags, args))
            .map_err(|_| anyhow::anyhow!("NetworkManager did not acknowledge a durable profile update; re-inventory before retrying"))?;
        ensure!(
            self.current_owner()? == edit.owner,
            "NetworkManager changed after write; verification required"
        );
        Ok(())
    }
}

fn validate_secret_reply(reply: &ConnectionSettings) -> Result<()> {
    for (section, values) in reply {
        for key in values.keys() {
            ensure!(
                known_keys(section).contains(&key.as_str())
                    || (section == "vpn" && key == "secrets")
                    || (section == "wireguard" && key == "peers"),
                "unknown secret schema; no update attempted"
            );
        }
    }
    Ok(())
}

fn validate_policy_changes(
    original: &ConnectionSettings,
    edited: &ConnectionSettings,
) -> Result<()> {
    for section in original.keys().filter(|s| edited.contains_key(*s)) {
        for key in known_keys(section) {
            let before = flags(original, section, key)?;
            let after = flags(edited, section, key)?;
            ensure!(
                before & NOT_SAVED == 0 || after & NOT_SAVED != 0,
                "refusing to make an existing temporary credential persistent"
            );
            ensure!(
                after & AGENT_OWNED == 0 || before & AGENT_OWNED != 0,
                "new agent-owned storage is unsupported"
            );
            ensure!(
                before & 4 == 0 || after & 4 != 0,
                "NOT_REQUIRED policy must be preserved during credential replacement"
            );
            if before & AGENT_OWNED != 0 && after & AGENT_OWNED == 0 {
                // Shared WEP flags do not tell us which optional slots exist
                // in an external agent. A normal prompt may return only one.
                // Require explicit source inventory rather than silently making
                // omitted agent-owned slots inaccessible by changing the group.
                ensure!(
                    !key.starts_with("wep-key"),
                    "shared WEP agent ownership requires explicit migration"
                );
                let supplied = text(edited, section, key).is_some();
                ensure!(
                    supplied,
                    "ownership conversion requires a supplied credential; use explicit migration"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
