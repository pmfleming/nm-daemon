use anyhow::Result;
use serde::Serialize;

use super::{ParityCheck, compare_optional};

#[derive(Serialize)]
pub(super) struct Versions {
    pub(super) running_networkmanager: Option<String>,
    pub(super) installed_nmcli: Option<String>,
    pub(super) errors: Vec<String>,
}

impl Versions {
    pub(super) fn collect(running: Result<String>, client: Result<String>) -> Self {
        let mut errors = Vec::new();
        let mut record = |source: &str, result: Result<String>| match result {
            Ok(version) => Some(version),
            Err(error) => {
                errors.push(format!("{source}: {error:#}"));
                None
            }
        };
        let running_networkmanager = record("running NetworkManager", running);
        let installed_nmcli = record("installed nmcli", client);
        Self {
            running_networkmanager,
            installed_nmcli,
            errors,
        }
    }

    pub(super) fn check(&self) -> ParityCheck {
        let mut check = compare_optional(
            "versions",
            "daemon versus client",
            self.running_networkmanager.clone(),
            self.installed_nmcli.clone(),
        );
        if check.status == "fail" {
            check.status = "warn";
        }
        check.detail = match check.status {
            "pass" => "version strings agree; this does not prove patch provenance",
            "warn" => "versions differ or one is unavailable; installed nmcli does not establish the running daemon version",
            _ => "versions unavailable; compatibility and backports remain unknown",
        }.into();
        check
    }
}

#[cfg(test)]
mod tests {
    use super::Versions;

    #[test]
    fn client_version_never_substitutes_for_the_running_daemon() {
        let versions = Versions::collect(Err(anyhow::anyhow!("unavailable")), Ok("1.58.1".into()));
        assert!(versions.running_networkmanager.is_none());
        assert_eq!(versions.installed_nmcli.as_deref(), Some("1.58.1"));
        assert_eq!(versions.errors.len(), 1);
        assert_eq!(versions.check().status, "warn");
        let versions = Versions::collect(Ok("1.56.0".into()), Ok("1.58.1".into()));
        assert_eq!(versions.check().status, "warn");
        let versions = Versions::collect(Ok("1.59.2-dev".into()), Ok("1.59.2-dev".into()));
        assert_eq!(versions.check().status, "pass");
        assert_eq!(
            versions.running_networkmanager.as_deref(),
            Some("1.59.2-dev")
        );
        let versions = Versions::collect(
            Err(anyhow::anyhow!("offline")),
            Err(anyhow::anyhow!("missing")),
        );
        assert_eq!(versions.check().status, "unknown");
        assert_eq!(versions.errors.len(), 2);
    }
}
