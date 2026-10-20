//! Storage semantics are validated separately from general D-Bus compatibility.
//! Both the preserving writer and post-activation confirmation must use this
//! policy. GetSecrets increments VersionId exactly once on the tested builds;
//! accepting a new version requires native storage AND actual-writer VM gates.
//! Version strings cannot establish backports or distinguish development commits:
//! the exact tested revisions/patches live in nix/networkmanager.nix/provenance.

pub(crate) fn validated_storage_version(version: &str) -> bool {
    matches!(version, "1.56.0" | "1.58.1" | "1.59.2-dev")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_policy_requires_explicit_validation_not_a_version_range() {
        for version in ["1.56.0", "1.58.1", "1.59.2-dev"] {
            assert!(validated_storage_version(version), "{version}");
        }
        for version in [
            "",
            "1.56.1",
            "1.58.2",
            "1.60.0",
            "1.60-rc1",
            "1.59.2",
            "1.58.1-vendor",
            " 1.58.1",
        ] {
            assert!(!validated_storage_version(version), "{version}");
        }
    }
}
