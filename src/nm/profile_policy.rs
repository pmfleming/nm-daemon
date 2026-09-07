use std::collections::HashMap;

use anyhow::Result;
use zvariant::OwnedValue;

use super::ConnectionSettings;
use crate::error::{DomainError, ErrorOperation};

/// NM's certificate/key properties use `ay`, not D-Bus strings. URI references
/// are NUL-terminated; embedded NULs must not silently truncate the trust path.
pub(super) fn set_certificate_reference(
    section: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<&str>,
    operation: ErrorOperation,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty() {
        section.remove(key);
        return Ok(());
    }
    if value.contains('\0') || !(value.starts_with("file://") || value.starts_with("pkcs11:")) {
        return Err(DomainError::validation(
            operation,
            "certificate references must be a file:// or pkcs11: URI without embedded NULs",
        )
        .with_detail("field", format!("802-1x.{key}"))
        .into());
    }
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    section.insert(key.to_string(), super::owned_value(bytes)?);
    Ok(())
}

/// Match upstream's private-profile CA-directory restriction (CVE-2026-19685)
/// before saving/activating settings. Never silently remove trust settings or
/// make a private profile public to get an activation through.
pub(super) fn validate_private_ca_paths(
    settings: &ConnectionSettings,
    operation: ErrorOperation,
) -> Result<()> {
    let private = settings
        .get("connection")
        .and_then(|section| section.get("permissions"))
        .and_then(|value| Vec::<String>::try_from(value.clone()).ok())
        .is_some_and(|permissions| !permissions.is_empty());
    if !private {
        return Ok(());
    }
    let Some(enterprise) = settings.get("802-1x") else {
        return Ok(());
    };
    for key in ["ca-path", "phase2-ca-path"] {
        if enterprise
            .get(key)
            .and_then(|value| String::try_from(value.clone()).ok())
            .is_some_and(|path| !path.is_empty())
        {
            // system-ca-certs only overrides these directories on NM builds
            // whose compiled-in CA store is a directory, not a bundle file.
            // Requiring explicit clears is portable and does not guess trust.
            return Err(DomainError::validation(operation, format!(
                "802-1x.{key} is not supported for private connections; clear the CA directory and use ca-cert/phase2-ca-cert or system-ca-certs instead"
            )).with_detail("field", format!("802-1x.{key}")).into());
        }
    }
    Ok(())
}
