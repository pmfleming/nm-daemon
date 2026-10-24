//! Transport-independent connection selectors and their precedence/error policy.
use crate::error::{DomainError, ErrorOperation};
use anyhow::Result;

/// Selects a saved profile, plus an optional activation device.
#[derive(Debug, Default)]
pub(crate) struct ProfileSelector {
    pub(crate) uuid: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) device: Option<String>,
}

/// Selects an active connection; an active path takes precedence over its UUID.
#[derive(Debug, Default)]
pub(crate) struct ActiveConnectionSelector {
    pub(crate) path: Option<String>,
    pub(crate) uuid: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct VpnSelector {
    pub(crate) uuid: Option<String>,
    pub(crate) path: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum SelectionKind {
    Profile,
    Active,
    Vpn,
}
enum Identity<'a> {
    Uuid(&'a str),
    Path(&'a str),
}

impl SelectionKind {
    fn contract(self) -> (ErrorOperation, &'static str, &'static str) {
        match self {
            Self::Profile => (
                ErrorOperation::Connect,
                "network.activateProfile requires uuid or path",
                "no saved profile matched the request",
            ),
            Self::Active => (
                ErrorOperation::Disconnect,
                "network.deactivate requires path or uuid",
                "no active connection matched the request",
            ),
            Self::Vpn => (
                ErrorOperation::VpnOperation,
                "vpn.connect requires uuid or path",
                "no saved VPN or WireGuard profile matched the request",
            ),
        }
    }

    fn identity<'a>(self, uuid: Option<&'a str>, path: Option<&'a str>) -> Result<Identity<'a>> {
        let identity = match self {
            Self::Active => path
                .map(Identity::Path)
                .or_else(|| uuid.map(Identity::Uuid)),
            _ => uuid
                .map(Identity::Uuid)
                .or_else(|| path.map(Identity::Path)),
        };
        let (operation, required, _) = self.contract();
        identity.ok_or_else(|| DomainError::validation(operation, required).into())
    }

    pub(crate) fn validate(self, uuid: Option<&str>, path: Option<&str>) -> Result<()> {
        self.identity(uuid, path).map(|_| ())
    }

    /// Choose once: failure of the preferred key never falls back to another
    /// connection. Preserve first-match ordering and include both requested keys
    /// in not-found diagnostics. Transport input normalization belongs to callers.
    pub(crate) fn select<T>(
        self,
        items: impl IntoIterator<Item = T>,
        uuid: Option<&str>,
        path: Option<&str>,
        fields: impl Fn(&T) -> (&str, &str),
    ) -> Result<T> {
        let identity = self.identity(uuid, path)?;
        let (operation, _, not_found) = self.contract();
        items
            .into_iter()
            .find(|item| {
                let (uuid, path) = fields(item);
                match identity {
                    Identity::Uuid(expected) => uuid == expected,
                    Identity::Path(expected) => path == expected,
                }
            })
            .ok_or_else(|| {
                DomainError::not_found(operation, not_found)
                    .with_detail("uuid", uuid.unwrap_or_default())
                    .with_detail("path", path.unwrap_or_default())
                    .into()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::SelectionKind;
    use crate::error::{ErrorCode, ErrorOperation, ErrorReport};

    #[test]
    fn selection_preserves_precedence_first_match_and_error_contracts() {
        for (kind, operation, preferred, required, missing) in [
            (
                SelectionKind::Profile,
                ErrorOperation::Connect,
                1,
                "network.activateProfile requires uuid or path",
                "no saved profile matched the request",
            ),
            (
                SelectionKind::Active,
                ErrorOperation::Disconnect,
                2,
                "network.deactivate requires path or uuid",
                "no active connection matched the request",
            ),
            (
                SelectionKind::Vpn,
                ErrorOperation::VpnOperation,
                1,
                "vpn.connect requires uuid or path",
                "no saved VPN or WireGuard profile matched the request",
            ),
        ] {
            let rows = [
                (1, "first", "/one"),
                (2, "second", "/two"),
                (3, "first", "/one"),
            ];
            let select = |uuid, path| kind.select(rows, uuid, path, |row| (row.1, row.2));
            for (uuid, path, expected) in [
                (Some("first"), Some("/two"), preferred),
                (Some("first"), None, 1),
                (None, Some("/two"), 2),
            ] {
                assert_eq!(select(uuid, path).unwrap().0, expected, "{kind:?}");
            }
            let error = kind.validate(None, None).unwrap_err();
            let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
            assert_eq!(
                (report.code, report.operation),
                (ErrorCode::ValidationError, operation)
            );
            assert_eq!(report.message, required);
            let (uuid, path) = if preferred == 1 {
                ("missing", "/two")
            } else {
                ("first", "/missing")
            };
            let error = select(Some(uuid), Some(path)).unwrap_err();
            let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
            assert_eq!(
                (report.code, report.operation),
                (ErrorCode::NotFound, operation)
            );
            assert_eq!(report.message, missing);
            assert_eq!(report.details["uuid"], uuid);
            assert_eq!(report.details["path"], path);
            assert!(
                kind.select(Vec::<(&str, &str)>::new(), Some("first"), None, |row| *row)
                    .is_err()
            );
        }
    }
}
