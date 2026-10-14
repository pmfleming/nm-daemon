use crate::error::{DomainError, ErrorOperation, ErrorReport};
use crate::model::{ConnectFailureReason, Security, WifiConnectTarget};

pub(crate) fn connect_failure_reason(err: &anyhow::Error) -> ConnectFailureReason {
    ErrorReport::from_error(err, ErrorOperation::Connect)
        .code
        .connect_reason()
        .unwrap_or(ConnectFailureReason::Unknown)
}

pub(crate) fn connect_failure(
    reason: ConnectFailureReason,
    message: impl Into<String>,
) -> anyhow::Error {
    DomainError::connect(reason, message).into()
}

pub(crate) fn connect_failure_from_error(
    reason: ConnectFailureReason,
    err: anyhow::Error,
) -> anyhow::Error {
    DomainError::connect_from_error(reason, format!("{err:#}"), err).into()
}

pub(crate) fn target_appears_to_need_secret(target: &WifiConnectTarget) -> bool {
    matches!(
        target.security.as_ref(),
        Some(Security::Wpa | Security::Wpa2Or3 | Security::Wep)
    ) || (target.hidden && target.security.is_none())
}
