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

pub(crate) fn should_return_secret_agent_error(
    password: Option<&str>,
    err: &anyhow::Error,
) -> bool {
    password.is_none()
        && matches!(
            connect_failure_reason(err),
            ConnectFailureReason::PasswordUnavailable | ConnectFailureReason::SecretRequired
        )
}

pub(crate) fn target_appears_to_need_secret(target: &WifiConnectTarget) -> bool {
    matches!(
        target.security.as_ref(),
        Some(Security::Wpa | Security::Wpa2Or3 | Security::Wep)
    ) || (target.hidden && target.security.is_none())
}

#[cfg(test)]
mod tests {
    use super::{connect_failure, connect_failure_reason};
    use crate::model::ConnectFailureReason;

    #[test]
    fn typed_connect_errors_provide_machine_readable_reasons() {
        let err = connect_failure(ConnectFailureReason::ValidationError, "bad target");

        assert_eq!(
            connect_failure_reason(&err),
            ConnectFailureReason::ValidationError
        );
    }

    #[test]
    fn rendered_connect_words_do_not_override_the_typed_reason() {
        let error = connect_failure(
            ConnectFailureReason::ActivationFailed,
            "wrong password timeout D-Bus no secrets",
        );
        assert_eq!(
            connect_failure_reason(&error),
            ConnectFailureReason::ActivationFailed
        );
    }
}
