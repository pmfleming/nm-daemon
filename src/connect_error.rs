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

pub(crate) fn connect_failure_from_error_with_message(
    reason: ConnectFailureReason,
    message: impl Into<String>,
    err: anyhow::Error,
) -> anyhow::Error {
    DomainError::connect_from_error(reason, message, err).into()
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

pub(crate) fn terminal_before_fallback(err: &anyhow::Error) -> bool {
    matches!(
        connect_failure_reason(err),
        ConnectFailureReason::ValidationError
            | ConnectFailureReason::AuthorizationRequired
            | ConnectFailureReason::WrongPassword
            | ConnectFailureReason::PasswordUnavailable
            | ConnectFailureReason::SecretRequired
    )
}

pub(crate) fn combined_connect_failure(
    dbus_err: &anyhow::Error,
    fallback_err: &anyhow::Error,
    message: String,
) -> anyhow::Error {
    let fallback_reason = connect_failure_reason(fallback_err);
    let dbus_reason = connect_failure_reason(dbus_err);
    let reason = if fallback_reason == ConnectFailureReason::Unknown
        || (fallback_reason == ConnectFailureReason::ActivationFailed
            && secret_or_password_failure(dbus_reason))
    {
        dbus_reason
    } else {
        fallback_reason
    };
    let dbus_report = ErrorReport::from_error(dbus_err, ErrorOperation::Connect);
    let fallback_report = ErrorReport::from_error(fallback_err, ErrorOperation::Connect);
    DomainError::connect(reason, message)
        .with_detail("dbus", dbus_report.detail_value())
        .with_detail("fallback", fallback_report.detail_value())
        .into()
}

fn secret_or_password_failure(reason: ConnectFailureReason) -> bool {
    matches!(
        reason,
        ConnectFailureReason::WrongPassword
            | ConnectFailureReason::PasswordUnavailable
            | ConnectFailureReason::SecretRequired
    )
}

pub(crate) fn fallback_failure_reason(
    target: &WifiConnectTarget,
    password: Option<&str>,
    err: &anyhow::Error,
) -> ConnectFailureReason {
    let typed_reason = connect_failure_reason(err);
    if typed_reason != ConnectFailureReason::Unknown {
        typed_reason
    } else if unsupported_security(target.security.as_ref()) {
        ConnectFailureReason::UnsupportedAuth
    } else if password.is_none() && target_appears_to_need_secret(target) {
        ConnectFailureReason::SecretRequired
    } else {
        ConnectFailureReason::Unknown
    }
}

pub(crate) fn target_appears_to_need_secret(target: &WifiConnectTarget) -> bool {
    matches!(
        target.security.as_ref(),
        Some(Security::Wpa | Security::Wpa2Or3 | Security::Wep)
    ) || (target.hidden && target.security.is_none())
}

fn unsupported_security(security: Option<&Security>) -> bool {
    security.is_some_and(|security| {
        !matches!(
            security,
            Security::Open | Security::Owe | Security::Wpa | Security::Wpa2Or3 | Security::Wep
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        connect_failure, connect_failure_reason, fallback_failure_reason, terminal_before_fallback,
    };
    use crate::error::{DomainError, ErrorCode, ErrorOperation, ErrorSource};
    use crate::model::{ConnectFailureReason, Security, example_connect_target};

    #[test]
    fn typed_connect_errors_provide_machine_readable_reasons() {
        let err = connect_failure(ConnectFailureReason::ValidationError, "bad target");

        assert_eq!(
            connect_failure_reason(&err),
            ConnectFailureReason::ValidationError
        );
    }

    #[test]
    fn fallback_reason_uses_typed_failure_and_target_metadata() {
        let mut target = example_connect_target(false);
        target.security = Some(Security::Wpa2Or3);
        let generic_err = connect_failure(ConnectFailureReason::Unknown, "generic failure");
        assert_eq!(
            fallback_failure_reason(&target, None, &generic_err),
            ConnectFailureReason::SecretRequired
        );

        target.security = Some(Security::Other("802.1X".to_string()));
        assert_eq!(
            fallback_failure_reason(&target, Some("secret"), &generic_err),
            ConnectFailureReason::UnsupportedAuth
        );

        let not_found_err: anyhow::Error = DomainError::new(
            ErrorCode::NotFound,
            ErrorOperation::RunNmcli,
            ErrorSource::Subprocess,
            "anything",
        )
        .into();
        assert_eq!(
            fallback_failure_reason(&target, Some("secret"), &not_found_err),
            ConnectFailureReason::NotFound
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

    #[test]
    fn validation_and_authorization_errors_are_terminal_before_fallback() {
        assert!(terminal_before_fallback(&connect_failure(
            ConnectFailureReason::ValidationError,
            "invalid password",
        )));
        assert!(terminal_before_fallback(&connect_failure(
            ConnectFailureReason::AuthorizationRequired,
            "permission denied",
        )));
        assert!(!terminal_before_fallback(&connect_failure(
            ConnectFailureReason::Timeout,
            "activation timed out",
        )));
    }
}
