use std::fmt;
use std::io;

use anyhow::Error;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::model::ConnectFailureReason;

pub(crate) struct ErrorChain<'a, E: ?Sized>(&'a E);

impl<E> fmt::Display for ErrorChain<'_, E>
where
    E: fmt::Display + ?Sized,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:#}", self.0)
    }
}

pub(crate) fn err_chain<E>(error: &E) -> ErrorChain<'_, E>
where
    E: fmt::Display + ?Sized,
{
    ErrorChain(error)
}

pub(crate) fn best_effort<T>(
    context: impl fmt::Display,
    operation: impl FnOnce() -> anyhow::Result<T>,
) -> Option<T> {
    match operation() {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(error = %err_chain(&error), "{context}");
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ErrorCode {
    ValidationError,
    NetworkmanagerUnavailable,
    AuthorizationRequired,
    NotFound,
    Timeout,
    Cancelled,
    SecretRequired,
    WrongPassword,
    PasswordUnavailable,
    UnsupportedAuth,
    DhcpFailed,
    ActivationFailed,
    SubprocessFailed,
    InternalError,
    Unknown,
}

impl From<ConnectFailureReason> for ErrorCode {
    fn from(reason: ConnectFailureReason) -> Self {
        match reason {
            ConnectFailureReason::SecretRequired => Self::SecretRequired,
            ConnectFailureReason::WrongPassword => Self::WrongPassword,
            ConnectFailureReason::PasswordUnavailable => Self::PasswordUnavailable,
            ConnectFailureReason::AuthorizationRequired => Self::AuthorizationRequired,
            ConnectFailureReason::UnsupportedAuth => Self::UnsupportedAuth,
            ConnectFailureReason::ValidationError => Self::ValidationError,
            ConnectFailureReason::NotFound => Self::NotFound,
            ConnectFailureReason::Timeout => Self::Timeout,
            ConnectFailureReason::DhcpFailed => Self::DhcpFailed,
            ConnectFailureReason::ActivationFailed => Self::ActivationFailed,
            ConnectFailureReason::Unknown => Self::Unknown,
        }
    }
}

impl ErrorCode {
    pub(crate) fn connect_reason(self) -> Option<ConnectFailureReason> {
        Some(match self {
            Self::ValidationError => ConnectFailureReason::ValidationError,
            Self::AuthorizationRequired => ConnectFailureReason::AuthorizationRequired,
            Self::NotFound => ConnectFailureReason::NotFound,
            Self::Timeout => ConnectFailureReason::Timeout,
            Self::Cancelled | Self::ActivationFailed | Self::SubprocessFailed => {
                ConnectFailureReason::ActivationFailed
            }
            Self::SecretRequired => ConnectFailureReason::SecretRequired,
            Self::WrongPassword => ConnectFailureReason::WrongPassword,
            Self::PasswordUnavailable => ConnectFailureReason::PasswordUnavailable,
            Self::UnsupportedAuth => ConnectFailureReason::UnsupportedAuth,
            Self::DhcpFailed => ConnectFailureReason::DhcpFailed,
            Self::NetworkmanagerUnavailable | Self::InternalError | Self::Unknown => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ErrorOperation {
    Initialize,
    ParseRequest,
    ConnectSystemBus,
    CreateDbusProxy,
    Status,
    Connectivity,
    Networks,
    Scan,
    Connect,
    Disconnect,
    ProfileOperation,
    Subscribe,
    SecretOperation,
    SerializeResponse,
    EmitEvent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ErrorSource {
    Validation,
    Dbus,
    Io,
    Subprocess,
    Serialization,
    NetworkManager,
    Cancellation,
    Internal,
}

#[derive(Debug)]
pub(crate) enum DomainError {
    Validation(DomainErrorContext),
    Dbus(DomainErrorContext),
    Io(DomainErrorContext),
    Subprocess(DomainErrorContext),
    Serialization(DomainErrorContext),
    NetworkManager(DomainErrorContext),
    Cancellation(DomainErrorContext),
    Internal(DomainErrorContext),
}

#[derive(Debug)]
pub(crate) struct DomainErrorContext {
    code: ErrorCode,
    operation: ErrorOperation,
    message: String,
    details: Map<String, Value>,
    cause: Option<Error>,
}

impl DomainError {
    pub(crate) fn new(
        code: ErrorCode,
        operation: ErrorOperation,
        source_kind: ErrorSource,
        message: impl Into<String>,
    ) -> Self {
        let context = DomainErrorContext {
            code,
            operation,
            message: message.into(),
            details: Map::new(),
            cause: None,
        };
        match source_kind {
            ErrorSource::Validation => Self::Validation(context),
            ErrorSource::Dbus => Self::Dbus(context),
            ErrorSource::Io => Self::Io(context),
            ErrorSource::Subprocess => Self::Subprocess(context),
            ErrorSource::Serialization => Self::Serialization(context),
            ErrorSource::NetworkManager => Self::NetworkManager(context),
            ErrorSource::Cancellation => Self::Cancellation(context),
            ErrorSource::Internal => Self::Internal(context),
        }
    }

    pub(crate) fn with_detail(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.context_mut().details.insert(key.into(), value.into());
        self
    }

    pub(crate) fn with_cause(mut self, cause: Error) -> Self {
        self.context_mut().cause = Some(cause);
        self
    }

    pub(crate) fn validation(operation: ErrorOperation, error: impl fmt::Display) -> Self {
        Self::new(
            ErrorCode::ValidationError,
            operation,
            ErrorSource::Validation,
            error.to_string(),
        )
    }

    pub(crate) fn connect(reason: ConnectFailureReason, message: impl Into<String>) -> Self {
        Self::new(
            reason.into(),
            ErrorOperation::Connect,
            ErrorSource::NetworkManager,
            message,
        )
    }

    pub(crate) fn connect_from_error(
        reason: ConnectFailureReason,
        message: impl Into<String>,
        cause: Error,
    ) -> Self {
        let report = ErrorReport::from_error(&cause, ErrorOperation::Connect);
        let mut error = Self::new(
            reason.into(),
            ErrorOperation::Connect,
            report.source,
            message,
        );
        error.context_mut().details = report.details;
        error.context_mut().cause = Some(cause);
        error
    }

    pub(crate) fn cancelled(message: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::Cancelled,
            ErrorOperation::Connect,
            ErrorSource::Cancellation,
            message,
        )
    }

    pub(crate) fn timeout(operation: ErrorOperation, message: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::Timeout,
            operation,
            ErrorSource::NetworkManager,
            message,
        )
    }

    pub(crate) fn not_found(operation: ErrorOperation, message: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::NotFound,
            operation,
            ErrorSource::NetworkManager,
            message,
        )
    }

    pub(crate) fn code(&self) -> ErrorCode {
        self.context().code
    }

    pub(crate) fn operation(&self) -> ErrorOperation {
        self.context().operation
    }

    pub(crate) fn source_kind(&self) -> ErrorSource {
        match self {
            Self::Validation(_) => ErrorSource::Validation,
            Self::Dbus(_) => ErrorSource::Dbus,
            Self::Io(_) => ErrorSource::Io,
            Self::Subprocess(_) => ErrorSource::Subprocess,
            Self::Serialization(_) => ErrorSource::Serialization,
            Self::NetworkManager(_) => ErrorSource::NetworkManager,
            Self::Cancellation(_) => ErrorSource::Cancellation,
            Self::Internal(_) => ErrorSource::Internal,
        }
    }

    pub(crate) fn message(&self) -> &str {
        &self.context().message
    }

    pub(crate) fn details(&self) -> &Map<String, Value> {
        &self.context().details
    }

    fn context(&self) -> &DomainErrorContext {
        match self {
            Self::Validation(context)
            | Self::Dbus(context)
            | Self::Io(context)
            | Self::Subprocess(context)
            | Self::Serialization(context)
            | Self::NetworkManager(context)
            | Self::Cancellation(context)
            | Self::Internal(context) => context,
        }
    }

    fn context_mut(&mut self) -> &mut DomainErrorContext {
        match self {
            Self::Validation(context)
            | Self::Dbus(context)
            | Self::Io(context)
            | Self::Subprocess(context)
            | Self::Serialization(context)
            | Self::NetworkManager(context)
            | Self::Cancellation(context)
            | Self::Internal(context) => context,
        }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for DomainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.context().cause.as_ref().map(|cause| cause.as_ref())
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ErrorReport {
    pub(crate) code: ErrorCode,
    pub(crate) operation: ErrorOperation,
    pub(crate) source: ErrorSource,
    pub(crate) message: String,
    pub(crate) details: Map<String, Value>,
}

impl ErrorReport {
    pub(crate) fn from_error(error: &Error, fallback_operation: ErrorOperation) -> Self {
        if let Some(domain) = find_domain_error(error) {
            return Self {
                code: domain.code(),
                operation: domain.operation(),
                source: domain.source_kind(),
                message: domain.message().to_string(),
                details: domain.details().clone(),
            };
        }

        let (code, source) = classify_concrete_source(error, fallback_operation);
        Self {
            code,
            operation: fallback_operation,
            source,
            message: format!("{error:#}"),
            details: concrete_source_details(error),
        }
    }

    pub(crate) fn api_details(&self) -> Value {
        let mut details = self.details.clone();
        details.insert("operation".to_string(), json!(self.operation));
        details.insert("source".to_string(), json!(self.source));
        Value::Object(details)
    }
}

pub(crate) fn find_domain_error(error: &Error) -> Option<&DomainError> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<DomainError>())
}

pub(crate) fn ensure_domain(operation: ErrorOperation, error: Error) -> Error {
    if find_domain_error(&error).is_some() {
        return error;
    }
    let message = format!("{error:#}");
    let (code, source_kind) = classify_concrete_source(&error, operation);
    let mut domain = DomainError::new(code, operation, source_kind, message);
    domain.context_mut().details = concrete_source_details(&error);
    domain.with_cause(error).into()
}

pub(crate) fn operation_result<T>(
    operation: ErrorOperation,
    result: anyhow::Result<T>,
) -> anyhow::Result<T> {
    result.map_err(|error| ensure_domain(operation, error))
}

fn classify_concrete_source(error: &Error, operation: ErrorOperation) -> (ErrorCode, ErrorSource) {
    if let Some(classification) = classify_zbus_source(error, operation) {
        return classification;
    }
    if let Some(classification) = classify_io_source(error) {
        return classification;
    }
    if contains_json_error(error) {
        return json_source_classification(operation);
    }
    (ErrorCode::InternalError, ErrorSource::Internal)
}

fn classify_zbus_source(
    error: &Error,
    operation: ErrorOperation,
) -> Option<(ErrorCode, ErrorSource)> {
    let error = find_cause::<zbus::Error>(error)?;
    Some((zbus_error_code(error, operation), ErrorSource::Dbus))
}

fn classify_io_source(error: &Error) -> Option<(ErrorCode, ErrorSource)> {
    let error = find_cause::<io::Error>(error)?;
    let code = if error.kind() == io::ErrorKind::TimedOut {
        ErrorCode::Timeout
    } else {
        ErrorCode::InternalError
    };
    Some((code, ErrorSource::Io))
}

fn contains_json_error(error: &Error) -> bool {
    find_cause::<serde_json::Error>(error).is_some()
}

fn json_source_classification(operation: ErrorOperation) -> (ErrorCode, ErrorSource) {
    if operation == ErrorOperation::ParseRequest {
        (ErrorCode::ValidationError, ErrorSource::Validation)
    } else {
        (ErrorCode::InternalError, ErrorSource::Serialization)
    }
}

fn find_cause<E>(error: &Error) -> Option<&E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    error.chain().find_map(|cause| cause.downcast_ref::<E>())
}

fn concrete_source_details(error: &Error) -> Map<String, Value> {
    if let Some(error) = find_cause::<zbus::Error>(error) {
        return zbus_source_details(error);
    }
    if let Some(error) = find_cause::<io::Error>(error) {
        return io_source_details(error);
    }
    find_cause::<serde_json::Error>(error)
        .map(json_source_details)
        .unwrap_or_default()
}

fn zbus_source_details(error: &zbus::Error) -> Map<String, Value> {
    match error {
        zbus::Error::MethodError(name, _, _) => {
            Map::from_iter([("dbus_error_name".to_string(), json!(name.as_str()))])
        }
        zbus::Error::InputOutput(error) => io_source_details(error),
        _ => Map::from_iter([("dbus_error_kind".to_string(), json!(format!("{error:?}")))]),
    }
}

fn io_source_details(error: &io::Error) -> Map<String, Value> {
    let mut details =
        Map::from_iter([("io_kind".to_string(), json!(format!("{:?}", error.kind())))]);
    if let Some(code) = error.raw_os_error() {
        details.insert("os_error".to_string(), json!(code));
    }
    details
}

fn json_source_details(error: &serde_json::Error) -> Map<String, Value> {
    Map::from_iter([
        ("line".to_string(), json!(error.line())),
        ("column".to_string(), json!(error.column())),
        (
            "json_error_category".to_string(),
            json!(format!("{:?}", error.classify()).to_lowercase()),
        ),
    ])
}

fn zbus_error_code(error: &zbus::Error, operation: ErrorOperation) -> ErrorCode {
    match error {
        zbus::Error::MethodError(name, _, _) if dbus_name_is_authorization(name.as_str()) => {
            ErrorCode::AuthorizationRequired
        }
        zbus::Error::MethodError(name, _, _) if dbus_name_is_not_found(name.as_str()) => {
            ErrorCode::NotFound
        }
        zbus::Error::InputOutput(error) if error.kind() == io::ErrorKind::TimedOut => {
            ErrorCode::Timeout
        }
        zbus::Error::Unsupported if operation == ErrorOperation::Connect => {
            ErrorCode::UnsupportedAuth
        }
        _ if networkmanager_operation(operation) => ErrorCode::NetworkmanagerUnavailable,
        _ => ErrorCode::InternalError,
    }
}

fn networkmanager_operation(operation: ErrorOperation) -> bool {
    matches!(
        operation,
        ErrorOperation::ConnectSystemBus
            | ErrorOperation::CreateDbusProxy
            | ErrorOperation::Status
            | ErrorOperation::Connectivity
            | ErrorOperation::Networks
            | ErrorOperation::Scan
            | ErrorOperation::Connect
            | ErrorOperation::Disconnect
            | ErrorOperation::ProfileOperation
    )
}

fn dbus_name_is_authorization(name: &str) -> bool {
    matches!(
        name,
        "org.freedesktop.NetworkManager.Settings.PermissionDenied"
            | "org.freedesktop.NetworkManager.PermissionDenied"
            | "org.freedesktop.DBus.Error.AccessDenied"
            | "org.freedesktop.PolicyKit1.Error.Failed"
    )
}

fn dbus_name_is_not_found(name: &str) -> bool {
    matches!(
        name,
        "org.freedesktop.DBus.Error.NameHasNoOwner"
            | "org.freedesktop.DBus.Error.ServiceUnknown"
            | "org.freedesktop.DBus.Error.UnknownObject"
            | "org.freedesktop.NetworkManager.UnknownConnection"
            | "org.freedesktop.NetworkManager.UnknownDevice"
    )
}

#[cfg(test)]
mod tests {
    use super::{DomainError, ErrorCode, ErrorOperation, ErrorReport, ErrorSource, ensure_domain};

    #[test]
    fn rendered_words_do_not_change_untyped_error_classification() {
        let error = anyhow::anyhow!("unrelated D-Bus parse timeout prose");
        let report = ErrorReport::from_error(&error, ErrorOperation::Status);
        assert_eq!(report.code, ErrorCode::InternalError);
        assert_eq!(report.source, ErrorSource::Internal);
    }

    #[test]
    fn typed_errors_preserve_operation_source_and_details() {
        let error: anyhow::Error =
            DomainError::validation(ErrorOperation::ParseRequest, "missing field `target`")
                .with_detail("field", "target")
                .into();
        let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::ValidationError);
        assert_eq!(report.operation, ErrorOperation::ParseRequest);
        assert_eq!(report.source, ErrorSource::Validation);
        assert_eq!(report.details["field"], "target");
    }

    #[test]
    fn concrete_io_errors_are_classified_without_message_searching() {
        let error = ensure_domain(
            ErrorOperation::Networks,
            std::io::Error::new(std::io::ErrorKind::TimedOut, "arbitrary").into(),
        );
        let report = ErrorReport::from_error(&error, ErrorOperation::Unknown);
        assert_eq!(report.code, ErrorCode::Timeout);
        assert_eq!(report.source, ErrorSource::Io);
    }

    #[test]
    fn dbus_source_is_only_networkmanager_unavailable_for_networkmanager_operations() {
        let status_error = ensure_domain(
            ErrorOperation::Status,
            zbus::Error::Failure("arbitrary".to_string()).into(),
        );
        let status_report = ErrorReport::from_error(&status_error, ErrorOperation::Unknown);
        assert_eq!(status_report.code, ErrorCode::NetworkmanagerUnavailable);

        let event_error = ensure_domain(
            ErrorOperation::EmitEvent,
            zbus::Error::Failure("NetworkManager D-Bus timeout".to_string()).into(),
        );
        let event_report = ErrorReport::from_error(&event_error, ErrorOperation::Unknown);
        assert_eq!(event_report.code, ErrorCode::InternalError);
        assert_eq!(event_report.source, ErrorSource::Dbus);
    }
}
