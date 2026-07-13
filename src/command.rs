pub(crate) mod iw;
pub(crate) mod nmcli;

use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{DomainError, ErrorCode, ErrorOperation, ErrorSource};

const POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(crate) trait CommandRunner: Send + Sync {
    fn run(
        &self,
        request: &CommandRequest,
        cancellation: Option<&AtomicBool>,
    ) -> Result<CommandOutput, CommandFailure>;
}

pub(crate) fn default_runner() -> Arc<dyn CommandRunner> {
    Arc::new(SystemCommandRunner)
}

#[derive(Debug, Default)]
pub(crate) struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(
        &self,
        request: &CommandRequest,
        cancellation: Option<&AtomicBool>,
    ) -> Result<CommandOutput, CommandFailure> {
        tracing::info!(
            program = %request.program.to_string_lossy(),
            args = ?request.redacted_args(),
            timeout_ms = request.timeout.as_millis(),
            "running external command"
        );
        if cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err(CommandFailure::cancelled(request));
        }

        let mut command = Command::new(&request.program);
        command
            .args(request.args.iter().map(|argument| &argument.value))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| CommandFailure::io(request, CommandStage::Spawn, error))?;
        let stdout = output_reader(child.stdout.take(), request, CommandStage::ReadStdout)?;
        let stderr = output_reader(child.stderr.take(), request, CommandStage::ReadStderr)?;
        let started = Instant::now();

        let status = loop {
            if cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                tracing::info!(
                    pid = child.id(),
                    "killing external command after cancellation"
                );
                let _ = child.kill();
                let _ = child.wait();
                let (stdout, stderr) = collect_output(stdout, stderr, request)?;
                return Err(CommandFailure::cancelled_with_output(
                    request, stdout, stderr,
                ));
            }
            if started.elapsed() >= request.timeout {
                tracing::warn!(pid = child.id(), "killing external command after timeout");
                let _ = child.kill();
                let _ = child.wait();
                let (stdout, stderr) = collect_output(stdout, stderr, request)?;
                return Err(CommandFailure::timed_out(request, stdout, stderr));
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(POLL_INTERVAL),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CommandFailure::io(request, CommandStage::Poll, error));
                }
            }
        };

        let (stdout, stderr) = collect_output(stdout, stderr, request)?;
        if !status.success() {
            tracing::warn!(
                program = %request.program.to_string_lossy(),
                exit_code = ?status.code(),
                "external command failed"
            );
            return Err(CommandFailure::exit(request, status.code(), stdout, stderr));
        }
        tracing::debug!(
            program = %request.program.to_string_lossy(),
            exit_code = ?status.code(),
            "external command succeeded"
        );
        Ok(CommandOutput { stdout, stderr })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CommandRequest {
    program: OsString,
    args: Vec<CommandArgument>,
    timeout: Duration,
    operation: ErrorOperation,
}

impl CommandRequest {
    pub(crate) fn new(
        program: impl Into<OsString>,
        operation: ErrorOperation,
        timeout: Duration,
    ) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout,
            operation,
        }
    }

    pub(crate) fn arg(mut self, value: impl Into<OsString>) -> Self {
        self.args.push(CommandArgument {
            value: value.into(),
            sensitive: false,
        });
        self
    }

    pub(crate) fn sensitive_arg(mut self, value: impl Into<OsString>) -> Self {
        self.args.push(CommandArgument {
            value: value.into(),
            sensitive: true,
        });
        self
    }

    pub(crate) fn args<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args
            .extend(values.into_iter().map(|value| CommandArgument {
                value: value.into(),
                sensitive: false,
            }));
        self
    }

    fn redacted_args(&self) -> Vec<String> {
        self.args
            .iter()
            .map(|argument| {
                if argument.sensitive {
                    "<redacted>".to_string()
                } else {
                    argument.value.to_string_lossy().into_owned()
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
struct CommandArgument {
    value: OsString,
    sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandOutput {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandFailureKind {
    Spawn,
    Poll,
    ReadStdout,
    ReadStderr,
    Exit,
    Timeout,
    Cancelled,
}

#[derive(Debug)]
pub(crate) struct CommandFailure {
    program: String,
    operation: ErrorOperation,
    kind: CommandFailureKind,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    message: String,
}

impl CommandFailure {
    pub(crate) fn kind(&self) -> CommandFailureKind {
        self.kind
    }

    pub(crate) fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub(crate) fn into_domain(self) -> DomainError {
        let code = match self.kind {
            CommandFailureKind::Timeout => ErrorCode::Timeout,
            CommandFailureKind::Cancelled => ErrorCode::Cancelled,
            _ => ErrorCode::SubprocessFailed,
        };
        let source = if self.kind == CommandFailureKind::Cancelled {
            ErrorSource::Cancellation
        } else {
            ErrorSource::Subprocess
        };
        self.into_domain_with_code(code, source)
    }

    pub(crate) fn into_domain_with_code(self, code: ErrorCode, source: ErrorSource) -> DomainError {
        DomainError::new(code, self.operation, source, self.message)
            .with_detail("program", self.program)
            .with_detail("stage", self.kind.as_str())
            .with_detail(
                "exit_code",
                self.exit_code
                    .map_or(serde_json::Value::Null, serde_json::Value::from),
            )
            .with_detail("stdout", self.stdout)
            .with_detail("stderr", self.stderr)
    }

    fn io(request: &CommandRequest, stage: CommandStage, error: std::io::Error) -> Self {
        Self {
            program: request.program.to_string_lossy().into_owned(),
            operation: request.operation,
            kind: stage.into(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            message: format!(
                "{} {} failed: {error}",
                stage.as_str(),
                request.program.to_string_lossy()
            ),
        }
    }

    fn exit(
        request: &CommandRequest,
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
    ) -> Self {
        let output = if stderr.is_empty() { &stdout } else { &stderr };
        let message = if output.is_empty() {
            format!(
                "{} exited unsuccessfully with code {:?}",
                request.program.to_string_lossy(),
                exit_code
            )
        } else {
            output.to_string()
        };
        Self {
            program: request.program.to_string_lossy().into_owned(),
            operation: request.operation,
            kind: CommandFailureKind::Exit,
            exit_code,
            stdout,
            stderr,
            message,
        }
    }

    fn timed_out(request: &CommandRequest, stdout: String, stderr: String) -> Self {
        Self {
            program: request.program.to_string_lossy().into_owned(),
            operation: request.operation,
            kind: CommandFailureKind::Timeout,
            exit_code: None,
            stdout,
            stderr,
            message: format!(
                "{} timed out after {} ms",
                request.program.to_string_lossy(),
                request.timeout.as_millis()
            ),
        }
    }

    fn cancelled(request: &CommandRequest) -> Self {
        Self::cancelled_with_output(request, String::new(), String::new())
    }

    fn cancelled_with_output(request: &CommandRequest, stdout: String, stderr: String) -> Self {
        Self {
            program: request.program.to_string_lossy().into_owned(),
            operation: request.operation,
            kind: CommandFailureKind::Cancelled,
            exit_code: None,
            stdout,
            stderr,
            message: format!("{} was cancelled", request.program.to_string_lossy()),
        }
    }
}

impl CommandFailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::Poll => "poll",
            Self::ReadStdout => "read-stdout",
            Self::ReadStderr => "read-stderr",
            Self::Exit => "exit",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }
}

impl fmt::Display for CommandFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CommandFailure {}

#[derive(Debug, Clone, Copy)]
enum CommandStage {
    Spawn,
    Poll,
    ReadStdout,
    ReadStderr,
}

impl CommandStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::Poll => "poll",
            Self::ReadStdout => "read stdout from",
            Self::ReadStderr => "read stderr from",
        }
    }
}

impl From<CommandStage> for CommandFailureKind {
    fn from(stage: CommandStage) -> Self {
        match stage {
            CommandStage::Spawn => Self::Spawn,
            CommandStage::Poll => Self::Poll,
            CommandStage::ReadStdout => Self::ReadStdout,
            CommandStage::ReadStderr => Self::ReadStderr,
        }
    }
}

type OutputReader = thread::JoinHandle<std::io::Result<Vec<u8>>>;

fn output_reader(
    pipe: Option<impl Read + Send + 'static>,
    request: &CommandRequest,
    stage: CommandStage,
) -> Result<OutputReader, CommandFailure> {
    let Some(mut pipe) = pipe else {
        return Err(CommandFailure {
            program: request.program.to_string_lossy().into_owned(),
            operation: request.operation,
            kind: stage.into(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            message: format!("{} pipe was not captured", stage.as_str()),
        });
    };
    Ok(thread::spawn(move || {
        let mut output = Vec::new();
        pipe.read_to_end(&mut output)?;
        Ok(output)
    }))
}

fn collect_output(
    stdout: OutputReader,
    stderr: OutputReader,
    request: &CommandRequest,
) -> Result<(String, String), CommandFailure> {
    let stdout = join_output(stdout, request, CommandStage::ReadStdout)?;
    let stderr = join_output(stderr, request, CommandStage::ReadStderr)?;
    Ok((decode_output(stdout), decode_output(stderr)))
}

fn join_output(
    reader: OutputReader,
    request: &CommandRequest,
    stage: CommandStage,
) -> Result<Vec<u8>, CommandFailure> {
    match reader.join() {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(CommandFailure::io(request, stage, error)),
        Err(_) => Err(CommandFailure {
            program: request.program.to_string_lossy().into_owned(),
            operation: request.operation,
            kind: stage.into(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            message: format!("{} reader thread panicked", stage.as_str()),
        }),
    }
}

fn decode_output(output: Vec<u8>) -> String {
    String::from_utf8_lossy(&output).trim().to_string()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::VecDeque;
    use std::ffi::OsStr;
    use std::sync::Mutex;

    use super::*;

    pub(crate) struct FakeRunner {
        responses: Mutex<VecDeque<Result<CommandOutput, CommandFailure>>>,
        requests: Mutex<Vec<CommandRequest>>,
    }

    impl FakeRunner {
        pub(crate) fn success(stdout: &str) -> Self {
            Self {
                responses: Mutex::new(VecDeque::from([Ok(CommandOutput {
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                })])),
                requests: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn nmcli_failure_then_success(exit_code: i32, stderr: &str) -> Self {
            let request =
                CommandRequest::new("nmcli", ErrorOperation::Connect, Duration::from_secs(90));
            Self {
                responses: Mutex::new(VecDeque::from([
                    Err(CommandFailure::exit(
                        &request,
                        Some(exit_code),
                        String::new(),
                        stderr.to_string(),
                    )),
                    Ok(CommandOutput {
                        stdout: String::new(),
                        stderr: String::new(),
                    }),
                ])),
                requests: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn redacted_args(&self) -> Vec<String> {
            self.requests.lock().unwrap()[0].redacted_args()
        }

        pub(crate) fn all_redacted_args(&self) -> Vec<Vec<String>> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(CommandRequest::redacted_args)
                .collect()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &self,
            request: &CommandRequest,
            _: Option<&AtomicBool>,
        ) -> Result<CommandOutput, CommandFailure> {
            self.requests.lock().unwrap().push(request.clone());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("fake command response")
        }
    }

    #[test]
    fn sensitive_arguments_are_redacted_from_command_metadata() {
        let request = CommandRequest::new(
            OsStr::new("tool"),
            ErrorOperation::RunNmcli,
            Duration::from_secs(1),
        )
        .arg("password")
        .sensitive_arg("secret");

        assert_eq!(request.redacted_args(), ["password", "<redacted>"]);
    }

    #[test]
    fn runner_returns_typed_nonzero_exit_with_captured_output() {
        let request = CommandRequest::new("sh", ErrorOperation::Status, Duration::from_secs(1))
            .args(["-c", "printf stdout; printf stderr >&2; exit 7"]);

        let failure = SystemCommandRunner.run(&request, None).unwrap_err();

        assert_eq!(failure.kind, CommandFailureKind::Exit);
        assert_eq!(failure.exit_code, Some(7));
        assert_eq!(failure.stdout, "stdout");
        assert_eq!(failure.stderr, "stderr");
    }

    #[test]
    fn runner_enforces_deadline_and_pre_spawn_cancellation() {
        let timeout = CommandRequest::new("sh", ErrorOperation::Status, Duration::from_millis(20))
            .args(["-c", "while :; do :; done"]);
        let failure = SystemCommandRunner.run(&timeout, None).unwrap_err();
        assert_eq!(failure.kind, CommandFailureKind::Timeout);

        let cancelled = AtomicBool::new(true);
        let failure = SystemCommandRunner
            .run(&timeout, Some(&cancelled))
            .unwrap_err();
        assert_eq!(failure.kind, CommandFailureKind::Cancelled);
    }
}
