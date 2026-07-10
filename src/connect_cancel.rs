use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::deadline::Deadline;
use crate::nm::Nm;

const NMCLI_CONNECT_TIMEOUT_SECS: &str = "90";
const ACTIVATION_POLL_INTERVAL: Duration = Duration::from_millis(500);
const ACTIVATION_SIGNAL_WAIT: Duration = Duration::from_secs(5);

pub(crate) fn cancellation_is_set(cancellation: Option<&AtomicBool>) -> bool {
    cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed))
}

pub(crate) fn check_cancelled(cancellation: Option<&AtomicBool>) -> Result<()> {
    if cancellation_is_set(cancellation) {
        cancelled_error()
    } else {
        Ok(())
    }
}

pub(crate) fn check_cancelled_and_abort(nm: &Nm, cancellation: Option<&AtomicBool>) -> Result<()> {
    if !cancellation_is_set(cancellation) {
        return Ok(());
    }
    abort_activation_best_effort(nm);
    cancelled_error()
}

pub(crate) fn cancelled_error<T>() -> Result<T> {
    anyhow::bail!("connection attempt cancelled")
}

pub(crate) fn abort_activation_best_effort(nm: &Nm) {
    match nm.disconnect_wifi() {
        Ok(result) => {
            tracing::info!(message = %result.message, "aborted Wi-Fi activation after cancellation")
        }
        Err(err) => {
            tracing::warn!(error = %format_args!("{err:#}"), "failed to abort Wi-Fi activation after cancellation")
        }
    }
}

pub(crate) fn wait_for_activation_signal(
    signal_rx: Option<&Receiver<()>>,
    deadline: Deadline,
    cancellation: Option<&AtomicBool>,
) -> Result<()> {
    let wait_until = Instant::now() + deadline.wait(ACTIVATION_SIGNAL_WAIT);
    while Instant::now() < wait_until {
        check_cancelled(cancellation)?;
        let wait = deadline.wait(
            ACTIVATION_POLL_INTERVAL.min(wait_until.saturating_duration_since(Instant::now())),
        );
        let Some(signal_rx) = signal_rx else {
            thread::sleep(wait);
            continue;
        };
        match signal_rx.recv_timeout(wait) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    Ok(())
}

pub(crate) fn nmcli(args: &[&str], cancellation: Option<&AtomicBool>) -> Result<String> {
    tracing::info!(args = ?redact_nmcli_args(args), "running nmcli fallback command");
    check_cancelled(cancellation)?;
    let mut child = Command::new("nmcli")
        .arg("--wait")
        .arg(NMCLI_CONNECT_TIMEOUT_SECS)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("run nmcli")?;

    loop {
        if cancellation_is_set(cancellation) {
            tracing::info!(
                pid = child.id(),
                "killing nmcli fallback after cancellation"
            );
            let _ = child.kill();
            let _ = child.wait();
            return cancelled_error();
        }
        if child.try_wait().context("poll nmcli")?.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let output = child.wait_with_output().context("collect nmcli output")?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        tracing::debug!(status = %output.status, stdout = %stdout, "nmcli command succeeded");
        return Ok(stdout);
    }

    let message = if stderr.is_empty() { stdout } else { stderr };
    tracing::warn!(status = %output.status, message = %message, "nmcli command failed");
    Err(anyhow::anyhow!(
        "nmcli exited with {}: {message}",
        output.status
    ))
}

fn redact_nmcli_args(args: &[&str]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            redacted.push("<redacted>".to_string());
            redact_next = false;
        } else {
            redacted.push((*arg).to_string());
            redact_next = *arg == "password";
        }
    }
    redacted
}
