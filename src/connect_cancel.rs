use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::DomainError;
use crate::nm::Nm;

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
    Err(DomainError::cancelled("connection attempt cancelled").into())
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
