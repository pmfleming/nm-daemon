use anyhow::Result;
use std::sync::atomic::AtomicBool;

use crate::application::Application;
use crate::error::{DomainError, best_effort, cancellation_requested};
use crate::model::WifiConnectTarget;
use crate::nm::Nm;

pub(crate) fn check_cancelled(cancellation: Option<&AtomicBool>) -> Result<()> {
    if cancellation_requested(cancellation) {
        cancelled_error()
    } else {
        Ok(())
    }
}

pub(crate) fn check_cancelled_and_abort(
    nm: &Nm,
    target: &WifiConnectTarget,
    cancellation: Option<&AtomicBool>,
) -> Result<()> {
    if !cancellation_requested(cancellation) {
        return Ok(());
    }
    abort_activation(nm, target);
    cancelled_error()
}

pub(crate) fn cancelled_error<T>() -> Result<T> {
    Err(DomainError::cancelled("connection attempt cancelled").into())
}

pub(crate) fn abort_activation(nm: &Nm, target: &WifiConnectTarget) {
    if let Some(result) = best_effort(
        "failed to abort Wi-Fi activation after cancellation",
        || Application::new(nm).disconnect_wifi_for_ssid(target.ssid_bytes()),
    ) {
        if result.status == "disconnected" {
            tracing::info!(ssid = %target.ssid, message = %result.message, "aborted Wi-Fi activation after cancellation");
        } else {
            tracing::info!(ssid = %target.ssid, message = %result.message, "skipped activation abort after cancelled target stopped matching");
        }
    }
}
