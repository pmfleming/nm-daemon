use std::time::Duration;

use crate::application::{Application, BackgroundScanScheduler, ScanRequest};
use crate::nm::Nm;

/// Direct-mode cache refresher. The daemon uses its bounded runtime instead;
/// direct CLI mode completes the refresh in-process before exiting.
pub(crate) struct InlineBackgroundScan<'a> {
    nm: &'a Nm,
}

impl<'a> InlineBackgroundScan<'a> {
    pub(crate) fn new(nm: &'a Nm) -> Self {
        Self { nm }
    }
}

impl BackgroundScanScheduler for InlineBackgroundScan<'_> {
    fn schedule_scan(&self, timeout: Duration) {
        if let Err(error) = Application::new(self.nm).scan(
            ScanRequest {
                timeout,
                strict: false,
                cache: true,
                ifname: None,
                ssids: Vec::new(),
            },
            None,
            |_| Ok(()),
        ) {
            tracing::warn!(error = %crate::error::err_chain(&error), "direct-mode cache refresh failed");
        }
    }
}
