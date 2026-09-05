use std::time::{Duration, Instant};

use anyhow::{Context, Result};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline(Instant);

impl Deadline {
    pub(crate) fn from_now(timeout: Duration) -> Result<Self> {
        Instant::now()
            .checked_add(timeout)
            .map(Self)
            .context("timeout is too large to represent as a monotonic deadline")
    }

    pub(crate) fn expired(self) -> bool {
        Instant::now() >= self.0
    }

    pub(crate) fn wait(self, max: Duration) -> Duration {
        max.min(self.0.saturating_duration_since(Instant::now()))
    }
}
