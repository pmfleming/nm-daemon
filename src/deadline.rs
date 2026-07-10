use std::thread::sleep;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline(Instant);

impl Deadline {
    pub(crate) fn from_now(timeout: Duration) -> Self {
        Self(Instant::now() + timeout)
    }

    pub(crate) fn min(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

    pub(crate) fn expired(self) -> bool {
        Instant::now() >= self.0
    }

    pub(crate) fn wait(self, max: Duration) -> Duration {
        max.min(self.0.saturating_duration_since(Instant::now()))
    }

    pub(crate) fn sleep(self, max: Duration) {
        sleep(self.wait(max));
    }
}
