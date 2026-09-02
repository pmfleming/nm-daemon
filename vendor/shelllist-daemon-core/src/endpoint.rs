use std::sync::atomic::{AtomicU64, Ordering};

/// Identity embedded in every versioned API response and event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiIdentity {
    pub protocol: &'static str,
    pub version: u32,
}

impl ApiIdentity {
    #[must_use]
    pub const fn new(protocol: &'static str, version: u32) -> Self {
        Self { protocol, version }
    }
}

/// Executable and D-Bus identity used by one daemon transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonEndpoint {
    pub executable: &'static str,
    pub bus_name: &'static str,
    pub object_path: &'static str,
    pub interface: &'static str,
}

impl DaemonEndpoint {
    #[must_use]
    pub const fn new(
        executable: &'static str,
        bus_name: &'static str,
        object_path: &'static str,
        interface: &'static str,
    ) -> Self {
        Self {
            executable,
            bus_name,
            object_path,
            interface,
        }
    }
}

/// Process-local monotonic identifier source.
#[derive(Debug)]
pub struct IdSequence {
    next: AtomicU64,
}

impl IdSequence {
    #[must_use]
    pub const fn new(first: u64) -> Self {
        Self {
            next: AtomicU64::new(first),
        }
    }

    #[must_use]
    pub fn next(&self, prefix: &str) -> String {
        format!("{prefix}-{}", self.next.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for IdSequence {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
mod tests {
    use super::IdSequence;

    #[test]
    fn generates_prefixed_monotonic_ids() {
        let ids = IdSequence::default();
        assert_eq!(ids.next("subscription"), "subscription-1");
        assert_eq!(ids.next("request"), "request-2");
    }
}
