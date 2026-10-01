//! NetworkManager error mapping and sizing around the shared blocking lane.
use crate::error::{DomainError, ErrorOperation};
use anyhow::Result;
use shelllist_daemon_tokio::LaneError;

pub(super) struct BlockingLane {
    lane: shelllist_daemon_tokio::BlockingLane,
    name: &'static str,
}

impl BlockingLane {
    pub(super) fn start(
        runtime: &tokio::runtime::Handle,
        name: &'static str,
        capacity: usize,
        concurrency: usize,
    ) -> Self {
        Self {
            lane: shelllist_daemon_tokio::BlockingLane::start(runtime, name, capacity, concurrency),
            name,
        }
    }

    fn error(&self, operation: ErrorOperation, error: LaneError) -> anyhow::Error {
        let message = match error {
            LaneError::Full => "daemon work queue is full",
            LaneError::Closed => "daemon runtime has stopped",
            LaneError::Panicked => "daemon blocking job panicked",
        };
        DomainError::internal(operation, message)
            .with_detail("queue", self.name)
            .into()
    }

    pub(super) fn try_submit(
        &self,
        operation: ErrorOperation,
        job: Box<dyn FnOnce() + Send + 'static>,
    ) -> Result<()> {
        self.lane
            .try_submit(job)
            .map_err(|error| self.error(operation, error))
    }

    pub(super) fn call<T: Send + 'static>(
        &self,
        operation: ErrorOperation,
        task: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.lane
            .call(task)
            .map_err(|error| self.error(operation, error))?
    }

    pub(super) async fn shutdown(&self) {
        self.lane.shutdown(super::RUNTIME_SHUTDOWN_TIMEOUT).await;
    }
}

#[cfg(test)]
mod tests {
    use super::BlockingLane;
    use crate::error::{ErrorOperation, ErrorReport};
    #[tokio::test]
    async fn lane_failures_keep_networkmanager_error_context() {
        let lane = BlockingLane::start(&tokio::runtime::Handle::current(), "test-lane", 1, 1);
        lane.shutdown().await;
        let error = lane
            .try_submit(ErrorOperation::Status, Box::new(|| {}))
            .unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&error, ErrorOperation::Status).details["queue"],
            "test-lane"
        );
    }
}
