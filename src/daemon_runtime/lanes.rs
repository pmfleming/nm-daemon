//! Bounded blocking execution, independent of NetworkManager and task registries.
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use anyhow::Result;
use tokio::sync::{Notify, Semaphore, mpsc as tokio_mpsc, watch};

use super::{RUNTIME_SHUTDOWN_TIMEOUT, recover_lock, runtime_stopped, tokio_queue_error};
use crate::error::ErrorOperation;

type Job = Box<dyn FnOnce() + Send + 'static>;

pub(super) struct BlockingLane {
    sender: tokio_mpsc::Sender<Job>,
    name: &'static str,
    shutdown: watch::Sender<bool>,
    dispatcher: Mutex<Option<tokio::task::JoinHandle<()>>>,
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

impl BlockingLane {
    pub(super) fn start(
        tokio: &tokio::runtime::Handle,
        name: &'static str,
        capacity: usize,
        concurrency: usize,
    ) -> Self {
        let (sender, receiver) = tokio_mpsc::channel(capacity);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let active = Arc::new(AtomicUsize::new(0));
        let idle = Arc::new(Notify::new());
        let dispatcher = tokio.spawn(run_blocking_lane(
            name,
            concurrency,
            receiver,
            shutdown_rx,
            Arc::clone(&active),
            Arc::clone(&idle),
        ));
        Self {
            sender,
            name,
            shutdown,
            dispatcher: Mutex::new(Some(dispatcher)),
            active,
            idle,
        }
    }

    pub(super) fn try_submit(&self, operation: ErrorOperation, job: Job) -> Result<()> {
        self.sender
            .try_send(job)
            .map_err(|error| tokio_queue_error(operation, self.name, error))
    }

    pub(super) fn call<T: Send + 'static>(
        &self,
        operation: ErrorOperation,
        task: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.try_submit(
            operation,
            Box::new(move || {
                let _ = reply_tx.send(task());
            }),
        )?;
        reply_rx.recv().map_err(|_| runtime_stopped(operation))?
    }

    pub(super) async fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        let dispatcher = recover_lock(&self.dispatcher, "blocking lane dispatcher").take();
        if let Some(dispatcher) = dispatcher
            && tokio::time::timeout(RUNTIME_SHUTDOWN_TIMEOUT, dispatcher)
                .await
                .is_err()
        {
            tracing::warn!(
                lane = self.name,
                "blocking lane dispatcher did not stop in time"
            );
        }
        if tokio::time::timeout(RUNTIME_SHUTDOWN_TIMEOUT, self.wait_until_idle())
            .await
            .is_err()
        {
            tracing::warn!(
                lane = self.name,
                active = self.active.load(Ordering::Acquire),
                "blocking lane jobs did not stop in time"
            );
        }
    }

    async fn wait_until_idle(&self) {
        loop {
            let notified = self.idle.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

async fn run_blocking_lane(
    name: &'static str,
    concurrency: usize,
    mut receiver: tokio_mpsc::Receiver<Job>,
    mut shutdown: watch::Receiver<bool>,
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
) {
    let permits = Arc::new(Semaphore::new(concurrency));
    loop {
        let permit = tokio::select! {
            _ = shutdown.changed() => return,
            permit = Arc::clone(&permits).acquire_owned() => {
                let Ok(permit) = permit else { return; };
                permit
            }
        };
        let job = tokio::select! {
            _ = shutdown.changed() => return,
            job = receiver.recv() => {
                let Some(job) = job else { return; };
                job
            }
        };
        let active = Arc::clone(&active);
        let idle = Arc::clone(&idle);
        active.fetch_add(1, Ordering::AcqRel);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if catch_unwind(AssertUnwindSafe(job)).is_err() {
                tracing::error!(
                    lane = name,
                    "daemon blocking job panicked; lane remains available"
                );
            }
            active.fetch_sub(1, Ordering::AcqRel);
            idle.notify_waiters();
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::BlockingLane;
    use crate::error::{ErrorOperation, ErrorReport};

    #[test]
    fn lanes_bound_admission_contain_panics_and_reject_after_shutdown() -> anyhow::Result<()> {
        let runtime = tokio::runtime::Runtime::new()?;
        let lane = BlockingLane::start(runtime.handle(), "test-lane", 1, 1);
        let operation = ErrorOperation::Status;
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        lane.try_submit(
            operation,
            Box::new(move || {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            }),
        )?;
        started_rx.recv_timeout(Duration::from_secs(5))?;
        let (queued_tx, queued_rx) = mpsc::sync_channel(1);
        lane.try_submit(
            operation,
            Box::new(move || {
                queued_tx.send(()).unwrap();
            }),
        )?;
        let error = lane
            .try_submit(operation, Box::new(|| panic!("must not be admitted")))
            .unwrap_err();
        assert_eq!(
            ErrorReport::from_error(&error, operation).details["queue"],
            "test-lane"
        );
        release_tx.send(())?;
        queued_rx.recv_timeout(Duration::from_secs(5))?;
        assert!(
            lane.call::<()>(operation, || panic!("injected job panic"))
                .is_err()
        );
        assert_eq!(lane.call(operation, || Ok(42))?, 42);
        runtime.block_on(lane.shutdown());
        assert!(
            lane.try_submit(operation, Box::new(|| panic!("closed lane")))
                .is_err()
        );
        Ok(())
    }
}
