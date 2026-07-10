use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::deadline::Deadline;
use crate::model::{ScanEvent, ScanStreamOptions, WifiDevice, retry_delay};
use crate::nm::{Nm, POLL_INTERVAL};
use crate::stream_emit::{
    emit_complete, emit_empty_device_stream, emit_snapshot, emit_status, emit_warning,
};

impl Nm {
    pub(crate) fn scan_stream(&self, options: ScanStreamOptions) -> Result<()> {
        tracing::info!(
            timeout_secs = options.timeout.as_secs(),
            retries = options.retries,
            cache = options.cache,
            "starting streaming Wi-Fi scan"
        );
        let deadline = Deadline::from_now(options.timeout);
        let devices = wait_for_stream_devices(self, &options, deadline)?;
        if devices.is_empty() {
            return emit_empty_device_stream(self, options.cache);
        }

        let rx = crate::stream_watch::spawn_device_watchers(self.connection(), &devices);
        emit_status("preparing scan watchers", options.cache)?;
        emit_snapshot(self, true, options.cache)?;
        drain_watcher_startup(
            &rx,
            devices.len() * crate::stream_watch::watcher_count_per_device(),
            options.cache,
            deadline,
        )?;

        ScanSession::new(self, rx, devices, options, deadline).run()
    }
}

fn wait_for_stream_devices(
    nm: &Nm,
    options: &ScanStreamOptions,
    deadline: Deadline,
) -> Result<Vec<WifiDevice>> {
    loop {
        let devices = nm
            .wifi_devices()?
            .into_iter()
            .filter(|device| {
                options
                    .ifname
                    .as_deref()
                    .is_none_or(|ifname| device.iface == ifname)
            })
            .collect::<Vec<_>>();
        if !devices.is_empty() || deadline.expired() {
            return Ok(devices);
        }
        emit_status("waiting for NetworkManager Wi-Fi device", options.cache)?;
        deadline.sleep(POLL_INTERVAL);
    }
}

struct DeviceScanState {
    device: WifiDevice,
    before: i64,
    completed: bool,
    attempts: u32,
    next_retry: Option<Instant>,
    request_succeeded: bool,
    request_failed: bool,
}

struct ScanSession<'a> {
    nm: &'a Nm,
    rx: Receiver<ScanEvent>,
    states: Vec<DeviceScanState>,
    options: ScanStreamOptions,
    deadline: Deadline,
    last_status: Instant,
    networks_found: usize,
    timed_out: bool,
}

impl<'a> ScanSession<'a> {
    fn new(
        nm: &'a Nm,
        rx: Receiver<ScanEvent>,
        devices: Vec<WifiDevice>,
        options: ScanStreamOptions,
        deadline: Deadline,
    ) -> Self {
        Self {
            nm,
            rx,
            states: devices
                .into_iter()
                .map(|device| DeviceScanState {
                    before: nm.last_scan(&device),
                    device,
                    completed: false,
                    attempts: 0,
                    next_retry: Some(Instant::now()),
                    request_succeeded: false,
                    request_failed: false,
                })
                .collect(),
            options,
            deadline,
            last_status: Instant::now(),
            networks_found: 0,
            timed_out: false,
        }
    }

    fn run(mut self) -> Result<()> {
        while self.states.iter().any(|state| !state.completed) {
            if self.stop_on_deadline()? {
                break;
            }
            self.retry_due_scan_requests()?;
            if self.recv_and_handle_event()? {
                break;
            }
            self.emit_periodic_status()?;
        }
        self.finish()
    }

    fn stop_on_deadline(&mut self) -> Result<bool> {
        if !self.deadline.expired() {
            return Ok(false);
        }
        self.timed_out = true;
        emit_warning(
            format!(
                "scan timed out after {}s; showing latest NetworkManager results",
                self.options.timeout.as_secs()
            ),
            self.options.cache,
        )?;
        Ok(true)
    }

    fn retry_due_scan_requests(&mut self) -> Result<()> {
        let max_attempts = self.options.retries.saturating_add(1);
        let now = Instant::now();
        for index in 0..self.states.len() {
            if retry_is_due(&self.states[index], now, max_attempts) {
                self.try_request_scan(index, now, max_attempts)?;
            }
        }
        Ok(())
    }

    fn try_request_scan(&mut self, index: usize, now: Instant, max_attempts: u32) -> Result<()> {
        self.states[index].attempts += 1;
        match self
            .nm
            .request_scan_for_ssids(&self.states[index].device, &self.options.ssid_bytes)
        {
            Ok(()) => self.note_scan_requested(index, max_attempts),
            Err(err) => self.note_scan_request_failed(index, now, max_attempts, err),
        }
    }

    fn note_scan_requested(&mut self, index: usize, max_attempts: u32) -> Result<()> {
        let state = &mut self.states[index];
        state.next_retry = None;
        state.request_succeeded = true;
        emit_status(
            format!(
                "requested scan on {} (attempt {}/{max_attempts}, {} target SSIDs)",
                state.device.iface,
                state.attempts,
                self.options.ssid_bytes.len()
            ),
            self.options.cache,
        )
    }

    fn note_scan_request_failed(
        &mut self,
        index: usize,
        now: Instant,
        max_attempts: u32,
        err: anyhow::Error,
    ) -> Result<()> {
        let state = &mut self.states[index];
        if state.attempts < max_attempts {
            let delay = retry_delay(state.attempts);
            state.next_retry = Some(now + delay);
            return emit_warning(
                format!(
                    "scan request on {} failed: {err:#}; retrying in {}s",
                    state.device.iface,
                    delay.as_secs()
                ),
                self.options.cache,
            );
        }
        state.next_retry = None;
        state.completed = true;
        state.request_failed = true;
        emit_warning(
            format!(
                "scan request on {} failed after {max_attempts} attempts: {err:#}; continuing with cached results",
                state.device.iface
            ),
            self.options.cache,
        )
    }

    fn recv_and_handle_event(&mut self) -> Result<bool> {
        match self.rx.recv_timeout(self.remaining_wait()) {
            Ok(event) => self.handle_event(event).map(|_| false),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.refresh_snapshot()?;
                Ok(false)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                emit_warning("D-Bus watcher channel disconnected", self.options.cache)?;
                Ok(true)
            }
        }
    }

    fn remaining_wait(&self) -> Duration {
        self.deadline.wait(POLL_INTERVAL)
    }

    fn handle_event(&mut self, event: ScanEvent) -> Result<()> {
        match event {
            ScanEvent::WatcherReady => Ok(()),
            ScanEvent::WatcherWarning(message) => emit_warning(message, self.options.cache),
            ScanEvent::AccessPointsChanged => self.refresh_snapshot(),
            ScanEvent::LastScanChanged { device_path, value } => {
                self.mark_completed_device(&device_path, value);
                self.refresh_snapshot()
            }
        }
    }

    fn mark_completed_device(&mut self, device_path: &str, value: i64) {
        for state in &mut self.states {
            if last_scan_matches(state, device_path, value) {
                state.completed = true;
            }
        }
    }

    fn refresh_snapshot(&mut self) -> Result<()> {
        self.networks_found = emit_snapshot(self.nm, true, self.options.cache)?;
        Ok(())
    }

    fn emit_periodic_status(&mut self) -> Result<()> {
        if self.last_status.elapsed() < Duration::from_secs(1) {
            return Ok(());
        }
        let pending = self.states.iter().filter(|state| !state.completed).count();
        emit_status(
            format!(
                "scanning; {} networks found; {pending} devices pending",
                self.networks_found
            ),
            self.options.cache,
        )?;
        self.last_status = Instant::now();
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        self.networks_found = emit_snapshot(self.nm, false, self.options.cache)?;
        if self.options.cache {
            if let Some(message) = self.final_scan_warning() {
                crate::cache::write_status("warning", message)?;
            } else {
                crate::cache::write_complete(self.timed_out, self.networks_found)?;
            }
        }
        tracing::info!(
            timed_out = self.timed_out,
            networks_found = self.networks_found,
            "streaming Wi-Fi scan finished"
        );
        emit_complete(self.timed_out, self.networks_found)
    }

    fn final_scan_warning(&self) -> Option<String> {
        if self.timed_out {
            return None;
        }
        let failed = self
            .states
            .iter()
            .filter(|state| state.request_failed)
            .count();
        if failed == 0 {
            return None;
        }
        let succeeded = self
            .states
            .iter()
            .filter(|state| state.request_succeeded)
            .count();
        if succeeded == 0 {
            return Some(format!(
                "scan request failed on all devices; showing cached results ({} networks available)",
                self.networks_found
            ));
        }
        Some(format!(
            "scan finished with {failed} device scan request failure(s); {} networks available",
            self.networks_found
        ))
    }
}

fn drain_watcher_startup(
    rx: &Receiver<ScanEvent>,
    expected_ready: usize,
    cache: bool,
    scan_deadline: Deadline,
) -> Result<()> {
    let deadline = Deadline::from_now(Duration::from_secs(1)).min(scan_deadline);
    let mut ready = 0;
    while ready < expected_ready && !deadline.expired() {
        ready += drain_one_startup_event(rx, deadline, cache)?;
    }
    warn_if_watchers_missing(ready, expected_ready, cache)
}

fn drain_one_startup_event(
    rx: &Receiver<ScanEvent>,
    deadline: Deadline,
    cache: bool,
) -> Result<usize> {
    match rx.recv_timeout(deadline.wait(POLL_INTERVAL)) {
        Ok(ScanEvent::WatcherReady) => Ok(1),
        Ok(ScanEvent::WatcherWarning(message)) => {
            emit_warning(message, cache)?;
            Ok(0)
        }
        Ok(_) | Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {
            Ok(0)
        }
    }
}

fn warn_if_watchers_missing(ready: usize, expected_ready: usize, cache: bool) -> Result<()> {
    if ready >= expected_ready {
        return Ok(());
    }
    emit_warning(
        format!("only {ready}/{expected_ready} D-Bus scan watchers became ready before scan start"),
        cache,
    )
}

fn retry_is_due(state: &DeviceScanState, now: Instant, max_attempts: u32) -> bool {
    !state.completed
        && state.attempts < max_attempts
        && state.next_retry.is_some_and(|next_retry| now >= next_retry)
}

fn last_scan_matches(state: &DeviceScanState, device_path: &str, value: i64) -> bool {
    state.device.path.as_str() == device_path && value != state.before && value >= 0
}
