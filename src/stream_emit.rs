use anyhow::Result;

use crate::nm::Nm;
use crate::output::{StreamOutput, emit_stream_event};

pub(crate) fn emit_status(message: impl Into<String>, cache: bool) -> Result<()> {
    emit_message(MessageKind::Status, message, cache)
}

pub(crate) fn emit_warning(message: impl Into<String>, cache: bool) -> Result<()> {
    emit_message(MessageKind::Warning, message, cache)
}

pub(crate) fn emit_snapshot(nm: &Nm, scanning: bool, cache: bool) -> Result<usize> {
    let access_points = nm.list_all_access_points()?;
    let networks_found = access_points.len();
    if cache {
        crate::cache::write_live_scan_snapshot(scanning, &access_points)?;
    }
    let mut networks = nm.network_entries_for_access_points(access_points)?;
    match crate::cache::attach_connection_details(&mut networks)? {
        crate::cache::CacheRead::Available(_) | crate::cache::CacheRead::Missing => {}
        state => tracing::warn!(
            message = %state.unavailable_message("known-connections cache").unwrap_or_default(),
            "connection details are unavailable for scan stream"
        ),
    }
    emit_stream_event(&StreamOutput::Snapshot {
        scanning,
        networks_found,
        networks: &networks,
    })?;
    Ok(networks_found)
}

pub(crate) fn emit_complete(timed_out: bool, networks_found: usize) -> Result<()> {
    emit_stream_event(&StreamOutput::Complete {
        timed_out,
        networks_found,
    })
}

pub(crate) fn emit_empty_device_stream(nm: &Nm, cache: bool) -> Result<()> {
    emit_warning(
        "no Wi-Fi devices found; showing cached NetworkManager results",
        cache,
    )?;
    let networks_found = emit_snapshot(nm, false, cache)?;
    if cache {
        crate::cache::write_complete(false, networks_found)?;
    }
    emit_complete(false, networks_found)
}

fn emit_message(kind: MessageKind, message: impl Into<String>, cache: bool) -> Result<()> {
    let message = message.into();
    if cache {
        crate::cache::write_status(kind.cache_state(), &message)?;
    }
    emit_stream_event(&kind.stream_output(message))
}

#[derive(Clone, Copy)]
enum MessageKind {
    Status,
    Warning,
}

impl MessageKind {
    fn cache_state(self) -> &'static str {
        if matches!(self, MessageKind::Status) {
            "status"
        } else {
            "warning"
        }
    }

    fn stream_output(self, message: String) -> StreamOutput<'static> {
        match self {
            MessageKind::Status => StreamOutput::Status { message },
            MessageKind::Warning => StreamOutput::Warning { message },
        }
    }
}
