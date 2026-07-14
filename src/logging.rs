use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Clone)]
struct SharedFileWriter {
    file: Arc<Mutex<std::fs::File>>,
}

struct LockedFileWriter {
    file: Arc<Mutex<std::fs::File>>,
}

impl<'a> MakeWriter<'a> for SharedFileWriter {
    type Writer = LockedFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LockedFileWriter {
            file: Arc::clone(&self.file),
        }
    }
}

impl Write for LockedFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?
            .flush()
    }
}

pub(crate) fn init(verbose: u8, log_file: Option<PathBuf>) -> Result<PathBuf> {
    let (log_path, use_default_log_path) = resolve_log_path(log_file);
    prepare_log_parent(&log_path, use_default_log_path)?;
    crate::cache::reject_symlink_file(&log_path, "log file")?;
    let file = open_log_file(&log_path)?;
    initialize_subscriber(verbose, file)?;
    tracing::info!(path = %log_path.display(), "logging initialized");
    Ok(log_path)
}

fn resolve_log_path(log_file: Option<PathBuf>) -> (PathBuf, bool) {
    let env_log_file = std::env::var_os("NM_DAEMON_LOG_FILE").map(PathBuf::from);
    let use_default_log_path = log_file.is_none() && env_log_file.is_none();
    let log_path = log_file
        .or(env_log_file)
        .unwrap_or_else(crate::cache::log_path);
    (log_path, use_default_log_path)
}

fn prepare_log_parent(log_path: &Path, use_default_log_path: bool) -> Result<()> {
    if let Some(parent) = log_path.parent() {
        if use_default_log_path {
            crate::cache::create_private_dir_all(parent)?;
        } else {
            create_log_parent(parent)?;
        }
    }
    Ok(())
}

fn open_log_file(log_path: &Path) -> Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(log_path)
        .with_context(|| format!("open log file {}", log_path.display()))?;
    enforce_private_log_permissions(log_path)?;
    Ok(file)
}

fn enforce_private_log_permissions(log_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(log_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", log_path.display()))?;
    }
    Ok(())
}

fn initialize_subscriber(verbose: u8, file: std::fs::File) -> Result<()> {
    let stderr_filter = EnvFilter::try_from_env("NM_DAEMON_STDERR_LOG")
        .unwrap_or_else(|_| EnvFilter::new(stderr_directive(verbose)));
    let file_filter = EnvFilter::try_from_env("NM_DAEMON_LOG")
        .unwrap_or_else(|_| EnvFilter::new(file_directive(verbose)));

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_filter(stderr_filter);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(SharedFileWriter {
            file: Arc::new(Mutex::new(file)),
        })
        .with_ansi(false)
        .with_filter(file_filter);

    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .try_init()
        .context("initialize tracing subscriber")?;
    Ok(())
}

fn create_log_parent(parent: &Path) -> Result<()> {
    if parent.exists() {
        return Ok(());
    }
    crate::cache::create_private_dir_all(parent)
}

fn stderr_directive(verbose: u8) -> &'static str {
    match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    }
}

fn file_directive(verbose: u8) -> &'static str {
    match verbose {
        0 | 1 => "nm_daemon=debug,warn",
        _ => "debug",
    }
}
