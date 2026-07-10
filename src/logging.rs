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
    let env_log_file = std::env::var_os("NM_DAEMON_LOG_FILE")
        .or_else(|| std::env::var_os("NM_API_LOG_FILE"))
        .map(PathBuf::from);
    let use_default_log_path = log_file.is_none() && env_log_file.is_none();
    let log_path = log_file
        .or(env_log_file)
        .unwrap_or_else(crate::cache::log_path);
    if let Some(parent) = log_path.parent() {
        if use_default_log_path {
            crate::cache::create_private_dir_all(parent)?;
        } else {
            create_log_parent(parent)?;
        }
    }
    reject_symlink(&log_path)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&log_path)
        .with_context(|| format!("open log file {}", log_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", log_path.display()))?;
    }

    let stderr_filter = EnvFilter::try_from_env("NM_DAEMON_STDERR_LOG")
        .or_else(|_| EnvFilter::try_from_env("NM_API_STDERR_LOG"))
        .unwrap_or_else(|_| EnvFilter::new(stderr_directive(verbose)));
    let file_filter = EnvFilter::try_from_env("NM_DAEMON_LOG")
        .or_else(|_| EnvFilter::try_from_env("NM_API_LOG"))
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

    tracing::info!(path = %log_path.display(), "logging initialized");
    Ok(log_path)
}

fn reject_symlink(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("lstat {}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symlinked log file {}", path.display());
    }
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
