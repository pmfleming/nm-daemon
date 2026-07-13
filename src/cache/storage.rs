use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};

use super::CacheRead;

const CACHE_DIR_NAME: &str = "nm-daemon";
const LOCK_FILE_NAME: &str = ".storage.lock";
const HISTORY_MAX_BYTES: u64 = 512 * 1024;
const HISTORY_ROTATIONS: usize = 3;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub(super) struct Repository {
    root: PathBuf,
}

impl Repository {
    pub(super) fn runtime() -> Self {
        Self { root: cache_dir() }
    }

    pub(super) fn state() -> Self {
        Self { root: state_dir() }
    }

    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    pub(super) fn read_json<T>(&self, name: &str) -> Result<CacheRead<T>>
    where
        T: DeserializeOwned,
    {
        read_json_path(&self.path(name))
    }

    pub(super) fn write_json<T>(&self, name: &str, value: &T) -> Result<()>
    where
        T: Serialize + ?Sized,
    {
        self.write_transaction(|repository| repository.write_json(name, value))
    }

    pub(super) fn write_transaction<T>(
        &self,
        operation: impl FnOnce(&LockedRepository<'_>) -> Result<T>,
    ) -> Result<T> {
        create_private_dir_all(&self.root)?;
        let lock = open_lock_file(&self.root.join(LOCK_FILE_NAME))?;
        lock_exclusive(&lock)?;
        operation(&LockedRepository { repository: self })
    }
}

pub(super) struct LockedRepository<'a> {
    repository: &'a Repository,
}

impl LockedRepository<'_> {
    pub(super) fn read_json<T>(&self, name: &str) -> Result<CacheRead<T>>
    where
        T: DeserializeOwned,
    {
        read_json_path(&self.repository.path(name))
    }

    pub(super) fn write_json<T>(&self, name: &str, value: &T) -> Result<()>
    where
        T: Serialize + ?Sized,
    {
        write_json_atomic(&self.repository.path(name), value)
    }

    pub(super) fn remove_if_exists(&self, name: &str) -> Result<()> {
        remove_file_if_exists(&self.repository.path(name))
    }

    pub(super) fn append_history<T>(&self, name: &str, value: &T) -> Result<()>
    where
        T: Serialize + ?Sized,
    {
        append_json_line_with_rotation(
            &self.repository.path(name),
            value,
            HISTORY_MAX_BYTES,
            HISTORY_ROTATIONS,
        )
    }
}

fn read_json_path<T>(path: &Path) -> Result<CacheRead<T>>
where
    T: DeserializeOwned,
{
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(CacheRead::Missing),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    match serde_json::from_str(&text) {
        Ok(value) => Ok(CacheRead::Available(value)),
        Err(error) => Ok(CacheRead::Corrupt {
            message: format!("parse {}: {error}", path.display()),
        }),
    }
}

fn write_json_atomic<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let parent = path.parent().context("cache path has no parent")?;
    create_private_dir_all(parent)?;
    reject_symlink_file(path, "cache file")?;
    let tmp_path = temp_path_for(path)?;
    let text = serde_json::to_string_pretty(value).context("serialize cache JSON")?;
    write_private_file(&tmp_path, format!("{text}\n").as_bytes())
        .with_context(|| format!("write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} to {}", tmp_path.display(), path.display()))?;
    sync_parent(parent)
}

fn append_json_line_with_rotation<T>(
    path: &Path,
    value: &T,
    max_bytes: u64,
    rotations: usize,
) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let parent = path.parent().context("state path has no parent")?;
    create_private_dir_all(parent)?;
    reject_symlink_file(path, "history file")?;
    let mut line = serde_json::to_vec(value).context("serialize JSONL record")?;
    line.push(b'\n');
    let current_bytes = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
    };
    if current_bytes > 0 && current_bytes.saturating_add(line.len() as u64) > max_bytes {
        rotate_files(path, rotations)?;
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    file.write_all(&line)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_data()
        .with_context(|| format!("sync {}", path.display()))?;
    set_private_file_permissions(path)
}

fn rotate_files(path: &Path, rotations: usize) -> Result<()> {
    if rotations == 0 {
        return remove_file_if_exists(path);
    }
    remove_file_if_exists(&rotated_path(path, rotations))?;
    for index in (1..rotations).rev() {
        rename_if_exists(&rotated_path(path, index), &rotated_path(path, index + 1))?;
    }
    rename_if_exists(path, &rotated_path(path, 1))?;
    sync_parent(path.parent().context("history path has no parent")?)
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn rename_if_exists(from: &Path, to: &Path) -> Result<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("rename {} to {}", from.display(), to.display()))
        }
    }
}

fn open_lock_file(path: &Path) -> Result<File> {
    reject_symlink_file(path, "storage lock")?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open storage lock {}", path.display()))?;
    set_private_file_permissions(path)?;
    Ok(file)
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::LockExclusive)
        .context("lock cache repository")
}

#[cfg(not(unix))]
fn lock_exclusive(_: &File) -> Result<()> {
    Ok(())
}

fn temp_path_for(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().context("cache path has no parent")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("cache path has no file name")?;
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        counter
    )))
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))?;
    set_private_file_permissions(path)
}

fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)
        .with_context(|| format!("open directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", parent.display()))
}

pub(crate) fn create_private_dir_all(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        create_private_dir_all_unix(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))
    }
}

#[cfg(unix)]
fn create_private_dir_all_unix(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    match fs::symlink_metadata(path) {
        Ok(link_metadata) => {
            if link_metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing to use symlinked cache directory {}",
                    path.display()
                );
            }
            let metadata =
                fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
            if !metadata.is_dir() {
                anyhow::bail!("{} exists but is not a directory", path.display());
            }
            let current_uid = current_euid();
            if metadata.uid() != current_uid {
                anyhow::bail!(
                    "refusing to use {} owned by uid {}; expected uid {}",
                    path.display(),
                    metadata.uid(),
                    current_uid
                );
            }
            if metadata.mode() & 0o077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("chmod 0700 {}", path.display()))?;
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("lstat {}", path.display()));
        }
    }

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))
}

#[cfg(unix)]
fn current_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub(crate) fn reject_symlink_file(path: &Path, file_kind: &str) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("lstat {}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symlinked {file_kind} {}", path.display());
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_: &Path) -> Result<()> {
    Ok(())
}

pub(crate) fn log_path() -> PathBuf {
    cache_dir().join("nm-daemon.log")
}

fn cache_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(runtime_dir) => PathBuf::from(runtime_dir).join(CACHE_DIR_NAME),
        None => std::env::temp_dir().join(format!("{CACHE_DIR_NAME}-{}", current_user_id())),
    }
}

fn state_dir() -> PathBuf {
    if let Some(state_home) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(state_home).join(CACHE_DIR_NAME);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join(CACHE_DIR_NAME);
    }
    cache_dir()
}

fn current_user_id() -> u32 {
    #[cfg(unix)]
    {
        current_euid()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::json;

    use super::{Repository, append_json_line_with_rotation, temp_path_for};
    use crate::cache::CacheRead;

    #[test]
    fn temp_paths_are_unique_for_same_cache_path() {
        let path = PathBuf::from("/tmp/nm-daemon/status.json");
        let first = temp_path_for(&path).unwrap();
        let second = temp_path_for(&path).unwrap();
        assert_ne!(first, second);
        assert_eq!(first.parent(), path.parent());
        assert_eq!(second.parent(), path.parent());
    }

    #[test]
    fn read_distinguishes_missing_corrupt_and_available() {
        let directory = TestDirectory::new("read-states");
        let repository = Repository {
            root: directory.path.clone(),
        };
        assert!(matches!(
            repository
                .read_json::<serde_json::Value>("value.json")
                .unwrap(),
            CacheRead::Missing
        ));
        fs::create_dir_all(&directory.path).unwrap();
        fs::write(repository.path("value.json"), "not json").unwrap();
        assert!(matches!(
            repository
                .read_json::<serde_json::Value>("value.json")
                .unwrap(),
            CacheRead::Corrupt { .. }
        ));
        fs::write(repository.path("value.json"), "{\"ok\":true}").unwrap();
        assert!(matches!(
            repository
                .read_json::<serde_json::Value>("value.json")
                .unwrap(),
            CacheRead::Available(_)
        ));
    }

    #[test]
    fn history_rotates_before_exceeding_limit() {
        let directory = TestDirectory::new("history-rotation");
        fs::create_dir_all(&directory.path).unwrap();
        let path = directory.path.join("connects.jsonl");
        append_json_line_with_rotation(&path, &json!({"n": 1}), 20, 2).unwrap();
        append_json_line_with_rotation(&path, &json!({"n": 2, "padding": "xxxxxxxx"}), 20, 2)
            .unwrap();
        assert!(path.exists());
        assert!(PathBuf::from(format!("{}.1", path.display())).exists());
    }

    #[test]
    fn transactions_serialize_read_modify_write_across_threads() {
        let directory = TestDirectory::new("concurrent-writers");
        let repository = Repository {
            root: directory.path.clone(),
        };
        repository.write_json("counter.json", &0_u64).unwrap();

        let readers = (0..4)
            .map(|_| {
                let repository = repository.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        assert!(matches!(
                            repository.read_json::<u64>("counter.json").unwrap(),
                            CacheRead::Available(_)
                        ));
                    }
                })
            })
            .collect::<Vec<_>>();

        let writers = (0..8)
            .map(|_| {
                let repository = repository.clone();
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        repository
                            .write_transaction(|locked| {
                                let CacheRead::Available(counter) =
                                    locked.read_json::<u64>("counter.json")?
                                else {
                                    panic!("counter cache unavailable");
                                };
                                locked.write_json("counter.json", &(counter + 1))
                            })
                            .unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().unwrap();
        }
        for reader in readers {
            reader.join().unwrap();
        }

        let CacheRead::Available(counter) = repository.read_json::<u64>("counter.json").unwrap()
        else {
            panic!("counter cache unavailable");
        };
        assert_eq!(counter, 200_u64);
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            Self {
                path: std::env::temp_dir().join(format!(
                    "nm-daemon-{label}-{}-{}",
                    std::process::id(),
                    super::TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                )),
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
