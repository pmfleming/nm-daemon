use std::{collections::BTreeMap, fs::File, path::PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use shelllist_daemon_core::{AtomicWritePolicy, read_bytes_bounded, write_json_atomic};

use super::{Intent, Mode, invalid};

const FALLBACKS: [&str; 3] = [
    "http://captive.apple.com/hotspot-detect.html",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://nmcheck.gnome.org/check_network_status.txt",
];
const LIMIT: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome {
    Opened,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Reserved,
    Claimed,
    Complete,
}

#[derive(Debug, Deserialize, Serialize)]
struct Launch {
    intent: Intent,
    owner: String,
    phase: Phase,
    outcome: Option<Outcome>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct Episode {
    automatic_attempted: bool,
    fallback_index: usize,
    launch: Option<Launch>,
}

#[derive(Debug, Deserialize, Serialize)]
struct State {
    version: u32,
    episodes: BTreeMap<String, Episode>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            episodes: BTreeMap::new(),
        }
    }
}

pub(crate) struct Ledger {
    path: PathBuf,
    state: State,
    poisoned: bool,
    _lock: File,
}

impl Ledger {
    pub(crate) fn open(path: PathBuf) -> Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
        let parent = path.parent().context("portal ledger parent")?;
        match std::fs::DirBuilder::new().mode(0o700).create(parent) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let metadata = std::fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0,
            "portal ledger directory must be private and owned by this user"
        );
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(parent.join("portal.lock"))?;
        ensure!(
            lock.metadata()?.is_file(),
            "portal lock must be a regular file"
        );
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        let state: State = read_bytes_bounded(&path, 2 * 1024 * 1024)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?
            .unwrap_or_default();
        ensure!(
            state.version == 1 && state.episodes.len() <= LIMIT,
            "unsupported or oversized portal ledger"
        );
        Ok(Self {
            path,
            state,
            poisoned: false,
            _lock: lock,
        })
    }

    fn persist(&mut self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "portal ledger unavailable after a persistence failure"
        );
        if serde_json::to_vec_pretty(&self.state)?.len() > 2 * 1024 * 1024 {
            self.poisoned = true;
            anyhow::bail!("portal ledger byte limit reached for this login session");
        }
        if let Err(error) = write_json_atomic(&self.path, &self.state, AtomicWritePolicy::PRIVATE) {
            // A failed fsync/rename may have committed. Never roll back and replay.
            self.poisoned = true;
            return Err(error.into());
        }
        Ok(())
    }

    pub(crate) fn reserve(
        &mut self,
        mut intent: Intent,
        owner: &str,
        fallback: bool,
        now: u64,
    ) -> Result<Option<Intent>> {
        ensure!(!self.poisoned, "portal ledger unavailable");
        if intent.reason == Mode::Automatic
            && self
                .state
                .episodes
                .get(&intent.episode)
                .is_some_and(|entry| entry.automatic_attempted)
        {
            return Ok(None);
        }
        ensure!(
            !self
                .state
                .episodes
                .values()
                .any(|entry| entry
                    .launch
                    .as_ref()
                    .is_some_and(|launch| launch.phase != Phase::Complete
                        && launch.intent.expires_at_ms > now)),
            "portal launch is busy"
        );
        ensure!(
            self.state.episodes.contains_key(&intent.episode) || self.state.episodes.len() < LIMIT,
            "portal episode limit reached for this login session"
        );
        let entry = self
            .state
            .episodes
            .entry(intent.episode.clone())
            .or_default();
        if fallback {
            intent.url = FALLBACKS[entry.fallback_index % FALLBACKS.len()].into();
            entry.fallback_index = (entry.fallback_index % FALLBACKS.len() + 1) % FALLBACKS.len();
        }
        entry.automatic_attempted |= intent.reason == Mode::Automatic;
        entry.launch = Some(Launch {
            intent: intent.clone(),
            owner: owner.into(),
            phase: Phase::Reserved,
            outcome: None,
        });
        self.persist()?;
        Ok(Some(intent))
    }

    fn launch(&mut self, id: &str, owner: &str) -> Result<&mut Launch> {
        ensure!(!self.poisoned, "portal ledger unavailable");
        self.state
            .episodes
            .values_mut()
            .filter_map(|entry| entry.launch.as_mut())
            .find(|launch| launch.intent.launch_id == id && launch.owner == owner)
            .ok_or_else(|| invalid("unknown portal launch for this caller"))
    }

    pub(crate) fn claim(
        &mut self,
        id: &str,
        owner: &str,
        episode: &str,
        captive: bool,
        now: u64,
    ) -> Result<Intent> {
        let launch = self.launch(id, owner)?;
        ensure!(
            launch.phase == Phase::Reserved && launch.intent.expires_at_ms > now,
            "portal launch already claimed or expired"
        );
        ensure!(
            launch.intent.episode == episode && (launch.intent.reason == Mode::Manual || captive),
            "portal connection changed or resolved"
        );
        launch.phase = Phase::Claimed;
        let intent = launch.intent.clone();
        self.persist()?;
        Ok(intent)
    }

    pub(crate) fn complete(&mut self, id: &str, owner: &str, outcome: Outcome) -> Result<()> {
        let launch = self.launch(id, owner)?;
        ensure!(
            launch.phase == Phase::Claimed
                || (launch.phase == Phase::Complete && launch.outcome == Some(outcome)),
            "portal launch was not claimed or outcome conflicts"
        );
        launch.phase = Phase::Complete;
        launch.outcome = Some(outcome);
        self.persist()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "nm-portal-{}",
                crate::random::random_uuid_v4().unwrap()
            ));
            Self(path)
        }
        fn open(&self) -> Ledger {
            Ledger::open(self.0.join("ledger.json")).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn intent(mode: Mode, episode: &str) -> Intent {
        Intent {
            launch_id: crate::random::random_uuid_v4().unwrap(),
            episode: episode.into(),
            reason: mode,
            url: "http://probe.example/".into(),
            expires_at_ms: 10000,
        }
    }
    #[test]
    fn lost_replies_and_ui_daemon_restarts_do_not_replay_automatic_launches() {
        let fixture = Fixture::new();
        let mut ledger = fixture.open();
        let i = ledger
            .reserve(intent(Mode::Automatic, "a"), "owner", false, 0)
            .unwrap()
            .unwrap();
        assert!(
            ledger
                .reserve(intent(Mode::Automatic, "a"), "other-ui", false, 0)
                .unwrap()
                .is_none()
        );
        ledger.claim(&i.launch_id, "owner", "a", true, 1).unwrap();
        assert!(ledger.claim(&i.launch_id, "owner", "a", true, 1).is_err());
        drop(ledger);
        let mut ledger = fixture.open();
        assert!(
            ledger
                .reserve(intent(Mode::Automatic, "a"), "new-ui", false, 11000)
                .unwrap()
                .is_none()
        );
        assert!(
            ledger
                .reserve(intent(Mode::Manual, "a"), "new-ui", false, 11000)
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn claims_fence_owner_expiry_network_and_resolution() {
        let fixture = Fixture::new();
        let mut ledger = fixture.open();
        let i = ledger
            .reserve(intent(Mode::Automatic, "a"), "owner", false, 0)
            .unwrap()
            .unwrap();
        for (owner, episode, captive, now) in [
            ("other", "a", true, 1),
            ("owner", "b", true, 1),
            ("owner", "a", false, 1),
            ("owner", "a", true, 10000),
        ] {
            assert!(
                ledger
                    .claim(&i.launch_id, owner, episode, captive, now)
                    .is_err()
            );
        }
        assert!(
            ledger
                .complete(&i.launch_id, "owner", Outcome::Opened)
                .is_err()
        );
        ledger.claim(&i.launch_id, "owner", "a", true, 1).unwrap();
        ledger
            .complete(&i.launch_id, "owner", Outcome::Failed)
            .unwrap();
        ledger
            .complete(&i.launch_id, "owner", Outcome::Failed)
            .unwrap();
        assert!(
            ledger
                .complete(&i.launch_id, "owner", Outcome::Opened)
                .is_err()
        );
        assert!(
            ledger
                .reserve(intent(Mode::Automatic, "a"), "owner", false, 2)
                .unwrap()
                .is_none()
        );
        assert!(
            ledger
                .reserve(intent(Mode::Automatic, "b"), "owner", false, 2)
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn overlapping_requests_are_bounded_and_fallback_rotation_is_per_episode() {
        let fixture = Fixture::new();
        let mut ledger = fixture.open();
        for expected in [FALLBACKS[0], FALLBACKS[1], FALLBACKS[2], FALLBACKS[0]] {
            let i = ledger
                .reserve(intent(Mode::Manual, "a"), "owner", true, 0)
                .unwrap()
                .unwrap();
            assert_eq!(i.url, expected);
            assert!(
                ledger
                    .reserve(intent(Mode::Manual, "b"), "other", true, 0)
                    .is_err()
            );
            ledger.claim(&i.launch_id, "owner", "a", false, 1).unwrap();
            ledger
                .complete(&i.launch_id, "owner", Outcome::Uncertain)
                .unwrap();
        }
        assert_eq!(
            ledger
                .reserve(intent(Mode::Manual, "b"), "owner", true, 0)
                .unwrap()
                .unwrap()
                .url,
            FALLBACKS[0]
        );
    }
    #[test]
    fn corrupt_state_and_write_failures_fail_closed() {
        let fixture = Fixture::new();
        let mut ledger = fixture.open();
        std::fs::create_dir(&ledger.path).unwrap();
        assert!(
            ledger
                .reserve(intent(Mode::Automatic, "a"), "owner", false, 0)
                .is_err()
        );
        std::fs::remove_dir(&ledger.path).unwrap();
        assert!(
            ledger
                .reserve(intent(Mode::Automatic, "b"), "owner", false, 11000)
                .is_err()
        );
        drop(ledger);
        std::fs::write(fixture.0.join("ledger.json"), b"broken").unwrap();
        assert!(Ledger::open(fixture.0.join("ledger.json")).is_err());
    }
}
