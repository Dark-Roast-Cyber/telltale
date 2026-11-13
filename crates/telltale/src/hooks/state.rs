//! Per-session host state: the journal, the cumulative risk ledger and the
//! decisions awaiting an outcome. One directory per session, serialized by an
//! advisory file lock so concurrent hook processes (parallel tool calls,
//! subagents) append and score in a single order.
//!
//! Trust note: these files are writable by the same OS user as the agent.
//! They are integrity-relevant but not tamper-proof; see docs/threat-model.md.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hooks::journal::Journal;

pub const STATE_VERSION: u32 = 1;
/// Decisions kept for outcome correlation; older ones are dropped.
const MAX_PENDING: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

/// A pre-execution decision remembered until the harness reports what happened.
///
/// Entries are keyed by a **journal ID** that is unique within the session;
/// the harness reports outcomes under `call_id`, which may repeat (a harness
/// without call IDs, a model-supplied ID reused by a nested call). When they
/// differ, the journal ID is the call ID plus the pending line's source time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDecision {
    pub record_id: String,
    /// The policy verdict.
    pub verdict: Verdict,
    /// Whether a verdict was returned to the harness (false in observe mode
    /// and for allow, which expresses no opinion).
    pub returned: bool,
    /// The verdict actually returned when it differs from `verdict`: an `ask`
    /// substituted by `deny` for a harness that cannot ask. Enforcement is
    /// accounted against this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returned_verdict: Option<Verdict>,
    pub action_score: u64,
    pub tool_name: String,
    pub agent_id: Option<String>,
    /// The harness's per-turn identity at decision time (`Context::prompt_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_id: Option<String>,
    pub decided_at: String,
    /// The correlation key the harness reports outcomes under, when it is not
    /// the entry's own key (older state files have no such field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
}

impl PendingDecision {
    /// The verdict the harness was given (the policy verdict unless substituted).
    pub fn effective_verdict(&self) -> Verdict {
        self.returned_verdict.unwrap_or(self.verdict)
    }

    /// The correlation key for an entry stored under `key`.
    pub fn call_id<'a>(&'a self, key: &'a str) -> &'a str {
        self.call_id.as_deref().unwrap_or(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settled {
    pub decision: PendingDecision,
    /// The outcome record a later result would supersede.
    pub outcome_record_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionState {
    pub version: u32,
    /// Last source time written to the journal, in Unix milliseconds.
    pub last_time_ms: i64,
    pub cumulative_score: u64,
    pub scored_actions: u64,
    pub denied_attempts: u32,
    pub asked_attempts: u32,
    /// journal ID -> decision awaiting an outcome.
    pub pending: BTreeMap<String, PendingDecision>,
    /// Insertion order of `pending`, oldest first.
    pub pending_order: Vec<String>,
    /// journal ID -> calls a batch or turn settled without a result.
    /// Provisional: a later result for the same call supersedes the settlement.
    #[serde(default)]
    pub settled: BTreeMap<String, Settled>,
    #[serde(default)]
    pub settled_order: Vec<String>,
    /// agent_id -> agent_type for subagents seen in this session.
    pub agents: BTreeMap<String, String>,
    pub prompts: u64,
}

impl SessionState {
    /// Next strictly increasing source time (ms). Telltale identifies the
    /// pending action by its source time, so no two journal lines share one.
    pub fn next_time_ms(&mut self, now_ms: i64) -> i64 {
        let next = now_ms.max(self.last_time_ms + 1);
        self.last_time_ms = next;
        next
    }

    /// The journal ID for a new pending call: its correlation key plus the
    /// pending line's source time, which is unique per session, so every
    /// journal line and every `tool_use`/`tool_result` link is unique even
    /// when the key repeats, in parallel or in sequence. Collision-proof by
    /// construction (the part after the last `~` is the unique time, so two
    /// IDs are equal only for the same time); the check below also covers a
    /// legacy entry keyed by a raw harness ID.
    ///
    /// The ID is written into journal lines Telltale reads, and a call ID is
    /// harness- or model-supplied, so it is made safe first
    /// ([`crate::hooks::journal::safe_id`]); `PendingDecision::call_id` keeps the raw key.
    pub fn journal_id(&self, call_id: &str, time_ms: i64) -> String {
        let mut id = format!("{}~{time_ms}", crate::hooks::journal::safe_id(call_id));
        while self.pending.contains_key(&id) || self.settled.contains_key(&id) {
            id.push('~');
        }
        id
    }

    pub fn remember(&mut self, journal_id: &str, decision: PendingDecision) {
        if self
            .pending
            .insert(journal_id.to_owned(), decision)
            .is_none()
        {
            self.pending_order.push(journal_id.to_owned());
        }
        while self.pending_order.len() > MAX_PENDING {
            let oldest = self.pending_order.remove(0);
            self.pending.remove(&oldest);
        }
    }

    pub fn settle(&mut self, journal_id: &str, settled: Settled) {
        if self
            .settled
            .insert(journal_id.to_owned(), settled)
            .is_none()
        {
            self.settled_order.push(journal_id.to_owned());
        }
        while self.settled_order.len() > MAX_PENDING {
            let oldest = self.settled_order.remove(0);
            self.settled.remove(&oldest);
        }
    }

    /// The oldest provisionally settled call reported under `call_id` by the
    /// same agent and, when the report carries one, the same turn; with its
    /// journal ID. Narrower than [`take`](Self::take) because a result for a
    /// settled call is the exception, and must not be matched across agents
    /// or turns.
    pub fn take_settled(
        &mut self,
        call_id: &str,
        agent_id: Option<&str>,
        prompt_id: Option<&str>,
    ) -> Option<(String, Settled)> {
        let journal_id = self
            .settled_order
            .iter()
            .find(|key| {
                self.settled.get(*key).is_some_and(|s| {
                    s.decision.call_id(key) == call_id
                        && s.decision.agent_id.as_deref() == agent_id
                        && (prompt_id.is_none() || s.decision.prompt_id.as_deref() == prompt_id)
                })
            })?
            .clone();
        let settled = self.settled.remove(&journal_id)?;
        self.settled_order.retain(|id| id != &journal_id);
        Some((journal_id, settled))
    }

    /// The oldest pending call reported under `call_id` (first in, first
    /// out when a key repeats), with its journal ID.
    pub fn take(&mut self, call_id: &str) -> Option<(String, PendingDecision)> {
        let journal_id = self
            .pending_order
            .iter()
            .find(|key| {
                self.pending
                    .get(*key)
                    .is_some_and(|d| d.call_id(key) == call_id)
            })?
            .clone();
        self.take_entry(&journal_id).map(|d| (journal_id, d))
    }

    /// Remove one pending entry by its journal ID.
    pub fn take_entry(&mut self, journal_id: &str) -> Option<PendingDecision> {
        let decision = self.pending.remove(journal_id)?;
        self.pending_order.retain(|id| id != journal_id);
        Some(decision)
    }
}

/// Exclusive handle on one session's directory. Dropping it releases the lock.
pub struct SessionHandle {
    dir: PathBuf,
    _lock: File,
    pub state: SessionState,
    /// Integrity signals found while opening, as closed telemetry codes. The
    /// files are writable by the agent's OS user. A ledger that does not
    /// parse, a ledger from another state version, or a half-missing session
    /// is recovered from (a fresh ledger; the journal still carries the
    /// history) and reported. Other session-file failures (unreadable or
    /// unwritable files, a directory in place of a file) are not recovered
    /// here: they surface as `StateError` and the runtime applies its
    /// session-file failure policy.
    pub anomalies: Vec<&'static str>,
}

#[derive(Debug)]
pub enum StateError {
    Io(&'static str, std::io::Error),
    Corrupt,
}

impl StateError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io(code, _) => code,
            Self::Corrupt => "state_corrupt",
        }
    }
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(code, error) => write!(f, "{code}: {error}"),
            Self::Corrupt => f.write_str("state_corrupt"),
        }
    }
}

impl std::error::Error for StateError {}

/// Directory name for a session: a hash, so harness-supplied IDs never become paths.
pub fn session_key(harness: &str, session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(harness.as_bytes());
    hasher.update([0]);
    hasher.update(session_id.as_bytes());
    hex::encode(&hasher.finalize()[..16])
}

fn not_regular() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "not a regular file (symlink, FIFO, socket, device or directory)",
    )
}

/// Open a **runtime file** (session files, telemetry, the evaluator's log and
/// markers), refusing anything but a regular file at that very path (or, with
/// `create`, a file this call creates). These live in directories writable by
/// the agent's OS user, who could plant a symlink (redirecting a write
/// elsewhere) or a FIFO (blocking the hook on open or read until the harness
/// gives up and, on Claude Code, runs the call). The entry is checked before
/// the open and the handle after it; on Unix the open itself refuses to
/// follow a symlink or block on a special file, and on Windows it opens a
/// reparse point itself rather than its target, so a symlink or junction is
/// seen for what it is and refused (other reparse points, such as cloud
/// placeholder or deduplicated files, are still regular files).
pub fn open_regular(options: &mut OpenOptions, path: &Path) -> std::io::Result<File> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => return Err(not_regular()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(not_regular());
    }
    Ok(file)
}

/// Open an **operator input** (the configuration file, rule, package and
/// policy files) for reading. The operator chose these paths, and symlinks
/// there are routine (dotfile managers, Nix, MDM), so symlinks and Windows
/// reparse points are followed; what they resolve to must be a regular file,
/// checked on the open handle, and on Unix the open never blocks on a FIFO.
pub fn open_operator_input(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(not_regular());
    }
    Ok(file)
}

/// Read a whole operator input as UTF-8 through [`open_operator_input`].
pub fn read_operator_input(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut text = String::new();
    open_operator_input(path)?.read_to_string(&mut text)?;
    Ok(text)
}

/// Read a whole runtime file through [`open_regular`].
pub fn read_regular(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    open_regular(OpenOptions::new().read(true), path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Create a fresh regular file at `path`, replacing whatever entry was there
/// (a leftover, or a planted symlink or FIFO) without ever writing through it.
pub fn create_fresh(path: &Path) -> std::io::Result<File> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    open_regular(OpenOptions::new().write(true).create_new(true), path)
}

impl SessionHandle {
    pub fn open(state_dir: &Path, harness: &str, session_id: &str) -> Result<Self, StateError> {
        let dir = state_dir
            .join("sessions")
            .join(session_key(harness, session_id));
        create_private_dir(&dir).map_err(|e| StateError::Io("state_dir_create_failed", e))?;
        let lock = open_regular(
            OpenOptions::new().create(true).truncate(false).write(true),
            &dir.join("lock"),
        )
        .map_err(|e| StateError::Io("state_lock_open_failed", e))?;
        lock.lock()
            .map_err(|e| StateError::Io("state_lock_failed", e))?;
        let fresh = || SessionState {
            version: STATE_VERSION,
            ..SessionState::default()
        };
        let mut anomalies = Vec::new();
        let journal_present = std::fs::symlink_metadata(dir.join("journal.jsonl"))
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        let state = match read_regular(&dir.join("state.json")) {
            Ok(bytes) => {
                match serde_json::from_slice::<SessionState>(&bytes) {
                    Ok(state) if state.version == STATE_VERSION => {
                        if !journal_present && state.last_time_ms > 0 {
                            anomalies.push("journal_missing_state_present");
                        }
                        state
                    }
                    // Another state version (an upgrade, not tampering):
                    // keep it aside and start over.
                    Ok(_) => {
                        let _ =
                            std::fs::rename(dir.join("state.json"), dir.join("state.json.stale"));
                        anomalies.push("state_version_reset");
                        fresh()
                    }
                    // Unparseable ledger: keep the evidence, continue from a
                    // fresh ledger (the journal still carries the history)
                    // and report it rather than failing the evaluation.
                    Err(_) => {
                        let _ =
                            std::fs::rename(dir.join("state.json"), dir.join("state.json.corrupt"));
                        anomalies.push("state_corrupt_reset");
                        fresh()
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if journal_present {
                    anomalies.push("state_missing_journal_present");
                }
                fresh()
            }
            Err(error) => return Err(StateError::Io("state_read_failed", error)),
        };
        Ok(Self {
            dir,
            _lock: lock,
            state,
            anomalies,
        })
    }

    pub fn journal(&self) -> Journal {
        Journal::new(self.dir.join("journal.jsonl"))
    }

    /// Stable scan path for this session (written under the lock).
    pub fn window_path(&self) -> PathBuf {
        self.dir.join("window.jsonl")
    }

    /// Atomically replace state.json (write temp, rename).
    pub fn save(&self) -> Result<(), StateError> {
        use std::io::Write;
        let tmp = self.dir.join("state.json.tmp");
        let bytes = serde_json::to_vec(&self.state).map_err(|_| StateError::Corrupt)?;
        create_fresh(&tmp)
            .and_then(|mut file| file.write_all(&bytes))
            .map_err(|e| StateError::Io("state_write_failed", e))?;
        // rename replaces the directory entry; it never follows it.
        std::fs::rename(&tmp, self.dir.join("state.json"))
            .map_err(|e| StateError::Io("state_write_failed", e))
    }
}

pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    // No explicit ACL: the directory inherits its parent's (the default
    // %LOCALAPPDATA% is private to the user). Explicit Windows ACL hardening
    // is a recorded residual risk (docs/threat-model.md).
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_ids_keep_safe_keys_and_encode_the_rest_injectively() {
        let state = SessionState::default();
        assert_eq!(state.journal_id("toolu_01:a%b.c", 7), "toolu_01:a%b.c~7");
        let encoded = state.journal_id("a/b", 7);
        assert!(encoded.starts_with("tth-esc-") && encoded.ends_with("~7"));
        assert_eq!(encoded.len(), "tth-esc-".len() + 32 + 2);
        assert_ne!(state.journal_id("a\\b", 7), encoded);
        for key in ["", "..", "a..b", "a\nb", "a\rb", "a\0b", &"k".repeat(257)] {
            assert!(state.journal_id(key, 1).starts_with("tth-esc-"), "{key:?}");
        }
        assert_eq!(state.journal_id(&"k".repeat(256), 1).len(), 256 + 2);
    }

    fn decision(id: &str) -> PendingDecision {
        PendingDecision {
            record_id: id.into(),
            verdict: Verdict::Allow,
            returned: false,
            action_score: 0,
            tool_name: "Bash".into(),
            agent_id: None,
            decided_at: String::new(),
            returned_verdict: None,
            prompt_id: None,
            call_id: None,
        }
    }

    #[test]
    fn times_strictly_increase() {
        let mut state = SessionState::default();
        assert_eq!(state.next_time_ms(1000), 1000);
        assert_eq!(state.next_time_ms(1000), 1001);
        assert_eq!(state.next_time_ms(900), 1002);
        assert_eq!(state.next_time_ms(5000), 5000);
    }

    #[test]
    fn state_round_trips_under_lock() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut handle = SessionHandle::open(dir.path(), "claude-code", "s1").unwrap();
            handle.state.cumulative_score = 42;
            handle.state.remember("toolu_1", decision("r1"));
            handle.save().unwrap();
        }
        let mut handle = SessionHandle::open(dir.path(), "claude-code", "s1").unwrap();
        assert_eq!(handle.state.cumulative_score, 42);
        assert_eq!(handle.state.take("toolu_1").unwrap().1.record_id, "r1");
        assert!(handle.state.take("toolu_1").is_none());
    }

    /// Older state files keyed entries by the harness call ID and had no
    /// `call_id` field: they still correlate.
    #[test]
    fn entries_without_a_call_id_field_correlate_by_key() {
        let json = serde_json::json!({
            "version": STATE_VERSION, "last_time_ms": 5, "cumulative_score": 0,
            "scored_actions": 0, "denied_attempts": 0, "asked_attempts": 0,
            "pending": {"toolu_old": {"record_id": "r", "verdict": "deny", "returned": true,
                "action_score": 90, "tool_name": "Bash", "agent_id": null, "decided_at": ""}},
            "pending_order": ["toolu_old"], "agents": {}, "prompts": 0
        });
        let mut state: SessionState = serde_json::from_value(json).unwrap();
        let (journal_id, decision) = state.take("toolu_old").unwrap();
        assert_eq!(journal_id, "toolu_old");
        assert_eq!(decision.effective_verdict(), Verdict::Deny);
        assert_eq!(decision.call_id("toolu_old"), "toolu_old");
    }

    /// The same correlation key pending twice (a harness without call IDs, or
    /// a nested call reusing its parent's ID): journal IDs stay unique, in
    /// parallel and in sequence, and outcomes settle first in, first out.
    #[test]
    fn repeated_keys_get_unique_journal_ids_and_settle_fifo() {
        let mut state = SessionState::default();
        let first = state.journal_id("k", 1000);
        assert_eq!(first, "k~1000");
        state.remember(
            &first,
            PendingDecision {
                call_id: Some("k".into()),
                ..decision("r1")
            },
        );
        let second = state.journal_id("k", 1001);
        assert_eq!(second, "k~1001");
        state.remember(
            &second,
            PendingDecision {
                call_id: Some("k".into()),
                ..decision("r2")
            },
        );
        // A harness ID that happens to look like a journal ID cannot collide.
        state.remember("k~1002", decision("legacy"));
        assert_eq!(state.journal_id("k", 1002), "k~1002~");

        let (id, d) = state.take("k").unwrap();
        assert_eq!((id.as_str(), d.record_id.as_str()), ("k~1000", "r1"));
        state.settle(
            &id,
            Settled {
                decision: d,
                outcome_record_id: "o1".into(),
            },
        );
        let (id, d) = state.take("k").unwrap();
        assert_eq!((id.as_str(), d.record_id.as_str()), ("k~1001", "r2"));
        assert!(state.take("k").is_none());
        // Sequential repeats get fresh IDs too.
        assert_eq!(state.journal_id("k", 1003), "k~1003");

        // A settled entry is only matched by the same agent and turn.
        assert!(state.take_settled("k", Some("agent"), None).is_none());
        assert!(state.take_settled("k", None, Some("turn-9")).is_none());
        let (id, settled) = state.take_settled("k", None, None).unwrap();
        assert_eq!(
            (id.as_str(), settled.outcome_record_id.as_str()),
            ("k~1000", "o1")
        );
        assert!(state.take_settled("k", None, None).is_none());
    }

    #[test]
    fn pending_is_bounded() {
        let mut state = SessionState::default();
        for i in 0..(MAX_PENDING + 5) {
            state.remember(&format!("t{i}"), decision("r"));
        }
        assert_eq!(state.pending.len(), MAX_PENDING);
        assert!(!state.pending.contains_key("t0"));
    }

    #[test]
    fn session_key_hides_raw_ids() {
        let key = session_key("claude-code", "../../etc/passwd");
        assert_eq!(key.len(), 32);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
