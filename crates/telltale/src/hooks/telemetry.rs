//! Host telemetry: one JSONL envelope per hook observation.
//!
//! Telltale's contract is that hosts forward its versioned records inside a
//! host-owned envelope and do not design their own action format
//! (docs/embedding.md "Host wire and durable handoff"). This envelope adds
//! only what Telltale does not model: harness/hook identity, subagent
//! relationships, the host verdict, and whether the harness honored it.
//! Detection content travels as unmodified `ActionRecordV1` values.
//! Schema: schemas/telltale-hooks-record-v1.schema.json.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::ActionRecordV1;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use telltale_schema::event::SanitizationContext;
use telltale_schema::hooks_record::{HOOKS_RECORD_MAX_INPUT_BYTES, readable_hook_label};
pub use telltale_sources::journal::RotationConfig;
use telltale_sources::journal::{self, JournalGeneration};

use crate::hooks::journal::escaped;
use crate::hooks::state::{create_private_dir, lock_within, open_regular};

/// Read-only bounded framing shared with the Hooks record feed, for local
/// diagnostics. This does not open an archive or acquire the writer lock.
#[doc(hidden)]
pub fn visit_active_suffix(
    file: &mut telltale_sources::journal::JournalFile,
    max_bytes: u64,
    visit: impl FnMut(Result<crate::HooksRecordV1, &'static str>),
) -> io::Result<bool> {
    crate::hooks_record_feed::visit_active_suffix(file, max_bytes, visit)
}

pub const RECORD_SCHEMA: &str = "telltale_hooks.record.v1";

/// `producer.name` in every record; the producer is the hooks runtime inside
/// the Telltale executable, under the name existing consumers match on.
pub const PRODUCER_NAME: &str = "telltale-hooks";

/// Keep a readable telemetry label, or replace the whole raw value with a
/// deterministic stand-in so its occurrences still link across records.
#[doc(hidden)]
pub fn label(value: &str, context: SanitizationContext) -> String {
    if readable_hook_label(value, context) {
        value.to_owned()
    } else {
        escaped(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A pre-execution verdict for a requested tool call.
    Decision,
    /// What the harness reported happened to a tool call.
    Outcome,
    /// Post-execution detection over a tool result.
    ResultFinding,
    /// Session, prompt, subagent and permission-prompt lifecycle.
    Lifecycle,
    /// The hook could not do its job; `on_error` applied.
    Error,
}

impl Kind {
    /// The name the record carries in `kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::Outcome => "outcome",
            Self::ResultFinding => "result_finding",
            Self::Lifecycle => "lifecycle",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Producer {
    pub name: &'static str,
    pub version: &'static str,
    /// Digest naming the Telltale build, see [`crate::hooks::identity::revision`].
    pub telltale_rev: &'static str,
    /// Telltale effective semantic identity, when an engine was built.
    pub semantic_identity: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Harness {
    pub name: &'static str,
    pub hook_event: String,
    pub permission_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub session_id: String,
    /// Present for calls made inside a subagent.
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub prompt_id: Option<String>,
    /// SHA-256 of the harness working directory (never the raw path).
    pub cwd_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Action {
    pub tool_use_id: Option<String>,
    pub tool_name: Option<String>,
    /// SHA-256 of the canonical JSON tool input (raw input is never logged).
    pub input_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvaluationInfo {
    pub status: &'static str,
    pub coverage: Option<&'static str>,
    pub visibility_limits: Vec<String>,
    pub failure_code: Option<String>,
    pub window_records: usize,
    /// Older session history existed outside the evaluated window.
    pub window_truncated: bool,
    pub build_ms: Option<u64>,
    pub scan_ms: Option<u64>,
    /// How long the call waited for its session's lock, over every time it
    /// took it: time spent behind the session's other calls, not scanning.
    pub lock_wait_ms: Option<u64>,
    /// "daemon" (long-lived evaluator) or "in_process".
    pub evaluator: &'static str,
    /// Why an in-process evaluation did not use the evaluator, if it tried.
    pub evaluator_fallback: Option<&'static str>,
    /// What the scans of a tool call did (requests only): counts, closed
    /// values and milliseconds, no content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scans: Option<crate::hooks::engine::ScanTrace>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionInfo {
    pub mode: &'static str,
    pub verdict: &'static str,
    /// The verdict was sent to the harness. `allow` is never sent: the hook
    /// expresses no opinion so the harness's own permission rules still apply.
    pub returned: bool,
    /// Present only when what was returned differs from `verdict`: an `ask`
    /// returned as `deny` because the harness cannot put an ask to a human.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned_verdict: Option<&'static str>,
    pub basis: &'static str,
    pub action_score: u64,
    pub session_score_before: u64,
    pub session_score_after: u64,
    pub denied_attempts_before: u32,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    /// Present only when a grant covered the call: nothing was returned,
    /// and the session's score was left as it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<GrantInfo>,
}

/// The grant that covered a call (`decision.grant`).
#[derive(Debug, Clone, Serialize)]
pub struct GrantInfo {
    /// `once` or `session`, or `project` or `user` for a grant in
    /// `grants.d`.
    pub scope: &'static str,
    /// The record ID of the `grant` lifecycle record that made a `once` or
    /// `session` grant; the grant ID of a `project` or `user` grant.
    pub granted_by: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutcomeInfo {
    /// executed | failed | interrupted | not_executed | unknown
    pub result: &'static str,
    /// Harness event that established the result.
    pub established_by: String,
    pub decision_record_id: Option<String>,
    pub prior_verdict: Option<&'static str>,
    pub prior_returned: Option<bool>,
    /// Present only when the decision returned a different verdict than
    /// `prior_verdict` (ask substituted by deny); `enforcement` is accounted
    /// against it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_returned_verdict: Option<&'static str>,
    /// honored | violated | declined | proceeded_after_ask | not_returned |
    /// no_decision | unknown, accounted against the verdict that was returned.
    pub enforcement: &'static str,
    pub duration_ms: Option<u64>,
    /// An earlier outcome for the same call that this one corrects (a batch
    /// settled the call as not executed, then a result arrived).
    pub supersedes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub schema: &'static str,
    pub record_id: String,
    pub recorded_at: String,
    pub kind: Kind,
    pub producer: Producer,
    pub harness: Harness,
    pub session: Session,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<EvaluationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<OutcomeInfo>,
    /// Lifecycle details (event-specific, content-free).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<Value>,
    /// Content-free error code for `Kind::Error` and degraded records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// On `error` records of a call that tried to take its session's lock:
    /// how long it waited, up to giving up (`state_lock_timeout`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_wait_ms: Option<u64>,
    /// Telltale action records anchored at this observation, unmodified,
    /// each with its Telltale delivery key.
    pub telltale: Vec<TelltaleAction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TelltaleAction {
    pub delivery_key: String,
    pub record: ActionRecordV1,
    /// Where an `exfil.outbound_upload` action sends, beside the frozen
    /// action record; absent for any other action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destinations: Option<crate::DestinationFacts>,
}

impl TelltaleAction {
    pub fn new(record: ActionRecordV1, destinations: Option<crate::DestinationFacts>) -> Self {
        Self {
            delivery_key: record.delivery_key(),
            record,
            destinations,
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Unique per record: time, process and a process-local counter, hashed.
pub fn new_record_id() -> String {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let digest = sha256_hex(format!("{nanos}:{}:{n}", std::process::id()).as_bytes());
    format!("tth:{}", &digest[..32])
}

pub struct Sink {
    path: PathBuf,
    rotation: RotationConfig,
    #[cfg(test)]
    max_line_bytes: usize,
}

/// A holder appends only one line. A hook must not wait on telemetry, so a
/// stalled writer cannot hold up other hook invocations.
const TELEMETRY_LOCK_WAIT: Duration = Duration::from_millis(200);

impl Sink {
    pub fn new(path: PathBuf) -> Self {
        Self::with_rotation(path, RotationConfig::default())
    }

    pub fn with_rotation(path: PathBuf, rotation: RotationConfig) -> Self {
        Self {
            path,
            rotation,
            #[cfg(test)]
            max_line_bytes: HOOKS_RECORD_MAX_INPUT_BYTES,
        }
    }

    #[cfg(test)]
    pub(super) fn with_line_limit(self, max_line_bytes: usize) -> Self {
        Self {
            max_line_bytes,
            ..self
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one complete record. Rotation and cleanup failures are reported
    /// separately from the result of the append.
    pub fn write(&self, record: &Record) -> io::Result<()> {
        #[cfg(not(test))]
        let limit = HOOKS_RECORD_MAX_INPUT_BYTES;
        #[cfg(test)]
        let limit = self.max_line_bytes;
        let mut line = Vec::new();
        encode(record, limit, &mut line)?;
        if let Some(parent) = self.path.parent() {
            create_private_dir(parent)?;
        }
        // Even a disabled writer must coordinate with a writer still using
        // enabled settings. The sidecar's name never changes during rotation.
        let lock = open_regular(
            OpenOptions::new().create(true).truncate(false).write(true),
            &lock_path(&self.path),
        )
        .ok()
        .filter(|file| lock_within(file, TELEMETRY_LOCK_WAIT).is_ok());
        // Regular files only: a FIFO or symlink planted at the telemetry
        // path must neither stall the hook nor receive the records.
        let mut active = self.open_active()?;
        let torn = ends_mid_line(&mut active);
        if lock.is_some() && self.rotation.is_enabled() {
            match self.prepare_rotation(&active, line.len() + usize::from(torn)) {
                Ok(Some((mut fresh, archives))) => {
                    let torn = ends_mid_line(&mut fresh);
                    return append_and_prune(&mut fresh, &frame(line, torn), archives);
                }
                Ok(None) => {}
                Err(error) => eprintln!("telltale hooks: telemetry rotation failed: {error}"),
            }
        }
        active.write_all(&frame(line, torn))
    }

    fn prepare_rotation(
        &self,
        active: &File,
        line_bytes: usize,
    ) -> io::Result<Option<(File, Vec<PathBuf>)>> {
        let size = active.metadata()?.len();
        if size == 0 || size.saturating_add(line_bytes as u64) <= self.rotation.max_size_bytes {
            return Ok(None);
        }
        let archives = self.rotate()?;
        Ok(Some((self.open_active()?, archives)))
    }

    fn open_active(&self) -> io::Result<File> {
        let file = open_regular(
            OpenOptions::new().create(true).read(true).append(true),
            &self.path,
        )?;
        journal::validate_file(&file)?;
        Ok(file)
    }

    /// Return archives to prune after the record is appended. A failed
    /// rotation before rename leaves the open active file available.
    fn rotate(&self) -> io::Result<Vec<PathBuf>> {
        let (stem, extension) = journal::rotation_components(&self.path)?;
        let discovery =
            journal::discover_generations(&self.path, journal::DEFAULT_MAX_DIRECTORY_ENTRIES)?;
        if discovery.directory_bound_reached {
            return Err(io::Error::other("journal directory entry limit reached"));
        }
        let archived: Vec<_> = discovery
            .generations
            .into_iter()
            .filter(|file| !file.is_active)
            .collect();
        let today = time::OffsetDateTime::now_utc().date().to_string();
        let (date, counter) = next_rotation(&archived, &stem, &extension, &today)?;
        let rotated = journal::rotated_path(&self.path, &date, counter)?;
        journal::rename_no_replace(&self.path, &rotated)?;
        let remove = (archived.len() + 1).saturating_sub(self.rotation.keep);
        Ok(archived
            .into_iter()
            .map(|file| file.path)
            .chain([rotated])
            .take(remove)
            .collect())
    }

    /// Check the exact wire size before an operation that will emit the record.
    #[doc(hidden)]
    pub fn check_record_size(record: &Record) -> io::Result<()> {
        encode(record, HOOKS_RECORD_MAX_INPUT_BYTES, io::sink())
    }
}

/// Whether the file ends in an unterminated line: an earlier append that
/// failed part way. Read through the handle the record will be appended to.
/// A file whose end cannot be read is appended to as it is; the check must
/// not cost a record.
fn ends_mid_line(active: &mut File) -> bool {
    let mut last = [0];
    let read = active.metadata().and_then(|metadata| {
        let Some(offset) = metadata.len().checked_sub(1) else {
            return Ok(false);
        };
        active.seek(SeekFrom::Start(offset))?;
        active.read_exact(&mut last)?;
        Ok(last != *b"\n")
    });
    read.unwrap_or(false)
}

/// The bytes of one append. After a torn line, a leading LF ends that line so
/// it is rejected alone and this record is read. The LF belongs to the torn
/// line: the record keeps its own size bound.
fn frame(mut line: Vec<u8>, torn: bool) -> Vec<u8> {
    if torn {
        line.insert(0, b'\n');
    }
    line
}

fn append_and_prune(active: &mut File, line: &[u8], archives: Vec<PathBuf>) -> io::Result<()> {
    active.write_all(line)?;
    for path in archives {
        if let Err(error) = fs::remove_file(path) {
            eprintln!("telltale hooks: telemetry cleanup failed: {error}");
        }
    }
    Ok(())
}

fn next_rotation(
    archived: &[JournalGeneration],
    stem: &str,
    extension: &str,
    today: &str,
) -> io::Result<(String, usize)> {
    if let Some((date, counter)) = archived.last().and_then(|file| {
        journal::parse_rotated_name(file.path.file_name()?.to_str()?, stem, extension)
    }) && date.as_str() >= today
    {
        return Ok((
            date,
            counter
                .checked_add(1)
                .ok_or_else(|| io::Error::other("rotation counter exhausted"))?,
        ));
    }
    Ok((today.to_owned(), 0))
}

#[cfg(test)]
mod rotation_tests {
    use super::*;

    #[test]
    fn failed_cleanup_reports_successful_append_and_keeps_pruning() {
        let directory = tempfile::tempdir().unwrap();
        let active = directory.path().join("records.jsonl");
        let unremovable = directory.path().join("records-2026-11-25.jsonl");
        let removable = directory.path().join("records-2026-11-26.jsonl");
        // Discovery had already planned cleanup. An archive can change
        // before removal; the reader's safe discovery must still reject it.
        fs::create_dir(&unremovable).unwrap();
        fs::write(&removable, b"synthetic archive\n").unwrap();
        let mut file = Sink::new(active.clone()).open_active().unwrap();
        let line = b"{\"synthetic\":true}\n";
        let result = append_and_prune(
            &mut file,
            line,
            vec![unremovable.clone(), removable.clone()],
        );
        assert_eq!(fs::read(active).unwrap(), line);
        assert!(unremovable.is_dir());
        assert!(!removable.exists());
        result.unwrap();
    }
}

fn lock_path(active: &Path) -> PathBuf {
    let mut name = active.as_os_str().to_owned();
    name.push(".lock");
    name.into()
}

fn encode(record: &Record, max_line_bytes: usize, output: impl Write) -> io::Result<()> {
    let mut line = BoundedLine {
        output,
        remaining: max_line_bytes,
        oversized: false,
    };
    serde_json::to_writer(&mut line, record).map_err(|error| {
        if line.oversized {
            io::Error::other(RecordTooLarge)
        } else {
            io::Error::other(error)
        }
    })?;
    line.write_all(b"\n")
}

#[derive(Debug)]
struct RecordTooLarge;

impl fmt::Display for RecordTooLarge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("record exceeds the Hooks telemetry line limit")
    }
}

impl std::error::Error for RecordTooLarge {}

/// Whether the sink refused a record before opening or writing the file.
#[doc(hidden)]
pub fn is_record_too_large(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<RecordTooLarge>())
}

struct BoundedLine<W> {
    output: W,
    remaining: usize,
    oversized: bool,
}

impl<W: Write> Write for BoundedLine<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(remaining) = self.remaining.checked_sub(bytes.len()) else {
            self.oversized = true;
            return Err(io::Error::other(RecordTooLarge));
        };
        self.output.write_all(bytes)?;
        self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
