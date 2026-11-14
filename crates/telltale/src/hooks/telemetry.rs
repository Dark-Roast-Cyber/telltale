//! Host telemetry: one JSONL envelope per hook observation.
//!
//! Telltale's contract is that hosts forward its versioned records inside a
//! host-owned envelope and do not design their own action format
//! (docs/embedding.md "Host wire and durable handoff"). This envelope adds
//! only what Telltale does not model: harness/hook identity, subagent
//! relationships, the host verdict, and whether the harness honored it.
//! Detection content travels as unmodified `ActionRecordV1` values.
//! Schema: schemas/telltale-hooks-record-v1.schema.json.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ActionRecordV1;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::hooks::state::{create_private_dir, open_regular};

pub const RECORD_SCHEMA: &str = "telltale_hooks.record.v1";

/// `producer.name` in every record; the producer is the hooks runtime inside
/// the Telltale executable, under the name existing consumers match on.
pub const PRODUCER_NAME: &str = "telltale-hooks";

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
    /// "daemon" (long-lived evaluator) or "in_process".
    pub evaluator: &'static str,
    /// Why an in-process evaluation did not use the evaluator, if it tried.
    pub evaluator_fallback: Option<&'static str>,
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
    /// Telltale action records anchored at this observation, unmodified,
    /// each with its Telltale delivery key.
    pub telltale: Vec<TelltaleAction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TelltaleAction {
    pub delivery_key: String,
    pub record: ActionRecordV1,
}

impl TelltaleAction {
    pub fn from_record(record: ActionRecordV1) -> Self {
        Self {
            delivery_key: record.delivery_key(),
            record,
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
}

impl Sink {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record as a single write. Errors are returned so the caller
    /// can apply its failure policy; telemetry loss is never silent.
    pub fn write(&self, record: &Record) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            create_private_dir(parent)?;
        }
        let mut line = serde_json::to_vec(record).map_err(std::io::Error::other)?;
        line.push(b'\n');
        // Regular files only: a FIFO or symlink planted at the telemetry
        // path must neither stall the hook nor receive the records.
        let mut file = open_regular(OpenOptions::new().create(true).append(true), &self.path)?;
        file.write_all(&line)
    }
}
