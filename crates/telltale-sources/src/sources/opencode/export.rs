//! Opt-in local investigation primitive for OpenCode 1.18.25 native exports.
//!
//! Returned canonical records are INTERNAL data, not a public transcript. Consumers
//! must use `telltale_detect::timeline::build_exported_session_timeline` before
//! exposing a result. No production parser, scanner or Event3 producer uses this API.
//! OpenCode under mandatory `--pure` is trusted harness code. Only its direct child
//! is managed; this is not a sandbox or process-tree containment boundary.

mod process;

use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use telltale_schema::canonical::{
    ConversationMessage, NormalizedRecordV1, Provenance, RecordMeta, ToolCallRecord,
    ToolResultRecord,
};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::{
    Event3Activity, Event3Family, Event3Record, evidence_hash, path_hash, redact_sensitive_text,
    terminal_identifier, terminal_session_id,
};
use telltale_schema::source::Source;

/// Independent, finite per-command limits. Larger-than-default limits are rejected.
#[derive(Debug, Clone)]
pub struct ExportLimits {
    pub candidates: usize,
    pub list_bytes: usize,
    pub export_bytes: usize,
    pub stderr_bytes: usize,
    pub deadline: Duration,
    pub json_depth: usize,
    pub records: usize,
}
impl Default for ExportLimits {
    fn default() -> Self {
        Self {
            candidates: 256,
            list_bytes: 1024 * 1024,
            export_bytes: 8 * 1024 * 1024,
            stderr_bytes: 64 * 1024,
            deadline: Duration::from_secs(10),
            json_depth: 64,
            records: 8192,
        }
    }
}

/// None resolves exactly `opencode` through PATH. No scanning or installation.
/// On Windows an explicit path must name an `.exe`, never a batch script.
#[derive(Clone, Default)]
pub struct ExportConfig {
    pub executable: Option<PathBuf>,
    pub limits: ExportLimits,
}

/// Payload-free errors; native stderr and OS/JSON diagnostics never escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExportError {
    InvalidLimits,
    SourceMismatch,
    SourceUnavailable,
    SessionUnavailable,
    AmbiguousSession,
    InvalidSessionId,
    InvalidExecutable,
    Spawn,
    Capture,
    Timeout,
    StdoutLimit,
    StderrLimit,
    NonzeroExit,
    JsonDepth,
    MalformedListing,
    CandidateLimit,
    MalformedExport,
    RecordLimit,
    IdentityMismatch,
}
impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "opencode export: {self:?}")
    }
}
impl std::error::Error for ExportError {}

/// Export an Event3-correlated session from a source supplied by local discovery.
/// The caller supplies the discovered Source, not an arbitrary executable target
/// or alternate database. OpenCode's trusted local store selection must correspond
/// to that discovery context. Telltale never opens the database or sidecars.
pub fn export_session(
    event: &Event3Record,
    source: &Source,
    config: &ExportConfig,
) -> Result<Vec<NormalizedRecordV1>, ExportError> {
    let hash = match event.family() {
        Event3Family::Detection(v) => Some(v.source_path_hash.as_str()),
        Event3Family::Activity(Event3Activity::Standard(v)) => Some(v.source_path_hash.as_str()),
        Event3Family::SessionRiskSummary(v) => v.source_path_hash.as_deref(),
        Event3Family::ProcessChain(v) => Some(v.source_path_hash.as_str()),
        _ => None,
    };
    if event.common().client != "opencode"
        || source.client != ClientId::OpenCode
        || source.kind != SourceKind::Sqlite
        || source.source_id != "opencode.sqlite"
        || hash != Some(path_hash(&source.path).as_str())
    {
        return Err(ExportError::SourceMismatch);
    }
    if !source.path.is_file() {
        return Err(ExportError::SourceUnavailable);
    }
    validate_limits(&config.limits)?;
    let terminal = &event.common().session_id;
    let raw = if safe_session_id(terminal) && terminal_session_id(terminal) == *terminal {
        terminal.clone()
    } else {
        let bytes = run(config, None)?;
        resolve_listing(&bytes, terminal, &config.limits)?
    };
    let bytes = run(config, Some(&raw))?;
    parse_export(&bytes, &raw, hash.expect("validated hash"), &config.limits)
}

fn validate_limits(v: &ExportLimits) -> Result<(), ExportError> {
    let d = ExportLimits::default();
    if [
        (v.candidates, d.candidates),
        (v.list_bytes, d.list_bytes),
        (v.export_bytes, d.export_bytes),
        (v.stderr_bytes, d.stderr_bytes),
        (v.json_depth, d.json_depth),
        (v.records, d.records),
    ]
    .iter()
    .any(|(v, max)| *v == 0 || v > max)
        || v.deadline.is_zero()
        || v.deadline > d.deadline
    {
        return Err(ExportError::InvalidLimits);
    }
    Ok(())
}

fn safe_session_id(v: &str) -> bool {
    v.starts_with("ses_")
        && v.len() > 4
        && v.len() <= 128
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn run(config: &ExportConfig, session: Option<&str>) -> Result<Vec<u8>, ExportError> {
    // Rust may implicitly use cmd.exe for batch files even with direct argv.
    #[cfg(windows)]
    if config.executable.as_ref().is_some_and(|path| {
        !path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
    }) {
        return Err(ExportError::InvalidExecutable);
    }
    let mut command = Command::new(
        config
            .executable
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new("opencode")),
    );
    command.arg("--pure");
    let cap = if let Some(id) = session {
        if !safe_session_id(id) {
            return Err(ExportError::InvalidSessionId);
        }
        command.args(["export", id, "--sanitize"]);
        config.limits.export_bytes
    } else {
        command
            .args(["session", "list", "--format", "json", "--max-count"])
            .arg(config.limits.candidates.to_string());
        config.limits.list_bytes
    };
    process::capture(
        &mut command,
        cap,
        config.limits.stderr_bytes,
        config.limits.deadline,
    )
}

// serde's ignored fields still need a lexical depth bound before deserialization.
fn check_json(bytes: &[u8], cap: usize, depth_cap: usize) -> Result<(), ExportError> {
    if bytes.len() > cap {
        return Err(ExportError::StdoutLimit);
    }
    let (mut depth, mut string, mut escape) = (0usize, false, false);
    for &b in bytes {
        if string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                string = false;
            }
        } else {
            match b {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > depth_cap {
                        return Err(ExportError::JsonDepth);
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct Listed {
    id: String,
}
fn resolve_listing(
    bytes: &[u8],
    terminal: &str,
    limits: &ExportLimits,
) -> Result<String, ExportError> {
    check_json(bytes, limits.list_bytes, limits.json_depth)?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(ExportError::SessionUnavailable);
    }
    let entries: Vec<Listed> =
        serde_json::from_slice(bytes).map_err(|_| ExportError::MalformedListing)?;
    if entries.len() > limits.candidates {
        return Err(ExportError::CandidateLimit);
    }
    let mut found = None;
    for entry in entries {
        if !safe_session_id(&entry.id) {
            return Err(ExportError::InvalidSessionId);
        }
        if terminal_session_id(&entry.id) == terminal {
            if found.is_some() {
                return Err(ExportError::AmbiguousSession);
            }
            found = Some(entry.id);
        }
    }
    found.ok_or(ExportError::SessionUnavailable)
}

#[derive(Deserialize)]
struct Export {
    info: SessionInfo,
    messages: Vec<Message>,
}
#[derive(Deserialize)]
struct SessionInfo {
    id: String,
}
#[derive(Deserialize)]
struct Message {
    info: MessageInfo,
    parts: Vec<Part>,
}
#[derive(Deserialize)]
struct MessageInfo {
    id: String,
    #[serde(rename = "sessionID")]
    session_id: String,
    role: String,
    time: MessageTime,
}
#[derive(Deserialize)]
struct MessageTime {
    created: u64,
}
#[derive(Deserialize)]
#[serde(tag = "type")]
enum Part {
    #[serde(rename = "text")]
    Text {
        #[serde(flatten)]
        ids: PartIds,
        text: String,
    },
    #[serde(rename = "tool")]
    Tool {
        #[serde(flatten)]
        ids: PartIds,
        #[serde(rename = "callID")]
        call_id: String,
        tool: String,
        state: ToolState,
    },
    #[serde(other)]
    Unknown,
}
#[derive(Deserialize)]
struct PartIds {
    id: String,
    #[serde(rename = "messageID")]
    message_id: String,
    #[serde(rename = "sessionID")]
    session_id: String,
}
#[derive(Deserialize)]
#[serde(tag = "status")]
enum ToolState {
    #[serde(rename = "pending")]
    Pending { input: BTreeMap<String, Value> },
    #[serde(rename = "running")]
    Running {
        input: BTreeMap<String, Value>,
        time: StartTime,
    },
    #[serde(rename = "completed")]
    Completed {
        input: BTreeMap<String, Value>,
        output: String,
        time: EndTime,
    },
    #[serde(rename = "error")]
    Error {
        input: BTreeMap<String, Value>,
        error: String,
        time: EndTime,
    },
}
#[derive(Deserialize)]
struct StartTime {
    start: u64,
}
#[derive(Deserialize)]
struct EndTime {
    start: u64,
    end: u64,
}

fn timestamp(millis: u64) -> Result<String, ExportError> {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .ok()
        .and_then(|v| {
            v.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .ok_or(ExportError::MalformedExport)
}

// Native --sanitize is not a privacy contract for arbitrary text (notably errors).
// Investigation retains sanitized-summary identity, not another public transcript.
fn summary(kind: &str, text: &str) -> String {
    format!(
        "[redacted:opencode-export:{kind}:{}]",
        evidence_hash(&redact_sensitive_text(text))
    )
}

fn parse_export(
    bytes: &[u8],
    session: &str,
    hash: &str,
    limits: &ExportLimits,
) -> Result<Vec<NormalizedRecordV1>, ExportError> {
    check_json(bytes, limits.export_bytes, limits.json_depth)?;
    let export: Export = serde_json::from_slice(bytes).map_err(|_| ExportError::MalformedExport)?;
    if export.info.id != session {
        return Err(ExportError::IdentityMismatch);
    }
    let mut records = Vec::new();
    let mut messages = BTreeSet::new();
    let mut parts = BTreeSet::new();
    let mut calls = BTreeSet::new();
    for message in export.messages {
        if message.info.session_id != session
            || message.info.id.is_empty()
            || message.info.id.len() > 256
            || !messages.insert(message.info.id.clone())
        {
            return Err(ExportError::IdentityMismatch);
        }
        if !matches!(message.info.role.as_str(), "user" | "assistant") {
            return Err(ExportError::MalformedExport);
        }
        let message_time = timestamp(message.info.time.created)?;
        for part in message.parts {
            let needed = match &part {
                Part::Tool {
                    state: ToolState::Completed { .. } | ToolState::Error { .. },
                    ..
                } => 2,
                Part::Unknown => 0,
                _ => 1,
            };
            if needed > limits.records.saturating_sub(records.len()) {
                return Err(ExportError::RecordLimit);
            }
            let ids = match &part {
                Part::Text { ids, .. } | Part::Tool { ids, .. } => ids,
                Part::Unknown => continue,
            };
            if ids.id.is_empty()
                || ids.id.len() > 256
                || ids.message_id != message.info.id
                || ids.session_id != session
                || !parts.insert(ids.id.clone())
            {
                return Err(ExportError::IdentityMismatch);
            }
            let mut meta = RecordMeta {
                session_id: session.into(),
                client: "opencode".into(),
                agent: None,
                model: None,
                provider: None,
                timestamp: Some(message_time.clone()),
                provenance: Provenance {
                    source_path_hash: hash.into(),
                    source_event_id: Some(ids.id.clone()),
                    offset: None,
                },
                extensions: BTreeMap::from([(
                    "source_adapter".into(),
                    Value::String("opencode.native-export.v1".into()),
                )]),
            };
            match part {
                Part::Text { text, .. } => {
                    let msg = ConversationMessage {
                        meta,
                        content: summary("text", &text),
                        content_parts: None,
                    };
                    records.push(if message.info.role == "user" {
                        NormalizedRecordV1::UserMessage(msg)
                    } else {
                        NormalizedRecordV1::AssistantMessage(msg)
                    });
                }
                Part::Tool {
                    call_id,
                    tool,
                    state,
                    ..
                } => {
                    if message.info.role != "assistant"
                        || call_id.is_empty()
                        || call_id.len() > 256
                        || !calls.insert(call_id.clone())
                        || tool.is_empty()
                    {
                        return Err(ExportError::IdentityMismatch);
                    }
                    let (input, start, result) = match state {
                        ToolState::Pending { input } => (input, None, None),
                        ToolState::Running { input, time } => (input, Some(time.start), None),
                        ToolState::Completed {
                            input,
                            output,
                            time,
                        } => (input, Some(time.start), Some((output, false, time.end))),
                        ToolState::Error { input, error, time } => {
                            (input, Some(time.start), Some((error, true, time.end)))
                        }
                    };
                    if let Some(start) = start {
                        meta.timestamp = Some(timestamp(start)?);
                    }
                    let arguments = serde_json::json!({"redacted": summary("arguments", &serde_json::to_string(&input).map_err(|_| ExportError::MalformedExport)?)});
                    let arguments_string = arguments.to_string();
                    let tool = terminal_identifier("tool", &redact_sensitive_text(&tool));
                    records.push(NormalizedRecordV1::ToolCall(ToolCallRecord {
                        meta: meta.clone(),
                        tool_name: tool.clone(),
                        arguments: Some(arguments),
                        arguments_string: Some(arguments_string),
                        call_id: Some(call_id.clone()),
                    }));
                    if let Some((output, is_error, end)) = result {
                        if start.is_some_and(|v| end < v) {
                            return Err(ExportError::MalformedExport);
                        }
                        meta.timestamp = Some(timestamp(end)?);
                        let output = summary("tool-result", &output);
                        records.push(NormalizedRecordV1::ToolResult(ToolResultRecord {
                            meta,
                            tool_name: Some(tool),
                            result: Some(Value::String(output.clone())),
                            result_string: Some(output),
                            call_id: Some(call_id),
                            is_error: Some(is_error),
                        }));
                    }
                }
                Part::Unknown => unreachable!(),
            }
        }
    }
    if records.is_empty() {
        Err(ExportError::SessionUnavailable)
    } else {
        Ok(records)
    }
}
