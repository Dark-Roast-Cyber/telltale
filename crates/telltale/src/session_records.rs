//! Bounded, read-only session record reader over one [`Source`].
//!
//! Records come in store order from the acquisition router's transcript read
//! ([`acquire_transcript`]), which owns every per-client decision: how the
//! store is opened (no link is followed; under the trust anchors of
//! [`SessionRecordOptions::root`] when given), how positions are assigned,
//! and which user records a harness filled with command output. This module
//! only filters, redacts, pages and keys records.

use std::path::PathBuf;

use sha2::{Digest, Sha256};
use telltale_schema::event::{
    parse_event_timestamp, redact_multiline_bounded, terminal_session_id, terminal_tool_label,
};
use telltale_schema::observation::{
    CanonicalObservationV2, IngestionMode, JsonValue, MessageRole, ObservationBody,
    ObservationStage, ObservedAt, canonical_identity_json,
};
use telltale_schema::source::Source;
use telltale_sources::acquisition::{
    AcquisitionOptions, MAX_TRANSCRIPT_SOURCE_BYTES, TranscriptReadOptions, acquire_transcript,
    transcript_message_text,
};

use crate::{Pipeline, PipelineError};

/// Default and largest redacted text bytes per record.
pub const DEFAULT_SESSION_RECORD_MAX_BYTES: usize = 4_096;
/// Largest redacted text bytes per record.
pub const MAX_SESSION_RECORD_BYTES: usize = 4_096;
/// Smallest redacted text bytes per record.
pub const MIN_SESSION_RECORD_BYTES: usize = 64;
/// Default records per page.
pub const DEFAULT_SESSION_RECORD_MAX_RECORDS: usize = 256;
/// Largest records per page.
pub const MAX_SESSION_RECORD_MAX_RECORDS: usize = 4_096;
/// Default redacted text bytes per page (256 KiB).
pub const DEFAULT_SESSION_RECORD_MAX_TOTAL_BYTES: usize = 256 * 1024;
/// Largest redacted text bytes per page (4 MiB).
pub const MAX_SESSION_RECORD_MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
/// Default and largest source bytes one read may load (128 MiB): the bound a
/// scan applies to a session source, so every source a scan reads is readable.
pub const MAX_SESSION_RECORD_SOURCE_BYTES: usize = MAX_TRANSCRIPT_SOURCE_BYTES;

/// Closed code for a cursor whose record is no longer the one returned.
pub const SESSION_RECORD_CURSOR_CHANGED: &str = "session_record_cursor_changed";

const RECORD_KEY_PREFIX: &str = "rec:v1:sha256:";
/// `AcquisitionOptions` requires an observation time; records never carry it.
const READ_ONLY_OBSERVED_AT: &str = "1970-01-01T00:00:00Z";
/// Store windows one read may visit before reporting the page incomplete.
const MAX_WINDOWS_PER_READ: usize = 4_096;

/// Kind of one transcript record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionRecordKind {
    UserMessage,
    AssistantMessage,
    ToolCall,
    ToolResult,
    Other,
}

impl SessionRecordKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserMessage => "user_message",
            Self::AssistantMessage => "assistant_message",
            Self::ToolCall => "tool_call",
            Self::ToolResult => "tool_result",
            Self::Other => "other",
        }
    }
}

/// Opt-in content classes for [`Pipeline::read_session_records`]. Every class
/// defaults to off. Tool results include command output a harness stored as
/// a user message. Tool calls carry the call's arguments, which for a write
/// or patch tool include the file body or patch text.
///
/// Non-exhaustive, so a new class is not a breaking change: start from
/// [`Default`], [`Self::transcript_without_results`] or [`Self::all`] and
/// set fields.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionRecordContent {
    pub user_messages: bool,
    pub assistant_messages: bool,
    pub tool_calls: bool,
    pub tool_results: bool,
    pub other: bool,
}

impl SessionRecordContent {
    /// User and assistant messages and tool calls; no tool results or other.
    pub const fn transcript_without_results() -> Self {
        Self {
            user_messages: true,
            assistant_messages: true,
            tool_calls: true,
            tool_results: false,
            other: false,
        }
    }

    /// Every class, including tool results.
    pub const fn all() -> Self {
        Self {
            user_messages: true,
            assistant_messages: true,
            tool_calls: true,
            tool_results: true,
            other: true,
        }
    }

    const fn includes(self, kind: SessionRecordKind) -> bool {
        match kind {
            SessionRecordKind::UserMessage => self.user_messages,
            SessionRecordKind::AssistantMessage => self.assistant_messages,
            SessionRecordKind::ToolCall => self.tool_calls,
            SessionRecordKind::ToolResult => self.tool_results,
            SessionRecordKind::Other => self.other,
        }
    }
}

/// Options for [`Pipeline::read_session_records`]. Out-of-range values fail
/// as [`PipelineError::InvalidOptions`] before any source I/O.
///
/// Non-exhaustive, so a new option is not a breaking change: start from
/// [`Default`] and set fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionRecordOptions {
    /// Return only records after this ordinal.
    pub after_ordinal: Option<u64>,
    /// The `record_key` of the record at `after_ordinal`. When set, the read
    /// fails as [`SESSION_RECORD_CURSOR_CHANGED`] unless the store still holds
    /// that record at that ordinal. Requires `after_ordinal`.
    pub after_record_key: Option<String>,
    /// Inclusive RFC 3339 lower bound on `occurred_at`; records without a
    /// source time are left out when a bound is set.
    pub since: Option<String>,
    /// Exclusive RFC 3339 upper bound on `occurred_at`.
    pub until: Option<String>,
    /// Only records of this session (raw or terminal form). Required for
    /// stores read per session (OpenCode).
    pub session_id: Option<String>,
    /// Records per page, `1..=4096`.
    pub max_records: usize,
    /// Redacted text bytes per page, `max_record_bytes..=4 MiB`.
    pub max_total_bytes: usize,
    /// Redacted text bytes per record, `64..=4096`.
    pub max_record_bytes: usize,
    /// Source bytes one read may load, `1..=128 MiB`. A JSONL or log source
    /// larger than this fails as `source_limit_exceeded`; a store read in
    /// windows stops there and reports the page incomplete.
    pub max_source_bytes: usize,
    pub content: SessionRecordContent,
    /// The approved discovery root the source belongs to: the source is
    /// opened under its trust anchors, as bounded discovery does. Without a
    /// root, the coordinate is resolved once and that path is opened without
    /// following a link, as a scan does.
    pub root: Option<PathBuf>,
}

impl Default for SessionRecordOptions {
    fn default() -> Self {
        Self {
            after_ordinal: None,
            after_record_key: None,
            since: None,
            until: None,
            session_id: None,
            max_records: DEFAULT_SESSION_RECORD_MAX_RECORDS,
            max_total_bytes: DEFAULT_SESSION_RECORD_MAX_TOTAL_BYTES,
            max_record_bytes: DEFAULT_SESSION_RECORD_MAX_BYTES,
            max_source_bytes: MAX_SESSION_RECORD_SOURCE_BYTES,
            content: SessionRecordContent::default(),
            root: None,
        }
    }
}

/// One redacted record, in store order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionRecord {
    ordinal: u64,
    session_id: Option<String>,
    occurred_at: Option<String>,
    kind: SessionRecordKind,
    tool_name: Option<String>,
    text: String,
    truncated: bool,
    imported: bool,
    record_key: String,
}

impl SessionRecord {
    /// Position in store order: increases with the store order and stays the
    /// same while the store only grows. Not dense.
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Terminal session identifier, when the store reports one.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Source-reported time (RFC 3339); never the read time.
    pub fn occurred_at(&self) -> Option<&str> {
        self.occurred_at.as_deref()
    }

    pub fn kind(&self) -> SessionRecordKind {
        self.kind
    }

    /// Terminal tool label of a tool call or result.
    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }

    /// Redacted text. Line breaks are kept; other whitespace runs in a line
    /// are one space.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether text was withheld (record or input bound, or a fail-closed cut).
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Whether the store holds this record as history imported from another
    /// session (for example a Codex turn imported into this rollout) rather
    /// than activity of this session. Imported records are returned in store
    /// order like any other.
    pub fn imported(&self) -> bool {
        self.imported
    }

    /// `rec:v1:sha256:<hex>` over kind, tool name, the record's redacted text
    /// at the largest per-record size, `occurred_at`, and [`Self::imported`].
    /// It hashes redacted text, so it reveals nothing redaction hides, and it
    /// does not depend on `max_record_bytes`.
    pub fn record_key(&self) -> &str {
        &self.record_key
    }
}

/// One page of [`Pipeline::read_session_records`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionRecordPage {
    records: Vec<SessionRecord>,
    has_more: bool,
    next_after_ordinal: Option<u64>,
    quarantined_units: usize,
    total_bytes: usize,
}

impl SessionRecordPage {
    pub fn records(&self) -> &[SessionRecord] {
        &self.records
    }

    /// When false, the page holds every matching record after the cursor.
    /// When true, more may remain: continue with [`Self::next_after_ordinal`]
    /// and [`Self::next_after_record_key`]. A page can be empty and still
    /// have more, when the part of the store this read could cover held no
    /// matching record.
    pub fn has_more(&self) -> bool {
        self.has_more
    }

    /// The cursor ordinal that continues after this page: the last record's
    /// ordinal, or for an empty page with more, the position the read
    /// reached.
    pub fn next_after_ordinal(&self) -> Option<u64> {
        self.records
            .last()
            .map(SessionRecord::ordinal)
            .or(self.next_after_ordinal)
    }

    /// The cursor key that continues after this page: the last record's key.
    /// `None` for an empty page, whose cursor is a store position, not a
    /// record.
    pub fn next_after_record_key(&self) -> Option<&str> {
        self.records.last().map(SessionRecord::record_key)
    }

    /// Native units of the part of the store this read covered that were
    /// left out because their own values exceed a bound.
    pub fn quarantined_units(&self) -> usize {
        self.quarantined_units
    }

    /// Redacted text bytes across [`Self::records`].
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

/// A failed read, as a closed code that carries no path or session content:
/// an acquisition code (such as `source_missing`, `non_regular_source`,
/// `source_limit_exceeded`, `malformed_source`, `unsupported_source_identity`,
/// `transcript_session_required`, `transcript_order_unavailable`) or
/// [`SESSION_RECORD_CURSOR_CHANGED`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRecordReadError {
    code: &'static str,
}

impl SessionRecordReadError {
    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl std::fmt::Display for SessionRecordReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for SessionRecordReadError {}

fn read_error(code: &'static str) -> PipelineError {
    PipelineError::SessionRecords(SessionRecordReadError { code })
}

impl Pipeline {
    /// Read one page of redacted records, in store order, from one supported
    /// source. Read-only: no scanner state, checkpoint or event is written.
    pub fn read_session_records(
        &self,
        source: &Source,
        options: &SessionRecordOptions,
    ) -> Result<SessionRecordPage, PipelineError> {
        read_session_records(source, options)
    }
}

/// [`Pipeline::read_session_records`] without a pipeline.
pub fn read_session_records(
    source: &Source,
    options: &SessionRecordOptions,
) -> Result<SessionRecordPage, PipelineError> {
    let (since, until) = validate_options(options)?;
    let session = options.session_id.as_deref().map(terminal_session_id);
    let resolved;
    let source = if options.root.is_some() {
        source
    } else {
        // As a scan: resolve once, then open that path without following links.
        let path = source.path.canonicalize().map_err(|error| {
            read_error(match error.kind() {
                std::io::ErrorKind::NotFound => "source_missing",
                std::io::ErrorKind::PermissionDenied => "source_permission_denied",
                _ => "source_unreadable",
            })
        })?;
        resolved = Source {
            path,
            ..source.clone()
        };
        &resolved
    };
    let acquisition = AcquisitionOptions::new(
        ObservedAt::new(READ_ONLY_OBSERVED_AT).expect("valid fixed observation time"),
    );

    let mut page = SessionRecordPage {
        records: Vec::new(),
        has_more: false,
        next_after_ordinal: None,
        quarantined_units: 0,
        total_bytes: 0,
    };
    let mut cursor_verified = options.after_record_key.is_none();
    // The first position this read needs. A keyed cursor reads its own row
    // again to compare the record; without a key the read starts after the
    // cursor, so a row the caller is past costs none of this read's budget.
    let mut from_position = match (options.after_ordinal, &options.after_record_key) {
        (Some(cursor), None) => Some(cursor.saturating_add(1)),
        (cursor, _) => cursor,
    };
    let mut source_bytes = options.max_source_bytes;
    for window in 0..MAX_WINDOWS_PER_READ {
        let batch = match acquire_transcript(
            source,
            acquisition.clone(),
            TranscriptReadOptions {
                root: options.root.as_deref(),
                max_source_bytes: source_bytes,
                session_id: session.as_deref(),
                from_position,
            },
        ) {
            Ok(batch) => batch,
            // The next store row does not fit what is left of this read's
            // budget; the next read starts at it with the whole budget. Only a
            // row larger than the whole budget fails.
            Err(error) if window > 0 && error.code() == "source_limit_exceeded" => break,
            Err(error) => return Err(read_error(error.code())),
        };
        page.quarantined_units += batch.quarantined.len();
        for entry in batch.entries {
            if let Some(cursor) = options.after_ordinal {
                if entry.position == cursor
                    && let Some(expected) = options.after_record_key.as_deref()
                {
                    let found = record_parts(&entry.observation, entry.harness_output)
                        .map(|parts| redacted_record(&entry.observation, parts).1);
                    if found.as_deref() != Some(expected) {
                        return Err(read_error(SESSION_RECORD_CURSOR_CHANGED));
                    }
                    cursor_verified = true;
                }
                if entry.position <= cursor {
                    continue;
                }
            }
            if !cursor_verified {
                return Err(read_error(SESSION_RECORD_CURSOR_CHANGED));
            }
            let observation = &entry.observation;
            let imported = is_imported(observation);
            let record_session = observation
                .session_id()
                .map(|id| terminal_session_id(id.value()));
            if session.is_some() && record_session != session {
                continue;
            }
            let occurred_at = observation
                .occurred_at()
                .map(|time| time.as_str().to_owned());
            if (since.is_some() || until.is_some())
                && !occurred_at
                    .as_deref()
                    .and_then(parse_event_timestamp)
                    .is_some_and(|time| {
                        since.is_none_or(|since| time >= since)
                            && until.is_none_or(|until| time < until)
                    })
            {
                continue;
            }
            let Some(parts) = record_parts(observation, entry.harness_output) else {
                continue;
            };
            if !options.content.includes(parts.kind) {
                continue;
            }
            if page.records.len() == options.max_records {
                page.has_more = true;
                return Ok(page);
            }
            let kind = parts.kind;
            let tool_name = parts.tool_name.clone();
            let raw = parts.text.clone();
            let ((text, truncated), record_key) = redacted_record(observation, parts);
            let (text, truncated) = if options.max_record_bytes < MAX_SESSION_RECORD_BYTES {
                redact_multiline_bounded(&raw, options.max_record_bytes)
            } else {
                (text, truncated)
            };
            if page.total_bytes + text.len() > options.max_total_bytes {
                page.has_more = true;
                return Ok(page);
            }
            page.total_bytes += text.len();
            page.records.push(SessionRecord {
                ordinal: entry.position,
                session_id: record_session,
                occurred_at,
                kind,
                tool_name,
                text,
                truncated,
                imported,
                record_key,
            });
        }
        let Some(next) = batch.continue_from else {
            if !cursor_verified {
                return Err(read_error(SESSION_RECORD_CURSOR_CHANGED));
            }
            return Ok(page);
        };
        from_position = Some(next);
        source_bytes = source_bytes.saturating_sub(batch.bytes_read);
        if source_bytes == 0 {
            break;
        }
    }
    // The read budget ran out with store rows left: continue from the first
    // row not read (positions after `next - 1`).
    if !cursor_verified {
        return Err(read_error(SESSION_RECORD_CURSOR_CHANGED));
    }
    page.has_more = true;
    page.next_after_ordinal = from_position.map(|next| next.saturating_sub(1));
    Ok(page)
}

type TimeBound = Option<time::OffsetDateTime>;

fn validate_options(
    options: &SessionRecordOptions,
) -> Result<(TimeBound, TimeBound), PipelineError> {
    let valid = (1..=MAX_SESSION_RECORD_MAX_RECORDS).contains(&options.max_records)
        && (MIN_SESSION_RECORD_BYTES..=MAX_SESSION_RECORD_BYTES)
            .contains(&options.max_record_bytes)
        && (options.max_record_bytes..=MAX_SESSION_RECORD_MAX_TOTAL_BYTES)
            .contains(&options.max_total_bytes)
        && (1..=MAX_SESSION_RECORD_SOURCE_BYTES).contains(&options.max_source_bytes)
        && (options.after_record_key.is_none() || options.after_ordinal.is_some())
        && options
            .session_id
            .as_deref()
            .is_none_or(|session| !session.trim().is_empty());
    if !valid {
        return Err(PipelineError::InvalidOptions);
    }
    let bound = |value: Option<&str>| {
        value
            .map(|value| parse_event_timestamp(value).ok_or(PipelineError::InvalidOptions))
            .transpose()
    };
    let since = bound(options.since.as_deref())?;
    let until = bound(options.until.as_deref())?;
    if let (Some(since), Some(until)) = (since, until)
        && since >= until
    {
        return Err(PipelineError::InvalidOptions);
    }
    Ok((since, until))
}

/// A record's kind, terminal tool label and raw text, before redaction.
struct RecordParts {
    kind: SessionRecordKind,
    tool_name: Option<String>,
    text: String,
}

/// The record an observation contributes, if any. A tool call is its
/// request and a tool result its returned result; other lifecycle stages
/// carry nothing new. Message text is taken from text parts only (or string
/// content when there are no parts): tool use, tool result, image and other
/// parts never enter it, so a result body appears only as a tool result.
fn record_parts(observation: &CanonicalObservationV2, harness_output: bool) -> Option<RecordParts> {
    let (kind, tool_name, text) = match observation.body() {
        ObservationBody::Message(message) => {
            let kind = match message.role() {
                Some(MessageRole::User) if harness_output => SessionRecordKind::ToolResult,
                Some(MessageRole::User) => SessionRecordKind::UserMessage,
                Some(MessageRole::Assistant) => SessionRecordKind::AssistantMessage,
                Some(MessageRole::Tool) => SessionRecordKind::ToolResult,
                _ => SessionRecordKind::Other,
            };
            (kind, None, transcript_message_text(message))
        }
        ObservationBody::Tool(tool) => {
            let tool_name = tool.name().map(terminal_tool_label);
            match observation.stage() {
                ObservationStage::ToolRequested => (
                    SessionRecordKind::ToolCall,
                    tool_name,
                    tool.searchable_arguments()
                        .map(str::to_owned)
                        .or_else(|| tool.arguments().map(json_text))
                        .unwrap_or_default(),
                ),
                ObservationStage::ToolResultReturned => (
                    SessionRecordKind::ToolResult,
                    tool_name,
                    tool.searchable_result()
                        .map(str::to_owned)
                        .or_else(|| tool.result().map(json_text))
                        .unwrap_or_default(),
                ),
                _ => return None,
            }
        }
        _ => return None,
    };
    (!text.is_empty() || tool_name.is_some()).then_some(RecordParts {
        kind,
        tool_name,
        text,
    })
}

fn json_text(value: &JsonValue) -> String {
    match value {
        JsonValue::String(text) => text.clone(),
        other => canonical_identity_json(other)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default(),
    }
}

/// The record's text redacted at the largest record size, whether it was
/// cut, and its key.
fn redacted_record(
    observation: &CanonicalObservationV2,
    parts: RecordParts,
) -> ((String, bool), String) {
    let (text, truncated) = redact_multiline_bounded(&parts.text, MAX_SESSION_RECORD_BYTES);
    let occurred_at = observation.occurred_at().map(|time| time.as_str());
    let key = record_key(
        parts.kind,
        parts.tool_name.as_deref(),
        &text,
        occurred_at,
        is_imported(observation),
    );
    ((text, truncated), key)
}

fn is_imported(observation: &CanonicalObservationV2) -> bool {
    observation.source().ingestion_mode() == IngestionMode::Import
}

/// The imported flag is part of the key: a store rewrite that turns a record
/// of this session into imported history, or back, is a different record for
/// a cursor, and an imported copy does not share the key of the original.
fn record_key(
    kind: SessionRecordKind,
    tool_name: Option<&str>,
    redacted_text: &str,
    occurred_at: Option<&str>,
    imported: bool,
) -> String {
    let parts = JsonValue::Array(vec![
        JsonValue::string("telltale:session-record-v1"),
        JsonValue::string(kind.as_str()),
        tool_name.map_or(JsonValue::Null, JsonValue::string),
        JsonValue::string(redacted_text),
        occurred_at.map_or(JsonValue::Null, JsonValue::string),
        JsonValue::Bool(imported),
    ]);
    let bytes = canonical_identity_json(&parts).expect("strings, booleans and nulls encode");
    format!("{RECORD_KEY_PREFIX}{}", hex::encode(Sha256::digest(bytes)))
}
