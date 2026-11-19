//! Crate-private Claude Code JSONL record and content-block structures, and
//! their extraction. A known schema failure is terminal; there is no fallback
//! parser.

use crate::acquisition::{
    AcquisitionError, DirectRead, SessionMetadata, SourceAccess, session_identity,
};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

use crate::source_read::{
    PRODUCTION_SOURCE_BYTES, SourceReadError, bounded_file_bytes, collect_string_values,
    confined_file_bytes, nested_string_field, resolved_file_bytes,
};
use telltale_schema::observation::{
    LOCAL_MAX_ARRAY_ITEMS, LOCAL_MAX_STRING_BYTES, TOOL_RESULT_MAX_TEXT_BYTES,
};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

#[derive(Debug, Clone)]
pub(crate) enum ClaudeContentBlock {
    Text {
        text: Option<String>,
    },
    ToolUse {
        id: Option<String>,
        name: Option<String>,
        input: Option<Value>,
    },
    ToolResult {
        tool_use_id: Option<String>,
        content: Option<Value>,
        is_error: Option<bool>,
        is_error_present: bool,
    },
    /// Reasoning and media blocks carry no text or tool facts; projection
    /// drops them from the message instead of rejecting the record.
    Ignored,
    Unknown,
}

#[derive(Debug, Clone)]
pub(crate) struct ClaudeNativeRecord {
    pub(crate) attestation: Result<SessionMetadata, AcquisitionError>,
    pub(crate) source_sequence: u64,
    /// Source-reported record `uuid`, used only to locate a quarantined record.
    pub(crate) native_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) timestamp: Option<String>,
    pub(crate) discriminator: Option<String>,
    pub(crate) is_bookkeeping: bool,
    pub(crate) role: Option<String>,
    pub(crate) message_content: Option<Value>,
    pub(crate) blocks: Option<Vec<ClaudeContentBlock>>,
    /// Source strings scanned for tool-call activity contributions. Empty unless
    /// this unit is an accounting tool call.
    pub(crate) contribution_strings: Vec<String>,
}

#[cfg(test)]
pub(crate) fn extract_claude_native_records(
    source: &Source,
) -> Result<Vec<ClaudeNativeRecord>, SourceReadError> {
    extract_claude_native_records_with_limits(source, crate::acquisition::SourceAccess::ByName)
        .map(|(records, _)| records)
}

pub(crate) fn extract_claude_native_records_with_limits(
    source: &Source,
    access: SourceAccess<'_>,
) -> Result<(Vec<ClaudeNativeRecord>, usize), SourceReadError> {
    let (values, bytes) = crate::source_read::read_jsonl_values_with_limits(source, access)?;
    let mut records = Vec::with_capacity(values.len());
    // Spilled results share the source's byte budget with the transcript.
    let mut spill_budget = match access {
        SourceAccess::Direct(direct) => direct.limits.bytes,
        SourceAccess::ByName | SourceAccess::Resolved => PRODUCTION_SOURCE_BYTES,
    }
    .saturating_sub(bytes);

    for (source_sequence, value) in values.into_iter().enumerate() {
        let Some(envelope) = value.as_object() else {
            return Err(SourceReadError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "JSONL record envelope must be an object",
            });
        };

        // Claude names a transcript by an outer `sessionId`. Current Claude Code
        // also writes an outer `session_id`, which can name a different session
        // that shares the transcript, so beside an outer `sessionId` only
        // `sessionId` claims ownership.
        let keys: &[&str] = if value
            .get("sessionId")
            .is_some_and(|value| !value.is_null() && value.as_str() != Some(""))
        {
            &["sessionId"]
        } else {
            &["session_id", "sessionID", "sessionId"]
        };
        let ownership = session_identity(
            claude_envelopes(&value)
                .into_iter()
                .flat_map(|envelope| keys.iter().filter_map(move |key| envelope.get(*key))),
        );
        let session_id = ownership.as_ref().ok().cloned().flatten();
        let discriminator = claude_discriminator(&value);
        let conversational = discriminator.is_none_or(is_known_claude_discriminator);
        let source_blocks = conversational.then(|| content_blocks(&value)).flatten();
        // Only mapped records interpret these arrays as content-block envelopes.
        // Skipped bookkeeping and unknown record payloads remain opaque.
        if source_blocks.is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| block.get("type").and_then(Value::as_str).is_none())
        }) {
            return Err(SourceReadError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "Claude content block must be an object with a string type",
            });
        }
        let mut blocks =
            source_blocks.map(|blocks| blocks.iter().map(claude_content_block).collect::<Vec<_>>());
        if let (Some(blocks), Some(session_id)) = (blocks.as_mut(), session_id.as_deref()) {
            resolve_spilled_results(source, access, session_id, blocks, &mut spill_budget);
        }
        let is_tool_call = blocks.as_ref().is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| matches!(block, ClaudeContentBlock::ToolUse { .. }))
        });
        let native = ClaudeNativeRecord {
            attestation: ownership.and_then(|_| claude_attestation(&value)),
            source_sequence: source_sequence as u64,
            native_id: value
                .get("uuid")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            session_id,
            timestamp: nested_string_field(&value, "timestamp"),
            discriminator: discriminator.map(ToOwned::to_owned),
            is_bookkeeping: is_claude_bookkeeping(envelope, discriminator),
            role: nested_string_field(&value, "role"),
            message_content: conversational
                .then(|| claude_message_content(&value))
                .flatten(),
            contribution_strings: if is_tool_call {
                collect_string_values(&value)
            } else {
                Vec::new()
            },
            blocks,
        };
        records.push(native);
    }

    Ok((records, bytes))
}

impl ClaudeNativeRecord {
    pub(crate) fn accounting_kind(&self) -> RecordKind {
        if self.blocks.as_ref().is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| matches!(block, ClaudeContentBlock::ToolUse { .. }))
        }) {
            return RecordKind::ToolCall;
        }
        if self.blocks.as_ref().is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| matches!(block, ClaudeContentBlock::ToolResult { .. }))
        }) {
            return RecordKind::ToolResult;
        }
        match self.discriminator.as_deref() {
            Some("user_message" | "user") => RecordKind::UserMessage,
            Some("assistant_message" | "assistant" | "model") => RecordKind::AssistantMessage,
            Some("text") if self.role.as_deref() == Some("user") => RecordKind::UserMessage,
            Some("text") if matches!(self.role.as_deref(), Some("assistant" | "model")) => {
                RecordKind::AssistantMessage
            }
            Some("tool_call") => RecordKind::ToolCall,
            Some("tool_result") => RecordKind::ToolResult,
            Some("session_meta") => RecordKind::SessionMeta,
            _ => RecordKind::Other,
        }
    }

    pub(crate) fn accounting_tool_name(&self) -> Option<&str> {
        self.blocks.as_ref()?.iter().find_map(|block| match block {
            ClaudeContentBlock::ToolUse { name, .. } => name.as_deref(),
            _ => None,
        })
    }

    pub(crate) fn contribution_strings(&self) -> &[String] {
        &self.contribution_strings
    }
}

fn claude_attestation(value: &Value) -> Result<SessionMetadata, AcquisitionError> {
    let mut metadata = SessionMetadata::default();
    for envelope in claude_envelopes(value) {
        metadata.merge(&SessionMetadata::from_fields(
            envelope,
            &["agent", "agent_nickname"],
            &["model"],
            &["provider", "model_provider"],
        )?);
    }
    Ok(metadata)
}

fn claude_envelopes(value: &Value) -> Vec<&Value> {
    // Claude conversational records and their message object are native envelopes.
    // A sibling payload/session_meta object on a conversation is not metadata.
    let mut envelopes = vec![value];
    if let Some(message) = value.get("message").filter(|v| v.is_object()) {
        envelopes.push(message);
    }
    if value.get("type").and_then(Value::as_str) == Some("session_meta")
        && let Some(payload) = value.get("payload").filter(|v| v.is_object())
    {
        envelopes.push(payload);
    }
    envelopes
}

pub(crate) fn claude_discriminator(value: &Value) -> Option<&str> {
    value
        .get("type")
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get("payload")
                .and_then(|payload| payload.get("type"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            value
                .get("payload")
                .and_then(|payload| payload.get("payload"))
                .and_then(|payload| payload.get("type"))
                .and_then(Value::as_str)
        })
        .or_else(|| value.get("role").and_then(Value::as_str))
        .or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("role"))
                .and_then(Value::as_str)
        })
}

pub(crate) fn is_known_claude_discriminator(kind: &str) -> bool {
    matches!(
        kind,
        "user_message"
            | "user"
            | "assistant_message"
            | "assistant"
            | "gemini"
            | "model"
            | "text"
            | "tool_call"
            | "tool_result"
            | "tool"
            | "session_meta"
    )
}

/// Claude Code session bookkeeping records (titles, queue state, file
/// snapshots, hook attachments). They are not conversation turns and carry no
/// tool lifecycle, so projection skips them.
fn is_claude_bookkeeping(envelope: &Map<String, Value>, kind: Option<&str>) -> bool {
    let Some(kind) = kind else { return false };
    if kind == "tag" {
        // The local Agent SDK writer persists only {type, tag, sessionId};
        // a fallback role/payload discriminator or a different shape is not a tag entry.
        return envelope.len() == 3
            && envelope.get("type").and_then(Value::as_str) == Some("tag")
            && envelope
                .get("tag")
                .and_then(Value::as_str)
                .is_some_and(|tag| tag.len() <= LOCAL_MAX_STRING_BYTES)
            && envelope
                .get("sessionId")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty());
    }
    if kind == "bridge-session" {
        // Remote Control bridge bookkeeping: which bridge session mirrors this
        // transcript and how far it has been relayed. No turn or tool content.
        return has_exact_keys(
            envelope,
            &[
                "type",
                "sessionId",
                "bridgeSessionId",
                "lastSequenceNum",
                "ownerAccountUuid",
                "ownerOrganizationUuid",
            ],
        ) && has_session_id(envelope)
            && [
                "bridgeSessionId",
                "ownerAccountUuid",
                "ownerOrganizationUuid",
            ]
            .iter()
            .all(|key| bounded_str(envelope.get(*key)))
            && envelope.get("lastSequenceNum").is_some_and(Value::is_u64);
    }
    if kind == "tools-used" {
        // A per-session list of tool names. The calls themselves are in the
        // conversation records; the names alone are not tool activity.
        return has_exact_keys(envelope, &["type", "sessionId", "tools"])
            && has_session_id(envelope)
            && envelope
                .get("tools")
                .and_then(Value::as_array)
                .is_some_and(|tools| {
                    tools.len() <= LOCAL_MAX_ARRAY_ITEMS
                        && tools.iter().all(|tool| bounded_str(Some(tool)))
                });
    }
    // No published source defines the next two; their shapes come from current
    // transcripts. Their identifiers are never projected.
    if kind == "session-owner" {
        // The account and organization that own the session.
        return has_exact_keys(
            envelope,
            &["type", "sessionId", "accountUuid", "organizationUuid"],
        ) && has_session_id(envelope)
            && ["accountUuid", "organizationUuid"]
                .iter()
                .all(|key| bounded_identifier(envelope.get(*key)));
    }
    if kind == "agent-setting" {
        // The named agent configuration the session runs with.
        return has_exact_keys(envelope, &["type", "sessionId", "agentSetting"])
            && has_session_id(envelope)
            && bounded_identifier(envelope.get("agentSetting"));
    }
    matches!(
        kind,
        "attachment"
            | "queue-operation"
            | "last-prompt"
            | "custom-title"
            | "ai-title"
            | "agent-name"
            | "atis-latch"
            | "file-history-snapshot"
            | "file-history-delta"
            | "summary"
            | "system"
            | "progress"
            | "api-request"
            | "api-request-blob"
            | "api-request-shape"
            | "mode"
            | "permission-mode"
            | "relocated"
            | "worktree-state"
            | "cost-state"
            | "pr-link"
            | "artifact-autoreact-ledger"
            | "artifact-comment-monitor"
            | "continued-in"
    )
}

fn has_exact_keys(envelope: &Map<String, Value>, keys: &[&str]) -> bool {
    envelope.len() == keys.len() && keys.iter().all(|key| envelope.contains_key(*key))
}

fn has_session_id(envelope: &Map<String, Value>) -> bool {
    envelope
        .get("sessionId")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty())
}

fn bounded_str(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| text.len() <= LOCAL_MAX_STRING_BYTES)
}

fn bounded_identifier(value: Option<&Value>) -> bool {
    bounded_str(value)
        && value
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty())
}

/// Claude Code writes a tool result over its inline limit to
/// `<session>/tool-results/<name>` and leaves only a `<persisted-output>`
/// notice with a short preview in the transcript. Replace such a notice with
/// the file it names, read from this transcript's own session directory: only
/// the file name is taken from the notice, so a relocated or copied store
/// still resolves and a notice cannot point outside that directory. The file is
/// opened the way the transcript was (never following a final link), must be
/// UTF-8 and fit the direct tool-result budget and the source's remaining byte
/// budget. Otherwise the notice and its preview stay as the result.
fn resolve_spilled_results(
    source: &Source,
    access: SourceAccess<'_>,
    session_id: &str,
    blocks: &mut [ClaudeContentBlock],
    budget: &mut usize,
) {
    for block in blocks {
        let ClaudeContentBlock::ToolResult {
            content: Some(content),
            ..
        } = block
        else {
            continue;
        };
        let Some(name) = spill_notice_text(content).and_then(spill_file_name) else {
            continue;
        };
        let Some(path) = spill_directory(&source.path, session_id).map(|dir| dir.join(name)) else {
            continue;
        };
        let cap = TOOL_RESULT_MAX_TEXT_BYTES.min(*budget);
        let bytes = match access {
            SourceAccess::Direct(DirectRead { root, .. }) => confined_file_bytes(root, &path, cap),
            SourceAccess::Resolved => resolved_file_bytes(&path, cap),
            SourceAccess::ByName => bounded_file_bytes(&path, cap),
        };
        if let Some(text) = bytes.ok().and_then(|bytes| String::from_utf8(bytes).ok()) {
            *budget -= text.len();
            *content = Value::String(text);
        }
    }
}

/// The notice text of a result that is exactly one spill notice: a string, or
/// an array holding a single text block. A result that merely quotes a notice
/// (a transcript printed by a tool) is not one.
fn spill_notice_text(content: &Value) -> Option<&str> {
    let text = match content {
        Value::String(text) => text.as_str(),
        Value::Array(items) if items.len() == 1 => {
            let item = items[0].as_object()?;
            (item.get("type").and_then(Value::as_str) == Some("text"))
                .then(|| item.get("text").and_then(Value::as_str))
                .flatten()?
        }
        _ => return None,
    };
    let body = text.strip_prefix("<persisted-output>\n")?;
    body.trim_end()
        .ends_with("</persisted-output>")
        .then_some(body)
}

/// The spill file name from the notice's first line,
/// `Output too large (<size>). Full output saved to: <dir>/tool-results/<name>`.
fn spill_file_name(body: &str) -> Option<&str> {
    let line = body.lines().next()?.strip_prefix("Output too large (")?;
    let (_, path) = line.split_once(". Full output saved to: ")?;
    let mut components = path.rsplit(['/', '\\']);
    let name = components.next()?;
    if components.next() != Some("tool-results") {
        return None;
    }
    let (stem, extension) = name.rsplit_once('.')?;
    (matches!(extension, "txt" | "json") && is_plain_name(stem)).then_some(name)
}

/// `<project>/<session>/tool-results` for a session transcript
/// (`<project>/<session>.jsonl`) or one of its subagents
/// (`<project>/<session>/subagents/<agent>.jsonl`).
fn spill_directory(transcript: &Path, session_id: &str) -> Option<PathBuf> {
    if !is_plain_name(session_id) {
        return None;
    }
    let parent = transcript.parent()?;
    let session_directory = if parent.file_name()? == "subagents" {
        let session_directory = parent.parent()?;
        (session_directory.file_name()? == session_id).then_some(session_directory)?;
        session_directory.to_path_buf()
    } else {
        parent.join(session_id)
    };
    Some(session_directory.join("tool-results"))
}

fn is_plain_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn content_blocks(value: &Value) -> Option<&Vec<Value>> {
    value
        .get("message")
        .and_then(|message| message.get("content"))
        .or_else(|| value.get("content"))
        .and_then(Value::as_array)
}

fn claude_message_content(value: &Value) -> Option<Value> {
    value
        .get("message")
        .and_then(|message| message.get("content"))
        .or_else(|| value.get("content"))
        .cloned()
}

fn claude_content_block(value: &Value) -> ClaudeContentBlock {
    let Some(object) = value.as_object() else {
        return ClaudeContentBlock::Unknown;
    };
    match object.get("type").and_then(Value::as_str) {
        Some("text") => ClaudeContentBlock::Text {
            text: object
                .get("text")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        },
        Some("tool_use") => ClaudeContentBlock::ToolUse {
            id: object
                .get("id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            name: object
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            input: object.get("input").cloned(),
        },
        Some("tool_result") => ClaudeContentBlock::ToolResult {
            tool_use_id: object
                .get("tool_use_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            content: object.get("content").cloned(),
            is_error: object.get("is_error").and_then(Value::as_bool),
            is_error_present: object.contains_key("is_error"),
        },
        Some("thinking" | "redacted_thinking" | "image" | "document") => {
            ClaudeContentBlock::Ignored
        }
        _ => ClaudeContentBlock::Unknown,
    }
}
