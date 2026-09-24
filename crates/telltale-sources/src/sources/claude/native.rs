#![allow(dead_code)]

use crate::acquisition::{AcquisitionError, SessionMetadata, session_identity};
use serde_json::Value;

use crate::source_read::{
    SourceReadError, collect_string_values, nested_string_field, read_jsonl_values,
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
        input_present: bool,
    },
    ToolResult {
        tool_use_id: Option<String>,
        content: Option<Value>,
        is_error: Option<bool>,
        is_error_present: bool,
    },
    Unknown,
}

#[derive(Debug, Clone)]
pub(crate) struct ClaudeNativeRecord {
    pub(crate) attestation: Result<SessionMetadata, AcquisitionError>,
    pub(crate) source_sequence: u64,
    pub(crate) session_id: Option<String>,
    pub(crate) timestamp: Option<String>,
    pub(crate) discriminator: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) message_content: Option<Value>,
    pub(crate) blocks: Option<Vec<ClaudeContentBlock>>,
    /// Source strings scanned for tool-call activity contributions. Empty unless
    /// this unit is an accounting tool call.
    pub(crate) contribution_strings: Vec<String>,
}

pub(crate) fn extract_claude_native_records(
    source: &Source,
) -> Result<Vec<ClaudeNativeRecord>, SourceReadError> {
    let values = read_jsonl_values(source)?;
    let mut records = Vec::with_capacity(values.len());

    for (source_sequence, value) in values.into_iter().enumerate() {
        if !value.is_object() {
            return Err(SourceReadError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "JSONL record envelope must be an object",
            });
        }

        let ownership =
            session_identity(claude_envelopes(&value).into_iter().flat_map(|envelope| {
                ["session_id", "sessionID", "sessionId"]
                    .into_iter()
                    .filter_map(move |key| envelope.get(key))
            }));
        let session_id = ownership.as_ref().ok().cloned().flatten();
        let blocks = content_blocks(&value)
            .map(|blocks| blocks.iter().map(claude_content_block).collect::<Vec<_>>());
        let is_tool_call = blocks.as_ref().is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| matches!(block, ClaudeContentBlock::ToolUse { .. }))
        });
        let native = ClaudeNativeRecord {
            attestation: ownership.and_then(|_| claude_attestation(&value)),
            source_sequence: source_sequence as u64,
            session_id,
            timestamp: nested_string_field(&value, "timestamp"),
            discriminator: claude_discriminator(&value).map(ToOwned::to_owned),
            role: nested_string_field(&value, "role"),
            message_content: claude_message_content(&value),
            contribution_strings: if is_tool_call {
                collect_string_values(&value)
            } else {
                Vec::new()
            },
            blocks,
        };
        records.push(native);
    }

    Ok(records)
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
        .get("payload")
        .and_then(|payload| payload.get("type"))
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get("payload")
                .and_then(|payload| payload.get("payload"))
                .and_then(|payload| payload.get("type"))
                .and_then(Value::as_str)
        })
        .or_else(|| value.get("type").and_then(Value::as_str))
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
            input_present: object.contains_key("input"),
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
        _ => ClaudeContentBlock::Unknown,
    }
}
