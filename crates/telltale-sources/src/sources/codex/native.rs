#![allow(dead_code)]

use crate::acquisition::{AcquisitionError, SessionMetadata, session_identity};
use serde_json::Value;

use crate::source_read::{
    SourceReadError, collect_string_values, nested_string_field, read_jsonl_values,
};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodexEnvelope {
    ResponseItem,
    EventMessage,
    Bare,
}

#[derive(Debug, Clone)]
pub(crate) enum CodexContentBlock {
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
        call_id: Option<String>,
        result: Option<Value>,
        result_present: bool,
        is_error: Option<bool>,
        is_error_present: bool,
    },
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CodexToolFields {
    pub(crate) name: Option<String>,
    pub(crate) arguments: Option<Value>,
    pub(crate) arguments_present: bool,
    pub(crate) call_id: Option<String>,
    pub(crate) result: Option<Value>,
    pub(crate) result_present: bool,
    pub(crate) status: Option<String>,
    pub(crate) error: Option<Value>,
    pub(crate) error_present: bool,
    pub(crate) is_error: Option<bool>,
    pub(crate) is_error_present: bool,
    pub(crate) command: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct CodexNativeRecord {
    pub(crate) attestation: Result<SessionMetadata, AcquisitionError>,
    pub(crate) source_sequence: u64,
    pub(crate) adapter_id: String,
    pub(crate) session_id: Option<String>,
    pub(crate) inherited_session_id: Option<String>,
    pub(crate) effective_session_id: Option<String>,
    pub(crate) timestamp: Option<String>,
    pub(crate) discriminator: Option<String>,
    pub(crate) session_metadata: bool,
    pub(crate) role: Option<String>,
    pub(crate) envelope: CodexEnvelope,
    pub(crate) payload_source: Option<String>,
    pub(crate) message_content: Option<Value>,
    pub(crate) blocks: Option<Vec<CodexContentBlock>>,
    pub(crate) tool: CodexToolFields,
    /// Source strings scanned for tool-call activity contributions.
    pub(crate) contribution_strings: Vec<String>,
}

pub(crate) fn extract_codex_native_records(
    source: &Source,
) -> Result<Vec<CodexNativeRecord>, SourceReadError> {
    let values = read_jsonl_values(source)?;
    let mut records = Vec::with_capacity(values.len());
    let mut inherited_session_id = None;

    for (source_sequence, value) in values.into_iter().enumerate() {
        if !value.is_object() {
            return Err(SourceReadError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "JSONL record envelope must be an object",
            });
        }

        let record_value = codex_record_value(&value);
        let envelope = codex_envelope(&value);
        let semantic_value = codex_semantic_value(&value, envelope);
        let ownership = session_identity(
            codex_envelopes(&value, semantic_value)
                .into_iter()
                .flat_map(|envelope| {
                    ["session_id", "sessionID", "sessionId"]
                        .into_iter()
                        .filter_map(move |key| envelope.get(key))
                }),
        );
        let session_id = ownership.as_ref().ok().cloned().flatten();
        let discriminator = codex_discriminator(record_value).map(ToOwned::to_owned);
        let session_metadata = discriminator.as_deref() == Some("session_meta")
            || (discriminator
                .as_deref()
                .is_none_or(|kind| !is_known_codex_discriminator(kind))
                && value.get("session_meta").is_some());
        let inherited_for_record = inherited_session_id.clone();
        let effective_session_id = session_id.clone().or(inherited_for_record.clone());
        let blocks = content_blocks(semantic_value)
            .map(|blocks| blocks.iter().map(codex_content_block).collect());
        let tool = codex_tool_fields(semantic_value);
        let role = codex_role(&value, semantic_value);
        let is_tool_call =
            codex_accounting_kind(discriminator.as_deref(), role.as_deref(), &blocks, &tool)
                == RecordKind::ToolCall;
        let native = CodexNativeRecord {
            attestation: ownership.and_then(|_| codex_attestation(&value, semantic_value)),
            source_sequence: source_sequence as u64,
            adapter_id: source.source_id.clone(),
            session_id: session_id.clone(),
            inherited_session_id: inherited_for_record,
            effective_session_id,
            timestamp: nested_string_field(&value, "timestamp"),
            discriminator,
            session_metadata,
            role: role.clone(),
            envelope,
            payload_source: codex_payload_source(&value),
            message_content: codex_message_content(semantic_value),
            contribution_strings: if is_tool_call {
                collect_string_values(record_value)
            } else {
                Vec::new()
            },
            blocks,
            tool,
        };

        if session_metadata && let Some(session_id) = session_id {
            inherited_session_id = Some(session_id);
        }
        records.push(native);
    }

    Ok(records)
}

fn codex_attestation(value: &Value, semantic: &Value) -> Result<SessionMetadata, AcquisitionError> {
    let mut metadata = SessionMetadata::default();
    for envelope in codex_envelopes(value, semantic) {
        metadata.merge(&SessionMetadata::from_fields(
            envelope,
            &["agent", "agent_nickname"],
            &["model"],
            &["provider", "model_provider"],
        )?);
    }
    Ok(metadata)
}

fn codex_envelopes<'a>(value: &'a Value, semantic: &'a Value) -> Vec<&'a Value> {
    let mut envelopes = vec![value, semantic];
    if let Some(message) = semantic.get("message").filter(|v| v.is_object()) {
        envelopes.push(message);
    }
    if matches!(
        value.get("type").and_then(Value::as_str),
        Some("session_meta" | "response_item" | "event_msg")
    ) && let Some(payload) = value.get("payload").filter(|v| v.is_object())
    {
        envelopes.push(payload);
    }
    envelopes
}

pub(crate) fn codex_record_value(value: &Value) -> &Value {
    if value.get("type").and_then(Value::as_str) == Some("response_item") {
        value
            .get("payload")
            .filter(|payload| payload.is_object())
            .unwrap_or(value)
    } else {
        value
    }
}

impl CodexNativeRecord {
    pub(crate) fn accounting_kind(&self) -> RecordKind {
        if self.session_metadata {
            return RecordKind::SessionMeta;
        }
        codex_accounting_kind(
            self.discriminator.as_deref(),
            self.role.as_deref(),
            &self.blocks,
            &self.tool,
        )
    }

    pub(crate) fn accounting_tool_name(&self) -> Option<&str> {
        self.tool.name.as_deref().or_else(|| {
            self.blocks.as_ref()?.iter().find_map(|block| match block {
                CodexContentBlock::ToolUse { name, .. } => name.as_deref(),
                _ => None,
            })
        })
    }

    pub(crate) fn contribution_strings(&self) -> &[String] {
        &self.contribution_strings
    }
}

fn codex_accounting_kind(
    discriminator: Option<&str>,
    role: Option<&str>,
    blocks: &Option<Vec<CodexContentBlock>>,
    tool: &CodexToolFields,
) -> RecordKind {
    if blocks.as_ref().is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| matches!(block, CodexContentBlock::ToolUse { .. }))
    }) || matches!(
        discriminator,
        Some("tool_call" | "function_call" | "custom_tool_call")
    ) {
        return RecordKind::ToolCall;
    }
    if discriminator == Some("tool")
        && (tool.result_present
            || tool.error_present
            || matches!(tool.status.as_deref(), Some("completed" | "error")))
    {
        return RecordKind::ToolResult;
    }
    if blocks.as_ref().is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| matches!(block, CodexContentBlock::ToolResult { .. }))
    }) || matches!(
        discriminator,
        Some("tool_result" | "function_call_output" | "custom_tool_call_output")
    ) {
        return RecordKind::ToolResult;
    }
    if discriminator == Some("tool") {
        return RecordKind::ToolCall;
    }
    match (discriminator, role) {
        (Some("user_message" | "user"), _) | (Some("text" | "message"), Some("user")) => {
            RecordKind::UserMessage
        }
        (Some("assistant_message" | "assistant" | "gemini" | "model"), _)
        | (Some("text" | "message"), Some("assistant" | "model")) => RecordKind::AssistantMessage,
        (Some("session_meta"), _) => RecordKind::SessionMeta,
        _ => RecordKind::Other,
    }
}

pub(crate) fn codex_discriminator(value: &Value) -> Option<&str> {
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

pub(crate) fn is_known_codex_discriminator(kind: &str) -> bool {
    matches!(
        kind,
        "user_message"
            | "user"
            | "assistant_message"
            | "assistant"
            | "gemini"
            | "model"
            | "text"
            | "message"
            | "tool_call"
            | "tool_result"
            | "custom_tool_call"
            | "custom_tool_call_output"
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

fn codex_envelope(value: &Value) -> CodexEnvelope {
    match value.get("type").and_then(Value::as_str) {
        Some("response_item") => CodexEnvelope::ResponseItem,
        Some("event_msg") => CodexEnvelope::EventMessage,
        _ => CodexEnvelope::Bare,
    }
}

fn codex_semantic_value(value: &Value, envelope: CodexEnvelope) -> &Value {
    match envelope {
        CodexEnvelope::ResponseItem | CodexEnvelope::EventMessage => value
            .get("payload")
            .filter(|payload| payload.is_object())
            .map(|payload| {
                if payload.get("type").is_none() {
                    payload
                        .get("payload")
                        .filter(|nested| nested.is_object())
                        .unwrap_or(payload)
                } else {
                    payload
                }
            })
            .unwrap_or(value),
        CodexEnvelope::Bare => value,
    }
}

fn codex_role(value: &Value, semantic_value: &Value) -> Option<String> {
    nested_string_field(value, "role").or_else(|| {
        semantic_value
            .get("message")
            .and_then(|message| message.get("role"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn codex_message_content(value: &Value) -> Option<Value> {
    if let Some(message) = value.get("message")
        && !message.is_array()
    {
        if let Some(content) = message.get("content") {
            return Some(content.clone());
        }
        if !message.is_object() {
            return Some(message.clone());
        }
    }
    value
        .get("content")
        .filter(|content| !content.is_array())
        .cloned()
        .or_else(|| value.get("text").cloned())
}

fn codex_content_block(value: &Value) -> CodexContentBlock {
    let Some(object) = value.as_object() else {
        return CodexContentBlock::Unknown;
    };
    match object.get("type").and_then(Value::as_str) {
        Some("text" | "input_text" | "output_text") => CodexContentBlock::Text {
            text: object
                .get("text")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        },
        Some("tool_use") => CodexContentBlock::ToolUse {
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
        Some("tool_result") => {
            let result = object
                .get("content")
                .or_else(|| object.get("output"))
                .or_else(|| object.get("result"))
                .cloned();
            CodexContentBlock::ToolResult {
                call_id: object
                    .get("tool_use_id")
                    .or_else(|| object.get("call_id"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                result_present: result.is_some(),
                result,
                is_error: object.get("is_error").and_then(Value::as_bool),
                is_error_present: object.contains_key("is_error"),
            }
        }
        _ => CodexContentBlock::Unknown,
    }
}

fn codex_tool_fields(value: &Value) -> CodexToolFields {
    let discriminator = value.get("type").and_then(Value::as_str);
    let arguments = value.get("arguments").or_else(|| value.get("input"));
    let is_generic = discriminator == Some("tool");
    let state = value.get("state").and_then(Value::as_object);
    let result = if is_generic {
        state.and_then(|state| state.get("output")).cloned()
    } else if matches!(
        discriminator,
        Some("tool_result" | "custom_tool_call_output" | "function_call_output")
    ) {
        value
            .get("output")
            .or_else(|| value.get("result"))
            .or_else(|| value.get("content"))
            .or_else(|| value.get("message"))
            .cloned()
    } else {
        None
    };
    let error = if is_generic {
        state.and_then(|state| state.get("error")).cloned()
    } else {
        value.get("error").cloned()
    };
    CodexToolFields {
        name: nested_string_field(value, "tool_name")
            .or_else(|| nested_string_field(value, "tool"))
            .or_else(|| nested_string_field(value, "name")),
        arguments: arguments.cloned(),
        arguments_present: arguments.is_some(),
        call_id: value
            .get("call_id")
            .or_else(|| value.get("tool_use_id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        result_present: result.is_some(),
        result,
        status: state
            .and_then(|state| state.get("status"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        error_present: error.is_some(),
        error,
        is_error: value.get("is_error").and_then(Value::as_bool),
        is_error_present: value.get("is_error").is_some(),
        command: value
            .get("command")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    }
}

fn codex_payload_source(value: &Value) -> Option<String> {
    value
        .get("payload")
        .and_then(|payload| payload.get("source"))
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get("session_meta")
                .and_then(|meta| meta.get("payload"))
                .and_then(|payload| payload.get("source"))
                .and_then(Value::as_str)
        })
        .map(ToOwned::to_owned)
}
