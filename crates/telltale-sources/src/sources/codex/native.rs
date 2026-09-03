#![allow(dead_code)]

use serde_json::Value;

use crate::parser::{
    ParseError, arguments_field, default_source_file_stem, read_jsonl_values, record_content,
    session_id_field, session_id_with_fallback, string_field,
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
    pub(crate) source_sequence: u64,
    pub(crate) adapter_id: String,
    pub(crate) session_id: Option<String>,
    pub(crate) inherited_session_id: Option<String>,
    pub(crate) effective_session_id: Option<String>,
    pub(crate) legacy_session_id: String,
    pub(crate) agent: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) timestamp: Option<String>,
    pub(crate) discriminator: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) envelope: CodexEnvelope,
    pub(crate) payload_source: Option<String>,
    pub(crate) message_content: Option<Value>,
    pub(crate) blocks: Option<Vec<CodexContentBlock>>,
    pub(crate) tool: CodexToolFields,
    pub(crate) legacy_kind: RecordKind,
    pub(crate) legacy_tool_name: Option<String>,
    pub(crate) legacy_arguments: Option<String>,
    pub(crate) legacy_content: String,
}

pub(crate) fn extract_codex_native_records(
    source: &Source,
) -> Result<Vec<CodexNativeRecord>, ParseError> {
    let values = read_jsonl_values(source)?;
    let default_session_id = default_source_file_stem(source);
    let mut records = Vec::with_capacity(values.len());
    let mut agent = None;
    let mut provider = None;
    let mut model = None;
    let mut inherited_session_id = None;

    for (source_sequence, value) in values.into_iter().enumerate() {
        if !value.is_object() {
            return Err(ParseError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "JSONL record envelope must be an object",
            });
        }

        agent = agent
            .or_else(|| string_field(&value, "agent_nickname"))
            .or_else(|| string_field(&value, "agent"));
        provider = provider
            .or_else(|| string_field(&value, "model_provider"))
            .or_else(|| string_field(&value, "providerID"))
            .or_else(|| string_field(&value, "provider"));
        model = model
            .or_else(|| string_field(&value, "model"))
            .or_else(|| string_field(&value, "model_name"))
            .or_else(|| string_field(&value, "modelID"));

        let record_value = codex_record_value(&value);
        let envelope = codex_envelope(&value);
        let semantic_value = codex_semantic_value(&value, envelope);
        let session_id = session_id_field(&value);
        let legacy_kind = codex_record_kind(record_value);
        let inherited_for_record = inherited_session_id.clone();
        let effective_session_id = session_id.clone().or(inherited_for_record.clone());
        let native = CodexNativeRecord {
            source_sequence: source_sequence as u64,
            adapter_id: source.source_id.clone(),
            session_id: session_id.clone(),
            inherited_session_id: inherited_for_record,
            effective_session_id,
            legacy_session_id: session_id_with_fallback(&value, &default_session_id),
            agent: agent.clone(),
            model: model.clone(),
            provider: provider.clone(),
            timestamp: string_field(&value, "timestamp"),
            discriminator: codex_discriminator(record_value).map(ToOwned::to_owned),
            role: codex_role(&value, semantic_value),
            envelope,
            payload_source: codex_payload_source(&value),
            message_content: codex_message_content(semantic_value),
            blocks: content_blocks(semantic_value)
                .map(|blocks| blocks.iter().map(codex_content_block).collect()),
            tool: codex_tool_fields(semantic_value),
            legacy_kind,
            legacy_tool_name: codex_tool_name(record_value),
            legacy_arguments: arguments_field(record_value)
                .or_else(|| codex_tool_input_as_string(record_value)),
            legacy_content: record_content(record_value),
        };

        if legacy_kind == RecordKind::SessionMeta
            && let Some(session_id) = session_id
        {
            inherited_session_id = Some(session_id);
        }
        records.push(native);
    }

    Ok(records)
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

pub(crate) fn codex_record_kind(value: &Value) -> RecordKind {
    let discriminator = codex_discriminator(value);
    if discriminator.is_some_and(|kind| !is_known_codex_discriminator(kind)) {
        return RecordKind::Other;
    }

    if content_blocks(value).is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
    }) {
        return RecordKind::ToolCall;
    }
    if content_blocks(value).is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"))
    }) {
        return RecordKind::ToolResult;
    }

    match discriminator {
        Some("user_message" | "user") => RecordKind::UserMessage,
        Some("assistant_message" | "assistant" | "gemini" | "model") => {
            RecordKind::AssistantMessage
        }
        Some("text") if value.get("role").and_then(Value::as_str) == Some("user") => {
            RecordKind::UserMessage
        }
        Some("text")
            if matches!(
                value.get("role").and_then(Value::as_str),
                Some("assistant" | "model")
            ) =>
        {
            RecordKind::AssistantMessage
        }
        Some("message") if value.get("role").and_then(Value::as_str) == Some("user") => {
            RecordKind::UserMessage
        }
        Some("message")
            if matches!(
                value.get("role").and_then(Value::as_str),
                Some("assistant" | "model")
            ) =>
        {
            RecordKind::AssistantMessage
        }
        Some("tool_call") => RecordKind::ToolCall,
        Some("tool_result") => RecordKind::ToolResult,
        Some("custom_tool_call") => RecordKind::ToolCall,
        Some("custom_tool_call_output") => RecordKind::ToolResult,
        Some("tool") if codex_tool_part_is_result(value) => RecordKind::ToolResult,
        Some("tool") => RecordKind::ToolCall,
        Some("session_meta") => RecordKind::SessionMeta,
        _ if value.get("session_meta").is_some() => RecordKind::SessionMeta,
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

pub(crate) fn codex_tool_part_is_result(value: &Value) -> bool {
    value
        .get("state")
        .and_then(|state| state.get("status"))
        .and_then(Value::as_str)
        .is_some_and(|status| matches!(status, "completed" | "error"))
        || value
            .get("state")
            .and_then(|state| state.get("output").or_else(|| state.get("error")))
            .is_some()
}

pub(crate) fn codex_tool_name(value: &Value) -> Option<String> {
    string_field(value, "tool_name")
        .or_else(|| string_field(value, "tool"))
        .or_else(|| string_field(value, "name"))
        .or_else(|| {
            content_blocks(value)?
                .iter()
                .find(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))?
                .get("name")?
                .as_str()
                .map(ToString::to_string)
        })
}

pub(crate) fn codex_tool_input_as_string(value: &Value) -> Option<String> {
    let input = content_blocks(value)?
        .iter()
        .find(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))?
        .get("input")?;
    match input {
        Value::String(item) => Some(item.clone()),
        Value::Null => None,
        item => serde_json::to_string(item).ok(),
    }
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
    string_field(value, "role").or_else(|| {
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
        name: string_field(value, "tool_name")
            .or_else(|| string_field(value, "tool"))
            .or_else(|| string_field(value, "name")),
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
