#![allow(dead_code)]

use serde_json::Value;

use crate::parser::{
    ParseError, arguments_field, default_source_file_stem, read_jsonl_values, record_content,
    session_id_field, session_id_with_fallback, string_field,
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
    pub(crate) source_sequence: u64,
    pub(crate) session_id: Option<String>,
    pub(crate) legacy_session_id: String,
    pub(crate) agent: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) timestamp: Option<String>,
    pub(crate) discriminator: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) message_content: Option<Value>,
    pub(crate) blocks: Option<Vec<ClaudeContentBlock>>,
    pub(crate) legacy_kind: RecordKind,
    pub(crate) legacy_tool_name: Option<String>,
    pub(crate) legacy_arguments: Option<String>,
    pub(crate) legacy_content: String,
}

pub(crate) fn extract_claude_native_records(
    source: &Source,
) -> Result<Vec<ClaudeNativeRecord>, ParseError> {
    let values = read_jsonl_values(source)?;
    let default_session_id = default_source_file_stem(source);
    let mut records = Vec::with_capacity(values.len());
    let mut agent = None;
    let mut provider = None;
    let mut model = None;

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

        let session_id = session_id_field(&value);
        let legacy_arguments =
            arguments_field(&value).or_else(|| claude_tool_input_as_string(&value));
        let native = ClaudeNativeRecord {
            source_sequence: source_sequence as u64,
            legacy_session_id: session_id_with_fallback(&value, &default_session_id),
            session_id,
            agent: agent.clone(),
            model: model.clone(),
            provider: provider.clone(),
            timestamp: string_field(&value, "timestamp"),
            discriminator: claude_discriminator(&value).map(ToOwned::to_owned),
            role: string_field(&value, "role"),
            message_content: claude_message_content(&value),
            blocks: content_blocks(&value)
                .map(|blocks| blocks.iter().map(claude_content_block).collect::<Vec<_>>()),
            legacy_kind: claude_record_kind(&value),
            legacy_tool_name: claude_tool_name(&value),
            legacy_arguments,
            legacy_content: record_content(&value),
        };
        records.push(native);
    }

    Ok(records)
}

pub(crate) fn claude_record_kind(value: &Value) -> RecordKind {
    let discriminator = claude_discriminator(value);
    if discriminator.is_some_and(|kind| !is_known_claude_discriminator(kind)) {
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
        Some("tool_call") => RecordKind::ToolCall,
        Some("tool_result") => RecordKind::ToolResult,
        Some("tool") if claude_tool_part_is_result(value) => RecordKind::ToolResult,
        Some("tool") => RecordKind::ToolCall,
        Some("session_meta") => RecordKind::SessionMeta,
        _ if value.get("session_meta").is_some() => RecordKind::SessionMeta,
        _ => RecordKind::Other,
    }
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

pub(crate) fn claude_tool_part_is_result(value: &Value) -> bool {
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

pub(crate) fn content_blocks(value: &Value) -> Option<&Vec<Value>> {
    value
        .get("message")
        .and_then(|message| message.get("content"))
        .or_else(|| value.get("content"))
        .and_then(Value::as_array)
}

pub(crate) fn claude_tool_name(value: &Value) -> Option<String> {
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

pub(crate) fn claude_tool_input_as_string(value: &Value) -> Option<String> {
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
