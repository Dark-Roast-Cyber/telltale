//! OpenCode source parsing: SQLite session store and legacy JSON messages.

use rusqlite::ErrorCode;
use serde_json::Value;

use crate::parser::{
    ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord, arguments_field,
    default_source_parent_name, model_field, provider_field, read_json_document, record_content,
    session_id_with_fallback, string_field,
};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

use super::native::extract_sqlite_native_source;
pub(crate) use super::native::opencode_tool_part_is_result;

pub(crate) const SQLITE_PART_LIMIT: i64 = 5_000;

pub(crate) fn extract_opencode_json_source(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let value = read_json_document(source)?;
    let default_session_id = default_source_parent_name(source);
    let values = match &value {
        Value::Object(_) => vec![&value],
        Value::Array(items) => {
            if items.iter().any(|item| !item.is_object()) {
                return Err(ParseError::SchemaDrift {
                    client: source.client,
                    source_id: source.source_id.clone(),
                    detail: "JSON document records must be objects",
                });
            }
            items.iter().collect()
        }
        _ => {
            return Err(ParseError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "JSON document envelope must be an object",
            });
        }
    };

    Ok(ExtractedSourceRecords::records(
        values
            .into_iter()
            .map(|value| opencode_json_record(value, &default_session_id))
            .collect(),
    ))
}

fn opencode_json_record(value: &Value, default_session_id: &str) -> ParsedRecord {
    ParsedRecord {
        session_id: session_id_with_fallback(value, default_session_id),
        agent: string_field(value, "agent"),
        model: model_field(value),
        provider: provider_field(value),
        timestamp: string_field(value, "timestamp").or_else(|| string_field(value, "time")),
        kind: opencode_json_record_kind(value),
        tool_name: opencode_json_tool_name(value),
        arguments: arguments_field(value),
        content: record_content(value),
    }
}

fn opencode_json_record_kind(value: &Value) -> RecordKind {
    let discriminator = opencode_json_discriminator(value);
    if discriminator.is_some_and(|kind| !is_known_opencode_json_discriminator(kind)) {
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
        Some("tool") if opencode_tool_part_is_result(value) => RecordKind::ToolResult,
        Some("tool") => RecordKind::ToolCall,
        Some("session_meta") => RecordKind::SessionMeta,
        _ if value.get("session_meta").is_some() => RecordKind::SessionMeta,
        _ => RecordKind::Other,
    }
}

fn opencode_json_discriminator(value: &Value) -> Option<&str> {
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

fn is_known_opencode_json_discriminator(kind: &str) -> bool {
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

fn content_blocks(value: &Value) -> Option<&Vec<Value>> {
    value
        .get("message")
        .and_then(|message| message.get("content"))
        .or_else(|| value.get("content"))
        .and_then(Value::as_array)
}

fn opencode_json_tool_name(value: &Value) -> Option<String> {
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

impl From<rusqlite::Error> for ParseError {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(ErrorCode::DatabaseBusy) | Some(ErrorCode::DatabaseLocked) => {
                ParseError::Locked(e.to_string())
            }
            _ => ParseError::Sqlite(e),
        }
    }
}

pub(crate) fn extract_sqlite_source(
    source: &Source,
    options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let extracted = extract_sqlite_native_source(source, options)?;
    Ok(ExtractedSourceRecords {
        records: extracted
            .records
            .into_iter()
            .map(|record| record.legacy_record())
            .collect(),
        sqlite_part_max_time_updated: extracted.sqlite_part_max_time_updated,
    })
}
