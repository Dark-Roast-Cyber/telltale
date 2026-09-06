#![allow(dead_code)]

use std::fmt;

use serde_json::{Map, Value};

use crate::parser::{
    ParseError, default_source_parent_name, epoch_millis_timestamp, read_bounded_json_document,
    source_contract_error,
};
use telltale_schema::source::Source;

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum RooSemantic {
    UserMessage,
    AssistantMessage,
    ToolCall {
        tool_name: String,
        arguments: Option<String>,
    },
    ToolResult {
        tool_name: Option<String>,
        content: String,
    },
    SessionMeta,
    Other,
}

#[derive(Clone)]
pub(crate) struct RooNativeRecord {
    pub(crate) source_sequence: usize,
    pub(crate) subtype: String,
    pub(crate) timestamp: String,
    pub(crate) text: Option<String>,
    pub(crate) partial: Option<bool>,
    pub(crate) semantic: RooSemantic,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RooMetadata {
    pub(crate) session_namespace: Option<String>,
}

impl fmt::Debug for RooMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RooMetadata")
            .field("session_namespace", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for RooSemantic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::UserMessage => "UserMessage",
            Self::AssistantMessage => "AssistantMessage",
            Self::ToolCall { .. } => "ToolCall",
            Self::ToolResult { .. } => "ToolResult",
            Self::SessionMeta => "SessionMeta",
            Self::Other => "Other",
        };
        formatter.write_str(name)
    }
}

impl fmt::Debug for RooNativeRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RooNativeRecord")
            .field("source_sequence", &"<redacted>")
            .field("subtype", &"<redacted>")
            .field("timestamp", &"<redacted>")
            .field("text", &"<redacted>")
            .field("partial", &"<redacted>")
            .field("semantic", &self.semantic)
            .finish()
    }
}

pub(crate) fn extract_roocode_native_records(
    source: &Source,
) -> Result<(RooMetadata, Vec<RooNativeRecord>), ParseError> {
    let value = read_bounded_json_document(source)?;
    let records = value
        .as_array()
        .ok_or(source_contract_error("root_not_array"))?;
    let metadata = read_metadata(source)?;

    let native_records = records
        .iter()
        .enumerate()
        .map(|(source_sequence, value)| parse_record(source_sequence, value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((metadata, native_records))
}

fn parse_record(source_sequence: usize, value: &Value) -> Result<RooNativeRecord, ParseError> {
    let object = value
        .as_object()
        .ok_or(source_contract_error("record_not_object"))?;
    let message_type = required_string(object, "type", "invalid_type")?;
    let subtype_field = match message_type {
        "ask" => "ask",
        "say" => "say",
        _ => return Err(source_contract_error("unknown_message_type")),
    };
    let subtype = required_string(object, subtype_field, "invalid_subtype")?;
    if !known_subtype(message_type, subtype) {
        return Err(source_contract_error("unknown_subtype"));
    }

    let timestamp = epoch_millis_timestamp(
        object
            .get("ts")
            .ok_or(source_contract_error("missing_timestamp"))?,
    )?;
    let text = optional_string(object, "text")?;
    let partial = optional_bool(object, "partial")?;
    let semantic = classify(message_type, subtype, text.as_deref(), partial)?;

    Ok(RooNativeRecord {
        source_sequence,
        subtype: subtype.to_string(),
        timestamp,
        text,
        partial,
        semantic,
    })
}

fn classify(
    message_type: &str,
    subtype: &str,
    text: Option<&str>,
    partial: Option<bool>,
) -> Result<RooSemantic, ParseError> {
    match (message_type, subtype) {
        ("say", "user_feedback" | "user_feedback_diff") => Ok(RooSemantic::UserMessage),
        ("say", "text" | "completion_result" | "subtask_result") | ("ask", "followup") => {
            Ok(RooSemantic::AssistantMessage)
        }
        ("ask", "command") => Ok(RooSemantic::ToolCall {
            tool_name: "command".to_string(),
            arguments: text.map(ToString::to_string),
        }),
        ("ask", "tool") => parse_tool_request(text),
        ("ask", "use_mcp_server") => parse_mcp_request(text, partial),
        ("ask", "command_output") => Ok(RooSemantic::ToolResult {
            tool_name: Some("command".to_string()),
            content: text.unwrap_or_default().to_string(),
        }),
        ("say", "command_output") => Ok(RooSemantic::ToolResult {
            tool_name: Some("command".to_string()),
            content: text.unwrap_or_default().to_string(),
        }),
        ("say", "mcp_server_response") => parse_mcp_result(text),
        ("say", "reasoning" | "image" | "tool") => Ok(RooSemantic::Other),
        _ => Ok(RooSemantic::SessionMeta),
    }
}

fn parse_tool_request(text: Option<&str>) -> Result<RooSemantic, ParseError> {
    let Some(text) = text else {
        return Ok(RooSemantic::Other);
    };
    let payload = parse_json_object(text, "invalid_tool_payload")?;
    let payload = payload
        .as_object()
        .ok_or(source_contract_error("invalid_tool_payload"))?;
    let tool_name = non_empty_string(payload, "tool", "invalid_tool_payload")?;
    let arguments = match payload.get("arguments") {
        None => None,
        Some(value) if value.is_object() => Some(compact_json(value)?),
        Some(_) => return Err(source_contract_error("invalid_tool_payload")),
    };
    Ok(RooSemantic::ToolCall {
        tool_name,
        arguments,
    })
}

fn parse_mcp_request(text: Option<&str>, partial: Option<bool>) -> Result<RooSemantic, ParseError> {
    let payload = parse_json_object(
        text.ok_or(source_contract_error("invalid_mcp_request"))?,
        "invalid_mcp_request",
    )?;
    let payload = payload
        .as_object()
        .ok_or(source_contract_error("invalid_mcp_request"))?;
    match payload.get("type").and_then(Value::as_str) {
        Some("use_mcp_tool") => {
            non_empty_string(payload, "serverName", "invalid_mcp_request")?;
            let tool_name = non_empty_string(payload, "toolName", "invalid_mcp_request")?;
            let arguments = match payload.get("arguments") {
                None => None,
                Some(Value::String(value)) => Some(value.clone()),
                Some(value) if partial == Some(true) && value.is_object() => {
                    Some(compact_json(value)?)
                }
                Some(_) => return Err(source_contract_error("invalid_mcp_request")),
            };
            Ok(RooSemantic::ToolCall {
                tool_name,
                arguments,
            })
        }
        Some("access_mcp_resource") => {
            non_empty_string(payload, "serverName", "invalid_mcp_request")?;
            non_empty_string(payload, "uri", "invalid_mcp_request")?;
            Ok(RooSemantic::ToolCall {
                tool_name: "access_mcp_resource".to_string(),
                arguments: None,
            })
        }
        _ => Err(source_contract_error("invalid_mcp_request")),
    }
}

fn parse_mcp_result(text: Option<&str>) -> Result<RooSemantic, ParseError> {
    Ok(RooSemantic::ToolResult {
        tool_name: None,
        content: text.unwrap_or_default().to_string(),
    })
}

fn known_subtype(message_type: &str, subtype: &str) -> bool {
    match message_type {
        "ask" => matches!(
            subtype,
            "followup"
                | "command"
                | "command_output"
                | "completion_result"
                | "tool"
                | "api_req_failed"
                | "resume_task"
                | "resume_completed_task"
                | "mistake_limit_reached"
                | "use_mcp_server"
                | "auto_approval_max_req_reached"
        ),
        "say" => matches!(
            subtype,
            "error"
                | "api_req_started"
                | "api_req_finished"
                | "api_req_retried"
                | "api_req_retry_delayed"
                | "api_req_rate_limit_wait"
                | "api_req_deleted"
                | "text"
                | "image"
                | "reasoning"
                | "completion_result"
                | "user_feedback"
                | "user_feedback_diff"
                | "command_output"
                | "shell_integration_warning"
                | "mcp_server_request_started"
                | "mcp_server_response"
                | "subtask_result"
                | "checkpoint_saved"
                | "rooignore_error"
                | "diff_error"
                | "condense_context"
                | "condense_context_error"
                | "sliding_window_truncation"
                | "codebase_search_result"
                | "user_edit_todos"
                | "too_many_tools_warning"
                | "tool"
        ),
        _ => false,
    }
}

fn parse_json_object(text: &str, category: &'static str) -> Result<Value, ParseError> {
    serde_json::from_str(text).map_err(|_| source_contract_error(category))
}

fn compact_json(value: &Value) -> Result<String, ParseError> {
    serde_json::to_string(value).map_err(|_| source_contract_error("invalid_tool_payload"))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    category: &'static str,
) -> Result<&'a str, ParseError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(source_contract_error(category))
}

fn non_empty_string(
    object: &Map<String, Value>,
    key: &str,
    category: &'static str,
) -> Result<String, ParseError> {
    let value = required_string(object, key, category)?;
    if value.is_empty() {
        return Err(source_contract_error(category));
    }
    Ok(value.to_string())
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Result<Option<String>, ParseError> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(source_contract_error("invalid_text")),
    }
}

fn optional_bool(object: &Map<String, Value>, key: &str) -> Result<Option<bool>, ParseError> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(source_contract_error("invalid_partial")),
    }
}

pub(crate) fn legacy_session_id(source: &Source) -> String {
    default_source_parent_name(source)
}

fn read_metadata(source: &Source) -> Result<RooMetadata, ParseError> {
    let Some(task_dir) = source.path.parent() else {
        return Ok(RooMetadata {
            session_namespace: None,
        });
    };
    let tasks_dir = task_dir.parent().ok_or(source_contract_error("metadata"))?;
    let history = read_optional_json(&task_dir.join("history_item.json"), "metadata_history")?;
    let index = read_optional_json(&tasks_dir.join("_index.json"), "metadata_index")?;

    let Some(history) = history else {
        // The cache can be checked for structure, but it cannot establish a
        // namespace without the direct task file.
        if let Some(index) = index {
            parse_index_ids(&index)?;
        }
        return Ok(RooMetadata {
            session_namespace: None,
        });
    };

    let history_id = parse_history_id(&history)?;
    let Some(index) = index else {
        return Ok(RooMetadata {
            session_namespace: Some(history_id),
        });
    };

    let index_ids = parse_index_ids(&index)?;
    if index_ids.iter().filter(|id| *id == &history_id).count() != 1 {
        return Err(source_contract_error("metadata_disagreement"));
    }

    Ok(RooMetadata {
        session_namespace: Some(history_id),
    })
}

fn parse_index_ids(value: &Value) -> Result<Vec<String>, ParseError> {
    let object = value
        .as_object()
        .ok_or(source_contract_error("metadata_index_root"))?;
    if object.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(source_contract_error("metadata_index_version"));
    }
    if !object.get("updatedAt").is_some_and(is_integer) {
        return Err(source_contract_error("metadata_index_updated_at"));
    }
    let entries = object
        .get("entries")
        .and_then(Value::as_array)
        .ok_or(source_contract_error("metadata_index_entries"))?;
    let mut ids = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = entry
            .as_object()
            .ok_or(source_contract_error("metadata_index_entry"))?;
        ids.push(non_empty_string(entry, "id", "metadata_index_id")?);
    }
    let unique = ids.iter().collect::<std::collections::HashSet<_>>();
    if unique.len() != ids.len() {
        return Err(source_contract_error("metadata_index_duplicate"));
    }
    Ok(ids)
}

fn parse_history_id(value: &Value) -> Result<String, ParseError> {
    let object = value
        .as_object()
        .ok_or(source_contract_error("metadata_history_root"))?;
    non_empty_string(object, "id", "metadata_history_id")
}

fn read_optional_json(
    path: &std::path::Path,
    category: &'static str,
) -> Result<Option<Value>, ParseError> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|_| source_contract_error(category)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(source_contract_error(category)),
    }
}

fn is_integer(value: &Value) -> bool {
    value.as_i64().is_some() || value.as_u64().is_some()
}
