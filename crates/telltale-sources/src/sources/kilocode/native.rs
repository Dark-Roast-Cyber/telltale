#![allow(dead_code)]

use std::fmt;

use serde_json::{Map, Value};

use crate::parser::{
    ParseError, default_source_parent_name, epoch_millis_timestamp, read_bounded_json_document,
    source_contract_error,
};
use telltale_schema::source::Source;

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum KiloSemantic {
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
pub(crate) struct KiloNativeRecord {
    pub(crate) source_sequence: usize,
    pub(crate) subtype: String,
    pub(crate) timestamp: String,
    pub(crate) text: Option<String>,
    pub(crate) partial: Option<bool>,
    pub(crate) semantic: KiloSemantic,
}

impl fmt::Debug for KiloSemantic {
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

impl fmt::Debug for KiloNativeRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KiloNativeRecord")
            .field("source_sequence", &"<redacted>")
            .field("subtype", &"<redacted>")
            .field("timestamp", &"<redacted>")
            .field("text", &"<redacted>")
            .field("partial", &"<redacted>")
            .field("semantic", &self.semantic)
            .finish()
    }
}

pub(crate) fn extract_kilocode_native_records(
    source: &Source,
) -> Result<Vec<KiloNativeRecord>, ParseError> {
    let value = read_bounded_json_document(source)?;
    let records = value
        .as_array()
        .ok_or(source_contract_error("root_not_array"))?;
    let native_records = records
        .iter()
        .enumerate()
        .map(|(source_sequence, value)| parse_record(source_sequence, value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(native_records)
}

fn parse_record(source_sequence: usize, value: &Value) -> Result<KiloNativeRecord, ParseError> {
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
    Ok(KiloNativeRecord {
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
) -> Result<KiloSemantic, ParseError> {
    match (message_type, subtype) {
        ("say", "user_feedback" | "user_feedback_diff") => Ok(KiloSemantic::UserMessage),
        ("say", "text" | "completion_result" | "subtask_result") | ("ask", "followup") => {
            Ok(KiloSemantic::AssistantMessage)
        }
        ("ask", "command") => Ok(KiloSemantic::ToolCall {
            tool_name: "command".to_string(),
            arguments: text.map(ToString::to_string),
        }),
        ("ask", "tool") => parse_tool_request(text),
        ("ask", "use_mcp_server") => parse_mcp_request(text, partial),
        ("say", "mcp_server_response") => parse_mcp_result(text),
        (
            "ask",
            "payment_required_prompt"
            | "unauthorized_prompt"
            | "promotion_model_sign_up_required_prompt"
            | "invalid_model"
            | "report_bug"
            | "condense"
            | "checkpoint_restore"
            | "browser_action_launch",
        ) => Ok(KiloSemantic::SessionMeta),
        ("say", "browser_action" | "browser_action_result" | "browser_session_status") => {
            Ok(KiloSemantic::Other)
        }
        ("ask", "command_output") | ("say", "command_output") => Ok(KiloSemantic::ToolResult {
            tool_name: Some("command".to_string()),
            content: text.unwrap_or_default().to_string(),
        }),
        ("say", "reasoning" | "image") => Ok(KiloSemantic::Other),
        _ => Ok(KiloSemantic::SessionMeta),
    }
}

fn parse_tool_request(text: Option<&str>) -> Result<KiloSemantic, ParseError> {
    let Some(text) = text else {
        return Ok(KiloSemantic::Other);
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
    Ok(KiloSemantic::ToolCall {
        tool_name,
        arguments,
    })
}

fn parse_mcp_request(
    text: Option<&str>,
    partial: Option<bool>,
) -> Result<KiloSemantic, ParseError> {
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
            Ok(KiloSemantic::ToolCall {
                tool_name,
                arguments,
            })
        }
        Some("access_mcp_resource") => {
            non_empty_string(payload, "serverName", "invalid_mcp_request")?;
            non_empty_string(payload, "uri", "invalid_mcp_request")?;
            Ok(KiloSemantic::ToolCall {
                tool_name: "access_mcp_resource".to_string(),
                arguments: None,
            })
        }
        _ => Err(source_contract_error("invalid_mcp_request")),
    }
}

fn parse_mcp_result(text: Option<&str>) -> Result<KiloSemantic, ParseError> {
    Ok(KiloSemantic::ToolResult {
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
                | "payment_required_prompt"
                | "unauthorized_prompt"
                | "promotion_model_sign_up_required_prompt"
                | "invalid_model"
                | "report_bug"
                | "condense"
                | "checkpoint_restore"
                | "browser_action_launch"
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
                | "browser_action"
                | "browser_action_result"
                | "browser_session_status"
                | "checkpoint_saved"
                | "rooignore_error"
                | "diff_error"
                | "condense_context"
                | "condense_context_error"
                | "sliding_window_truncation"
                | "codebase_search_result"
                | "user_edit_todos" // Kilo's writer does not persist Roo's say:tool or
                                    // say:too_many_tools_warning variants.
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
