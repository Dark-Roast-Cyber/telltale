#![allow(dead_code)]

use crate::acquisition::{AcquisitionError, SessionMetadata, session_identity};
use serde_json::Value;

use crate::source_read::{
    SourceReadError, collect_string_values, nested_string_field, read_jsonl_values,
};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

#[derive(Clone)]
pub(crate) enum QwenContentBlock {
    Text {
        text: Option<String>,
    },
    ToolUse {
        call_id: Option<String>,
        name: Option<String>,
        input: Option<Value>,
        input_present: bool,
    },
    ToolResult {
        tool_call_id: Option<String>,
        result: Option<Value>,
        result_present: bool,
        is_error: Option<bool>,
        is_error_present: bool,
    },
    Unknown,
}

#[derive(Clone, Default)]
pub(crate) struct QwenToolFields {
    pub(crate) name: Option<String>,
    pub(crate) arguments: Option<Value>,
    pub(crate) arguments_present: bool,
    pub(crate) call_id: Option<String>,
    pub(crate) result: Option<Value>,
    pub(crate) result_present: bool,
    pub(crate) error: Option<Value>,
    pub(crate) error_present: bool,
    pub(crate) is_error: Option<bool>,
    pub(crate) is_error_present: bool,
    pub(crate) status: Option<String>,
}

#[derive(Clone)]
pub(crate) struct QwenNativeRecord {
    pub(crate) attestation: Result<SessionMetadata, AcquisitionError>,
    pub(crate) source_sequence: u64,
    pub(crate) native_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) timestamp: Option<String>,
    pub(crate) source_timestamp: Option<String>,
    pub(crate) discriminator: Option<String>,
    pub(crate) payload_discriminator: bool,
    pub(crate) role: Option<String>,
    pub(crate) message_content: Option<Value>,
    pub(crate) blocks: Option<Vec<QwenContentBlock>>,
    pub(crate) tool_calls: Vec<QwenToolFields>,
    pub(crate) tool: QwenToolFields,
    pub(crate) contribution_strings: Vec<String>,
}

pub(crate) fn extract_qwen_native_records(
    source: &Source,
) -> Result<Vec<QwenNativeRecord>, SourceReadError> {
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

        let selected_envelope = qwen_selected_envelope(&value);
        let discriminator = qwen_discriminator(&value).map(ToOwned::to_owned);
        let ownership = canonical_session_id(&value);
        let session_id = ownership.as_ref().ok().cloned().flatten();
        let blocks =
            content_blocks(&value).map(|blocks| blocks.iter().map(qwen_content_block).collect());
        let tool_calls = qwen_tool_calls(&value);
        let tool = qwen_tool_fields(&value);
        let role = qwen_role(&value);
        let is_tool_call = qwen_accounting_kind(
            discriminator.as_deref(),
            role.as_deref(),
            &blocks,
            &tool_calls,
            &tool,
        ) == RecordKind::ToolCall;
        let native = QwenNativeRecord {
            attestation: ownership.and_then(|_| {
                selected_envelope.map_or_else(
                    || Ok(SessionMetadata::default()),
                    |envelope| {
                        let mut metadata = qwen_metadata(envelope.value)?;
                        if let Some(message) =
                            envelope.value.get("message").filter(|v| v.is_object())
                        {
                            metadata.merge(&qwen_metadata(message)?);
                        }
                        Ok(metadata)
                    },
                )
            }),
            source_sequence: source_sequence as u64,
            native_id: qwen_native_id(&value, discriminator.as_deref()),
            session_id,
            timestamp: nested_string_field(&value, "timestamp"),
            source_timestamp: selected_envelope
                .and_then(|envelope| selected_string_field(envelope.value, "timestamp")),
            discriminator,
            payload_discriminator: has_payload_discriminator(&value),
            role,
            message_content: qwen_message_content(&value),
            contribution_strings: if is_tool_call {
                collect_string_values(&value)
            } else {
                Vec::new()
            },
            blocks,
            tool_calls,
            tool,
        };
        records.push(native);
    }

    Ok(records)
}

impl QwenNativeRecord {
    pub(crate) fn accounting_kind(&self) -> RecordKind {
        qwen_accounting_kind(
            self.discriminator.as_deref(),
            self.role.as_deref(),
            &self.blocks,
            &self.tool_calls,
            &self.tool,
        )
    }

    pub(crate) fn accounting_tool_name(&self) -> Option<&str> {
        self.tool_calls
            .iter()
            .find_map(|tool| tool.name.as_deref())
            .or(self.tool.name.as_deref())
            .or_else(|| {
                self.blocks.as_ref()?.iter().find_map(|block| match block {
                    QwenContentBlock::ToolUse { name, .. } => name.as_deref(),
                    _ => None,
                })
            })
    }

    pub(crate) fn contribution_strings(&self) -> &[String] {
        &self.contribution_strings
    }
}

fn qwen_accounting_kind(
    discriminator: Option<&str>,
    role: Option<&str>,
    blocks: &Option<Vec<QwenContentBlock>>,
    tool_calls: &[QwenToolFields],
    tool: &QwenToolFields,
) -> RecordKind {
    let has_tool_use = blocks.as_ref().is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| matches!(block, QwenContentBlock::ToolUse { .. }))
    }) || !tool_calls.is_empty()
        || matches!(discriminator, Some("tool_call"))
        || (discriminator == Some("tool") && tool.result.is_none() && tool.error.is_none());
    if has_tool_use {
        return RecordKind::ToolCall;
    }
    if blocks.as_ref().is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| matches!(block, QwenContentBlock::ToolResult { .. }))
    }) || matches!(discriminator, Some("tool_result"))
        || tool.result.is_some()
        || tool.error.is_some()
    {
        return RecordKind::ToolResult;
    }
    match (discriminator, role) {
        (Some("user_message" | "user"), _) | (Some("text"), Some("user")) => {
            RecordKind::UserMessage
        }
        (Some("assistant_message" | "assistant" | "gemini" | "model"), _)
        | (Some("text"), Some("assistant" | "model")) => RecordKind::AssistantMessage,
        (Some("session_meta"), _) => RecordKind::SessionMeta,
        _ => RecordKind::Other,
    }
}

pub(crate) fn qwen_discriminator(value: &Value) -> Option<&str> {
    qwen_selected_envelope(value).map(|envelope| envelope.discriminator)
}

#[derive(Clone, Copy)]
struct QwenSelectedEnvelope<'a> {
    value: &'a Value,
    discriminator: &'a str,
}

fn qwen_selected_envelope(value: &Value) -> Option<QwenSelectedEnvelope<'_>> {
    if let Some(payload) = value.get("payload") {
        if let Some(discriminator) = payload.get("type").and_then(Value::as_str) {
            return Some(QwenSelectedEnvelope {
                value: payload,
                discriminator,
            });
        }
        if let Some(nested_payload) = payload.get("payload")
            && let Some(discriminator) = nested_payload.get("type").and_then(Value::as_str)
        {
            return Some(QwenSelectedEnvelope {
                value: nested_payload,
                discriminator,
            });
        }
    }
    if let Some(discriminator) = value.get("type").and_then(Value::as_str) {
        return Some(QwenSelectedEnvelope {
            value,
            discriminator,
        });
    }
    if let Some(discriminator) = value.get("role").and_then(Value::as_str) {
        return Some(QwenSelectedEnvelope {
            value,
            discriminator,
        });
    }
    value.get("message").and_then(|message| {
        message
            .get("role")
            .and_then(Value::as_str)
            .map(|discriminator| QwenSelectedEnvelope {
                value: message,
                discriminator,
            })
    })
}

fn selected_field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .get(key)
        .or_else(|| value.get("message").and_then(|message| message.get(key)))
}

fn selected_string_field(value: &Value, key: &str) -> Option<String> {
    selected_field(value, key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn has_payload_discriminator(value: &Value) -> bool {
    value
        .get("payload")
        .and_then(|payload| payload.get("type"))
        .is_some_and(Value::is_string)
        || value
            .get("payload")
            .and_then(|payload| payload.get("payload"))
            .and_then(|payload| payload.get("type"))
            .is_some_and(Value::is_string)
}

pub(crate) fn is_known_qwen_discriminator(kind: &str) -> bool {
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
    let selected = qwen_selected_envelope(value)?;
    selected_field(selected.value, "content").and_then(Value::as_array)
}

fn qwen_role(value: &Value) -> Option<String> {
    let selected = qwen_selected_envelope(value)?;
    selected_string_field(selected.value, "role").or_else(|| match selected.discriminator {
        "user_message" | "user" => Some("user".to_owned()),
        "assistant_message" | "assistant" | "gemini" | "model" => Some("assistant".to_owned()),
        _ => None,
    })
}

fn canonical_session_id(value: &Value) -> Result<Option<String>, AcquisitionError> {
    let Some(selected) = qwen_selected_envelope(value) else {
        return Ok(None);
    };
    let mut envelopes = vec![selected.value];
    if let Some(message) = selected.value.get("message").filter(|v| v.is_object()) {
        envelopes.push(message);
    }
    session_identity(envelopes.into_iter().flat_map(|envelope| {
        ["session_id", "sessionID", "sessionId"]
            .into_iter()
            .filter_map(move |key| envelope.get(key))
    }))
}

fn qwen_metadata(value: &Value) -> Result<SessionMetadata, AcquisitionError> {
    SessionMetadata::from_fields(
        value,
        &["agent", "agent_nickname"],
        &["model", "model_name", "modelID"],
        &["provider", "providerID", "model_provider"],
    )
}

fn qwen_message_content(value: &Value) -> Option<Value> {
    let selected = qwen_selected_envelope(value)?;
    selected_field(selected.value, "content")
        .cloned()
        .or_else(|| {
            if !is_known_qwen_discriminator(selected.discriminator) {
                return None;
            }
            selected
                .value
                .get("message")
                .and_then(Value::as_str)
                .map(|message| Value::String(message.to_owned()))
        })
}

fn qwen_content_block(value: &Value) -> QwenContentBlock {
    let Some(object) = value.as_object() else {
        return QwenContentBlock::Unknown;
    };
    match object.get("type").and_then(Value::as_str) {
        Some("text") => QwenContentBlock::Text {
            text: object
                .get("text")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        },
        Some("tool_use") => QwenContentBlock::ToolUse {
            call_id: qwen_tool_object_call_id(object),
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
                .or_else(|| object.get("result"))
                .or_else(|| object.get("output"))
                .cloned();
            QwenContentBlock::ToolResult {
                tool_call_id: qwen_result_call_id_object(object),
                result_present: result.is_some(),
                result,
                is_error: object.get("is_error").and_then(Value::as_bool),
                is_error_present: object.contains_key("is_error"),
            }
        }
        _ => QwenContentBlock::Unknown,
    }
}

fn qwen_tool_calls(value: &Value) -> Vec<QwenToolFields> {
    let calls = qwen_selected_envelope(value)
        .and_then(|envelope| selected_field(envelope.value, "tool_calls"))
        .and_then(Value::as_array);
    calls
        .into_iter()
        .flat_map(|calls| calls.iter())
        .map(qwen_tool_call_fields)
        .collect()
}

fn qwen_tool_call_fields(value: &Value) -> QwenToolFields {
    let arguments = value.get("arguments").or_else(|| value.get("input"));
    QwenToolFields {
        name: value
            .get("name")
            .or_else(|| value.get("tool_name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        arguments: arguments.cloned(),
        arguments_present: arguments.is_some(),
        call_id: value.as_object().and_then(qwen_tool_object_call_id),
        ..QwenToolFields::default()
    }
}

fn qwen_tool_fields(value: &Value) -> QwenToolFields {
    let Some(selected) = qwen_selected_envelope(value) else {
        return QwenToolFields::default();
    };
    let value = selected.value;
    let discriminator = selected.discriminator;
    let is_generic = discriminator == "tool";
    let arguments = selected_field(value, "arguments")
        .or_else(|| selected_field(value, "input"))
        .or_else(|| {
            if is_generic {
                selected_state_field(value, "input")
            } else {
                None
            }
        });
    let result = if discriminator == "tool_result" {
        selected_field(value, "content")
            .or_else(|| selected_field(value, "result"))
            .or_else(|| selected_field(value, "output"))
    } else if is_generic {
        selected_field(value, "output")
            .or_else(|| selected_state_field(value, "output"))
            .or_else(|| selected_field(value, "result"))
    } else {
        None
    };
    let error = if is_generic {
        selected_field(value, "error").or_else(|| selected_state_field(value, "error"))
    } else {
        selected_field(value, "error")
    };

    QwenToolFields {
        name: selected_string_field(value, "tool_name")
            .or_else(|| selected_string_field(value, "tool"))
            .or_else(|| selected_string_field(value, "name")),
        arguments: arguments.cloned(),
        arguments_present: arguments.is_some(),
        call_id: if discriminator == "tool_result" {
            qwen_selected_result_call_id(selected)
        } else {
            qwen_selected_call_id(selected)
        },
        result_present: result.is_some(),
        result: result.cloned(),
        error_present: error.is_some(),
        error: error.cloned(),
        is_error: selected_field(value, "is_error").and_then(Value::as_bool),
        is_error_present: selected_field(value, "is_error").is_some(),
        status: selected_state_field(value, "status")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    }
}

fn qwen_native_id(value: &Value, discriminator: Option<&str>) -> Option<String> {
    if !matches!(
        discriminator,
        Some(
            "user_message"
                | "user"
                | "assistant_message"
                | "assistant"
                | "gemini"
                | "model"
                | "text"
        )
    ) {
        return None;
    }
    let discriminator = discriminator?;
    let selected = qwen_selected_envelope(value)?;
    (selected.discriminator == discriminator)
        .then(|| selected_field(selected.value, "id"))
        .flatten()
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn qwen_selected_call_id(selected: QwenSelectedEnvelope<'_>) -> Option<String> {
    qwen_explicit_call_id_selected(selected)
}

fn qwen_selected_result_call_id(selected: QwenSelectedEnvelope<'_>) -> Option<String> {
    qwen_explicit_call_id_selected(selected)
}

fn qwen_explicit_call_id_selected(selected: QwenSelectedEnvelope<'_>) -> Option<String> {
    let selected_value = selected.value;
    let call_id = [
        "tool_call_id",
        "call_id",
        "callID",
        "callId",
        "toolCallId",
        "tool_use_id",
    ]
    .into_iter()
    .find_map(|key| {
        selected_field(selected_value, key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    });
    call_id.or_else(|| {
        selected_value
            .get("tool_result")
            .and_then(Value::as_object)
            .and_then(qwen_explicit_call_id_object)
    })
}

fn qwen_explicit_call_id_object(value: &serde_json::Map<String, Value>) -> Option<String> {
    [
        "tool_call_id",
        "call_id",
        "callID",
        "callId",
        "toolCallId",
        "tool_use_id",
    ]
    .into_iter()
    .find_map(|key| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn qwen_tool_object_call_id(value: &serde_json::Map<String, Value>) -> Option<String> {
    qwen_explicit_call_id_object(value).or_else(|| {
        value
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn qwen_result_call_id_object(value: &serde_json::Map<String, Value>) -> Option<String> {
    [
        "tool_call_id",
        "call_id",
        "callID",
        "callId",
        "toolCallId",
        "tool_use_id",
    ]
    .into_iter()
    .find_map(|key| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn selected_state_field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get("state").and_then(|state| state.get(key))
}
