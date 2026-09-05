#![allow(dead_code)]

use serde_json::Value;

use crate::parser::{
    ParseError, arguments_field, default_source_file_stem, read_jsonl_values, record_content,
    session_id_with_fallback, string_field,
};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

#[derive(Clone)]
pub(crate) enum OpenClawContentBlock {
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
        result: Option<Value>,
        result_present: bool,
        is_error: Option<bool>,
        is_error_present: bool,
    },
    Unknown,
}

#[derive(Clone, Default)]
pub(crate) struct OpenClawToolFields {
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
pub(crate) struct OpenClawNativeRecord {
    pub(crate) source_sequence: u64,
    pub(crate) native_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) legacy_session_id: String,
    pub(crate) reported_agent: Option<String>,
    pub(crate) reported_provider: Option<String>,
    pub(crate) reported_model: Option<String>,
    pub(crate) legacy_effective_agent: Option<String>,
    pub(crate) legacy_effective_provider: Option<String>,
    pub(crate) legacy_effective_model: Option<String>,
    pub(crate) timestamp: Option<String>,
    pub(crate) source_timestamp: Option<String>,
    pub(crate) discriminator: Option<String>,
    pub(crate) payload_discriminator: bool,
    pub(crate) role: Option<String>,
    pub(crate) message_content: Option<Value>,
    pub(crate) blocks: Option<Vec<OpenClawContentBlock>>,
    pub(crate) tool_calls: Vec<OpenClawToolFields>,
    pub(crate) tool: OpenClawToolFields,
    pub(crate) legacy_kind: RecordKind,
    pub(crate) legacy_tool_name: Option<String>,
    pub(crate) legacy_arguments: Option<String>,
    pub(crate) legacy_content: String,
}

pub(crate) fn extract_openclaw_native_records(
    source: &Source,
) -> Result<Vec<OpenClawNativeRecord>, ParseError> {
    let values = read_jsonl_values(source)?;
    let default_session_id = default_source_file_stem(source);
    let mut records = Vec::with_capacity(values.len());
    let mut effective_agent = None;
    let mut effective_provider = None;
    let mut effective_model = None;

    for (source_sequence, value) in values.into_iter().enumerate() {
        if !value.is_object() {
            return Err(ParseError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "JSONL record envelope must be an object",
            });
        }

        let selected_envelope = openclaw_selected_envelope(&value);
        let reported_agent = selected_envelope
            .and_then(|envelope| selected_string_field(envelope.value, "agent_nickname"))
            .or_else(|| {
                selected_envelope
                    .and_then(|envelope| selected_string_field(envelope.value, "agent"))
            });
        let reported_provider = selected_envelope
            .and_then(|envelope| selected_string_field(envelope.value, "model_provider"))
            .or_else(|| {
                selected_envelope
                    .and_then(|envelope| selected_string_field(envelope.value, "providerID"))
            })
            .or_else(|| {
                selected_envelope
                    .and_then(|envelope| selected_string_field(envelope.value, "provider"))
            });
        let reported_model = selected_envelope
            .and_then(|envelope| selected_string_field(envelope.value, "model"))
            .or_else(|| {
                selected_envelope
                    .and_then(|envelope| selected_string_field(envelope.value, "model_name"))
            })
            .or_else(|| {
                selected_envelope
                    .and_then(|envelope| selected_string_field(envelope.value, "modelID"))
            });

        // The effective values deliberately retain the pre-v2 legacy lookup,
        // including its session_meta compatibility behavior.
        effective_agent = effective_agent
            .or_else(|| string_field(&value, "agent_nickname"))
            .or_else(|| string_field(&value, "agent"));
        effective_provider = effective_provider
            .or_else(|| string_field(&value, "model_provider"))
            .or_else(|| string_field(&value, "providerID"))
            .or_else(|| string_field(&value, "provider"));
        effective_model = effective_model
            .or_else(|| string_field(&value, "model"))
            .or_else(|| string_field(&value, "model_name"))
            .or_else(|| string_field(&value, "modelID"));

        let discriminator = openclaw_discriminator(&value).map(ToOwned::to_owned);
        let legacy_kind = openclaw_record_kind(&value);
        let native = OpenClawNativeRecord {
            source_sequence: source_sequence as u64,
            native_id: openclaw_native_id(&value, discriminator.as_deref()),
            session_id: canonical_session_id(&value),
            legacy_session_id: session_id_with_fallback(&value, &default_session_id),
            reported_agent,
            reported_provider,
            reported_model,
            legacy_effective_agent: effective_agent.clone(),
            legacy_effective_provider: effective_provider.clone(),
            legacy_effective_model: effective_model.clone(),
            timestamp: string_field(&value, "timestamp"),
            source_timestamp: selected_envelope
                .and_then(|envelope| selected_string_field(envelope.value, "timestamp")),
            discriminator,
            payload_discriminator: has_payload_discriminator(&value),
            role: openclaw_role(&value),
            message_content: openclaw_message_content(&value),
            blocks: content_blocks(&value)
                .map(|blocks| blocks.iter().map(openclaw_content_block).collect()),
            tool_calls: openclaw_tool_calls(&value),
            tool: openclaw_tool_fields(&value),
            legacy_kind,
            legacy_tool_name: openclaw_tool_name(&value),
            legacy_arguments: arguments_field(&value)
                .or_else(|| openclaw_tool_input_as_string(&value)),
            legacy_content: record_content(&value),
        };
        records.push(native);
    }

    Ok(records)
}

pub(crate) fn openclaw_record_kind(value: &Value) -> RecordKind {
    let discriminator = openclaw_discriminator(value);
    if discriminator.is_some_and(|kind| !is_known_openclaw_discriminator(kind)) {
        return RecordKind::Other;
    }

    if legacy_content_blocks(value).is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
    }) {
        return RecordKind::ToolCall;
    }
    if legacy_content_blocks(value).is_some_and(|blocks| {
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
        Some("tool") if openclaw_tool_part_is_result(value) => RecordKind::ToolResult,
        Some("tool") => RecordKind::ToolCall,
        Some("session_meta") => RecordKind::SessionMeta,
        _ if value.get("session_meta").is_some() => RecordKind::SessionMeta,
        _ => RecordKind::Other,
    }
}

pub(crate) fn openclaw_discriminator(value: &Value) -> Option<&str> {
    openclaw_selected_envelope(value).map(|envelope| envelope.discriminator)
}

#[derive(Clone, Copy)]
struct OpenClawSelectedEnvelope<'a> {
    value: &'a Value,
    discriminator: &'a str,
}

fn openclaw_selected_envelope(value: &Value) -> Option<OpenClawSelectedEnvelope<'_>> {
    if let Some(payload) = value.get("payload") {
        if let Some(discriminator) = payload.get("type").and_then(Value::as_str) {
            return Some(OpenClawSelectedEnvelope {
                value: payload,
                discriminator,
            });
        }
        if let Some(nested_payload) = payload.get("payload")
            && let Some(discriminator) = nested_payload.get("type").and_then(Value::as_str)
        {
            return Some(OpenClawSelectedEnvelope {
                value: nested_payload,
                discriminator,
            });
        }
    }
    if let Some(discriminator) = value.get("type").and_then(Value::as_str) {
        return Some(OpenClawSelectedEnvelope {
            value,
            discriminator,
        });
    }
    if let Some(discriminator) = value.get("role").and_then(Value::as_str) {
        return Some(OpenClawSelectedEnvelope {
            value,
            discriminator,
        });
    }
    value.get("message").and_then(|message| {
        message
            .get("role")
            .and_then(Value::as_str)
            .map(|discriminator| OpenClawSelectedEnvelope {
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

pub(crate) fn is_known_openclaw_discriminator(kind: &str) -> bool {
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

pub(crate) fn openclaw_tool_part_is_result(value: &Value) -> bool {
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

pub(crate) fn openclaw_tool_name(value: &Value) -> Option<String> {
    string_field(value, "tool_name")
        .or_else(|| string_field(value, "tool"))
        .or_else(|| string_field(value, "name"))
        .or_else(|| {
            legacy_content_blocks(value)?
                .iter()
                .find(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))?
                .get("name")?
                .as_str()
                .map(ToString::to_string)
        })
}

pub(crate) fn openclaw_tool_input_as_string(value: &Value) -> Option<String> {
    let input = legacy_content_blocks(value)?
        .iter()
        .find(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))?
        .get("input")?;
    match input {
        Value::String(item) => Some(item.clone()),
        Value::Null => None,
        item => serde_json::to_string(item).ok(),
    }
}

fn content_blocks(value: &Value) -> Option<&Vec<Value>> {
    let selected = openclaw_selected_envelope(value)?;
    selected_field(selected.value, "content").and_then(Value::as_array)
}

fn legacy_content_blocks(value: &Value) -> Option<&Vec<Value>> {
    value
        .get("message")
        .and_then(|message| message.get("content"))
        .or_else(|| value.get("content"))
        .and_then(Value::as_array)
}

fn openclaw_role(value: &Value) -> Option<String> {
    let selected = openclaw_selected_envelope(value)?;
    selected_string_field(selected.value, "role").or_else(|| match selected.discriminator {
        "user_message" | "user" => Some("user".to_owned()),
        "assistant_message" | "assistant" | "gemini" | "model" => Some("assistant".to_owned()),
        _ => None,
    })
}

fn canonical_session_id(value: &Value) -> Option<String> {
    let selected = openclaw_selected_envelope(value)?;
    ["session_id", "sessionID", "sessionId"]
        .into_iter()
        .find_map(|key| {
            selected_field(selected.value, key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
}

fn openclaw_message_content(value: &Value) -> Option<Value> {
    let selected = openclaw_selected_envelope(value)?;
    selected_field(selected.value, "content")
        .cloned()
        .or_else(|| {
            if !is_known_openclaw_discriminator(selected.discriminator) {
                return None;
            }
            selected
                .value
                .get("message")
                .and_then(Value::as_str)
                .map(|message| Value::String(message.to_owned()))
        })
}

fn openclaw_content_block(value: &Value) -> OpenClawContentBlock {
    let Some(object) = value.as_object() else {
        return OpenClawContentBlock::Unknown;
    };
    match object.get("type").and_then(Value::as_str) {
        Some("text") => OpenClawContentBlock::Text {
            text: object
                .get("text")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        },
        Some("tool_use") => OpenClawContentBlock::ToolUse {
            id: openclaw_call_id_object(object),
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
            OpenClawContentBlock::ToolResult {
                tool_use_id: openclaw_result_call_id_object(object),
                result_present: result.is_some(),
                result,
                is_error: object.get("is_error").and_then(Value::as_bool),
                is_error_present: object.contains_key("is_error"),
            }
        }
        _ => OpenClawContentBlock::Unknown,
    }
}

fn openclaw_tool_calls(value: &Value) -> Vec<OpenClawToolFields> {
    let calls = openclaw_selected_envelope(value)
        .and_then(|envelope| selected_field(envelope.value, "tool_calls"))
        .and_then(Value::as_array);
    calls
        .into_iter()
        .flat_map(|calls| calls.iter())
        .map(openclaw_tool_call_fields)
        .collect()
}

fn openclaw_tool_call_fields(value: &Value) -> OpenClawToolFields {
    let arguments = value.get("arguments").or_else(|| value.get("input"));
    OpenClawToolFields {
        name: value
            .get("name")
            .or_else(|| value.get("tool_name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        arguments: arguments.cloned(),
        arguments_present: arguments.is_some(),
        call_id: value.as_object().and_then(openclaw_call_id_object),
        ..OpenClawToolFields::default()
    }
}

fn openclaw_tool_fields(value: &Value) -> OpenClawToolFields {
    let Some(selected) = openclaw_selected_envelope(value) else {
        return OpenClawToolFields::default();
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

    OpenClawToolFields {
        name: selected_string_field(value, "tool_name")
            .or_else(|| selected_string_field(value, "tool"))
            .or_else(|| selected_string_field(value, "name")),
        arguments: arguments.cloned(),
        arguments_present: arguments.is_some(),
        call_id: if discriminator == "tool_result" {
            openclaw_selected_result_call_id(selected)
        } else {
            openclaw_selected_call_id(selected)
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

fn openclaw_native_id(value: &Value, discriminator: Option<&str>) -> Option<String> {
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
    let selected = openclaw_selected_envelope(value)?;
    (selected.discriminator == discriminator)
        .then(|| selected_field(selected.value, "id"))
        .flatten()
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn openclaw_selected_call_id(selected: OpenClawSelectedEnvelope<'_>) -> Option<String> {
    let selected_value = selected.value;
    [
        "id",
        "tool_call_id",
        "tool_use_id",
        "call_id",
        "callID",
        "callId",
        "toolCallId",
    ]
    .into_iter()
    .find_map(|key| {
        selected_field(selected_value, key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
    .or_else(|| {
        selected_value
            .get("tool_result")
            .and_then(Value::as_object)
            .and_then(openclaw_call_id_object)
    })
}

fn openclaw_selected_result_call_id(selected: OpenClawSelectedEnvelope<'_>) -> Option<String> {
    let selected_value = selected.value;
    selected_field(selected_value, "tool_call_id")
        .or_else(|| selected_field(selected_value, "tool_use_id"))
        .or_else(|| selected_field(selected_value, "call_id"))
        .or_else(|| selected_field(selected_value, "callID"))
        .or_else(|| selected_field(selected_value, "callId"))
        .or_else(|| selected_field(selected_value, "toolCallId"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            selected_value
                .get("tool_result")
                .and_then(Value::as_object)
                .and_then(openclaw_result_call_id_object)
        })
}

fn openclaw_call_id_object(value: &serde_json::Map<String, Value>) -> Option<String> {
    [
        "id",
        "tool_call_id",
        "tool_use_id",
        "call_id",
        "callID",
        "callId",
        "toolCallId",
    ]
    .into_iter()
    .find_map(|key| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn openclaw_result_call_id_object(value: &serde_json::Map<String, Value>) -> Option<String> {
    [
        "tool_call_id",
        "tool_use_id",
        "call_id",
        "callID",
        "callId",
        "toolCallId",
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
