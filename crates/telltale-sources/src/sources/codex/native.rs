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

#[derive(Debug, Clone, PartialEq)]
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
    pub(crate) call_id: Option<String>,
    pub(crate) result: Option<Value>,
    pub(crate) result_present: bool,
    pub(crate) status: Option<String>,
    pub(crate) error: Option<Value>,
    pub(crate) error_present: bool,
    pub(crate) is_error: Option<bool>,
    pub(crate) is_error_present: bool,
    pub(crate) command: Option<String>,
    pub(crate) cwd: Option<String>,
    pub(crate) completed_command: bool,
    pub(crate) output_fidelity: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub(crate) struct CompletedCoordinates {
    pub(crate) turn_id: String,
    pub(crate) item_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CodexNativeRecord {
    pub(crate) attestation: Result<SessionMetadata, AcquisitionError>,
    pub(crate) source_sequence: u64,
    pub(crate) adapter_id: String,
    pub(crate) effective_session_id: Option<String>,
    pub(crate) timestamp: Option<String>,
    pub(crate) discriminator: Option<String>,
    pub(crate) session_metadata: bool,
    pub(crate) auxiliary: bool,
    pub(crate) external_import: bool,
    pub(crate) role: Option<String>,
    pub(crate) message_content: Option<Value>,
    pub(crate) blocks: Option<Vec<CodexContentBlock>>,
    pub(crate) tool: CodexToolFields,
    /// Source strings scanned for tool-call activity contributions.
    pub(crate) contribution_strings: Vec<String>,
    pub(crate) completed: Option<CompletedCoordinates>,
    pub(crate) root_session_id: Option<String>,
    pub(crate) response_id: Option<String>,
    pub(crate) response_turn_id: Option<String>,
    pub(crate) paginated: bool,
    pub(crate) mirrored: bool,
}

#[cfg(test)]
pub(crate) fn extract_codex_native_records(
    source: &Source,
) -> Result<Vec<CodexNativeRecord>, SourceReadError> {
    extract_codex_native_records_with_limits(source, None)
}

pub(crate) fn extract_codex_native_records_with_limits(
    source: &Source,
    limits: Option<crate::acquisition::DirectReadLimits>,
) -> Result<Vec<CodexNativeRecord>, SourceReadError> {
    let values = match limits {
        Some(limits) => crate::source_read::read_jsonl_values_with_limits(source, Some(limits))?,
        None => read_jsonl_values(source)?,
    };
    let ordinal_mode =
        validate_native_ordinals(&values).map_err(|detail| SourceReadError::SchemaDrift {
            client: source.client,
            source_id: source.source_id.clone(),
            detail,
        })?;
    let mut records = Vec::with_capacity(values.len());
    let mut inherited_session_id = None;
    let mut import_turns = std::collections::BTreeMap::new();
    let mut inherited_root_id = None;
    let mut paginated = false;

    for (position, value) in values.into_iter().enumerate() {
        let source_sequence = if ordinal_mode {
            value
                .get("ordinal")
                .and_then(Value::as_u64)
                .expect("validated native ordinal")
        } else {
            position as u64
        };
        if !value.is_object() {
            return Err(SourceReadError::SchemaDrift {
                client: source.client,
                source_id: source.source_id.clone(),
                detail: "JSONL record envelope must be an object",
            });
        }

        let record_value = codex_record_value(&value);
        let drift = |detail| SourceReadError::SchemaDrift {
            client: source.client,
            source_id: source.source_id.clone(),
            detail,
        };
        let auxiliary = is_codex_auxiliary(&value).map_err(drift)?;
        if !auxiliary && codex_discriminator(&value) == Some("item_completed") {
            records.push(
                completed_record(
                    &value,
                    source,
                    source_sequence,
                    inherited_session_id.as_deref(),
                    inherited_root_id.clone(),
                    paginated,
                )
                .map_err(drift)?,
            );
            continue;
        }
        let envelope = codex_envelope(&value);
        let semantic_value = codex_semantic_value(&value, envelope);
        let response_message = envelope == CodexEnvelope::ResponseItem
            && value
                .get("payload")
                .and_then(|p| p.get("type"))
                .and_then(Value::as_str)
                == Some("message");
        let metadata_payload = (value.get("type").and_then(Value::as_str) == Some("session_meta"))
            .then(|| value.get("payload"))
            .flatten()
            .filter(|p| p.is_object());
        let public_meta = metadata_payload.filter(|p| p.get("id").is_some());
        if metadata_payload.is_some_and(|p| {
            ["history_base", "subagent_history_start_ordinal"]
                .iter()
                .any(|key| p.get(key).is_some_and(|v| !v.is_null()))
        }) {
            return Err(drift("Codex inherited history coordinates are unsupported"));
        }
        let ownership = if let Some(meta) = public_meta {
            let id = required_string(meta, "id").map_err(drift)?;
            if let Some(root) = meta.get("session_id").filter(|v| !v.is_null()) {
                required_string(meta, "session_id").map_err(drift)?;
                session_identity([root])
                    .map_err(|_| drift("Codex root session correlation is invalid"))?;
            }
            let owner = Value::String(id.to_owned());
            session_identity(
                std::iter::once(&owner)
                    .chain(
                        ["session_id", "sessionID", "sessionId", "thread_id"]
                            .into_iter()
                            .filter_map(|key| value.get(key)),
                    )
                    .chain(
                        ["sessionID", "sessionId", "thread_id"]
                            .into_iter()
                            .filter_map(|key| meta.get(key)),
                    ),
            )
        } else {
            session_identity(
                codex_envelopes(&value, semantic_value)
                    .into_iter()
                    .flat_map(|envelope| {
                        ["session_id", "sessionID", "sessionId"]
                            .into_iter()
                            .filter_map(move |key| envelope.get(key))
                    }),
            )
        };
        let session_id = ownership.as_ref().ok().cloned().flatten();
        let discriminator = codex_discriminator(record_value).map(ToOwned::to_owned);
        let session_metadata = !auxiliary
            && (discriminator.as_deref() == Some("session_meta")
                || (discriminator.is_none() && value.get("session_meta").is_some()));
        let effective_session_id = session_id.clone().or(inherited_session_id.clone());
        if value.get("type").and_then(Value::as_str) == Some("event_msg")
            && let Some(payload) = value.get("payload")
            && payload.get("type").and_then(Value::as_str) == Some("task_started")
            && let Some(turn) = payload.get("turn_id").and_then(Value::as_str)
        {
            import_turns.insert(
                effective_session_id.clone(),
                turn.starts_with("external-import-turn-"),
            );
        }
        let external_import = import_turns
            .get(&effective_session_id)
            .copied()
            .unwrap_or(false);
        if response_message {
            for envelope in [&value, semantic_value] {
                if let Some(thread) = envelope.get("thread_id")
                    && (thread.as_str().is_none_or(|id| id.trim().is_empty())
                        || effective_session_id
                            .as_deref()
                            .is_some_and(|owner| thread.as_str() != Some(owner)))
                {
                    return Err(drift("Codex raw response has conflicting thread ownership"));
                }
            }
        }
        let response_turn_id = if response_message {
            raw_message_turn_id(&value, semantic_value).map_err(drift)?
        } else {
            None
        };
        let blocks = (!auxiliary)
            .then(|| content_blocks(semantic_value))
            .flatten()
            .map(|blocks| blocks.iter().map(codex_content_block).collect());
        let tool = if auxiliary {
            CodexToolFields::default()
        } else {
            codex_tool_fields(semantic_value)
        };
        let role = if auxiliary {
            None
        } else {
            codex_role(&value, semantic_value)
        };
        let is_tool_call = !auxiliary
            && codex_accounting_kind(discriminator.as_deref(), role.as_deref(), &blocks, &tool)
                == RecordKind::ToolCall;
        let native = CodexNativeRecord {
            attestation: ownership.and_then(|_| codex_attestation(&value, semantic_value)),
            source_sequence,
            adapter_id: source.source_id.clone(),
            effective_session_id,
            timestamp: nested_string_field(&value, "timestamp"),
            discriminator,
            session_metadata,
            auxiliary,
            external_import,
            role: role.clone(),
            message_content: if auxiliary {
                None
            } else {
                codex_message_content(semantic_value)
            },
            contribution_strings: if is_tool_call {
                collect_string_values(record_value)
            } else {
                Vec::new()
            },
            blocks,
            tool,
            completed: None,
            root_session_id: None,
            response_id: response_message
                .then(|| {
                    semantic_value
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|v| !v.is_empty())
                        .map(ToOwned::to_owned)
                })
                .flatten(),
            response_turn_id,
            paginated,
            mirrored: false,
        };

        if session_metadata
            && value.get("type").and_then(Value::as_str) == Some("session_meta")
            && let Some(session_id) = session_id
        {
            inherited_session_id = Some(session_id);
            inherited_root_id = public_meta
                .and_then(|p| p.get("session_id"))
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned);
            paginated = public_meta.is_some_and(|p| {
                p.get("history_mode").and_then(Value::as_str) == Some("paginated")
            });
        }
        records.push(native);
    }

    resolve_mirrors(&mut records).map_err(|detail| SourceReadError::SchemaDrift {
        client: source.client,
        source_id: source.source_id.clone(),
        detail,
    })?;
    Ok(records)
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| {
            !v.trim().is_empty()
                && v.len() <= telltale_schema::observation::LOCAL_MAX_STRING_BYTES
                && !v.chars().any(char::is_control)
        })
        .ok_or("Codex source coordinates must be nonempty bounded strings")
}

fn validate_native_ordinals(values: &[Value]) -> Result<bool, &'static str> {
    if !values.iter().any(|value| value.get("ordinal").is_some()) {
        return Ok(false);
    }
    let first = values.first().expect("ordinal mode has a record");
    let metadata = first
        .get("payload")
        .filter(|v| v.is_object())
        .ok_or("Codex native ordinal mode requires public session metadata first")?;
    if first.get("type").and_then(Value::as_str) != Some("session_meta")
        || metadata.get("history_mode").and_then(Value::as_str) != Some("paginated")
        || metadata.get("type").is_some()
        || metadata.get("payload").is_some()
    {
        return Err("Codex native ordinal mode requires exact paginated session metadata first");
    }
    required_string(metadata, "id")?;
    if ["history_base", "subagent_history_start_ordinal"]
        .iter()
        .any(|key| metadata.get(key).is_some_and(|v| !v.is_null()))
    {
        return Err("Codex referenced or inherited ordinal history is unsupported");
    }
    let mut expected = Some(0_u64);
    for value in values {
        let ordinal = value
            .get("ordinal")
            .and_then(Value::as_u64)
            .ok_or("Codex native ordinal mode requires a u64 ordinal on every record")?;
        if expected != Some(ordinal) {
            return Err("Codex native ordinals must start at zero and remain consecutive");
        }
        expected = ordinal.checked_add(1);
    }
    Ok(true)
}

fn raw_message_turn_id(value: &Value, payload: &Value) -> Result<Option<String>, &'static str> {
    let turn = match payload.get("internal_chat_message_metadata_passthrough") {
        None | Some(Value::Null) => None,
        Some(metadata) if metadata.is_object() => match metadata.get("turn_id") {
            None | Some(Value::Null) => None,
            Some(_) => Some(required_string(metadata, "turn_id")?),
        },
        Some(_) => return Err("Codex raw message passthrough metadata must be an object"),
    };
    let mut consistent_turn = turn;
    for envelope in [value, payload] {
        if envelope.get("turn_id").is_some() {
            let coordinate = required_string(envelope, "turn_id")?;
            if consistent_turn.is_some_and(|previous| previous != coordinate) {
                return Err("Codex raw message has conflicting turn coordinates");
            }
            consistent_turn = Some(coordinate);
        }
    }
    // Harness metadata and stray direct coordinates cannot establish mirror authority.
    Ok(turn.map(ToOwned::to_owned))
}

fn completed_record(
    value: &Value,
    source: &Source,
    sequence: u64,
    inherited_owner: Option<&str>,
    root_session_id: Option<String>,
    paginated: bool,
) -> Result<CodexNativeRecord, &'static str> {
    if value.get("type").and_then(Value::as_str) != Some("event_msg") {
        return Err("Codex completed item requires exact event_msg wrapper");
    }
    let payload = value
        .get("payload")
        .filter(|v| v.is_object())
        .ok_or("Codex completed item payload must be an object")?;
    if payload.get("type").and_then(Value::as_str) != Some("item_completed") {
        return Err("Codex completed item requires direct payload discriminator");
    }
    let item = payload
        .get("item")
        .filter(|v| v.is_object())
        .ok_or("Codex completed item must be an object")?;
    let owner = required_string(payload, "thread_id")?;
    let turn_id = required_string(payload, "turn_id")?.to_owned();
    let item_id = required_string(item, "id")?.to_owned();
    for envelope in [value, payload, item] {
        for key in ["session_id", "sessionID", "sessionId", "thread_id"] {
            if let Some(id) = envelope.get(key)
                && id.as_str() != Some(owner)
            {
                return Err("Codex completed item has conflicting owner coordinates");
            }
        }
        if let Some(turn) = envelope.get("turn_id")
            && turn.as_str() != Some(&turn_id)
        {
            return Err("Codex completed item has conflicting turn coordinates");
        }
    }
    if inherited_owner.is_some_and(|id| id != owner) {
        return Err("Codex completed item disagrees with session metadata owner");
    }
    let mut tool = CodexToolFields::default();
    let mut blocks = None;
    let (discriminator, role, auxiliary) = match item.get("type").and_then(Value::as_str) {
        Some(kind @ ("AgentMessage" | "UserMessage")) => {
            let content = item
                .get("content")
                .and_then(Value::as_array)
                .ok_or("Codex completed message content must be an array")?;
            let tag = if kind == "AgentMessage" {
                "Text"
            } else {
                "text"
            };
            let mut text = Vec::with_capacity(content.len());
            for part in content {
                if part.get("type").and_then(Value::as_str) != Some(tag) {
                    return Err("Codex completed message content variant is unsupported");
                }
                text.push(CodexContentBlock::Text {
                    text: Some(
                        part.get("text")
                            .and_then(Value::as_str)
                            .ok_or("Codex completed text must be a string")?
                            .to_owned(),
                    ),
                });
            }
            blocks = Some(text);
            if kind == "AgentMessage" {
                ("assistant_message", Some("assistant"), false)
            } else {
                ("user_message", Some("user"), false)
            }
        }
        Some("Reasoning") => ("reasoning", None, true),
        Some("CommandExecution") => {
            let argv = item
                .get("command")
                .and_then(Value::as_array)
                .filter(|v| !v.is_empty() && v.iter().all(Value::is_string))
                .ok_or("Codex completed command requires structured argv")?;
            let status = item
                .get("status")
                .and_then(Value::as_str)
                .filter(|s| matches!(*s, "completed" | "failed" | "declined"))
                .ok_or("Codex completed command status is unsupported or nonterminal")?;
            let mut result = serde_json::Map::new();
            for key in ["exit_code", "aggregated_output"] {
                if let Some(v) = item.get(key) {
                    if !v.is_null()
                        && !(if key == "exit_code" {
                            v.as_i64().is_some()
                        } else {
                            v.is_string()
                        })
                    {
                        return Err("Codex completed command result field has invalid type");
                    }
                    result.insert(key.to_owned(), v.clone());
                }
            }
            tool.arguments = Some(Value::Array(argv.clone()));
            tool.call_id = Some(item_id.clone());
            tool.status = Some(status.to_owned());
            tool.result_present = !result.is_empty();
            tool.result = (!result.is_empty()).then_some(Value::Object(result));
            tool.completed_command = true;
            tool.output_fidelity = Some(
                match item.get("aggregated_output").and_then(Value::as_str) {
                    None => "not_captured",
                    Some(output)
                        if output.contains("... command output truncated for persistence ...") =>
                    {
                        "truncated"
                    }
                    Some(_) if status != "completed" => "diagnostic_or_capture",
                    Some(_) => "capture_completeness_unknown",
                },
            );
            tool.cwd = match item.get("cwd") {
                None | Some(Value::Null) => None,
                Some(Value::String(v)) => Some(v.clone()),
                _ => return Err("Codex completed command cwd must be a string"),
            };
            ("tool_result", None, false)
        }
        _ => return Err("Codex completed item variant is unsupported"),
    };
    let attestation = session_identity([&Value::String(owner.to_owned())]).and_then(|_| {
        let mut metadata = SessionMetadata::default();
        for envelope in [value, payload, item] {
            metadata.merge(&SessionMetadata::from_fields(
                envelope,
                &["agent", "agent_nickname"],
                &["model"],
                &["provider", "model_provider"],
            )?);
        }
        Ok(metadata)
    });
    Ok(CodexNativeRecord {
        attestation,
        source_sequence: sequence,
        adapter_id: source.source_id.clone(),
        effective_session_id: Some(owner.to_owned()),
        timestamp: value
            .get("timestamp")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        discriminator: Some(discriminator.to_owned()),
        session_metadata: false,
        auxiliary,
        external_import: false,
        role: role.map(ToOwned::to_owned),
        message_content: None,
        blocks,
        tool,
        contribution_strings: Vec::new(),
        completed: Some(CompletedCoordinates { turn_id, item_id }),
        root_session_id,
        response_id: None,
        response_turn_id: None,
        paginated,
        mirrored: false,
    })
}

fn resolve_mirrors(records: &mut [CodexNativeRecord]) -> Result<(), &'static str> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut assistant = BTreeMap::new();
    let mut user_turns = BTreeSet::new();
    for (index, record) in records.iter().enumerate() {
        let (Some(coords), Some(owner)) = (&record.completed, &record.effective_session_id) else {
            continue;
        };
        if record.role.as_deref() == Some("assistant") {
            let key = (
                owner.clone(),
                coords.turn_id.clone(),
                coords.item_id.clone(),
            );
            if let Some(previous) = assistant.insert(key, index)
                && records[previous].blocks != record.blocks
            {
                return Err("Codex stable-ID completed messages disagree");
            }
        } else if record.role.as_deref() == Some("user") && record.paginated {
            user_turns.insert((owner.clone(), coords.turn_id.clone()));
        }
    }
    let mut mirrored = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let (Some(owner), Some(turn)) = (&record.effective_session_id, &record.response_turn_id)
        else {
            continue;
        };
        if record.discriminator.as_deref() != Some("message")
            || !record.blocks.as_ref().is_some_and(|b| {
                b.iter()
                    .all(|p| matches!(p, CodexContentBlock::Text { text: Some(_) }))
            })
        {
            continue;
        }
        if record.role.as_deref() == Some("assistant") {
            if let Some(id) = &record.response_id
                && let Some(completed) = assistant.get(&(owner.clone(), turn.clone(), id.clone()))
            {
                if records[*completed].blocks != record.blocks {
                    return Err("Codex stable-ID message mirrors disagree");
                }
                mirrored.push(index);
            }
        } else if record.role.as_deref() == Some("user")
            && record.paginated
            && user_turns.contains(&(owner.clone(), turn.clone()))
        {
            mirrored.push(index);
        }
    }
    for index in mirrored {
        records[index].mirrored = true;
    }
    Ok(())
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
    if value.get("type").and_then(Value::as_str) == Some("world_state") {
        return vec![
            value,
            value.get("payload").expect("validated world state payload"),
        ];
    }
    let mut envelopes = vec![value, semantic];
    if let Some(message) = semantic.get("message").filter(|v| v.is_object()) {
        envelopes.push(message);
    }
    if matches!(
        value.get("type").and_then(Value::as_str),
        Some("session_meta" | "response_item" | "event_msg" | "turn_context")
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
        if self.auxiliary {
            return RecordKind::Other;
        }
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
        (_, Some("system" | "developer")) => RecordKind::Other,
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

// Own the exact outer shape here; the permissive conversational discriminator
// lookup must never grant auxiliary support to bare, unknown, or nested wrappers.
fn is_codex_auxiliary(value: &Value) -> Result<bool, &'static str> {
    if value.get("type").and_then(Value::as_str) == Some("world_state") {
        let payload = value
            .get("payload")
            .filter(|payload| payload.is_object())
            .ok_or("Codex world state payload must be an object")?;
        if payload.get("type").is_some() || payload.get("payload").is_some() {
            return Err("Codex world state payload must not contain discriminator or wrapper keys");
        }
        if !payload.get("full").is_some_and(Value::is_boolean)
            || !payload.get("state").is_some_and(Value::is_object)
        {
            return Err("Codex world state requires boolean full and object state");
        }
        return Ok(true);
    }
    let Some(payload) = value.get("payload").filter(|payload| payload.is_object()) else {
        return Ok(false);
    };
    Ok(match value.get("type").and_then(Value::as_str) {
        Some("turn_context") => {
            if payload.get("type").is_some() || payload.get("payload").is_some() {
                return Err(
                    "Codex turn context payload must not contain discriminator or wrapper keys",
                );
            }
            true
        }
        Some("response_item") => payload.get("type").and_then(Value::as_str) == Some("reasoning"),
        Some("event_msg") => matches!(
            payload.get("type").and_then(Value::as_str),
            Some(
                "task_started"
                    | "task_complete"
                    | "token_count"
                    | "agent_reasoning"
                    | "agent_reasoning_raw_content"
                    | "agent_reasoning_section_break"
                    | "reasoning_content_delta"
                    | "reasoning_raw_content_delta"
            )
        ),
        _ => false,
    })
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
        ..CodexToolFields::default()
    }
}
