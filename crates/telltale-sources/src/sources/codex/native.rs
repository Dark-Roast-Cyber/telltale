use crate::acquisition::{AcquisitionError, SessionMetadata, session_identity};
use serde_json::Value;

use crate::source_read::{SourceReadError, collect_string_values, nested_string_field};
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
    pub(crate) completed_file_change: bool,
    pub(crate) exit_code: Option<i64>,
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
    pub(crate) envelope: CodexEnvelope,
    pub(crate) message_phase: Option<String>,
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
    /// A record this adapter recognizes as a unit but cannot map; projection
    /// quarantines it by itself with this code.
    pub(crate) quarantine: Option<&'static str>,
}

#[cfg(test)]
pub(crate) fn extract_codex_native_records(
    source: &Source,
) -> Result<Vec<CodexNativeRecord>, SourceReadError> {
    extract_codex_native_records_with_limits(source, None).map(|(records, _)| records)
}

pub(crate) fn extract_codex_native_records_with_limits(
    source: &Source,
    limits: Option<crate::acquisition::DirectReadLimits>,
) -> Result<(Vec<CodexNativeRecord>, usize), SourceReadError> {
    let (values, bytes) = crate::source_read::read_jsonl_values_with_limits(source, limits)?;
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
        // Inter-agent messages persist as their own response item type, not as
        // a misplaced legacy event. That unmapped unit is quarantined by itself
        // and keeps no content; a nested wrapper still fails the source below.
        let inter_agent = envelope == CodexEnvelope::ResponseItem
            && value.get("payload").is_some_and(|p| {
                p.get("type").and_then(Value::as_str) == Some("agent_message")
                    && p.get("payload").is_none()
            });
        let legacy_message = !inter_agent
            && [&value, record_value]
                .into_iter()
                .any(|value| codex_discriminator(value) == Some("agent_message"));
        let web_search = [&value, record_value]
            .into_iter()
            .any(|value| codex_discriminator(value) == Some("web_search_call"));
        for (selected, kind, wrapper) in [
            (legacy_message, "agent_message", "event_msg"),
            (web_search, "web_search_call", "response_item"),
        ] {
            if selected
                && (value.get("type").and_then(Value::as_str) != Some(wrapper)
                    || value
                        .get("payload")
                        .and_then(|p| p.get("type"))
                        .and_then(Value::as_str)
                        != Some(kind)
                    || value
                        .get("payload")
                        .is_some_and(|p| p.get("payload").is_some()))
            {
                return Err(drift("Codex activity requires its exact direct wrapper"));
            }
        }
        let message_phase = if response_message || legacy_message {
            optional_string(semantic_value, "phase").map_err(drift)?
        } else {
            None
        };
        let metadata_payload = (value.get("type").and_then(Value::as_str) == Some("session_meta"))
            .then(|| value.get("payload"))
            .flatten()
            .filter(|p| p.is_object());
        let public_meta = metadata_payload.filter(|p| p.get("id").is_some());
        // A forked thread's file starts after its parent's history, which
        // stays in the parent's own file; only the first record of an ordinal
        // source may say so, and validate_native_ordinals checked it.
        if metadata_payload.is_some_and(|p| {
            p.get("subagent_history_start_ordinal")
                .is_some_and(|v| !v.is_null())
                || (p.get("history_base").is_some_and(|v| !v.is_null())
                    && !(ordinal_mode && position == 0))
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
        if response_message || legacy_message || web_search {
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
        let blocks = if legacy_message {
            Some(vec![CodexContentBlock::Text {
                text: Some(
                    semantic_value
                        .get("message")
                        .and_then(Value::as_str)
                        .ok_or_else(|| drift("Codex agent message must contain string text"))?
                        .to_owned(),
                ),
            }])
        } else if web_search || inter_agent {
            None
        } else {
            (!auxiliary)
                .then(|| content_blocks(semantic_value))
                .flatten()
                .map(|blocks| blocks.iter().map(codex_content_block).collect())
        };
        let (tool, quarantine) = if web_search {
            web_search_fields(semantic_value).map_err(drift)?
        } else if auxiliary || legacy_message || inter_agent {
            (
                CodexToolFields::default(),
                inter_agent.then_some("unknown_discriminator"),
            )
        } else {
            (codex_tool_fields(semantic_value), None)
        };
        let role = if legacy_message {
            Some("assistant".to_owned())
        } else if auxiliary || web_search || inter_agent {
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
            envelope,
            message_phase,
            session_metadata,
            auxiliary,
            external_import,
            role: role.clone(),
            message_content: if auxiliary || legacy_message || web_search || inter_agent {
                None
            } else {
                codex_message_content(semantic_value)
            },
            contribution_strings: if web_search {
                tool.arguments
                    .as_ref()
                    .map(collect_string_values)
                    .unwrap_or_default()
            } else if is_tool_call {
                collect_string_values(record_value)
            } else {
                Vec::new()
            },
            blocks,
            tool,
            completed: None,
            root_session_id: None,
            response_id: (response_message || web_search)
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
            quarantine,
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
    Ok((records, bytes))
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

fn optional_string(value: &Value, key: &str) -> Result<Option<String>, &'static str> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        _ => Err("Codex optional activity field must be a string"),
    }
}

fn web_search_fields(
    value: &Value,
) -> Result<(CodexToolFields, Option<&'static str>), &'static str> {
    if value.get("id").is_some_and(|id| !id.is_null()) {
        required_string(value, "id")?;
    }
    let mut tool = CodexToolFields {
        name: Some("web_search".to_owned()),
        status: optional_string(value, "status")?,
        ..CodexToolFields::default()
    };
    let action = match value.get("action") {
        None | Some(Value::Null) => return Ok((tool, None)),
        Some(action) if action.is_object() => action,
        _ => return Err("Codex web search action must be an object"),
    };
    let kind = action
        .get("type")
        .and_then(Value::as_str)
        .ok_or("Codex web search action requires a discriminator")?;
    let keys: &[&str] = match kind {
        "search" => &["query", "queries"],
        "open_page" => &["url"],
        "find_in_page" => &["url", "pattern"],
        _ => return Ok((tool, Some("unknown_discriminator"))),
    };
    let mut fields =
        serde_json::Map::from_iter([("type".to_owned(), Value::String(kind.to_owned()))]);
    for &key in keys {
        if let Some(value) = action.get(key) {
            if !value.is_null()
                && if key == "queries" {
                    !value
                        .as_array()
                        .is_some_and(|items| items.iter().all(Value::is_string))
                } else {
                    !value.is_string()
                }
            {
                return Err("Codex web search action field has invalid type");
            }
            fields.insert(key.to_owned(), value.clone());
        }
    }
    tool.arguments = Some(Value::Object(fields));
    Ok((tool, None))
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
    if metadata
        .get("subagent_history_start_ordinal")
        .is_some_and(|v| !v.is_null())
    {
        return Err("Codex referenced or inherited ordinal history is unsupported");
    }
    let mut expected = Some(history_base_end(metadata)?);
    for value in values {
        let ordinal = value
            .get("ordinal")
            .and_then(Value::as_u64)
            .ok_or("Codex native ordinal mode requires a u64 ordinal on every record")?;
        if expected != Some(ordinal) {
            return Err(
                "Codex native ordinals must start at the history base and remain consecutive",
            );
        }
        expected = ordinal.checked_add(1);
    }
    Ok(true)
}

/// Where a forked thread's own ordinals start. Its `history_base` names the
/// parent thread and the end of the parent history it continues from; that
/// history is the parent's file, not this one. Absent, ordinals start at zero.
fn history_base_end(metadata: &Value) -> Result<u64, &'static str> {
    let base = match metadata.get("history_base") {
        None | Some(Value::Null) => return Ok(0),
        Some(base) => base,
    };
    let invalid = "Codex referenced or inherited ordinal history is unsupported";
    let members = base.as_object().ok_or(invalid)?;
    if members.len() != 3 {
        return Err(invalid);
    }
    required_string(base, "thread_id").map_err(|_| invalid)?;
    base.get("end_byte_offset")
        .and_then(Value::as_u64)
        .ok_or(invalid)?;
    base.get("end_ordinal_exclusive")
        .and_then(Value::as_u64)
        .ok_or(invalid)
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
    if let Some(file_owner) = inherited_owner.filter(|id| *id != owner) {
        // A parent thread's rollout repeats its subagents' completed items.
        // The item is not this thread's: it is quarantined by itself under
        // the file's owner, never attributed or projected here.
        return Ok(CodexNativeRecord {
            attestation: Ok(SessionMetadata::default()),
            source_sequence: sequence,
            adapter_id: source.source_id.clone(),
            effective_session_id: Some(file_owner.to_owned()),
            timestamp: None,
            discriminator: Some("item_completed".to_owned()),
            envelope: CodexEnvelope::EventMessage,
            message_phase: None,
            session_metadata: false,
            auxiliary: false,
            external_import: false,
            role: None,
            message_content: None,
            blocks: None,
            tool: CodexToolFields {
                call_id: Some(item_id),
                ..CodexToolFields::default()
            },
            contribution_strings: Vec::new(),
            completed: None,
            root_session_id,
            response_id: None,
            response_turn_id: None,
            paginated,
            mirrored: false,
            quarantine: Some("foreign_thread_item"),
        });
    }
    let mut tool = CodexToolFields::default();
    let mut blocks = None;
    let mut quarantine = None;
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
                    // An image or other part this adapter cannot map leaves
                    // the message out by itself, not the whole source.
                    quarantine = Some("unknown_content_block");
                    break;
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
            blocks = quarantine.is_none().then_some(text);
            if kind == "AgentMessage" {
                ("assistant_message", Some("assistant"), false)
            } else {
                ("user_message", Some("user"), false)
            }
        }
        Some("Reasoning") => ("reasoning", None, true),
        Some("Plan") => {
            blocks = Some(vec![CodexContentBlock::Text {
                text: Some(
                    item.get("text")
                        .and_then(Value::as_str)
                        .ok_or("Codex completed plan text must be a string")?
                        .to_owned(),
                ),
            }]);
            ("plan", Some("assistant"), false)
        }
        // Lifecycle markers: a compaction point and review-mode boundaries.
        Some("ContextCompaction" | "EnteredReviewMode" | "ExitedReviewMode") => {
            ("lifecycle", None, true)
        }
        // Known activity this adapter does not map yet. Each is quarantined
        // by itself and reported, never silently dropped.
        Some("McpToolCall" | "Extension") => {
            quarantine = Some("unsupported_completed_item");
            ("item_completed", None, false)
        }
        Some("FileChange") => {
            tool.status = match item.get("status") {
                None | Some(Value::Null) => None,
                Some(Value::String(status))
                    if matches!(status.as_str(), "completed" | "failed" | "declined") =>
                {
                    Some(status.clone())
                }
                _ => return Err("Codex completed file change status is invalid"),
            };
            tool.result = completed_file_change_result(item)?;
            if tool.result.is_none() {
                quarantine = Some("unsupported_completed_item");
            }
            tool.result_present = tool.result.is_some();
            tool.completed_file_change = true;
            ("tool_result", None, false)
        }
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
            // The output is the direct tool result, so it gets the tool-result
            // text budget; the exit code is its own reported fact.
            let invalid = "Codex completed command result field has invalid type";
            let output = match item.get("aggregated_output") {
                None | Some(Value::Null) => None,
                Some(Value::String(output)) => Some(Value::String(output.clone())),
                Some(_) => return Err(invalid),
            };
            tool.exit_code = match item.get("exit_code") {
                None | Some(Value::Null) => None,
                Some(code) => Some(code.as_i64().ok_or(invalid)?),
            };
            tool.arguments = Some(Value::Array(argv.clone()));
            tool.call_id = Some(item_id.clone());
            tool.status = Some(status.to_owned());
            tool.result_present = output.is_some();
            tool.result = output;
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
        _ => {
            quarantine = Some("unknown_discriminator");
            ("item_completed", None, false)
        }
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
        envelope: CodexEnvelope::EventMessage,
        message_phase: None,
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
        quarantine,
    })
}

fn completed_file_change_result(item: &Value) -> Result<Option<Value>, &'static str> {
    let invalid = "Codex completed file change field has invalid type";
    let changes = item
        .get("changes")
        .and_then(Value::as_object)
        .ok_or(invalid)?;
    let mut admitted = serde_json::Map::new();
    let mut unsupported = false;
    for (path, change) in changes {
        let kind = change.get("type").and_then(Value::as_str).ok_or(invalid)?;
        let text_key = match kind {
            "add" | "delete" => "content",
            "update" => "unified_diff",
            _ => {
                unsupported = true;
                continue;
            }
        };
        let text = change
            .get(text_key)
            .filter(|v| v.is_string())
            .ok_or(invalid)?;
        let mut fields = serde_json::Map::from_iter([
            ("type".to_owned(), Value::String(kind.to_owned())),
            (text_key.to_owned(), text.clone()),
        ]);
        if kind == "update"
            && let Some(path) = change.get("move_path")
        {
            if !path.is_null() && !path.is_string() {
                return Err(invalid);
            }
            fields.insert("move_path".to_owned(), path.clone());
        }
        admitted.insert(path.clone(), Value::Object(fields));
    }
    let mut result = serde_json::Map::from_iter([("changes".to_owned(), Value::Object(admitted))]);
    for key in ["status", "auto_approved", "stdout", "stderr"] {
        if let Some(value) = item.get(key) {
            if !value.is_null()
                && if key == "auto_approved" {
                    !value.is_boolean()
                } else {
                    !value.is_string()
                }
            {
                return Err(invalid);
            }
            result.insert(key.to_owned(), value.clone());
        }
    }
    Ok((!unsupported).then_some(Value::Object(result)))
}

fn resolve_mirrors(records: &mut [CodexNativeRecord]) -> Result<(), &'static str> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut assistant = BTreeMap::new();
    let mut user_turns = BTreeSet::new();
    for (index, record) in records.iter().enumerate() {
        // A quarantined completed message cannot stand in for its raw mirror.
        let (Some(coords), Some(owner), None) = (
            &record.completed,
            &record.effective_session_id,
            record.quarantine,
        ) else {
            continue;
        };
        if record.role.as_deref() == Some("assistant")
            && record.discriminator.as_deref() == Some("assistant_message")
        {
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

/// Legacy events have no shared IDs. Pair only an adjacent, ordered per-text
/// fanout with one raw response, never equal text elsewhere in the session.
/// The canonical owner must validate the raw response before suppressing events.
pub(crate) fn legacy_message_group(
    records: &[CodexNativeRecord],
    start: usize,
) -> Option<(usize, usize)> {
    let raw = if records[start].is_legacy_agent_message() {
        start
            + records[start..]
                .iter()
                .take_while(|record| record.is_legacy_agent_message())
                .count()
    } else {
        start
    };
    let response = records.get(raw)?;
    if response.paginated
        || response.mirrored
        || response.envelope != CodexEnvelope::ResponseItem
        || response.discriminator.as_deref() != Some("message")
        || response.role.as_deref() != Some("assistant")
    {
        return None;
    }
    let parts = response.blocks.as_ref().filter(|parts| !parts.is_empty())?;
    let event_start = if raw == start { raw + 1 } else { start };
    let event_end = event_start.checked_add(parts.len())?;
    if raw != start && event_end != raw {
        return None;
    }
    let events = records.get(event_start..event_end)?;
    let owner = response.effective_session_id.as_ref()?;
    for (part, event) in parts.iter().zip(events) {
        if !matches!(part, CodexContentBlock::Text { text: Some(_) })
            || !event.is_legacy_agent_message()
            || event.effective_session_id.as_ref() != Some(owner)
            || event.message_phase != response.message_phase
            || event.blocks.as_deref() != Some(std::slice::from_ref(part))
        {
            return None;
        }
    }
    Some((raw, if raw == start { event_end } else { raw + 1 }))
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
    if semantic.get("type").and_then(Value::as_str) != Some("web_search_call")
        && let Some(message) = semantic.get("message").filter(|v| v.is_object())
    {
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
    pub(crate) fn is_legacy_agent_message(&self) -> bool {
        !self.paginated
            && self.envelope == CodexEnvelope::EventMessage
            && self.discriminator.as_deref() == Some("agent_message")
    }

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

    /// A content-free native coordinate for a quarantined record: the
    /// completed item, response or tool call id, when the record has one.
    pub(crate) fn quarantine_native_id(&self) -> String {
        self.completed
            .as_ref()
            .map(|coords| coords.item_id.clone())
            .or_else(|| self.response_id.clone())
            .or_else(|| self.tool.call_id.clone())
            .unwrap_or_default()
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
        Some("tool_call" | "function_call" | "custom_tool_call" | "web_search_call")
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
        // Legacy agent_message events carry an assistant role; an inter-agent
        // response item sharing the discriminator stays Other.
        (Some("assistant_message" | "assistant" | "gemini" | "model" | "plan"), _)
        | (Some("text" | "message" | "agent_message"), Some("assistant" | "model")) => {
            RecordKind::AssistantMessage
        }
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
            | "agent_message"
            | "assistant"
            | "gemini"
            | "model"
            | "text"
            | "message"
            | "tool_call"
            | "web_search_call"
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
        // Per-response token counters, and a compaction checkpoint whose
        // replacement history restates turns already in this file.
        Some("token_usage_record" | "compacted") => {
            if payload.get("type").is_some() || payload.get("payload").is_some() {
                return Err(
                    "Codex bookkeeping payload must not contain discriminator or wrapper keys",
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
                    | "turn_aborted"
                    | "thread_settings_applied"
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
