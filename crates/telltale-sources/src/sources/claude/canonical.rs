//! Maps native Claude Code records to Canonical Observation v2, including
//! per-unit quarantine. Reached only through the acquisition router.

use std::fmt;

use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId, ContentPart,
    ContentPartKind, CorrelationId, CorrelationIds, FactMetadata, FactProvenance, Fidelity,
    IngestionMode, JsonValue, MessageObservation, MessageRole, ObservationBody, ObservationBuilder,
    ObservationError, ObservationStage, ObservedAt, SemanticFacet, SourceProvenance,
    SourceTimestamp, ToolObservation,
};

use telltale_schema::observation::{CanonicalBoundContext, CanonicalFieldCategory};

use super::native::{
    ClaudeContentBlock, ClaudeNativeRecord, is_claude_metadata_discriminator,
    is_known_claude_discriminator,
};

#[derive(Clone)]
pub(crate) struct ClaudeCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
    pub(crate) scale: telltale_schema::observation::SourceScale,
}

impl ClaudeCanonicalOptions {
    pub(crate) fn new(observed_at: ObservedAt) -> Self {
        Self {
            observed_at,
            scale: telltale_schema::observation::SourceScale::FLOOR,
        }
    }

    /// Scales the source-wide retention budget; each record keeps the floor.
    pub(crate) fn with_scale(self, scale: telltale_schema::observation::SourceScale) -> Self {
        Self { scale, ..self }
    }
}

pub(crate) enum ClaudeCanonicalError {
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl ClaudeCanonicalError {
    #[cfg(test)]
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Mapping { code, .. } => code,
            Self::Observation(error) => error.code(),
        }
    }
}

impl fmt::Debug for ClaudeCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping { code, detail } => formatter
                .debug_struct("ClaudeCanonicalError::Mapping")
                .field("code", code)
                .field("detail", detail)
                .finish(),
            Self::Observation(error) => formatter
                .debug_struct("ClaudeCanonicalError::Observation")
                .field("code", &error.code())
                .finish(),
        }
    }
}

impl fmt::Display for ClaudeCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping { code, detail } => {
                write!(
                    formatter,
                    "Claude canonical mapping failed ({code}): {detail}"
                )
            }
            Self::Observation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ClaudeCanonicalError {}

impl From<ObservationError> for ClaudeCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

#[derive(Debug)]
pub(crate) struct ClaudeProjection {
    pub(crate) observations: Vec<CanonicalObservationV2>,
    /// Records left out by themselves; every other record was still mapped.
    pub(crate) quarantined: Vec<ClaudeQuarantinedRecord>,
}

/// Coordinates of a record excluded from projection, never its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeQuarantinedRecord {
    pub(crate) source_sequence: u64,
    pub(crate) code: &'static str,
    pub(crate) bound: Option<CanonicalBoundContext>,
}

/// Map each record on its own. A record whose type or content block this
/// adapter does not know, or whose own values exceed a canonical bound, is
/// quarantined so one record cannot blind the whole session. Integrity
/// failures and the source-wide retained budget still fail the source.
pub(crate) fn project_claude_native_records(
    records: &[ClaudeNativeRecord],
    options: &ClaudeCanonicalOptions,
) -> Result<ClaudeProjection, ClaudeCanonicalError> {
    let mut observations = crate::acquisition::CanonicalCollector::scaled(options.scale);
    let mut quarantined = Vec::new();
    for record in records {
        let mut unit = crate::acquisition::CanonicalCollector::default();
        match project_record(record, options, &mut unit) {
            Ok(()) => {
                for observation in unit.finish() {
                    observations.push(observation)?;
                }
            }
            Err(error) => match quarantine_code(&error) {
                Some(code) => quarantined.push(ClaudeQuarantinedRecord {
                    source_sequence: record.source_sequence,
                    code,
                    bound: match &error {
                        ClaudeCanonicalError::Observation(error) => error.bound_context(),
                        ClaudeCanonicalError::Mapping { .. } => None,
                    },
                }),
                None => return Err(error),
            },
        }
    }
    Ok(ClaudeProjection {
        observations: observations.finish(),
        quarantined,
    })
}

fn quarantine_code(error: &ClaudeCanonicalError) -> Option<&'static str> {
    match error {
        ClaudeCanonicalError::Mapping { code, .. }
            if matches!(*code, "unknown_discriminator" | "unknown_content_block") =>
        {
            Some(code)
        }
        ClaudeCanonicalError::Observation(error) if error.code() == "unbounded_value" => {
            Some("unbounded_value")
        }
        _ => None,
    }
}

fn project_record(
    record: &ClaudeNativeRecord,
    options: &ClaudeCanonicalOptions,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), ClaudeCanonicalError> {
    if let Some(kind) = record.discriminator.as_deref() {
        if is_claude_metadata_discriminator(kind) {
            return Ok(());
        }
        if !is_known_claude_discriminator(kind) {
            return Err(mapping(
                "unknown_discriminator",
                "explicit Claude record discriminator is not supported",
            ));
        }
    }

    let role = canonical_role(record)?;
    let mut child_ordinal = 0;
    let Some(blocks) = &record.blocks else {
        if !matches!(role, MessageRole::User | MessageRole::Assistant) {
            return Err(mapping(
                "unsupported_record",
                "record does not describe a conversational message",
            ));
        }
        emit_message(
            record,
            options,
            role,
            None,
            &mut child_ordinal,
            observations,
        )?;
        return Ok(());
    };

    if blocks
        .iter()
        .any(|block| matches!(block, ClaudeContentBlock::Unknown))
    {
        return Err(mapping(
            "unknown_content_block",
            "Claude content block type is not supported",
        ));
    }
    let kept = blocks
        .iter()
        .filter(|block| !matches!(block, ClaudeContentBlock::Ignored))
        .cloned()
        .collect::<Vec<_>>();
    if kept.is_empty() && !blocks.is_empty() {
        // A turn of reasoning or media only has no text or tool facts.
        return Ok(());
    }
    let blocks = &kept[..];

    let has_tool_result = blocks
        .iter()
        .any(|block| matches!(block, ClaudeContentBlock::ToolResult { .. }));
    let message_required = !(role == MessageRole::User
        && has_tool_result
        && blocks
            .iter()
            .all(|block| matches!(block, ClaudeContentBlock::ToolResult { .. })));

    let message = if message_required {
        Some(build_message_body(record, role, blocks)?)
    } else {
        None
    };

    if role == MessageRole::Assistant {
        if let Some(body) = message {
            emit_message_body(record, options, body, &mut child_ordinal, observations)?;
        }
        for block in blocks {
            if matches!(
                block,
                ClaudeContentBlock::ToolUse { .. } | ClaudeContentBlock::ToolResult { .. }
            ) {
                emit_tool(record, options, block, &mut child_ordinal, observations)?;
            }
        }
    } else {
        let mut message_emitted = false;
        for block in blocks {
            match block {
                ClaudeContentBlock::ToolResult { .. } => {
                    emit_tool(record, options, block, &mut child_ordinal, observations)?;
                }
                ClaudeContentBlock::Text { .. } | ClaudeContentBlock::ToolUse { .. } => {
                    if !message_emitted && let Some(body) = message.clone() {
                        emit_message_body(record, options, body, &mut child_ordinal, observations)?;
                        message_emitted = true;
                    }
                    if let ClaudeContentBlock::ToolUse { .. } = block {
                        emit_tool(record, options, block, &mut child_ordinal, observations)?;
                    }
                }
                ClaudeContentBlock::Ignored | ClaudeContentBlock::Unknown => unreachable!(),
            }
        }
        if message_required
            && !message_emitted
            && let Some(body) = message
        {
            emit_message_body(record, options, body, &mut child_ordinal, observations)?;
        }
    }
    Ok(())
}

fn canonical_role(record: &ClaudeNativeRecord) -> Result<MessageRole, ClaudeCanonicalError> {
    let role = record.role.as_deref().or_else(|| {
        record.discriminator.as_deref().and_then(|kind| match kind {
            "user_message" | "user" => Some("user"),
            "assistant_message" | "assistant" | "gemini" | "model" => Some("assistant"),
            _ => None,
        })
    });
    match role {
        Some("user") => Ok(MessageRole::User),
        Some("assistant" | "model") => Ok(MessageRole::Assistant),
        Some(_) => Err(mapping(
            "unsupported_role",
            "Claude record role is not a user or assistant role",
        )),
        None => Err(mapping(
            "missing_role",
            "Claude conversational record has no role",
        )),
    }
}

fn build_message_body(
    record: &ClaudeNativeRecord,
    role: MessageRole,
    blocks: &[ClaudeContentBlock],
) -> Result<MessageObservation, ClaudeCanonicalError> {
    let mut body = MessageObservation::new(role);
    if blocks.is_empty() {
        if let Some(content) = &record.message_content {
            body = body.with_content(JsonValue::try_from_source_message_content(content)?);
        }
    } else {
        for block in blocks {
            body = body.with_content_part(content_part(block)?);
        }
    }
    Ok(body)
}

fn content_part(block: &ClaudeContentBlock) -> Result<ContentPart, ClaudeCanonicalError> {
    match block {
        ClaudeContentBlock::Text { text } => {
            let text = text.as_deref().ok_or_else(|| {
                mapping(
                    "invalid_content_block",
                    "text content block has no text value",
                )
            })?;
            Ok(ContentPart::new(
                ContentPartKind::Text,
                JsonValue::try_from_source_message_text(text)?,
            ))
        }
        // Tool parts reference their lifecycle by call id. Arguments and
        // results live once, on the linked tool observation, so a message
        // never repeats them under the tighter nested-value bounds.
        ClaudeContentBlock::ToolUse { id, name, .. } => {
            let id = id.as_deref().ok_or_else(|| {
                mapping("missing_tool_id", "tool_use block has no source call id")
            })?;
            let name = name
                .as_deref()
                .ok_or_else(|| mapping("missing_tool_name", "tool_use block has no tool name"))?;
            let fields = vec![
                ("id".to_owned(), JsonValue::string(id)),
                ("name".to_owned(), JsonValue::string(name)),
            ];
            Ok(ContentPart::new(
                ContentPartKind::ToolUse,
                JsonValue::object(fields)?,
            ))
        }
        ClaudeContentBlock::ToolResult {
            tool_use_id,
            is_error,
            is_error_present,
            ..
        } => {
            let tool_use_id = tool_use_id.as_deref().ok_or_else(|| {
                mapping("missing_tool_id", "tool_result block has no source call id")
            })?;
            if *is_error_present && is_error.is_none() {
                return Err(mapping(
                    "invalid_content_block",
                    "tool_result error state is not boolean",
                ));
            }
            let mut fields = vec![("tool_use_id".to_owned(), JsonValue::string(tool_use_id))];
            if let Some(is_error) = is_error {
                fields.push(("is_error".to_owned(), JsonValue::Bool(*is_error)));
            }
            Ok(ContentPart::new(
                ContentPartKind::ToolResult,
                JsonValue::object(fields)?,
            ))
        }
        ClaudeContentBlock::Ignored | ClaudeContentBlock::Unknown => Err(mapping(
            "unknown_content_block",
            "Claude content block type is not supported",
        )),
    }
}

fn emit_message(
    record: &ClaudeNativeRecord,
    options: &ClaudeCanonicalOptions,
    role: MessageRole,
    blocks: Option<&[ClaudeContentBlock]>,
    child_ordinal: &mut usize,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), ClaudeCanonicalError> {
    let empty = [];
    let body = build_message_body(record, role, blocks.unwrap_or(&empty))?;
    emit_message_body(record, options, body, child_ordinal, observations)
}

fn emit_message_body(
    record: &ClaudeNativeRecord,
    options: &ClaudeCanonicalOptions,
    body: MessageObservation,
    child_ordinal: &mut usize,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), ClaudeCanonicalError> {
    let has_content = body.content().is_some();
    let has_content_parts = !body.content_parts().is_empty();
    let mut builder = common_builder(
        record,
        options,
        ObservationBody::Message(body),
        ObservationStage::MessageObserved,
        None,
        *child_ordinal,
    )?;
    for path in [
        Some("message.role"),
        has_content.then_some("message.content"),
        has_content_parts.then_some("message.content_parts"),
    ]
    .into_iter()
    .flatten()
    {
        builder = builder.fact_metadata(path, normal_reported()?);
    }
    observations.push(builder.build()?)?;
    *child_ordinal += 1;
    Ok(())
}

fn emit_tool(
    record: &ClaudeNativeRecord,
    options: &ClaudeCanonicalOptions,
    block: &ClaudeContentBlock,
    child_ordinal: &mut usize,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), ClaudeCanonicalError> {
    let ToolBody {
        body,
        facts,
        resource_path,
    } = tool_body(block)?;
    let mut builder = common_builder(
        record,
        options,
        ObservationBody::Tool(body),
        match block {
            ClaudeContentBlock::ToolUse { .. } => ObservationStage::ToolRequested,
            ClaudeContentBlock::ToolResult { .. } => ObservationStage::ToolResultReturned,
            _ => unreachable!(),
        },
        tool_call_id(block)?,
        *child_ordinal,
    )?;
    for (path, provenance) in facts {
        builder = builder.fact_metadata(path, normal(provenance)?);
    }
    if let ClaudeContentBlock::ToolUse {
        input: Some(serde_json::Value::Object(input)),
        ..
    } = block
        && let Some(command) = input
            .get("command")
            .and_then(serde_json::Value::as_str)
            .or_else(|| input.get("cmd").and_then(serde_json::Value::as_str))
    {
        builder = builder
            .facet(
                "command.text",
                SemanticFacet::new(JsonValue::string(command)),
            )?
            .fact_metadata("command.text", normal(FactProvenance::Parsed)?);
    }
    if let Some(path) = resource_path {
        builder = builder
            .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
            .fact_metadata("resource.path", normal(FactProvenance::Parsed)?);
    }
    observations.push(builder.build()?)?;
    *child_ordinal += 1;
    Ok(())
}

struct ToolBody {
    body: ToolObservation,
    facts: Vec<(&'static str, FactProvenance)>,
    resource_path: Option<String>,
}

fn tool_body(block: &ClaudeContentBlock) -> Result<ToolBody, ClaudeCanonicalError> {
    match block {
        ClaudeContentBlock::ToolUse { id: _, name, input } => {
            let name = name
                .as_deref()
                .ok_or_else(|| mapping("missing_tool_name", "tool_use block has no tool name"))?;
            let mut body = ToolObservation::new().with_name(name)?;
            let mut paths = vec![("tool.name", FactProvenance::Reported)];
            let mut facet = None;
            if let Some(input) = input {
                let input = JsonValue::try_from_source_tool_arguments(Some(name), input).map_err(
                    |error| error.with_bound_category(CanonicalFieldCategory::ToolArguments),
                )?;
                facet = resource_path(&input).map(ToOwned::to_owned);
                body = body.with_arguments(input);
                paths.push(("tool.arguments", FactProvenance::Reported));
            }
            Ok(ToolBody {
                body,
                facts: paths,
                resource_path: facet,
            })
        }
        ClaudeContentBlock::ToolResult {
            tool_use_id: _,
            content,
            is_error,
            is_error_present,
        } => {
            if *is_error_present && is_error.is_none() {
                return Err(mapping(
                    "invalid_content_block",
                    "tool_result error state is not boolean",
                ));
            }
            let mut body = ToolObservation::new();
            let mut paths = Vec::new();
            if let Some(content) = content {
                let joined = joined_text_result(content);
                body = body.with_result(
                    JsonValue::try_from_source_tool_result(joined.as_ref().unwrap_or(content))
                        .map_err(|error| {
                            error.with_bound_category(CanonicalFieldCategory::ToolResult)
                        })?,
                );
                paths.push((
                    "tool.result",
                    if joined.is_some() {
                        FactProvenance::Derived
                    } else {
                        FactProvenance::Reported
                    },
                ));
            }
            if let Some(is_error) = is_error {
                body = body.with_is_error(*is_error);
                paths.push(("tool.is_error", FactProvenance::Reported));
            }
            if paths.is_empty() {
                return Err(mapping(
                    "invalid_tool_result",
                    "tool_result block has no result or error state",
                ));
            }
            Ok(ToolBody {
                body,
                facts: paths,
                resource_path: None,
            })
        }
        _ => Err(mapping(
            "unsupported_tool_block",
            "content block is not a tool lifecycle fact",
        )),
    }
}

fn tool_call_id(
    block: &ClaudeContentBlock,
) -> Result<Option<CorrelationIds>, ClaudeCanonicalError> {
    let value = match block {
        ClaudeContentBlock::ToolUse { id, .. } => id.as_deref(),
        ClaudeContentBlock::ToolResult { tool_use_id, .. } => tool_use_id.as_deref(),
        _ => None,
    }
    .ok_or_else(|| mapping("missing_tool_id", "tool block has no source call id"))?;
    Ok(Some(
        CorrelationIds::new().with_call_id(CorrelationId::source_reported(value)?),
    ))
}

fn common_builder(
    record: &ClaudeNativeRecord,
    options: &ClaudeCanonicalOptions,
    body: ObservationBody,
    stage: ObservationStage,
    correlation: Option<CorrelationIds>,
    child_ordinal: usize,
) -> Result<ObservationBuilder, ClaudeCanonicalError> {
    let mut source_provenance = SourceProvenance::new(
        IngestionMode::SessionStore,
        "claude_code",
        "claude.projects",
        Fidelity::PartialStructured,
    )?
    .with_source_sequence(record.source_sequence);
    if let Some(session_id) = &record.session_id {
        source_provenance =
            source_provenance.with_identity_source_sequence(session_id, record.source_sequence)?;
    }
    let mut builder = CanonicalObservationV2::builder(
        body,
        stage,
        options.observed_at.clone(),
        source_provenance,
    )
    .sequence(record.source_sequence)
    .capability_context(capabilities());
    if let Some(session_id) = &record.session_id {
        builder = builder.session_id(CorrelationId::source_reported(session_id)?);
    }
    if let Some(correlation) = correlation {
        builder = builder.correlation(correlation);
    }
    if let Some(timestamp) = &record.timestamp
        && let Ok(timestamp) = SourceTimestamp::new(timestamp)
    {
        builder = builder.occurred_at(timestamp);
    }
    builder = builder.child_ordinal(
        u32::try_from(child_ordinal)
            .map_err(|_| mapping("child_ordinal_overflow", "too many observations in record"))?,
    );
    Ok(builder)
}

fn capabilities() -> CapabilityContext {
    CapabilityContext::new()
        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported)
        .with_override(
            CapabilityId::ToolExecution,
            CapabilityAvailability::Unsupported,
        )
        .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported)
}

fn normal_reported() -> Result<FactMetadata, ClaudeCanonicalError> {
    normal(FactProvenance::Reported)
}

fn normal(provenance: FactProvenance) -> Result<FactMetadata, ClaudeCanonicalError> {
    Ok(match provenance {
        FactProvenance::Reported => FactMetadata::reported()?,
        FactProvenance::Parsed => FactMetadata::parsed()?,
        _ => FactMetadata::new(
            provenance,
            telltale_schema::observation::Sensitivity::Normal,
        )?,
    })
}

fn resource_path(value: &JsonValue) -> Option<&str> {
    match value {
        JsonValue::Object(fields) => match fields.get("file_path") {
            Some(JsonValue::String(path)) => Some(path),
            _ => None,
        },
        _ => None,
    }
}

/// Claude Code stores most tool output as `[{"type":"text","text":...}]`.
/// Join an all-text result into one direct string so it gets the tool-result
/// text budget; any other shape keeps ordinary structured conversion.
fn joined_text_result(content: &serde_json::Value) -> Option<serde_json::Value> {
    let items = content.as_array()?;
    let texts = items
        .iter()
        .map(
            |item| match item.get("type").and_then(serde_json::Value::as_str) {
                Some("text") => item.get("text").and_then(serde_json::Value::as_str),
                _ => None,
            },
        )
        .collect::<Option<Vec<_>>>()?;
    (!texts.is_empty()).then(|| serde_json::Value::String(texts.join("\n")))
}

fn mapping(code: &'static str, detail: &'static str) -> ClaudeCanonicalError {
    ClaudeCanonicalError::Mapping { code, detail }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::source::Source;

    use telltale_schema::observation::{
        CapabilityAvailability, CapabilityId, ContentPartKind, Fidelity, IngestionMode, JsonValue,
        MessageRole, ObservationBody, ObservationFamily, ObservationStage, ObservedAt,
    };
    use tempfile::tempdir;

    use super::{ClaudeCanonicalOptions, project_claude_native_records};

    const OBSERVED_AT: &str = "2026-09-02T12:00:00Z";

    fn fixture_source(relative: &str) -> Source {
        Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path: crate::test_fixture_path(relative),
        }
    }

    fn project(relative: &str) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
        project_claude_native_records(
            &super::super::native::extract_claude_native_records(&fixture_source(relative))
                .unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect("canonical observations")
        .observations
    }

    #[test]
    fn basic_conversation_without_source_session_is_replay_unverifiable() {
        let mut source = fixture_source("session_stores/claude/projects/project-a/session-a.jsonl");
        let temp = tempfile::tempdir().unwrap();
        let input = std::fs::read_to_string(&source.path).unwrap();
        source.path = temp.path().join("session-a.jsonl");
        std::fs::write(
            &source.path,
            input.replace("\"sessionId\":\"session-a\",", ""),
        )
        .unwrap();
        let error = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "replay_unverifiable");
    }

    #[test]
    fn tool_flow_retains_parts_call_ids_and_structured_values() {
        let observations =
            project("session_stores/claude/projects/project-b/session-tool-use.jsonl");
        assert_eq!(observations.len(), 4);

        let ObservationBody::Message(user) = observations[0].body() else {
            panic!("expected user message")
        };
        assert_eq!(user.role(), Some(MessageRole::User));
        assert_eq!(user.content_parts().len(), 1);
        assert_eq!(user.content_parts()[0].kind(), ContentPartKind::Text);
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "claude-tool-use"
        );

        let ObservationBody::Message(assistant) = observations[1].body() else {
            panic!("expected assistant message")
        };
        assert_eq!(assistant.role(), Some(MessageRole::Assistant));
        assert_eq!(assistant.content_parts().len(), 2);
        assert_eq!(assistant.content_parts()[0].kind(), ContentPartKind::Text);
        assert_eq!(
            assistant.content_parts()[1].kind(),
            ContentPartKind::ToolUse
        );

        assert_eq!(observations[1].stage(), ObservationStage::MessageObserved);
        let ObservationBody::Tool(tool) = observations[2].body() else {
            panic!("expected tool request")
        };
        assert_eq!(tool.name(), Some("Read"));
        assert_eq!(observations[2].stage(), ObservationStage::ToolRequested);
        assert_eq!(
            observations[3].stage(),
            ObservationStage::ToolResultReturned
        );
        assert!(observations.iter().all(|observation| !matches!(
            observation.stage(),
            ObservationStage::ToolExecutionStarted
                | ObservationStage::ToolExecutionCompleted
                | ObservationStage::ToolProposed
        )));

        let ObservationBody::Tool(result) = observations[3].body() else {
            panic!("expected tool result")
        };
        assert_eq!(result.is_error(), Some(false));
        assert_eq!(
            result.result(),
            Some(&JsonValue::string(
                "# Telltale\nSynthetic README excerpt for parser coverage."
            ))
        );
        assert_eq!(
            observations[3].correlation().call_id().unwrap().value(),
            "toolu_fixture_read"
        );
        assert_eq!(
            observations[3].correlation().call_id().unwrap().origin(),
            telltale_schema::observation::CorrelationOrigin::SourceReported
        );
        assert_eq!(observations[2].source().source_sequence(), Some(1));
        assert_eq!(observations[3].source().source_sequence(), Some(2));
        assert_eq!(observations[1].identity_basis().child_ordinal(), 0);
        assert_eq!(observations[2].identity_basis().child_ordinal(), 1);
        assert_eq!(observations[3].identity_basis().child_ordinal(), 0);
        assert_eq!(
            observations[1].identity_basis().domain(),
            "claude_code:claude.projects"
        );
        assert!(matches!(
            observations[1].identity_basis().coordinate().unwrap().1,
            telltale_schema::observation::IdentityCoordinateValue::SourceSequence {
                namespace,
                ordinal: 1
            } if namespace == "claude-tool-use"
        ));

        let ObservationBody::Tool(request) = observations[2].body() else {
            panic!("expected tool request")
        };
        assert_eq!(request.name(), Some("Read"));
        assert_eq!(
            request.arguments(),
            Some(
                &JsonValue::object([("file_path".to_owned(), JsonValue::string("README.md"),)])
                    .unwrap()
            )
        );
        assert_eq!(
            observations[2].correlation().call_id().unwrap().value(),
            "toolu_fixture_read"
        );
        assert_eq!(
            observations[2]
                .facets()
                .get("resource.path")
                .unwrap()
                .value(),
            &JsonValue::string("README.md")
        );
        assert_eq!(
            observations[2]
                .fact_metadata()
                .get("resource.path")
                .unwrap()
                .provenance(),
            telltale_schema::observation::FactProvenance::Parsed
        );
        assert_eq!(observations[2].fact_metadata().len(), 3);
        assert_eq!(observations[3].fact_metadata().len(), 2);
        assert!(
            observations
                .iter()
                .all(|observation| observation.kind() != ObservationFamily::File
                    && observation.kind() != ObservationFamily::Process
                    && observation.kind() != ObservationFamily::Network)
        );
    }

    #[test]
    fn scoped_identity_is_stable_across_artifact_moves_and_detects_content_change() {
        let contents =
            r#"{"type":"user","sessionId":"synthetic-session","content":"Synthetic message."}"#;
        let first_directory = tempdir().unwrap();
        let second_directory = tempdir().unwrap();
        let first_path = first_directory.path().join("first-name.jsonl");
        let second_path = second_directory.path().join("moved-name.jsonl");
        fs::write(&first_path, contents).unwrap();
        fs::write(&second_path, contents).unwrap();
        let source = |path| Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path,
        };
        let first = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source(first_path)).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap()
        .observations;
        let moved = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source(second_path)).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap()
        .observations;
        assert_eq!(first[0].observation_id(), moved[0].observation_id());
        assert_eq!(first[0].session_id().unwrap().value(), "synthetic-session");

        let changed_directory = tempdir().unwrap();
        let changed_path = changed_directory.path().join("changed.jsonl");
        fs::write(
            &changed_path,
            r#"{"type":"user","sessionId":"synthetic-session","content":"Synthetic changed message."}"#,
        )
        .unwrap();
        let changed = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source(changed_path)).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap()
        .observations;
        assert_eq!(first[0].observation_id(), changed[0].observation_id());
        assert_eq!(
            first[0]
                .semantic_comparison()
                .compare(changed[0].semantic_comparison()),
            telltale_schema::observation::SemanticReplayVerdict::Mutated
        );
    }

    #[test]
    fn different_source_sessions_scope_local_ordinals() {
        let first_directory = tempdir().unwrap();
        let second_directory = tempdir().unwrap();
        let first_path = first_directory.path().join("session-a.jsonl");
        let second_path = second_directory.path().join("session-b.jsonl");
        fs::write(
            &first_path,
            r#"{"type":"user","sessionId":"synthetic-session-a","content":"Synthetic message."}"#,
        )
        .unwrap();
        fs::write(
            &second_path,
            r#"{"type":"user","sessionId":"synthetic-session-b","content":"Synthetic message."}"#,
        )
        .unwrap();
        let source = |path| Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path,
        };
        let first = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source(first_path)).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap()
        .observations;
        let second = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source(second_path)).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap()
        .observations;
        assert_ne!(first[0].observation_id(), second[0].observation_id());
    }

    #[test]
    fn object_command_facets_preserve_paths_without_result_or_execution_inference() {
        use serde_json::json;
        use telltale_schema::observation::{FactProvenance, Sensitivity};

        let directory = tempdir().unwrap();
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path: directory.path().join("synthetic-command-facets.jsonl"),
        };
        for (case, mut input, expected) in [
            (
                "command",
                json!({"command":"printf synthetic"}),
                Some("printf synthetic"),
            ),
            (
                "cmd",
                json!({"cmd":"synthetic fallback"}),
                Some("synthetic fallback"),
            ),
            (
                "precedence",
                json!({"command":"printf synthetic","cmd":"synthetic fallback"}),
                Some("printf synthetic"),
            ),
            ("non-string", json!({"command":7}), None),
            (
                "non-string-fallback",
                json!({"command":7,"cmd":"synthetic fallback"}),
                Some("synthetic fallback"),
            ),
            ("no-command", json!({"cmd":false}), None),
        ] {
            input["file_path"] = json!("synthetic-file.txt");
            let request = json!({"type":"assistant","sessionId":"synthetic-command-session","message":{"role":"assistant","content":[{"type":"tool_use","id":"synthetic-call","name":"shell","input":input}]}});
            let result = json!({"type":"user","sessionId":"synthetic-command-session","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"synthetic-call","content":"printf synthetic"}]}});
            fs::write(&source.path, format!("{request}\n{result}\n")).unwrap();
            let observations = project_claude_native_records(
                &super::super::native::extract_claude_native_records(&source).unwrap(),
                &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
            )
            .unwrap()
            .observations;
            let request = observations
                .iter()
                .find(|o| o.stage() == ObservationStage::ToolRequested)
                .unwrap();
            assert!(
                request
                    .facets()
                    .get("command.text")
                    .map(|facet| facet.value())
                    == expected.map(JsonValue::string).as_ref(),
                "{case}: command.text"
            );
            if expected.is_some() {
                let metadata = &request.fact_metadata()["command.text"];
                assert!(
                    metadata.provenance() == FactProvenance::Parsed,
                    "{case}: command.provenance"
                );
                assert!(
                    metadata.sensitivity() == Sensitivity::Normal,
                    "{case}: command.sensitivity"
                );
            } else {
                assert!(
                    !request.fact_metadata().contains_key("command.text"),
                    "{case}: command.metadata_absent"
                );
            }
            assert!(
                request.facets()["resource.path"].value()
                    == &JsonValue::string("synthetic-file.txt"),
                "{case}: resource.path"
            );
            assert!(
                request.fact_metadata()["resource.path"].provenance() == FactProvenance::Parsed,
                "{case}: resource.provenance"
            );
            let result = observations
                .iter()
                .find(|o| o.stage() == ObservationStage::ToolResultReturned)
                .unwrap();
            assert!(result.facets().is_empty(), "{case}: result.facets_absent");
            assert!(
                !result.fact_metadata().contains_key("command.text"),
                "{case}: result.command_metadata_absent"
            );
            assert!(
                observations
                    .iter()
                    .all(|o| o.kind() != ObservationFamily::Process
                        && !matches!(
                            o.stage(),
                            ObservationStage::ToolExecutionStarted
                                | ObservationStage::ToolExecutionCompleted
                        )),
                "{case}: execution.absent"
            );
        }
    }

    #[test]
    fn additional_tool_result_fixture_links_call_ids() {
        let observations =
            project("session_stores/claude/projects/project-c/uc001-claude-tool-result.jsonl");
        assert_eq!(observations.len(), 4);
        assert_eq!(observations[2].stage(), ObservationStage::ToolRequested);
        assert_eq!(
            observations[3].stage(),
            ObservationStage::ToolResultReturned
        );
        assert_eq!(
            observations[2].correlation().call_id().unwrap().value(),
            "toolu_fixture_repo_status"
        );
        assert_eq!(
            observations[3].correlation().call_id().unwrap().value(),
            "toolu_fixture_repo_status"
        );
    }

    #[test]
    fn assistant_tool_result_is_emitted_after_message() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("assistant-tool-result.jsonl");
        fs::write(
            &path,
            br#"{"type":"assistant","sessionId":"synthetic-assistant","message":{"role":"assistant","content":[{"type":"text","text":"Synthetic assistant response."},{"type":"tool_result","tool_use_id":"toolu_assistant_result","content":"Synthetic tool result."}]}}"#,
        )
        .unwrap();
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path,
        };

        let observations = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect("assistant tool result should project")
        .observations;

        assert_eq!(
            observations
                .iter()
                .map(|observation| observation.kind())
                .collect::<Vec<_>>(),
            vec![ObservationFamily::Message, ObservationFamily::Tool]
        );
        assert_eq!(observations[0].stage(), ObservationStage::MessageObserved);
        assert_eq!(
            observations[1].stage(),
            ObservationStage::ToolResultReturned
        );
        assert_eq!(
            observations[1].correlation().call_id().unwrap().value(),
            "toolu_assistant_result"
        );
        assert_eq!(
            observations[1].correlation().call_id().unwrap().origin(),
            telltale_schema::observation::CorrelationOrigin::SourceReported
        );
    }

    #[test]
    fn capability_fidelity_and_source_provenance_are_explicit() {
        let observations =
            project("session_stores/claude/projects/project-b/session-tool-use.jsonl");
        for observation in observations {
            assert_eq!(
                observation.source().ingestion_mode(),
                IngestionMode::SessionStore
            );
            assert_eq!(observation.source().adapter_type(), "claude_code");
            assert_eq!(observation.source().adapter_id(), "claude.projects");
            assert_eq!(observation.source().adapter_version(), None);
            assert_eq!(observation.source().fidelity(), Fidelity::PartialStructured);
            assert_eq!(observation.source().native_id(), None);
            assert_eq!(observation.source().source_path_hash(), None);
            let capabilities = observation.capability_context().unwrap();
            assert_eq!(capabilities.overrides().len(), 3);
            assert_eq!(
                capabilities.resolve(CapabilityId::ToolCall),
                CapabilityAvailability::Supported
            );
            assert_eq!(
                capabilities.resolve(CapabilityId::ToolExecution),
                CapabilityAvailability::Unsupported
            );
            assert_eq!(
                capabilities.resolve(CapabilityId::UserContext),
                CapabilityAvailability::Supported
            );
        }
    }

    #[test]
    fn unknown_discriminators_are_quarantined_without_content() {
        let source = fixture_source("parser_maturity/non_discovered/unknown-variant.jsonl");
        let projection = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap();
        assert!(projection.observations.is_empty());
        assert_eq!(projection.quarantined.len(), 1);
        assert_eq!(projection.quarantined[0].code, "unknown_discriminator");
        assert!(
            !format!("{:?}", projection.quarantined).contains("Synthetic unknown record variant")
        );
    }

    #[test]
    fn source_schema_errors_remain_distinct_and_missing_call_ids_fail_closed() {
        let drift = fixture_source("parser_maturity/non_discovered/schema-drift.jsonl");
        let error = crate::acquisition::acquire_source(
            &drift,
            crate::acquisition::AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .err()
        .expect("schema drift must remain a source error");
        assert_eq!(error.code(), "source_read");
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(!rendered.contains("schema-drift.jsonl"));
            assert!(!rendered.contains("Synthetic"));
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("missing-id.jsonl");
        fs::write(
            &path,
            br#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Read","input":{"file_path":"README.md"}}]}}"#,
        )
        .unwrap();
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path,
        };
        let error = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("tool_use without id must fail");
        assert_eq!(error.code(), "missing_tool_id");
    }

    #[test]
    fn unknown_content_blocks_quarantine_only_their_record() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("unknown-block.jsonl");
        fs::write(
            &path,
            concat!(
                r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"future_block","value":"synthetic payload"}]}}"#,
                "\n",
                r#"{"type":"user","sessionId":"s","message":{"role":"user","content":"Synthetic next turn."}}"#,
            ),
        )
        .unwrap();
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path,
        };
        let projection = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap();
        assert_eq!(projection.observations.len(), 1);
        assert_eq!(
            projection.observations[0].source().source_sequence(),
            Some(1)
        );
        assert_eq!(projection.quarantined.len(), 1);
        assert_eq!(projection.quarantined[0].source_sequence, 0);
        assert_eq!(projection.quarantined[0].code, "unknown_content_block");
        assert!(!format!("{:?}", projection.quarantined).contains("synthetic payload"));
    }

    fn project_lines(lines: &[&str]) -> super::ClaudeProjection {
        let directory = tempdir().unwrap();
        let path = directory.path().join("session.jsonl");
        fs::write(&path, lines.join("\n")).unwrap();
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path,
        };
        project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn claude_code_metadata_records_are_skipped() {
        let mut lines = [
            "attachment",
            "queue-operation",
            "last-prompt",
            "custom-title",
            "ai-title",
            "agent-name",
            "atis-latch",
            "file-history-snapshot",
            "file-history-delta",
            "summary",
            "system",
            "progress",
            "api-request",
            "api-request-blob",
            "api-request-shape",
            "mode",
            "permission-mode",
            "relocated",
            "worktree-state",
            "cost-state",
            "pr-link",
            "artifact-autoreact-ledger",
            "artifact-comment-monitor",
            "continued-in",
        ]
        .map(|kind| format!(r#"{{"type":"{kind}","sessionId":"s","content":"synthetic"}}"#))
        .to_vec();
        let metadata_count = lines.len();
        lines.push(
            r#"{"type":"user","sessionId":"s","message":{"role":"user","content":"Synthetic turn."}}"#
                .to_owned(),
        );
        let projection = project_lines(&lines.iter().map(String::as_str).collect::<Vec<_>>());
        assert!(projection.quarantined.is_empty());
        assert_eq!(projection.observations.len(), 1);
        assert_eq!(
            projection.observations[0].source().source_sequence(),
            Some(metadata_count as u64)
        );
    }

    #[test]
    fn reasoning_and_media_blocks_are_dropped_from_messages() {
        let projection = project_lines(&[
            r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"thinking","thinking":"synthetic reasoning","signature":"x"}]}}"#,
            r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"redacted_thinking","data":"x"},{"type":"text","text":"Synthetic answer."}]}}"#,
            r#"{"type":"user","sessionId":"s","message":{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}},{"type":"text","text":"Synthetic caption."}]}}"#,
        ]);
        assert!(projection.quarantined.is_empty());
        assert_eq!(projection.observations.len(), 2);
        for observation in &projection.observations {
            let ObservationBody::Message(message) = observation.body() else {
                panic!("expected message")
            };
            assert_eq!(message.content_parts().len(), 1);
            assert_eq!(message.content_parts()[0].kind(), ContentPartKind::Text);
        }
    }

    #[test]
    fn nested_and_authored_tool_arguments_project_on_the_tool_observation() {
        let long = "x".repeat(20_000);
        let write = format!(
            r#"{{"type":"assistant","sessionId":"s","message":{{"role":"assistant","content":[{{"type":"tool_use","id":"toolu_write","name":"Write","input":{{"file_path":"C:\\repo\\big.txt","content":"{long}"}}}}]}}}}"#
        );
        let projection = project_lines(&[
            r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"text","text":"Planning."},{"type":"tool_use","id":"toolu_todo","name":"TodoWrite","input":{"todos":[{"content":"Synthetic step","status":"pending","activeForm":"Doing it"}]}}]}}"#,
            r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_multi","name":"MultiEdit","input":{"file_path":"C:\\repo\\a.rs","edits":[{"old_string":"a","new_string":"b"}]}}]}}"#,
            &write,
            r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_ps","name":"PowerShell","input":{"command":"Get-ChildItem $env:USERPROFILE\\.ssh"}}]}}"#,
        ]);
        assert!(
            projection.quarantined.is_empty(),
            "{:?}",
            projection.quarantined
        );
        let tools = projection
            .observations
            .iter()
            .filter_map(|observation| match observation.body() {
                ObservationBody::Tool(tool) => Some((observation, tool)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            tools
                .iter()
                .map(|(_, tool)| tool.name())
                .collect::<Vec<_>>(),
            vec![
                Some("TodoWrite"),
                Some("MultiEdit"),
                Some("Write"),
                Some("PowerShell")
            ]
        );
        assert!(tools.iter().all(|(_, tool)| tool.arguments().is_some()));
        let (write, _) = tools[2];
        assert_eq!(
            write.facets().get("resource.path").unwrap().value(),
            &JsonValue::string("C:\\repo\\big.txt")
        );
        let (shell, _) = tools[3];
        assert!(shell.facets().get("command.text").is_some());
        // The message part references the call without repeating its input.
        let ObservationBody::Message(message) = projection.observations[0].body() else {
            panic!("expected message")
        };
        assert_eq!(
            message.content_parts()[1].value(),
            &JsonValue::object([
                ("id".to_owned(), JsonValue::string("toolu_todo")),
                ("name".to_owned(), JsonValue::string("TodoWrite")),
            ])
            .unwrap()
        );
    }

    #[test]
    fn text_array_tool_results_join_into_direct_text() {
        let long = "y".repeat(10_000);
        let line = format!(
            r#"{{"type":"user","sessionId":"s","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"toolu_a","content":[{{"type":"text","text":"first"}},{{"type":"text","text":"{long}"}}]}}]}}}}"#
        );
        let projection = project_lines(&[&line]);
        assert!(projection.quarantined.is_empty());
        let ObservationBody::Tool(tool) = projection.observations[0].body() else {
            panic!("expected tool result")
        };
        assert_eq!(
            tool.result(),
            Some(&JsonValue::string(format!("first\n{long}")))
        );
    }

    #[test]
    fn oversized_tool_arguments_quarantine_only_their_record() {
        let long = "z".repeat(5_000);
        let line = format!(
            r#"{{"type":"assistant","sessionId":"s","message":{{"role":"assistant","content":[{{"type":"tool_use","id":"toolu_x","name":"Grep","input":{{"pattern":"{long}"}}}}]}}}}"#
        );
        let projection = project_lines(&[
            &line,
            r#"{"type":"user","sessionId":"s","message":{"role":"user","content":"Synthetic turn."}}"#,
        ]);
        assert_eq!(projection.observations.len(), 1);
        assert_eq!(projection.quarantined.len(), 1);
        assert_eq!(projection.quarantined[0].code, "unbounded_value");
        assert_eq!(
            projection.quarantined[0].bound.map(|bound| bound.category),
            Some(telltale_schema::observation::CanonicalFieldCategory::ToolArguments)
        );
    }
}
