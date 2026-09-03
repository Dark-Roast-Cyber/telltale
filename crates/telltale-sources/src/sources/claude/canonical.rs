#![allow(dead_code)]

use std::fmt;

use telltale_schema::clients::ClientId;
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId, ContentPart,
    ContentPartKind, CorrelationId, CorrelationIds, FactMetadata, FactProvenance, Fidelity,
    IngestionMode, JsonValue, MessageObservation, MessageRole, ObservationBody, ObservationBuilder,
    ObservationError, ObservationStage, ObservedAt, SemanticFacet, SourceProvenance,
    SourceTimestamp, ToolObservation,
};
use telltale_schema::source::Source;

use super::native::{
    ClaudeContentBlock, ClaudeNativeRecord, extract_claude_native_records,
    is_known_claude_discriminator,
};
use crate::parser::ParseError;

#[derive(Clone)]
pub(crate) struct ClaudeCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
}

impl ClaudeCanonicalOptions {
    pub(crate) fn new(observed_at: ObservedAt) -> Self {
        Self { observed_at }
    }
}

pub(crate) enum ClaudeCanonicalError {
    Source(ParseError),
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl ClaudeCanonicalError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Source(error) => {
                let _ = error;
                "source_parse"
            }
            Self::Mapping { code, .. } => code,
            Self::Observation(error) => error.code(),
        }
    }
}

impl fmt::Debug for ClaudeCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("ClaudeCanonicalError::Source")
            }
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
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("Claude source could not be parsed")
            }
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

impl From<ParseError> for ClaudeCanonicalError {
    fn from(error: ParseError) -> Self {
        Self::Source(error)
    }
}

impl From<ObservationError> for ClaudeCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

pub(crate) fn project_claude_canonical_observations(
    source: &Source,
    options: ClaudeCanonicalOptions,
) -> Result<Vec<CanonicalObservationV2>, ClaudeCanonicalError> {
    if source.client != ClientId::Claude || source.source_id != "claude.projects" {
        return Err(mapping(
            "unsupported_source_identity",
            "canonical projection requires the Claude projects source",
        ));
    }
    if source.kind != telltale_schema::clients::SourceKind::Jsonl {
        return Err(mapping(
            "unsupported_source_kind",
            "canonical projection requires JSONL input",
        ));
    }

    let records = extract_claude_native_records(source)?;
    let mut observations = Vec::new();
    for record in records {
        project_record(&record, &options, &mut observations)?;
    }
    Ok(observations)
}

fn project_record(
    record: &ClaudeNativeRecord,
    options: &ClaudeCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), ClaudeCanonicalError> {
    if record
        .discriminator
        .as_deref()
        .is_some_and(|kind| !is_known_claude_discriminator(kind))
    {
        return Err(mapping(
            "unknown_discriminator",
            "explicit Claude record discriminator is not supported",
        ));
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
                ClaudeContentBlock::Unknown => unreachable!(),
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
            body = body.with_content(value_to_json(content)?);
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
                JsonValue::string(text),
            ))
        }
        ClaudeContentBlock::ToolUse {
            id,
            name,
            input,
            input_present,
        } => {
            let id = id.as_deref().ok_or_else(|| {
                mapping("missing_tool_id", "tool_use block has no source call id")
            })?;
            let name = name
                .as_deref()
                .ok_or_else(|| mapping("missing_tool_name", "tool_use block has no tool name"))?;
            let mut fields = vec![
                ("id".to_owned(), JsonValue::string(id)),
                ("name".to_owned(), JsonValue::string(name)),
            ];
            if *input_present && let Some(input) = input {
                fields.push(("input".to_owned(), value_to_json(input)?));
            }
            Ok(ContentPart::new(
                ContentPartKind::ToolUse,
                JsonValue::object(fields)?,
            ))
        }
        ClaudeContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            is_error_present,
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
            if let Some(content) = content {
                fields.push(("content".to_owned(), value_to_json(content)?));
            }
            if let Some(is_error) = is_error {
                fields.push(("is_error".to_owned(), JsonValue::Bool(*is_error)));
            }
            Ok(ContentPart::new(
                ContentPartKind::ToolResult,
                JsonValue::object(fields)?,
            ))
        }
        ClaudeContentBlock::Unknown => Err(mapping(
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
    observations: &mut Vec<CanonicalObservationV2>,
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
    observations: &mut Vec<CanonicalObservationV2>,
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
    observations.push(builder.build()?);
    *child_ordinal += 1;
    Ok(())
}

fn emit_tool(
    record: &ClaudeNativeRecord,
    options: &ClaudeCanonicalOptions,
    block: &ClaudeContentBlock,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), ClaudeCanonicalError> {
    let (body, paths, facet) = tool_body(block)?;
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
    for path in paths {
        builder = builder.fact_metadata(path, normal_reported()?);
    }
    if let Some(path) = facet {
        builder = builder
            .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
            .fact_metadata("resource.path", normal(FactProvenance::Parsed)?);
    }
    observations.push(builder.build()?);
    *child_ordinal += 1;
    Ok(())
}

fn tool_body(
    block: &ClaudeContentBlock,
) -> Result<(ToolObservation, Vec<&'static str>, Option<String>), ClaudeCanonicalError> {
    match block {
        ClaudeContentBlock::ToolUse {
            id: _,
            name,
            input,
            input_present: _,
        } => {
            let name = name
                .as_deref()
                .ok_or_else(|| mapping("missing_tool_name", "tool_use block has no tool name"))?;
            let mut body = ToolObservation::new().with_name(name)?;
            let mut paths = vec!["tool.name"];
            let mut facet = None;
            if let Some(input) = input {
                let input = value_to_json(input)?;
                facet = resource_path(&input).map(ToOwned::to_owned);
                body = body.with_arguments(input);
                paths.push("tool.arguments");
            }
            Ok((body, paths, facet))
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
                body = body.with_result(value_to_json(content)?);
                paths.push("tool.result");
            }
            if let Some(is_error) = is_error {
                body = body.with_is_error(*is_error);
                paths.push("tool.is_error");
            }
            if paths.is_empty() {
                return Err(mapping(
                    "invalid_tool_result",
                    "tool_result block has no result or error state",
                ));
            }
            Ok((body, paths, None))
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

fn value_to_json(value: &serde_json::Value) -> Result<JsonValue, ClaudeCanonicalError> {
    Ok(JsonValue::try_from_source_value(value)?)
}

fn mapping(code: &'static str, detail: &'static str) -> ClaudeCanonicalError {
    ClaudeCanonicalError::Mapping { code, detail }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::{
        CapabilityAvailability, CapabilityId, ContentPartKind, Fidelity, IngestionMode, JsonValue,
        MessageRole, ObservationBody, ObservationFamily, ObservationStage, ObservedAt,
    };
    use telltale_schema::source::Source;
    use tempfile::tempdir;

    use super::{ClaudeCanonicalOptions, project_claude_canonical_observations};
    use crate::parser::parse_source_records;

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
        project_claude_canonical_observations(
            &fixture_source(relative),
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect("canonical observations")
    }

    #[test]
    fn basic_conversation_without_source_session_fails_v2_but_keeps_legacy_fallback() {
        let source = fixture_source("session_stores/claude/projects/project-a/session-a.jsonl");
        let error = project_claude_canonical_observations(
            &source,
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "replay_unverifiable");
        let legacy = parse_source_records(&source).expect("legacy projection");
        assert_eq!(legacy.len(), 2);
        assert!(legacy.iter().all(|record| record.session_id == "session-a"));
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
        let first = project_claude_canonical_observations(
            &source(first_path),
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap();
        let moved = project_claude_canonical_observations(
            &source(second_path),
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap();
        assert_eq!(first[0].observation_id(), moved[0].observation_id());
        assert_eq!(first[0].session_id().unwrap().value(), "synthetic-session");

        let changed_directory = tempdir().unwrap();
        let changed_path = changed_directory.path().join("changed.jsonl");
        fs::write(
            &changed_path,
            r#"{"type":"user","sessionId":"synthetic-session","content":"Synthetic changed message."}"#,
        )
        .unwrap();
        let changed = project_claude_canonical_observations(
            &source(changed_path),
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap();
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
        let first = project_claude_canonical_observations(
            &source(first_path),
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap();
        let second = project_claude_canonical_observations(
            &source(second_path),
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap();
        assert_ne!(first[0].observation_id(), second[0].observation_id());
    }

    #[test]
    fn additional_tool_result_fixture_keeps_legacy_detection_evidence_linked() {
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
    fn assistant_tool_result_is_emitted_after_message_without_affecting_legacy_parse() {
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

        let observations = project_claude_canonical_observations(
            &source,
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect("assistant tool result should project");

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
        assert!(parse_source_records(&source).is_ok());
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
    fn canonical_failures_are_isolated_from_legacy_projection() {
        let source = fixture_source("parser_maturity/non_discovered/unknown-variant.jsonl");
        let error = project_claude_canonical_observations(
            &source,
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("unknown discriminator must fail canonical mapping");
        assert_eq!(error.code(), "unknown_discriminator");
        assert!(
            !error
                .to_string()
                .contains("Synthetic unknown record variant")
        );
        assert!(!format!("{error:?}").contains("Synthetic unknown record variant"));

        let legacy = parse_source_records(&source).expect("legacy projection remains available");
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].kind, telltale_schema::record::RecordKind::Other);
    }

    #[test]
    fn source_schema_errors_remain_distinct_and_missing_call_ids_fail_closed() {
        let drift = fixture_source("parser_maturity/non_discovered/schema-drift.jsonl");
        let error = project_claude_canonical_observations(
            &drift,
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("schema drift must remain a source error");
        assert_eq!(error.code(), "source_parse");

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
        let error = project_claude_canonical_observations(
            &source,
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("tool_use without id must fail");
        assert_eq!(error.code(), "missing_tool_id");
        assert!(parse_source_records(&source).is_ok());
    }

    #[test]
    fn unknown_content_blocks_fail_without_changing_legacy_parsing() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("unknown-block.jsonl");
        fs::write(
            &path,
            br#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"future_block","value":"synthetic payload"}]}}"#,
        )
        .unwrap();
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path,
        };
        let error = project_claude_canonical_observations(
            &source,
            ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("unknown content block must fail");
        assert_eq!(error.code(), "unknown_content_block");
        assert!(!error.to_string().contains("synthetic payload"));
        assert!(parse_source_records(&source).is_ok());
    }
}
