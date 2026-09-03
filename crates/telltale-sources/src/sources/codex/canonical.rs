#![allow(dead_code)]

use std::fmt;

use serde_json::Value;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId, ContentPart,
    ContentPartKind, CorrelationId, CorrelationIds, CorrelationOrigin, FactMetadata,
    FactProvenance, Fidelity, IngestionMode, JsonValue, MessageObservation, MessageRole,
    ObservationBody, ObservationBuilder, ObservationError, ObservationStage, ObservedAt,
    SemanticFacet, SourceProvenance, SourceTimestamp, ToolObservation, ToolStatus,
};
use telltale_schema::source::Source;

use super::native::{
    CodexContentBlock, CodexNativeRecord, CodexToolFields, extract_codex_native_records,
    is_known_codex_discriminator,
};
use crate::parser::ParseError;

#[derive(Clone)]
pub(crate) struct CodexCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
}

impl CodexCanonicalOptions {
    pub(crate) fn new(observed_at: ObservedAt) -> Self {
        Self { observed_at }
    }
}

pub(crate) enum CodexCanonicalError {
    Source(ParseError),
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl CodexCanonicalError {
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

impl fmt::Debug for CodexCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("CodexCanonicalError::Source")
            }
            Self::Mapping { code, detail } => formatter
                .debug_struct("CodexCanonicalError::Mapping")
                .field("code", code)
                .field("detail", detail)
                .finish(),
            Self::Observation(error) => formatter
                .debug_struct("CodexCanonicalError::Observation")
                .field("code", &error.code())
                .finish(),
        }
    }
}

impl fmt::Display for CodexCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("Codex source could not be parsed")
            }
            Self::Mapping { code, detail } => {
                write!(
                    formatter,
                    "Codex canonical mapping failed ({code}): {detail}"
                )
            }
            Self::Observation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CodexCanonicalError {}

impl From<ParseError> for CodexCanonicalError {
    fn from(error: ParseError) -> Self {
        Self::Source(error)
    }
}

impl From<ObservationError> for CodexCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

pub(crate) fn project_codex_canonical_observations(
    source: &Source,
    options: CodexCanonicalOptions,
) -> Result<Vec<CanonicalObservationV2>, CodexCanonicalError> {
    if source.client != ClientId::Codex || !is_registered_source_id(&source.source_id) {
        return Err(mapping(
            "unsupported_source_identity",
            "canonical projection requires a registered Codex source",
        ));
    }
    if !matching_source_kind(&source.source_id, source.kind) {
        return Err(mapping(
            "unsupported_source_kind",
            "canonical projection requires the registered source kind",
        ));
    }

    let records = extract_codex_native_records(source)?;
    let mut observations = Vec::new();
    for record in records {
        project_record(&record, &options, &mut observations)?;
    }
    Ok(observations)
}

fn is_registered_source_id(source_id: &str) -> bool {
    matches!(
        source_id,
        "codex.sessions"
            | "codex.archived_sessions"
            | "codex.headless_sessions"
            | "codex.project_sessions"
    )
}

fn matching_source_kind(source_id: &str, kind: SourceKind) -> bool {
    matches!(
        (source_id, kind),
        ("codex.sessions", SourceKind::Jsonl)
            | ("codex.archived_sessions", SourceKind::ArchivedJsonl)
            | ("codex.headless_sessions", SourceKind::HeadlessJsonl)
            | ("codex.project_sessions", SourceKind::Jsonl)
    )
}

fn project_record(
    record: &CodexNativeRecord,
    options: &CodexCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), CodexCanonicalError> {
    if record.discriminator.as_deref().is_some_and(|kind| {
        !is_known_codex_discriminator(kind) && !is_known_canonical_discriminator(kind)
    }) {
        return Err(mapping(
            "unknown_discriminator",
            "explicit Codex record discriminator is not supported",
        ));
    }

    if record.legacy_kind == telltale_schema::record::RecordKind::SessionMeta {
        return Ok(());
    }

    let mut child_ordinal = 0;
    if let Some(blocks) = record.blocks.as_deref().filter(|blocks| !blocks.is_empty()) {
        if blocks
            .iter()
            .any(|block| matches!(block, CodexContentBlock::Unknown))
        {
            return Err(mapping(
                "unknown_content_block",
                "Codex content block type is not supported",
            ));
        }

        let has_tool = blocks.iter().any(CodexContentBlock::is_tool);
        let has_text = blocks
            .iter()
            .any(|block| matches!(block, CodexContentBlock::Text { .. }));
        let role = if has_text || is_message_record(record) || has_tool_context_role(record) {
            Some(canonical_role(record)?)
        } else {
            None
        };
        let message_required = role.is_some_and(|role| {
            !(role == MessageRole::User
                && !blocks.is_empty()
                && blocks.iter().all(CodexContentBlock::is_tool_result))
        });

        if message_required {
            let body = build_message_body(record, role.expect("message role"), blocks)?;
            emit_message_body(record, options, body, &mut child_ordinal, observations)?;
        }
        for block in blocks {
            if let Some((fields, stage)) = block_tool(block)? {
                emit_tool(
                    record,
                    options,
                    fields,
                    stage,
                    &mut child_ordinal,
                    observations,
                )?;
            }
        }
        if message_required || has_tool {
            return Ok(());
        }
        return Err(mapping(
            "unsupported_record",
            "Codex record does not describe a supported message or tool",
        ));
    }

    match record.discriminator.as_deref() {
        Some(
            "user_message" | "user" | "assistant_message" | "assistant" | "gemini" | "model"
            | "text" | "message",
        ) => {
            let body = build_message_body(record, canonical_role(record)?, &[])?;
            emit_message_body(record, options, body, &mut child_ordinal, observations)
        }
        Some("tool_call" | "custom_tool_call" | "function_call") => emit_tool(
            record,
            options,
            record.tool.clone(),
            ObservationStage::ToolRequested,
            &mut child_ordinal,
            observations,
        ),
        Some("tool_result" | "custom_tool_call_output" | "function_call_output") => emit_tool(
            record,
            options,
            record.tool.clone(),
            ObservationStage::ToolResultReturned,
            &mut child_ordinal,
            observations,
        ),
        Some("tool") => {
            let is_result = record.tool.result_present
                || record.tool.error_present
                || matches!(record.tool.status.as_deref(), Some("completed" | "error"));
            emit_tool(
                record,
                options,
                record.tool.clone(),
                if is_result {
                    ObservationStage::ToolResultReturned
                } else {
                    ObservationStage::ToolRequested
                },
                &mut child_ordinal,
                observations,
            )
        }
        _ => Err(mapping(
            "unsupported_record",
            "Codex record does not describe a supported message or tool",
        )),
    }
}

fn is_known_canonical_discriminator(kind: &str) -> bool {
    matches!(kind, "function_call" | "function_call_output")
}

fn is_message_record(record: &CodexNativeRecord) -> bool {
    matches!(
        record.discriminator.as_deref(),
        Some(
            "user_message"
                | "user"
                | "assistant_message"
                | "assistant"
                | "gemini"
                | "model"
                | "text"
                | "message"
        )
    )
}

fn has_tool_context_role(record: &CodexNativeRecord) -> bool {
    record.role.is_some()
        && record
            .discriminator
            .as_deref()
            .is_some_and(|kind| matches!(kind, "tool_call" | "tool_result"))
}

fn canonical_role(record: &CodexNativeRecord) -> Result<MessageRole, CodexCanonicalError> {
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
            "Codex record role is not a user or assistant role",
        )),
        None => Err(mapping(
            "missing_role",
            "Codex conversational record has no role",
        )),
    }
}

fn build_message_body(
    record: &CodexNativeRecord,
    role: MessageRole,
    blocks: &[CodexContentBlock],
) -> Result<MessageObservation, CodexCanonicalError> {
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

fn content_part(block: &CodexContentBlock) -> Result<ContentPart, CodexCanonicalError> {
    match block {
        CodexContentBlock::Text { text } => {
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
        CodexContentBlock::ToolUse {
            id,
            name,
            input,
            input_present,
        } => {
            let mut fields = Vec::new();
            if let Some(id) = id {
                fields.push(("id".to_owned(), JsonValue::string(id)));
            }
            if let Some(name) = name {
                fields.push(("name".to_owned(), JsonValue::string(name)));
            }
            if *input_present && let Some(input) = input {
                fields.push(("input".to_owned(), value_to_json(input)?));
            }
            Ok(ContentPart::new(
                ContentPartKind::ToolUse,
                JsonValue::object(fields)?,
            ))
        }
        CodexContentBlock::ToolResult {
            call_id,
            result,
            result_present,
            is_error,
            is_error_present,
        } => {
            if *is_error_present && is_error.is_none() {
                return Err(mapping(
                    "invalid_content_block",
                    "tool result error state is not boolean",
                ));
            }
            let mut fields = Vec::new();
            if let Some(call_id) = call_id {
                fields.push(("tool_use_id".to_owned(), JsonValue::string(call_id)));
            }
            if *result_present && let Some(result) = result {
                fields.push(("content".to_owned(), value_to_json(result)?));
            }
            if let Some(is_error) = is_error {
                fields.push(("is_error".to_owned(), JsonValue::Bool(*is_error)));
            }
            Ok(ContentPart::new(
                ContentPartKind::ToolResult,
                JsonValue::object(fields)?,
            ))
        }
        CodexContentBlock::Unknown => Err(mapping(
            "unknown_content_block",
            "Codex content block type is not supported",
        )),
    }
}

fn block_tool(
    block: &CodexContentBlock,
) -> Result<Option<(CodexToolFields, ObservationStage)>, CodexCanonicalError> {
    match block {
        CodexContentBlock::ToolUse {
            id,
            name,
            input,
            input_present,
        } => Ok(Some((
            CodexToolFields {
                name: name.clone(),
                arguments: input.clone(),
                arguments_present: *input_present,
                call_id: id.clone(),
                ..CodexToolFields::default()
            },
            ObservationStage::ToolRequested,
        ))),
        CodexContentBlock::ToolResult {
            call_id,
            result,
            result_present,
            is_error,
            is_error_present,
        } => Ok(Some((
            CodexToolFields {
                call_id: call_id.clone(),
                result: result.clone(),
                result_present: *result_present,
                is_error: *is_error,
                is_error_present: *is_error_present,
                ..CodexToolFields::default()
            },
            ObservationStage::ToolResultReturned,
        ))),
        CodexContentBlock::Text { .. } => Ok(None),
        CodexContentBlock::Unknown => Err(mapping(
            "unknown_content_block",
            "Codex content block type is not supported",
        )),
    }
}

fn emit_message_body(
    record: &CodexNativeRecord,
    options: &CodexCanonicalOptions,
    body: MessageObservation,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), CodexCanonicalError> {
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
    record: &CodexNativeRecord,
    options: &CodexCanonicalOptions,
    fields: CodexToolFields,
    stage: ObservationStage,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), CodexCanonicalError> {
    if fields.is_error_present && fields.is_error.is_none() {
        return Err(mapping(
            "invalid_tool_result",
            "tool error state is not boolean",
        ));
    }

    let generic = record.discriminator.as_deref() == Some("tool");
    let source_error = fields.error_present || fields.status.as_deref() == Some("error");
    let has_result = fields.result_present || fields.error_present;
    let has_explicit_body = fields.name.is_some()
        || fields.arguments.is_some()
        || fields.result.is_some()
        || fields.is_error.is_some();

    if stage == ObservationStage::ToolResultReturned
        && !has_result
        && !generic
        && fields.is_error.is_none()
    {
        return Err(mapping(
            "invalid_tool_result",
            "tool result has no returned value or error state",
        ));
    }

    let mut body = ToolObservation::new();
    let mut paths = Vec::new();
    if let Some(name) = &fields.name {
        body = body.with_name(name)?;
        paths.push(("tool.name", FactProvenance::Reported));
    }
    if let Some(arguments) = &fields.arguments {
        body = body.with_arguments(value_to_json(arguments)?);
        paths.push(("tool.arguments", FactProvenance::Reported));
    }
    if let Some(result) = &fields.result {
        body = body.with_result(value_to_json(result)?);
        paths.push(("tool.result", FactProvenance::Reported));
    } else if let Some(error) = &fields.error {
        body = body.with_result(value_to_json(error)?);
        paths.push(("tool.result", FactProvenance::Reported));
    }
    if let Some(is_error) = fields.is_error {
        body = body.with_is_error(is_error);
        paths.push(("tool.is_error", FactProvenance::Reported));
    }
    if source_error {
        body = body.with_reported_status(ToolStatus::Failed);
        paths.push(("tool.reported_status", FactProvenance::Reported));
    } else if generic && (!has_explicit_body || !has_result && fields.is_error.is_none()) {
        // The source reports a state but not a success/failure fact. Unknown is
        // only a structural minimum for the Tool body; it is not execution
        // telemetry or an inferred completion status.
        body = body.with_reported_status(ToolStatus::Unknown);
        paths.push(("tool.reported_status", FactProvenance::Parsed));
    }

    if paths.is_empty() {
        return Err(mapping(
            "invalid_tool_request",
            "tool record has no canonical tool fact",
        ));
    }

    let mut builder = common_builder(
        record,
        options,
        ObservationBody::Tool(body),
        stage,
        tool_correlation(fields.call_id.as_deref())?,
        *child_ordinal,
    )?;
    for (path, provenance) in paths {
        builder = builder.fact_metadata(path, normal(provenance)?);
    }

    let argument_view = fields.arguments.as_ref().and_then(parsed_argument_view);
    let command = fields
        .command
        .clone()
        .or_else(|| argument_command(fields.arguments.as_ref(), argument_view.as_ref()));
    if let Some(command) = command {
        builder = builder
            .facet(
                "command.text",
                SemanticFacet::new(JsonValue::string(command)),
            )?
            .fact_metadata("command.text", normal(FactProvenance::Parsed)?);
    }
    if let Some(path) = argument_view
        .as_ref()
        .and_then(|arguments| argument_string(arguments, "file_path"))
    {
        builder = builder
            .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
            .fact_metadata("resource.path", normal(FactProvenance::Parsed)?);
    }

    observations.push(builder.build()?);
    *child_ordinal += 1;
    Ok(())
}

fn tool_correlation(call_id: Option<&str>) -> Result<Option<CorrelationIds>, CodexCanonicalError> {
    let Some(value) = call_id else {
        return Ok(None);
    };
    Ok(Some(CorrelationIds::new().with_call_id(
        CorrelationId::new(value, CorrelationOrigin::SourceReported)?,
    )))
}

fn common_builder(
    record: &CodexNativeRecord,
    options: &CodexCanonicalOptions,
    body: ObservationBody,
    stage: ObservationStage,
    correlation: Option<CorrelationIds>,
    child_ordinal: usize,
) -> Result<ObservationBuilder, CodexCanonicalError> {
    let source_provenance = SourceProvenance::new(
        IngestionMode::SessionStore,
        "codex",
        &record.adapter_id,
        Fidelity::PartialStructured,
    )?
    .with_source_sequence(record.source_sequence);
    let mut builder = CanonicalObservationV2::builder(
        body,
        stage,
        options.observed_at.clone(),
        source_provenance,
    )
    .sequence(record.source_sequence)
    .capability_context(capabilities());
    if let Some(session_id) = &record.effective_session_id {
        builder = builder.session_id(CorrelationId::new(
            session_id,
            CorrelationOrigin::SourceReported,
        )?);
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

fn normal_reported() -> Result<FactMetadata, CodexCanonicalError> {
    normal(FactProvenance::Reported)
}

fn normal(provenance: FactProvenance) -> Result<FactMetadata, CodexCanonicalError> {
    Ok(FactMetadata::new(
        provenance,
        telltale_schema::observation::Sensitivity::Normal,
    )?)
}

fn parsed_argument_view(value: &Value) -> Option<Value> {
    match value {
        Value::String(value) => serde_json::from_str(value).ok(),
        Value::Object(_) => Some(value.clone()),
        _ => None,
    }
}

fn argument_command(arguments: Option<&Value>, parsed: Option<&Value>) -> Option<String> {
    parsed
        .and_then(|arguments| argument_string(arguments, "command"))
        .or_else(|| parsed.and_then(|arguments| argument_string(arguments, "cmd")))
        .or_else(|| arguments.and_then(|arguments| argument_string(arguments, "command")))
        .or_else(|| arguments.and_then(|arguments| argument_string(arguments, "cmd")))
}

fn argument_string(value: &Value, key: &str) -> Option<String> {
    value
        .as_object()?
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn value_to_json(value: &Value) -> Result<JsonValue, CodexCanonicalError> {
    match value {
        Value::Null => Ok(JsonValue::Null),
        Value::Bool(value) => Ok(JsonValue::Bool(*value)),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(JsonValue::Integer(value))
            } else if let Some(value) = value.as_u64() {
                Ok(JsonValue::Unsigned(value))
            } else {
                let value = value.as_f64().ok_or_else(|| {
                    mapping(
                        "non_finite_number",
                        "Codex number cannot be represented safely",
                    )
                })?;
                Ok(JsonValue::number(value)?)
            }
        }
        Value::String(value) => Ok(JsonValue::string(value)),
        Value::Array(values) => values
            .iter()
            .map(value_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(JsonValue::Array),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), value_to_json(value)?)))
            .collect::<Result<Vec<_>, CodexCanonicalError>>()
            .and_then(|values| Ok(JsonValue::object(values)?)),
    }
}

fn mapping(code: &'static str, detail: &'static str) -> CodexCanonicalError {
    CodexCanonicalError::Mapping { code, detail }
}

impl CodexContentBlock {
    fn is_tool(&self) -> bool {
        matches!(self, Self::ToolUse { .. } | Self::ToolResult { .. })
    }

    fn is_tool_result(&self) -> bool {
        matches!(self, Self::ToolResult { .. })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::{
        CapabilityAvailability, CapabilityId, ContentPartKind, Fidelity, IdentityCoordinateKind,
        IngestionMode, JsonValue, MessageRole, ObservationBody, ObservationFamily,
        ObservationStage, ObservedAt, ToolStatus,
    };
    use telltale_schema::record::RecordKind;
    use telltale_schema::source::Source;
    use tempfile::tempdir;

    use super::{CodexCanonicalOptions, project_codex_canonical_observations};
    use crate::parser::parse_source_records;

    const OBSERVED_AT: &str = "2026-09-02T12:00:00Z";

    fn source(source_id: &str, kind: SourceKind, relative: &str) -> Source {
        Source {
            client: ClientId::Codex,
            kind,
            source_id: source_id.to_owned(),
            path: crate::test_fixture_path(relative),
        }
    }

    fn temp_source(
        source_id: &str,
        kind: SourceKind,
        contents: &str,
    ) -> (tempfile::TempDir, Source) {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("synthetic-codex.jsonl");
        fs::write(&path, contents).expect("Codex fixture");
        (
            directory,
            Source {
                client: ClientId::Codex,
                kind,
                source_id: source_id.to_owned(),
                path,
            },
        )
    }

    fn project(source: &Source) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
        project_codex_canonical_observations(
            source,
            CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect("canonical observations")
    }

    #[test]
    fn simple_messages_use_source_time_but_not_filename_session() {
        let source = source(
            "codex.sessions",
            SourceKind::Jsonl,
            "session_stores/codex/sessions/2026/04/session-a.jsonl",
        );
        let first = project(&source);
        let second = project(&source);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].kind(), ObservationFamily::Message);
        assert_eq!(first[0].stage(), ObservationStage::MessageObserved);
        assert_eq!(first[0].session_id(), None);
        assert_eq!(first[0].source().source_sequence(), Some(1));
        assert_eq!(first[0].observed_at().as_str(), OBSERVED_AT);
        assert_eq!(
            first[0].occurred_at().map(|value| value.as_str()),
            Some("2026-04-01T00:00:01Z")
        );
        assert_eq!(
            first[0].observation_id(),
            second[0].observation_id(),
            "same bytes and observed time replay identically"
        );
        assert_eq!(
            first[0].identity_basis().coordinate().unwrap().0,
            IdentityCoordinateKind::SourceSequence
        );
        let legacy = parse_source_records(&source).expect("legacy records");
        assert_eq!(legacy[1].session_id, "session-a");
    }

    #[test]
    fn event_messages_map_to_truthful_roles() {
        let source = source(
            "codex.sessions",
            SourceKind::Jsonl,
            "session_stores/codex/sessions/2026/04/uc001-positive.jsonl",
        );
        let observations = project(&source);
        assert_eq!(observations.len(), 2);
        for (observation, role) in observations
            .iter()
            .zip([MessageRole::User, MessageRole::Assistant])
        {
            let ObservationBody::Message(message) = observation.body() else {
                panic!("expected message")
            };
            assert_eq!(message.role(), Some(role));
            assert_eq!(observation.stage(), ObservationStage::MessageObserved);
        }
    }

    #[test]
    fn direct_source_session_id_is_used_without_filename_identity() {
        let (_directory, source) = temp_source(
            "codex.sessions",
            SourceKind::Jsonl,
            r#"{"type":"user","sessionId":"source-session","content":"Synthetic user message."}"#,
        );
        let observations = project(&source);
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "source-session"
        );
        assert_eq!(observations[0].source().source_sequence(), Some(0));
    }

    #[test]
    fn unknown_message_role_fails_closed() {
        let (_directory, source) = temp_source(
            "codex.sessions",
            SourceKind::Jsonl,
            r#"{"type":"message","role":"system","content":"Synthetic role marker."}"#,
        );
        let error = super::project_codex_canonical_observations(
            &source,
            CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("unknown role");
        assert_eq!(error.code(), "unsupported_role");
        assert!(!error.to_string().contains("Synthetic role marker"));
        assert_eq!(
            parse_source_records(&source).unwrap()[0].kind,
            RecordKind::Other
        );
    }

    #[test]
    fn response_items_preserve_ordered_parts_and_custom_native_string_input() {
        let (_directory, source) = temp_source(
            "codex.sessions",
            SourceKind::Jsonl,
            r#"{"type":"session_meta","payload":{"session_id":"codex-app-session"}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Inspect."}]}}
{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"I will inspect."},{"type":"tool_use","name":"exec","input":{"cmd":"git status"}}]}}
{"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"call-1","input":"{\"cmd\":\"git status\"}"}}
{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"call-1","output":{"status":"clean"}}}
"#,
        );
        let observations = project(&source);
        assert_eq!(observations.len(), 5);
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "codex-app-session"
        );
        assert_eq!(observations[1].kind(), ObservationFamily::Message);
        assert_eq!(observations[2].kind(), ObservationFamily::Tool);
        assert_eq!(observations[2].stage(), ObservationStage::ToolRequested);
        let ObservationBody::Tool(content_tool) = observations[2].body() else {
            panic!("expected content tool")
        };
        assert_eq!(
            content_tool.arguments(),
            Some(
                &JsonValue::object([("cmd".to_owned(), JsonValue::string("git status")),]).unwrap()
            )
        );
        assert_eq!(observations[3].stage(), ObservationStage::ToolRequested);
        let ObservationBody::Tool(custom_tool) = observations[3].body() else {
            panic!("expected custom tool")
        };
        assert_eq!(
            custom_tool.arguments(),
            Some(&JsonValue::string(r#"{"cmd":"git status"}"#))
        );
        assert_eq!(
            observations[3].facets()["command.text"].value(),
            &JsonValue::string("git status")
        );
        assert_eq!(
            observations[3].correlation().call_id().unwrap().value(),
            "call-1"
        );
        assert_eq!(
            observations[4].stage(),
            ObservationStage::ToolResultReturned
        );
        assert_eq!(
            observations[4].correlation().call_id().unwrap().value(),
            "call-1"
        );
        assert_eq!(observations[1].identity_basis().child_ordinal(), 0);
        assert_eq!(observations[2].identity_basis().child_ordinal(), 1);
    }

    #[test]
    fn function_call_records_are_canonical_tools_without_changing_legacy_kind() {
        let (_directory, source) = temp_source(
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
            r#"{"type":"event_msg","payload":{"type":"function_call","name":"shell","call_id":"call-function-1","arguments":{"command":"printf synthetic"}}}
{"type":"event_msg","payload":{"type":"function_call_output","call_id":"call-function-1","output":{"exit_code":0}}}"#,
        );
        let observations = project(&source);
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
        assert_eq!(
            observations[1].stage(),
            ObservationStage::ToolResultReturned
        );
        assert_eq!(
            observations[0].correlation().call_id().unwrap().value(),
            "call-function-1"
        );
        let ObservationBody::Tool(tool) = observations[0].body() else {
            panic!("expected function call tool")
        };
        assert_eq!(tool.name(), Some("shell"));
        assert_eq!(
            tool.arguments(),
            Some(
                &JsonValue::object([
                    ("command".to_owned(), JsonValue::string("printf synthetic"),)
                ])
                .unwrap()
            )
        );
        let ObservationBody::Tool(result) = observations[1].body() else {
            panic!("expected function call result")
        };
        assert_eq!(
            result.result(),
            Some(&JsonValue::object([("exit_code".to_owned(), JsonValue::Integer(0))]).unwrap())
        );
        let legacy = parse_source_records(&source).expect("legacy records");
        assert!(legacy.iter().all(|record| record.kind == RecordKind::Other));
    }

    #[test]
    fn content_block_tool_ids_are_optional_and_values_stay_structured() {
        let (_directory, source) = temp_source(
            "codex.sessions",
            SourceKind::Jsonl,
            r#"{"type":"assistant","session_id":"content-blocks","content":[{"type":"text","text":"Run it."},{"type":"tool_use","name":"exec","input":{"command":"printf synthetic"}}]}
{"type":"assistant","content":[{"type":"tool_result","content":{"exit_code":0}}]}"#,
        );
        let observations = project(&source);
        assert_eq!(observations.len(), 4);
        assert_eq!(observations[0].kind(), ObservationFamily::Message);
        let ObservationBody::Message(message) = observations[0].body() else {
            panic!("expected message")
        };
        assert_eq!(message.content_parts()[0].kind(), ContentPartKind::Text);
        assert_eq!(observations[1].stage(), ObservationStage::ToolRequested);
        assert_eq!(observations[2].stage(), ObservationStage::MessageObserved);
        assert_eq!(
            observations[3].stage(),
            ObservationStage::ToolResultReturned
        );
        assert_eq!(observations[1].correlation().call_id(), None);
        let ObservationBody::Tool(tool) = observations[1].body() else {
            panic!("expected tool")
        };
        assert!(matches!(tool.arguments(), Some(JsonValue::Object(_))));
        assert_eq!(observations[3].correlation().call_id(), None);
        let ObservationBody::Tool(result) = observations[3].body() else {
            panic!("expected result tool")
        };
        assert_eq!(
            result.result(),
            Some(&JsonValue::object([("exit_code".to_owned(), JsonValue::Integer(0),)]).unwrap())
        );
    }

    #[test]
    fn generic_tool_states_never_become_execution_stages() {
        let (_directory, source) = temp_source(
            "codex.sessions",
            SourceKind::Jsonl,
            r#"{"type":"tool","state":{"status":"running"}}
{"type":"tool","name":"exec","state":{"status":"completed"}}
{"type":"tool","state":{"status":"error","error":{"message":"synthetic failure"}}}"#,
        );
        let observations = project(&source);
        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
        assert_eq!(
            observations[1].stage(),
            ObservationStage::ToolResultReturned
        );
        assert_eq!(
            observations[2].stage(),
            ObservationStage::ToolResultReturned
        );
        let ObservationBody::Tool(running) = observations[0].body() else {
            panic!("expected running tool")
        };
        assert_eq!(running.reported_status(), Some(ToolStatus::Unknown));
        let ObservationBody::Tool(completed) = observations[1].body() else {
            panic!("expected completed tool")
        };
        assert_eq!(completed.reported_status(), Some(ToolStatus::Unknown));
        let ObservationBody::Tool(error) = observations[2].body() else {
            panic!("expected error tool")
        };
        assert_eq!(error.reported_status(), Some(ToolStatus::Failed));
        assert!(observations.iter().all(|observation| !matches!(
            observation.stage(),
            ObservationStage::ToolProposed
                | ObservationStage::ToolExecutionStarted
                | ObservationStage::ToolExecutionCompleted
        )));
    }

    #[test]
    fn session_meta_is_skipped_and_its_id_is_inherited() {
        let source = source(
            "codex.sessions",
            SourceKind::Jsonl,
            "session_stores/codex/sessions/2026/04/encoded-http-exfil.jsonl",
        );
        let observations = project(&source);
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "encoded-http-exfil"
        );
        assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
    }

    #[test]
    fn headless_turn_context_is_skipped_without_process_observations() {
        let headless_source = source(
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
            "session_stores/codex/headless/headless-a.jsonl",
        );
        assert!(project(&headless_source).is_empty());
        let headless_source = source(
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
            "session_stores/codex/headless/uc001-headless.jsonl",
        );
        let observations = project(&headless_source);
        assert_eq!(observations.len(), 2);
        assert!(
            observations
                .iter()
                .all(|observation| observation.kind() != ObservationFamily::Process)
        );
        assert!(
            observations
                .iter()
                .all(|observation| observation.source().adapter_id() == "codex.headless_sessions")
        );
    }

    #[test]
    fn provenance_capabilities_and_four_source_identities_are_explicit() {
        let contents =
            r#"{"type":"user","session_id":"same-shape","content":"Synthetic message."}"#;
        let identities = [
            ("codex.sessions", SourceKind::Jsonl),
            ("codex.archived_sessions", SourceKind::ArchivedJsonl),
            ("codex.headless_sessions", SourceKind::HeadlessJsonl),
            ("codex.project_sessions", SourceKind::Jsonl),
        ];
        let mut ids = Vec::new();
        for (source_id, kind) in identities {
            let (_directory, source) = temp_source(source_id, kind, contents);
            let observations = project(&source);
            let observation = &observations[0];
            assert_eq!(observation.source().adapter_type(), "codex");
            assert_eq!(observation.source().adapter_id(), source_id);
            assert_eq!(
                observation.source().ingestion_mode(),
                IngestionMode::SessionStore
            );
            assert_eq!(observation.source().fidelity(), Fidelity::PartialStructured);
            assert_eq!(observation.source().adapter_version(), None);
            assert_eq!(observation.source().native_id(), None);
            assert_eq!(observation.source().source_path_hash(), None);
            let capabilities = observation.capability_context().unwrap();
            assert_eq!(capabilities.overrides().len(), 3);
            assert_eq!(
                capabilities.resolve(CapabilityId::ToolCall),
                CapabilityAvailability::Supported
            );
            assert_eq!(
                capabilities.resolve(CapabilityId::UserContext),
                CapabilityAvailability::Supported
            );
            assert_eq!(
                capabilities.resolve(CapabilityId::ToolExecution),
                CapabilityAvailability::Unsupported
            );
            ids.push(observation.observation_id().to_owned());
        }
        assert_eq!(ids.windows(2).filter(|pair| pair[0] == pair[1]).count(), 0);
    }

    #[test]
    fn command_and_resource_facets_do_not_create_activity_families() {
        let (_directory, source) = temp_source(
            "codex.project_sessions",
            SourceKind::Jsonl,
            r#"{"type":"tool_call","arguments":{"command":"git status","file_path":"README.md"},"message":"synthetic command"}"#,
        );
        let observations = project(&source);
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].facets()["command.text"].value(),
            &JsonValue::string("git status")
        );
        assert_eq!(
            observations[0].facets()["resource.path"].value(),
            &JsonValue::string("README.md")
        );
        assert!(matches!(
            observations[0].fact_metadata()["command.text"].provenance(),
            telltale_schema::observation::FactProvenance::Parsed
        ));
        assert!(observations.iter().all(|observation| !matches!(
            observation.kind(),
            ObservationFamily::File | ObservationFamily::Process | ObservationFamily::Network
        )));
    }

    #[test]
    fn unknown_and_schema_errors_are_safe_and_legacy_is_unchanged() {
        let unknown_source = source(
            "codex.sessions",
            SourceKind::Jsonl,
            "parser_maturity/non_discovered/unknown-variant.jsonl",
        );
        let error = super::project_codex_canonical_observations(
            &unknown_source,
            CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("unknown discriminator");
        assert_eq!(error.code(), "unknown_discriminator");
        assert!(
            !error
                .to_string()
                .contains("Synthetic unknown record variant")
        );
        assert!(!format!("{error:?}").contains("Synthetic unknown record variant"));
        let legacy = parse_source_records(&unknown_source).expect("legacy remains available");
        assert_eq!(legacy[0].kind, RecordKind::Other);

        let drift = source(
            "codex.archived_sessions",
            SourceKind::ArchivedJsonl,
            "parser_maturity/non_discovered/schema-drift.jsonl",
        );
        let error = super::project_codex_canonical_observations(
            &drift,
            CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("schema drift");
        assert_eq!(error.code(), "source_parse");
    }

    #[test]
    fn unknown_content_block_fails_without_changing_legacy() {
        let (_directory, source) = temp_source(
            "codex.sessions",
            SourceKind::Jsonl,
            r#"{"type":"assistant","content":[{"type":"future_block","value":"Synthetic payload marker."}]}"#,
        );
        let error = super::project_codex_canonical_observations(
            &source,
            CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("unknown block");
        assert_eq!(error.code(), "unknown_content_block");
        assert!(!error.to_string().contains("Synthetic payload marker"));
        assert!(parse_source_records(&source).is_ok());
    }

    #[test]
    fn all_projected_families_are_bounded_to_messages_and_tools() {
        let source = source(
            "codex.project_sessions",
            SourceKind::Jsonl,
            "parser_maturity/codex/project_sessions/project-session.jsonl",
        );
        let observations = project(&source);
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].source().adapter_id(),
            "codex.project_sessions"
        );
        assert!(observations.iter().all(|observation| matches!(
            observation.kind(),
            ObservationFamily::Message | ObservationFamily::Tool
        )));
        assert!(observations.iter().all(|observation| !matches!(
            observation.kind(),
            ObservationFamily::File
                | ObservationFamily::Process
                | ObservationFamily::Network
                | ObservationFamily::Session
                | ObservationFamily::Inference
        )));
    }
}
