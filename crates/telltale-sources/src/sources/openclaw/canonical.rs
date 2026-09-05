#![allow(dead_code)]

use std::fmt;

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId, ContentPart,
    ContentPartKind, CorrelationId, CorrelationIds, FactMetadata, FactProvenance, Fidelity,
    IngestionMode, JsonValue, MessageObservation, MessageRole, ObservationBody, ObservationBuilder,
    ObservationError, ObservationStage, ObservedAt, SemanticFacet, SourceProvenance,
    SourceTimestamp, ToolObservation,
};
use telltale_schema::source::Source;

use super::native::{
    OpenClawContentBlock, OpenClawNativeRecord, OpenClawToolFields,
    extract_openclaw_native_records, is_known_openclaw_discriminator,
};
use crate::parser::ParseError;

#[derive(Clone)]
pub(crate) struct OpenClawCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
}

impl OpenClawCanonicalOptions {
    pub(crate) fn new(observed_at: ObservedAt) -> Self {
        Self { observed_at }
    }
}

pub(crate) enum OpenClawCanonicalError {
    Source(ParseError),
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl OpenClawCanonicalError {
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

impl fmt::Debug for OpenClawCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("OpenClawCanonicalError::Source")
            }
            Self::Mapping { code, detail } => formatter
                .debug_struct("OpenClawCanonicalError::Mapping")
                .field("code", code)
                .field("detail", detail)
                .finish(),
            Self::Observation(error) => formatter
                .debug_struct("OpenClawCanonicalError::Observation")
                .field("code", &error.code())
                .finish(),
        }
    }
}

impl fmt::Display for OpenClawCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("OpenClaw source could not be parsed")
            }
            Self::Mapping { code, detail } => {
                write!(
                    formatter,
                    "OpenClaw canonical mapping failed ({code}): {detail}"
                )
            }
            Self::Observation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for OpenClawCanonicalError {}

impl From<ParseError> for OpenClawCanonicalError {
    fn from(error: ParseError) -> Self {
        Self::Source(error)
    }
}

impl From<ObservationError> for OpenClawCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

pub(crate) fn project_openclaw_canonical_observations(
    source: &Source,
    options: OpenClawCanonicalOptions,
) -> Result<Vec<CanonicalObservationV2>, OpenClawCanonicalError> {
    if source.client != ClientId::OpenClaw || source.source_id != "openclaw.agents" {
        return Err(mapping(
            "unsupported_source_identity",
            "canonical projection requires the OpenClaw agents source",
        ));
    }
    if source.kind != SourceKind::Jsonl {
        return Err(mapping(
            "unsupported_source_kind",
            "canonical projection requires JSONL input",
        ));
    }

    let records = extract_openclaw_native_records(source)?;
    let mut observations = Vec::new();
    for record in records {
        project_record(&record, &options, &mut observations)?;
    }
    Ok(observations)
}

fn project_record(
    record: &OpenClawNativeRecord,
    options: &OpenClawCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), OpenClawCanonicalError> {
    if record
        .discriminator
        .as_deref()
        .is_some_and(|kind| !is_known_openclaw_discriminator(kind))
    {
        return Err(mapping(
            "unknown_discriminator",
            "explicit OpenClaw record discriminator is not supported",
        ));
    }

    if record.legacy_kind == telltale_schema::record::RecordKind::SessionMeta {
        return Ok(());
    }

    if record.payload_discriminator
        && record
            .discriminator
            .as_deref()
            .is_some_and(is_message_discriminator)
        && record.message_content.is_none()
        && record.blocks.is_none()
        && record.tool_calls.is_empty()
    {
        return Err(mapping(
            "missing_payload_evidence",
            "OpenClaw payload message has no supported content or tool fact",
        ));
    }

    let mut child_ordinal = 0;
    if let Some(blocks) = record.blocks.as_deref() {
        if blocks
            .iter()
            .any(|block| matches!(block, OpenClawContentBlock::Unknown))
        {
            return Err(mapping(
                "unknown_content_block",
                "OpenClaw content block type is not supported",
            ));
        }

        let message_record = record
            .discriminator
            .as_deref()
            .is_some_and(is_message_discriminator);
        let has_message_content = blocks.iter().any(|block| {
            matches!(
                block,
                OpenClawContentBlock::Text { .. } | OpenClawContentBlock::ToolUse { .. }
            )
        });
        let message_required = message_record && (blocks.is_empty() || has_message_content);
        let mut message_emitted = false;

        for block in blocks {
            if message_required
                && !message_emitted
                && !matches!(block, OpenClawContentBlock::ToolResult { .. })
            {
                emit_message_body(
                    record,
                    options,
                    build_message_body(record, canonical_role(record)?, blocks)?,
                    &mut child_ordinal,
                    observations,
                )?;
                message_emitted = true;
            }
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
        if message_required && !message_emitted {
            emit_message_body(
                record,
                options,
                build_message_body(record, canonical_role(record)?, blocks)?,
                &mut child_ordinal,
                observations,
            )?;
        }
    } else {
        match record.discriminator.as_deref() {
            Some(kind) if is_message_discriminator(kind) => {
                let payload_tool_calls_only = record.payload_discriminator
                    && record.message_content.is_none()
                    && record.blocks.is_none()
                    && !record.tool_calls.is_empty();
                if !payload_tool_calls_only {
                    emit_message(
                        record,
                        options,
                        canonical_role(record)?,
                        &mut child_ordinal,
                        observations,
                    )?;
                }
            }
            Some("tool_call") => emit_tool(
                record,
                options,
                record.tool.clone(),
                ObservationStage::ToolRequested,
                &mut child_ordinal,
                observations,
            )?,
            Some("tool_result") => emit_tool(
                record,
                options,
                record.tool.clone(),
                ObservationStage::ToolResultReturned,
                &mut child_ordinal,
                observations,
            )?,
            Some("tool") => emit_generic_tool(record, options, &mut child_ordinal, observations)?,
            _ => {
                return Err(mapping(
                    "unsupported_record",
                    "OpenClaw record does not describe a supported message or tool",
                ));
            }
        }
    }

    for fields in &record.tool_calls {
        emit_tool(
            record,
            options,
            fields.clone(),
            ObservationStage::ToolRequested,
            &mut child_ordinal,
            observations,
        )?;
    }
    Ok(())
}

fn is_message_discriminator(kind: &str) -> bool {
    matches!(
        kind,
        "user_message" | "user" | "assistant_message" | "assistant" | "gemini" | "model" | "text"
    )
}

fn canonical_role(record: &OpenClawNativeRecord) -> Result<MessageRole, OpenClawCanonicalError> {
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
            "OpenClaw record role is not a user or assistant role",
        )),
        None => Err(mapping(
            "missing_role",
            "OpenClaw conversational record has no role",
        )),
    }
}

fn build_message_body(
    record: &OpenClawNativeRecord,
    role: MessageRole,
    blocks: &[OpenClawContentBlock],
) -> Result<MessageObservation, OpenClawCanonicalError> {
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

fn emit_message(
    record: &OpenClawNativeRecord,
    options: &OpenClawCanonicalOptions,
    role: MessageRole,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), OpenClawCanonicalError> {
    let body = build_message_body(record, role, &[])?;
    emit_message_body(record, options, body, child_ordinal, observations)
}

fn emit_message_body(
    record: &OpenClawNativeRecord,
    options: &OpenClawCanonicalOptions,
    body: MessageObservation,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), OpenClawCanonicalError> {
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

fn content_part(block: &OpenClawContentBlock) -> Result<ContentPart, OpenClawCanonicalError> {
    match block {
        OpenClawContentBlock::Text { text } => {
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
        OpenClawContentBlock::ToolUse {
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
        OpenClawContentBlock::ToolResult {
            tool_use_id,
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
            if let Some(tool_use_id) = tool_use_id {
                fields.push(("tool_use_id".to_owned(), JsonValue::string(tool_use_id)));
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
        OpenClawContentBlock::Unknown => Err(mapping(
            "unknown_content_block",
            "OpenClaw content block type is not supported",
        )),
    }
}

fn block_tool(
    block: &OpenClawContentBlock,
) -> Result<Option<(OpenClawToolFields, ObservationStage)>, OpenClawCanonicalError> {
    match block {
        OpenClawContentBlock::ToolUse {
            id,
            name,
            input,
            input_present,
        } => Ok(Some((
            OpenClawToolFields {
                name: name.clone(),
                arguments: input.clone(),
                arguments_present: *input_present,
                call_id: id.clone(),
                ..OpenClawToolFields::default()
            },
            ObservationStage::ToolRequested,
        ))),
        OpenClawContentBlock::ToolResult {
            tool_use_id,
            result,
            result_present,
            is_error,
            is_error_present,
        } => Ok(Some((
            OpenClawToolFields {
                call_id: tool_use_id.clone(),
                result: result.clone(),
                result_present: *result_present,
                is_error: *is_error,
                is_error_present: *is_error_present,
                ..OpenClawToolFields::default()
            },
            ObservationStage::ToolResultReturned,
        ))),
        OpenClawContentBlock::Text { .. } => Ok(None),
        OpenClawContentBlock::Unknown => Err(mapping(
            "unknown_content_block",
            "OpenClaw content block type is not supported",
        )),
    }
}

fn emit_generic_tool(
    record: &OpenClawNativeRecord,
    options: &OpenClawCanonicalOptions,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), OpenClawCanonicalError> {
    let fields = &record.tool;
    let has_request = fields.name.is_some() || fields.arguments_present;
    let has_result = fields.result_present || fields.error_present || fields.is_error.is_some();
    if !has_request && !has_result {
        return Err(mapping(
            "unsupported_record",
            "OpenClaw tool snapshot has no direct request or result fact",
        ));
    }
    if has_request {
        emit_tool(
            record,
            options,
            fields.clone(),
            ObservationStage::ToolRequested,
            child_ordinal,
            observations,
        )?;
    }
    if has_result {
        emit_tool(
            record,
            options,
            fields.clone(),
            ObservationStage::ToolResultReturned,
            child_ordinal,
            observations,
        )?;
    }
    Ok(())
}

fn emit_tool(
    record: &OpenClawNativeRecord,
    options: &OpenClawCanonicalOptions,
    fields: OpenClawToolFields,
    stage: ObservationStage,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), OpenClawCanonicalError> {
    if fields.is_error_present && fields.is_error.is_none() {
        return Err(mapping(
            "invalid_tool_result",
            "OpenClaw tool error state is not boolean",
        ));
    }

    let result = fields.result.as_ref().or(fields.error.as_ref());
    let has_result = fields.result_present || fields.error_present;
    if stage == ObservationStage::ToolResultReturned && !has_result && fields.is_error.is_none() {
        return Err(mapping(
            "invalid_tool_result",
            "OpenClaw tool result has no returned value or error state",
        ));
    }

    let mut body = ToolObservation::new();
    let mut metadata = Vec::new();
    if let Some(name) = &fields.name {
        body = body.with_name(name)?;
        metadata.push(("tool.name", FactProvenance::Reported));
    }
    if let Some(arguments) = &fields.arguments {
        body = body.with_arguments(value_to_json(arguments)?);
        metadata.push(("tool.arguments", FactProvenance::Reported));
    }
    if let Some(result) = result {
        body = body.with_result(value_to_json(result)?);
        metadata.push(("tool.result", FactProvenance::Reported));
    }
    if let Some(is_error) = fields.is_error {
        body = body.with_is_error(is_error);
        metadata.push(("tool.is_error", FactProvenance::Reported));
    }
    if metadata.is_empty() {
        return Err(mapping(
            "invalid_tool_request",
            "OpenClaw tool record has no canonical tool fact",
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
    for (path, provenance) in metadata {
        builder = builder.fact_metadata(path, normal(provenance)?);
    }

    if let Some(arguments) = fields.arguments.as_ref().and_then(parsed_argument_view) {
        if let Some(command) =
            argument_string(arguments, "command").or_else(|| argument_string(arguments, "cmd"))
        {
            builder = builder
                .facet(
                    "command.text",
                    SemanticFacet::new(JsonValue::string(command)),
                )?
                .fact_metadata("command.text", normal(FactProvenance::Parsed)?);
        }
        if let Some(path) =
            argument_string(arguments, "file_path").or_else(|| argument_string(arguments, "path"))
        {
            builder = builder
                .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
                .fact_metadata("resource.path", normal(FactProvenance::Parsed)?);
        }
    }

    observations.push(builder.build()?);
    *child_ordinal += 1;
    Ok(())
}

fn tool_correlation(
    call_id: Option<&str>,
) -> Result<Option<CorrelationIds>, OpenClawCanonicalError> {
    let Some(call_id) = call_id else {
        return Ok(None);
    };
    Ok(Some(
        CorrelationIds::new().with_call_id(CorrelationId::source_reported(call_id)?),
    ))
}

fn common_builder(
    record: &OpenClawNativeRecord,
    options: &OpenClawCanonicalOptions,
    body: ObservationBody,
    stage: ObservationStage,
    correlation: Option<CorrelationIds>,
    child_ordinal: usize,
) -> Result<ObservationBuilder, OpenClawCanonicalError> {
    let mut source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "openclaw",
        "openclaw.agents",
        Fidelity::PartialStructured,
    )?
    .with_source_sequence(record.source_sequence);
    if let Some(native_id) = &record.native_id {
        source = source.with_native_id(native_id)?;
    } else if let Some(session_id) = &record.session_id {
        source = source.with_identity_source_sequence(session_id, record.source_sequence)?;
    }

    let mut builder =
        CanonicalObservationV2::builder(body, stage, options.observed_at.clone(), source)
            .sequence(record.source_sequence)
            .capability_context(capabilities());
    if let Some(session_id) = &record.session_id {
        builder = builder.session_id(CorrelationId::source_reported(session_id)?);
    }
    if let Some(correlation) = correlation {
        builder = builder.correlation(correlation);
    }
    if let Some(timestamp) = &record.source_timestamp
        && let Ok(timestamp) = SourceTimestamp::new(timestamp)
    {
        builder = builder.occurred_at(timestamp);
    }
    Ok(builder.child_ordinal(
        u32::try_from(child_ordinal)
            .map_err(|_| mapping("child_ordinal_overflow", "too many observations in record"))?,
    ))
}

fn capabilities() -> CapabilityContext {
    CapabilityContext::new()
        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported)
        .with_override(CapabilityId::ToolExecution, CapabilityAvailability::Unknown)
        .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported)
}

fn normal_reported() -> Result<FactMetadata, OpenClawCanonicalError> {
    normal(FactProvenance::Reported)
}

fn normal(provenance: FactProvenance) -> Result<FactMetadata, OpenClawCanonicalError> {
    Ok(match provenance {
        FactProvenance::Reported => FactMetadata::reported()?,
        FactProvenance::Parsed => FactMetadata::parsed()?,
        _ => FactMetadata::new(
            provenance,
            telltale_schema::observation::Sensitivity::Normal,
        )?,
    })
}

fn parsed_argument_view(
    value: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    value.as_object()
}

fn argument_string(
    value: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn value_to_json(value: &serde_json::Value) -> Result<JsonValue, OpenClawCanonicalError> {
    Ok(JsonValue::try_from_source_value(value)?)
}

fn mapping(code: &'static str, detail: &'static str) -> OpenClawCanonicalError {
    OpenClawCanonicalError::Mapping { code, detail }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::{
        CapabilityAvailability, CapabilityId, ContentPartKind, Fidelity, IdentityCoordinateKind,
        IdentityCoordinateValue, IngestionMode, JsonValue, MessageRole, ObservationBody,
        ObservationFamily, ObservationStage, ObservedAt, SemanticReplayVerdict,
    };
    use telltale_schema::record::RecordKind;
    use telltale_schema::source::Source;
    use tempfile::tempdir;

    use super::{OpenClawCanonicalOptions, project_openclaw_canonical_observations};
    use crate::parser::parse_source_records;

    const OBSERVED_AT: &str = "2026-09-04T12:00:00Z";

    fn source(path: std::path::PathBuf) -> Source {
        Source {
            client: ClientId::OpenClaw,
            kind: SourceKind::Jsonl,
            source_id: "openclaw.agents".to_owned(),
            path,
        }
    }

    fn project(
        path: std::path::PathBuf,
    ) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
        project_openclaw_canonical_observations(
            &source(path),
            OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect("OpenClaw canonical observations")
    }

    #[test]
    fn benign_baseline_preserves_direct_tool_calls_and_legacy_flattening() {
        let path = crate::test_fixture_path(
            "benign_baselines/openclaw/agents/baseline-project/benign-baseline.jsonl",
        );
        let observations = project(path.clone());
        assert_eq!(observations.len(), 5);

        assert_eq!(observations[0].kind(), ObservationFamily::Message);
        assert_eq!(observations[0].stage(), ObservationStage::MessageObserved);
        assert_eq!(observations[0].observed_at().as_str(), OBSERVED_AT);
        assert_eq!(
            observations[0].occurred_at().unwrap().as_str(),
            "2026-05-10T17:00:00Z"
        );
        let ObservationBody::Message(user) = observations[0].body() else {
            panic!("expected user message")
        };
        assert_eq!(user.role(), Some(MessageRole::User));
        assert_eq!(
            user.content(),
            Some(&JsonValue::string("Show me the contents of the Makefile."))
        );

        let ObservationBody::Message(assistant) = observations[1].body() else {
            panic!("expected assistant message")
        };
        assert_eq!(assistant.role(), Some(MessageRole::Assistant));
        assert_eq!(observations[1].source().source_sequence(), Some(1));
        assert_eq!(observations[1].identity_basis().child_ordinal(), 0);

        let ObservationBody::Tool(request) = observations[2].body() else {
            panic!("expected direct tool request")
        };
        assert_eq!(request.name(), Some("read_file"));
        assert_eq!(
            request.arguments(),
            Some(&JsonValue::object([("path".to_owned(), JsonValue::string("Makefile"))]).unwrap())
        );
        assert_eq!(observations[2].stage(), ObservationStage::ToolRequested);
        assert_eq!(observations[2].identity_basis().child_ordinal(), 1);
        assert_eq!(
            observations[2].correlation().call_id().unwrap().value(),
            "tc-openclaw-baseline-001"
        );
        assert_eq!(
            observations[2].facets()["resource.path"].value(),
            &JsonValue::string("Makefile")
        );
        assert_eq!(
            observations[2].fact_metadata()["resource.path"].provenance(),
            telltale_schema::observation::FactProvenance::Parsed
        );

        let ObservationBody::Tool(result) = observations[3].body() else {
            panic!("expected tool result")
        };
        assert_eq!(
            observations[3].stage(),
            ObservationStage::ToolResultReturned
        );
        assert_eq!(
            result.result().map(|value| value
                == &JsonValue::string(
                    "build:\n\tcargo build --release\n\ntest:\n\tcargo test\n\nclean:\tcargo clean"
                )),
            Some(true)
        );
        assert_eq!(
            observations[3].correlation().call_id().unwrap().value(),
            "tc-openclaw-baseline-001"
        );

        assert!(observations.iter().all(|observation| {
            observation.source().ingestion_mode() == IngestionMode::SessionStore
                && observation.source().adapter_type() == "openclaw"
                && observation.source().adapter_id() == "openclaw.agents"
                && observation.source().fidelity() == Fidelity::PartialStructured
                && observation
                    .capability_context()
                    .unwrap()
                    .resolve(CapabilityId::ToolCall)
                    == CapabilityAvailability::Supported
                && observation
                    .capability_context()
                    .unwrap()
                    .resolve(CapabilityId::ToolExecution)
                    == CapabilityAvailability::Unknown
                && observation
                    .capability_context()
                    .unwrap()
                    .resolve(CapabilityId::UserContext)
                    == CapabilityAvailability::Supported
        }));

        let legacy = parse_source_records(&source(path)).expect("legacy records");
        assert_eq!(legacy.len(), 4);
        assert_eq!(legacy[1].kind, RecordKind::AssistantMessage);
        assert_eq!(legacy[1].arguments, None);
        assert_eq!(legacy[2].kind, RecordKind::ToolResult);
    }

    #[test]
    fn structured_tool_fixture_keeps_values_and_allows_missing_call_ids() {
        let path = crate::test_fixture_path(
            "session_stores/openclaw/agents/project-b/uc001-openclaw-tool-result.jsonl",
        );
        let observations = project(path);
        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0].kind(), ObservationFamily::Message);
        assert_eq!(observations[1].stage(), ObservationStage::ToolRequested);
        assert_eq!(
            observations[2].stage(),
            ObservationStage::ToolResultReturned
        );
        assert_eq!(observations[1].correlation().call_id(), None);
        assert_eq!(observations[2].correlation().call_id(), None);

        let ObservationBody::Tool(request) = observations[1].body() else {
            panic!("expected tool request")
        };
        assert_eq!(
            request.arguments(),
            Some(&JsonValue::object([("format".to_owned(), JsonValue::string("json"))]).unwrap())
        );
        let ObservationBody::Tool(result) = observations[2].body() else {
            panic!("expected tool result")
        };
        assert!(matches!(result.result(), Some(JsonValue::String(_))));
        assert!(observations.iter().all(|observation| {
            !matches!(
                observation.stage(),
                ObservationStage::ToolProposed
                    | ObservationStage::ToolExecutionStarted
                    | ObservationStage::ToolExecutionCompleted
            )
        }));
    }

    #[test]
    fn generic_tool_snapshots_emit_only_direct_request_and_result_facts() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("generic-tools.jsonl");
        fs::write(
            &path,
            r#"{"type":"tool","sessionId":"generic-session","tool":"shell","callID":"call-running","state":{"status":"running","input":{"command":"printf synthetic"}}}
{"type":"tool","sessionId":"generic-session","tool":"shell","callID":"call-completed","state":{"status":"completed","output":{"status":"ok"}}}"#,
        )
        .unwrap();
        let observations = project(path);
        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
        assert_eq!(
            observations[2].stage(),
            ObservationStage::ToolResultReturned
        );
        let ObservationBody::Tool(result) = observations[2].body() else {
            panic!("expected returned result")
        };
        assert_eq!(
            result.result(),
            Some(&JsonValue::object([("status".to_owned(), JsonValue::string("ok"))]).unwrap())
        );
        assert!(observations.iter().all(|observation| {
            !matches!(
                observation.stage(),
                ObservationStage::ToolExecutionStarted | ObservationStage::ToolExecutionCompleted
            )
        }));
    }

    #[test]
    fn explicit_call_id_forms_are_correlation_not_native_identity() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("call-id-forms.jsonl");
        let keys = [
            "tool_call_id",
            "call_id",
            "callID",
            "callId",
            "toolCallId",
            "tool_use_id",
        ];
        let contents = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                format!(
                    "{{\"type\":\"tool_result\",\"sessionId\":\"call-id-session\",\"{key}\":\"call-{index}\",\"content\":{{\"ok\":true}}}}"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, contents).unwrap();
        let observations = project(path);
        assert_eq!(observations.len(), keys.len());
        for (index, observation) in observations.iter().enumerate() {
            assert_eq!(observation.source().native_id(), None);
            assert_eq!(
                observation.correlation().call_id().unwrap().value(),
                format!("call-{index}")
            );
        }
    }

    #[test]
    fn mixed_content_keeps_ordered_parts_without_empty_result_message() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("mixed.jsonl");
        fs::write(
            &path,
            r#"{"type":"assistant","sessionId":"mixed-session","content":[{"type":"text","text":"Synthetic request."},{"type":"tool_use","id":"call-mixed","name":"read_file","input":{"file_path":"synthetic.txt"}}]}
{"type":"user","sessionId":"mixed-session","content":[{"type":"tool_result","tool_use_id":"call-mixed","content":{"status":"ok"}}]}"#,
        )
        .unwrap();

        let observations = project(path);
        assert_eq!(observations.len(), 3);
        let ObservationBody::Message(message) = observations[0].body() else {
            panic!("expected assistant message")
        };
        assert_eq!(message.content_parts().len(), 2);
        assert_eq!(message.content_parts()[0].kind(), ContentPartKind::Text);
        assert_eq!(message.content_parts()[1].kind(), ContentPartKind::ToolUse);
        assert_eq!(observations[0].identity_basis().child_ordinal(), 0);
        assert_eq!(observations[1].stage(), ObservationStage::ToolRequested);
        assert_eq!(observations[1].identity_basis().child_ordinal(), 1);
        assert_ne!(
            observations[0].observation_id(),
            observations[1].observation_id()
        );
        assert_eq!(
            observations[2].stage(),
            ObservationStage::ToolResultReturned
        );
        assert_eq!(observations[2].identity_basis().child_ordinal(), 0);
        assert!(observations.iter().all(|observation| {
            !(observation.kind() == ObservationFamily::Message
                && observation.source().source_sequence() == Some(1))
        }));
    }

    #[test]
    fn payload_envelopes_preserve_messages_tools_and_structured_arguments() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("payloads.jsonl");
        fs::write(
            &path,
            r#"{"payload":{"type":"user","sessionId":"payload-session","content":"Synthetic payload user."}}
{"content":"Synthetic outer nested assistant.","sessionId":"outer-nested-session","id":"outer-nested-id","timestamp":"2026-09-04T10:00:00Z","payload":{"payload":{"type":"assistant","sessionId":"nested-payload-session","id":"nested-payload-id","timestamp":"2026-09-04T10:00:01Z","content":"Synthetic nested assistant."}}}
{"payload":{"type":"tool_call","sessionId":"payload-tool-session","tool_name":"read_file","arguments":{"path":"synthetic.txt","options":{"depth":1}}}}
{"payload":{"type":"user_message","sessionId":"payload-message-session","message":"Synthetic payload message."}}"#,
        )
        .unwrap();

        let observations = project(path);
        assert_eq!(observations.len(), 4);

        let ObservationBody::Message(user) = observations[0].body() else {
            panic!("expected payload user message")
        };
        assert_eq!(
            user.content(),
            Some(&JsonValue::string("Synthetic payload user."))
        );
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "payload-session"
        );

        let ObservationBody::Message(assistant) = observations[1].body() else {
            panic!("expected nested payload assistant message")
        };
        assert_eq!(
            assistant.content(),
            Some(&JsonValue::string("Synthetic nested assistant."))
        );
        assert_eq!(
            observations[1].session_id().unwrap().value(),
            "nested-payload-session"
        );
        assert_eq!(
            observations[1].source().native_id(),
            Some("nested-payload-id")
        );
        assert_eq!(
            observations[1].occurred_at().unwrap().as_str(),
            "2026-09-04T10:00:01Z"
        );

        let ObservationBody::Tool(tool) = observations[2].body() else {
            panic!("expected payload tool request")
        };
        assert_eq!(
            tool.arguments(),
            Some(
                &JsonValue::object([
                    ("path".to_owned(), JsonValue::string("synthetic.txt")),
                    (
                        "options".to_owned(),
                        JsonValue::object([("depth".to_owned(), JsonValue::Integer(1))]).unwrap(),
                    ),
                ])
                .unwrap(),
            )
        );
        assert_eq!(observations[2].stage(), ObservationStage::ToolRequested);

        let ObservationBody::Message(message) = observations[3].body() else {
            panic!("expected payload message-field message")
        };
        assert_eq!(
            message.content(),
            Some(&JsonValue::string("Synthetic payload message."))
        );
    }

    #[test]
    fn payload_message_identity_is_stable_when_content_changes() {
        let first_directory = tempdir().unwrap();
        let second_directory = tempdir().unwrap();
        let first_path = first_directory.path().join("first.jsonl");
        let second_path = second_directory.path().join("moved.jsonl");
        fs::write(
            &first_path,
            r#"{"payload":{"type":"user","id":"payload-message-identity","sessionId":"stable-payload-session","content":"Synthetic first payload."}}"#,
        )
        .unwrap();
        fs::write(
            &second_path,
            r#"{"payload":{"type":"user","id":"payload-message-identity","sessionId":"stable-payload-session","content":"Synthetic changed payload."}}"#,
        )
        .unwrap();

        let first = project(first_path);
        let changed = project(second_path);
        assert_eq!(
            first[0].source().native_id(),
            Some("payload-message-identity")
        );
        assert_eq!(
            changed[0].source().native_id(),
            Some("payload-message-identity")
        );
        assert!(matches!(
            first[0].identity_basis().coordinate(),
            Some((
                IdentityCoordinateKind::NativeId,
                IdentityCoordinateValue::NativeId(value)
            )) if value == "payload-message-identity"
        ));
        assert_eq!(first[0].observation_id(), changed[0].observation_id());
        let ObservationBody::Message(message) = changed[0].body() else {
            panic!("expected payload message")
        };
        assert_eq!(
            message.content(),
            Some(&JsonValue::string("Synthetic changed payload."))
        );
    }

    #[test]
    fn selected_payload_owns_message_and_tool_evidence_over_outer_fields() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("conflicting-payload.jsonl");
        fs::write(
            &path,
            r#"{"type":"assistant","role":"assistant","sessionId":"outer-session","id":"outer-message-id","timestamp":"2026-09-04T11:00:00Z","content":"Synthetic outer content.","tool_calls":[{"id":"outer-call","name":"outer_tool","arguments":{"command":"outer"}}],"payload":{"type":"user","sessionId":"inner-session","id":"inner-message-id","timestamp":"2026-09-04T11:00:01Z","content":"Synthetic inner content.","tool_calls":[{"id":"inner-call","name":"inner_tool","arguments":{"command":"inner"}}]}}"#,
        )
        .unwrap();

        let observations = project(path);
        assert_eq!(observations.len(), 2);
        let ObservationBody::Message(message) = observations[0].body() else {
            panic!("expected selected payload message")
        };
        assert_eq!(message.role(), Some(MessageRole::User));
        assert_eq!(
            message.content(),
            Some(&JsonValue::string("Synthetic inner content."))
        );
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "inner-session"
        );
        assert_eq!(
            observations[0].source().native_id(),
            Some("inner-message-id")
        );
        assert_eq!(
            observations[0].occurred_at().unwrap().as_str(),
            "2026-09-04T11:00:01Z"
        );

        let ObservationBody::Tool(tool) = observations[1].body() else {
            panic!("expected selected payload tool call")
        };
        assert_eq!(tool.name(), Some("inner_tool"));
        assert_eq!(
            tool.arguments(),
            Some(
                &JsonValue::object([("command".to_owned(), JsonValue::string("inner"),)]).unwrap()
            )
        );
        assert_eq!(
            observations[1].correlation().call_id().unwrap().value(),
            "inner-call"
        );
    }

    #[test]
    fn selected_payload_call_ids_ignore_outer_tool_results_but_keep_selected_nested_results() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("conflicting-payload-call-ids.jsonl");
        fs::write(
            &path,
            r#"{"call_id":"outer-direct-call","tool_result":{"call_id":"outer-payload-call"},"payload":{"type":"tool_call","sessionId":"payload-call-session","tool_name":"payload_tool","arguments":{"command":"inner"}}}
{"call_id":"outer-direct-result","tool_result":{"tool_use_id":"outer-payload-result"},"payload":{"type":"tool_result","sessionId":"payload-result-session","content":"Synthetic payload result."}}
{"tool_result":{"call_id":"outer-nested-call"},"payload":{"payload":{"type":"tool_call","sessionId":"nested-call-session","tool_name":"nested_tool","arguments":{"command":"nested"},"tool_result":{"call_id":"inner-nested-call"}}}}
{"tool_result":{"tool_use_id":"outer-nested-result"},"payload":{"payload":{"type":"tool_result","sessionId":"nested-result-session","content":"Synthetic nested result.","tool_result":{"tool_use_id":"inner-nested-result"}}}}"#,
        )
        .unwrap();

        let observations = project(path);
        assert_eq!(observations.len(), 4);
        assert_eq!(observations[0].correlation().call_id(), None);
        assert_eq!(observations[1].correlation().call_id(), None);
        assert_eq!(
            observations[2].correlation().call_id().unwrap().value(),
            "inner-nested-call"
        );
        assert_eq!(
            observations[3].correlation().call_id().unwrap().value(),
            "inner-nested-result"
        );
    }

    #[test]
    fn payload_tool_calls_array_is_preserved() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("payload-tool-calls.jsonl");
        fs::write(
            &path,
            r#"{"payload":{"type":"assistant","sessionId":"payload-tool-calls-session","content":"Synthetic response.","tool_calls":[{"id":"payload-call","name":"read_file","arguments":{"path":"synthetic.txt"}}]}}"#,
        )
        .unwrap();

        let observations = project(path);
        assert_eq!(observations.len(), 2);
        let ObservationBody::Tool(tool) = observations[1].body() else {
            panic!("expected payload tool call")
        };
        assert_eq!(tool.name(), Some("read_file"));
        assert_eq!(
            tool.arguments(),
            Some(
                &JsonValue::object([("path".to_owned(), JsonValue::string("synthetic.txt"),)])
                    .unwrap()
            )
        );
        assert_eq!(
            observations[1].correlation().call_id().unwrap().value(),
            "payload-call"
        );
    }

    #[test]
    fn payload_assistant_tool_calls_without_content_skip_empty_message() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("payload-tool-calls-only.jsonl");
        fs::write(
            &path,
            r#"{"payload":{"type":"assistant","sessionId":"payload-tool-calls-only-session","tool_calls":[{"id":"payload-call-only","name":"shell","arguments":{"command":"printf synthetic"}}]}}"#,
        )
        .unwrap();

        let observations = project(path);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].kind(), ObservationFamily::Tool);
        assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
        let ObservationBody::Tool(tool) = observations[0].body() else {
            panic!("expected payload tool call")
        };
        assert_eq!(tool.name(), Some("shell"));
        assert_eq!(
            tool.arguments(),
            Some(
                &JsonValue::object(
                    [("command".to_owned(), JsonValue::string("printf synthetic")),]
                )
                .unwrap()
            )
        );
    }

    #[test]
    fn payload_message_without_evidence_fails_but_top_level_empty_message_remains_valid() {
        let directory = tempdir().unwrap();
        let payload_path = directory.path().join("payload-empty.jsonl");
        fs::write(
            &payload_path,
            r#"{"content":"Synthetic outer content.","sessionId":"outer-session","payload":{"type":"user","sessionId":"payload-empty-session","name":"x"}}"#,
        )
        .unwrap();
        let error = project_openclaw_canonical_observations(
            &source(payload_path.clone()),
            OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("payload message without evidence must fail closed");
        assert_eq!(error.code(), "missing_payload_evidence");
        let legacy = parse_source_records(&source(payload_path)).expect("legacy records");
        assert_eq!(legacy[0].kind, RecordKind::UserMessage);
        assert!(legacy[0].content.contains("Synthetic outer content."));

        let top_level_path = directory.path().join("top-level-empty.jsonl");
        fs::write(
            &top_level_path,
            r#"{"type":"user","sessionId":"top-level-empty-session"}"#,
        )
        .unwrap();
        let observations = project(top_level_path);
        assert_eq!(observations.len(), 1);
        let ObservationBody::Message(message) = observations[0].body() else {
            panic!("expected top-level empty message")
        };
        assert_eq!(message.content(), None);
    }

    #[test]
    fn payload_generic_tool_snapshot_maps_state_facts_without_execution_lifecycle() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("payload-generic-tool.jsonl");
        fs::write(
            &path,
            r#"{"payload":{"type":"tool","sessionId":"s","tool":"shell","state":{"status":"completed","input":{"command":"printf synthetic"},"output":"ok"}}}"#,
        )
        .unwrap();
        let source_path = path.clone();
        let observations = project(path);

        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].kind(), ObservationFamily::Tool);
        assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
        let ObservationBody::Tool(request) = observations[0].body() else {
            panic!("expected payload tool request")
        };
        assert_eq!(request.name(), Some("shell"));
        assert_eq!(
            request.arguments(),
            Some(
                &JsonValue::object(
                    [("command".to_owned(), JsonValue::string("printf synthetic")),]
                )
                .unwrap()
            )
        );

        assert_eq!(
            observations[1].stage(),
            ObservationStage::ToolResultReturned
        );
        let ObservationBody::Tool(result) = observations[1].body() else {
            panic!("expected payload tool result")
        };
        assert_eq!(result.result(), Some(&JsonValue::string("ok")));
        assert!(observations.iter().all(|observation| {
            observation
                .capability_context()
                .expect("capabilities")
                .resolve(CapabilityId::ToolExecution)
                == CapabilityAvailability::Unknown
                && !matches!(
                    observation.stage(),
                    ObservationStage::ToolExecutionStarted
                        | ObservationStage::ToolExecutionCompleted
                )
        }));

        let legacy = parse_source_records(&source(source_path)).expect("legacy records");
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].kind, RecordKind::ToolCall);
        assert_eq!(legacy[0].tool_name.as_deref(), Some("shell"));
        assert_eq!(legacy[0].arguments, None);
    }

    #[test]
    fn selected_payload_owns_generic_tool_state_over_outer_state() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("conflicting-tool-state.jsonl");
        fs::write(
            &path,
            r#"{"state":{"status":"completed","input":{"command":"outer"},"output":"Synthetic outer result."},"payload":{"type":"tool","sessionId":"inner-tool-session","call_id":"inner-tool-call","tool":"inner_shell","state":{"status":"completed","input":{"command":"inner"},"output":"Synthetic inner result."}}}"#,
        )
        .unwrap();

        let observations = project(path);
        assert_eq!(observations.len(), 2);
        for observation in &observations {
            assert_eq!(
                observation.session_id().unwrap().value(),
                "inner-tool-session"
            );
            assert_eq!(
                observation.correlation().call_id().unwrap().value(),
                "inner-tool-call"
            );
        }
        let ObservationBody::Tool(request) = observations[0].body() else {
            panic!("expected selected payload tool request")
        };
        assert_eq!(request.name(), Some("inner_shell"));
        assert_eq!(
            request.arguments(),
            Some(
                &JsonValue::object([("command".to_owned(), JsonValue::string("inner"),)]).unwrap()
            )
        );
        let ObservationBody::Tool(result) = observations[1].body() else {
            panic!("expected selected payload tool result")
        };
        assert_eq!(
            result.result(),
            Some(&JsonValue::string("Synthetic inner result."))
        );
    }

    #[test]
    fn metadata_inheritance_is_legacy_only() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("metadata.jsonl");
        fs::write(
            &path,
            b"{\"type\":\"session_meta\",\"sessionId\":\"metadata-session\",\"agent\":\"fixture-agent\",\"provider\":\"fixture-provider\",\"model\":\"fixture-model\"}\n{\"type\":\"assistant\",\"sessionId\":\"metadata-session\",\"content\":\"Synthetic response.\"}\n",
        )
        .unwrap();

        let native = super::super::native::extract_openclaw_native_records(&source(path.clone()))
            .expect("native records");
        assert_eq!(
            native[0].reported_provider.as_deref(),
            Some("fixture-provider")
        );
        assert_eq!(native[1].reported_provider, None);
        assert_eq!(
            native[1].legacy_effective_provider.as_deref(),
            Some("fixture-provider")
        );
        assert_eq!(native[1].reported_agent, None);
        assert_eq!(
            native[1].legacy_effective_agent.as_deref(),
            Some("fixture-agent")
        );

        let legacy = parse_source_records(&source(path)).expect("legacy records");
        assert_eq!(legacy[1].provider.as_deref(), Some("fixture-provider"));
        assert_eq!(legacy[1].agent.as_deref(), Some("fixture-agent"));
    }

    #[test]
    fn canonical_session_does_not_inherit_from_session_meta() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("session-meta-only.jsonl");
        fs::write(
            &path,
            b"{\"type\":\"session_meta\",\"sessionId\":\"meta-session\"}\n{\"type\":\"assistant\",\"content\":\"Synthetic response.\"}\n",
        )
        .unwrap();
        let error = project_openclaw_canonical_observations(
            &source(path.clone()),
            OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("session meta must not scope the following record");
        assert_eq!(error.code(), "replay_unverifiable");
        let native = super::super::native::extract_openclaw_native_records(&source(path.clone()))
            .expect("native records");
        assert_eq!(native[1].session_id, None);
        assert_eq!(
            parse_source_records(&source(path)).unwrap()[1].session_id,
            "session-meta-only"
        );
    }

    #[test]
    fn native_record_id_is_used_only_for_message_envelopes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("native-id.jsonl");
        fs::write(
            &path,
            b"{\"type\":\"user\",\"id\":\"message-native-id\",\"content\":\"Synthetic message.\"}\n{\"type\":\"tool_call\",\"sessionId\":\"tool-session\",\"id\":\"call-native-id\",\"name\":\"read_file\",\"input\":{\"path\":\"synthetic.txt\"}}\n",
        )
        .unwrap();
        let observations = project(path);
        assert_eq!(observations.len(), 2);
        assert_eq!(
            observations[0].source().native_id(),
            Some("message-native-id")
        );
        assert_eq!(observations[0].session_id(), None);
        assert_eq!(observations[1].source().native_id(), None);
        assert_eq!(
            observations[1].correlation().call_id().unwrap().value(),
            "call-native-id"
        );
    }

    #[test]
    fn source_session_scopes_ids_across_moves_and_content_changes() {
        let first_directory = tempdir().unwrap();
        let second_directory = tempdir().unwrap();
        let first_path = first_directory.path().join("first.jsonl");
        let second_path = second_directory.path().join("moved.jsonl");
        fs::write(
            &first_path,
            r#"{"type":"user","sessionId":"stable-session","content":"Synthetic first message."}"#,
        )
        .unwrap();
        fs::write(
            &second_path,
            r#"{"type":"user","sessionId":"stable-session","content":"Synthetic changed message."}"#,
        )
        .unwrap();
        let first = project(first_path);
        let changed = project(second_path);
        assert_eq!(first[0].observation_id(), changed[0].observation_id());
        assert_eq!(
            first[0]
                .semantic_comparison()
                .compare(changed[0].semantic_comparison()),
            SemanticReplayVerdict::Mutated
        );
        assert!(matches!(
            first[0].identity_basis().coordinate().unwrap().1,
            telltale_schema::observation::IdentityCoordinateValue::SourceSequence {
                namespace,
                ordinal: 0
            } if namespace == "stable-session"
        ));
    }

    #[test]
    fn unknown_canonical_inputs_fail_without_changing_legacy_output() {
        let unknown =
            crate::test_fixture_path("parser_maturity/non_discovered/unknown-variant.jsonl");
        let error = project_openclaw_canonical_observations(
            &source(unknown.clone()),
            OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("unknown discriminator must fail canonical mapping");
        assert_eq!(error.code(), "unknown_discriminator");
        assert!(!error.to_string().contains("Synthetic unknown"));
        assert!(!format!("{error:?}").contains("Synthetic unknown"));
        assert_eq!(
            parse_source_records(&source(unknown)).unwrap()[0].kind,
            RecordKind::Other
        );

        let directory = tempdir().unwrap();
        let path = directory.path().join("payload-unknown.jsonl");
        fs::write(
            &path,
            r#"{"payload":{"type":"future_payload_kind","content":"Synthetic payload secret."}}"#,
        )
        .unwrap();
        let error = project_openclaw_canonical_observations(
            &source(path.clone()),
            OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("unknown payload discriminator must fail canonical mapping");
        assert_eq!(error.code(), "unknown_discriminator");
        assert!(!error.to_string().contains("Synthetic payload secret"));
        assert!(!format!("{error:?}").contains("payload-unknown.jsonl"));
        assert_eq!(
            parse_source_records(&source(path)).unwrap()[0].kind,
            RecordKind::Other
        );

        let directory = tempdir().unwrap();
        let path = directory.path().join("unknown-block.jsonl");
        fs::write(
            &path,
            br#"{"type":"assistant","sessionId":"unknown-block","content":[{"type":"future_block","value":"synthetic payload"}]}"#,
        )
        .unwrap();
        let error = project_openclaw_canonical_observations(
            &source(path.clone()),
            OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("unknown content block must fail canonical mapping");
        assert_eq!(error.code(), "unknown_content_block");
        assert!(!error.to_string().contains("synthetic payload"));
        assert!(parse_source_records(&source(path)).is_ok());
    }

    #[test]
    fn source_parse_failure_is_distinct_and_legacy_stays_available() {
        let source = source(crate::test_fixture_path(
            "parser_maturity/non_discovered/schema-drift.jsonl",
        ));
        let error = project_openclaw_canonical_observations(
            &source,
            OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect_err("schema drift must remain a source error");
        assert_eq!(error.code(), "source_parse");
        assert!(parse_source_records(&source).is_err());
    }

    #[test]
    fn canonical_identity_and_kind_are_exact() {
        let wrong_identity = Source {
            client: ClientId::OpenClaw,
            kind: SourceKind::Jsonl,
            source_id: "openclaw.other".to_owned(),
            path: "does-not-exist.jsonl".into(),
        };
        let error = project_openclaw_canonical_observations(
            &wrong_identity,
            OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "unsupported_source_identity");
        assert!(!error.to_string().contains("does-not-exist"));

        let wrong_kind = Source {
            client: ClientId::OpenClaw,
            kind: SourceKind::LegacyJson,
            source_id: "openclaw.agents".to_owned(),
            path: "does-not-exist.jsonl".into(),
        };
        let error = project_openclaw_canonical_observations(
            &wrong_kind,
            OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "unsupported_source_kind");
        assert!(!error.to_string().contains("does-not-exist"));
    }
}
