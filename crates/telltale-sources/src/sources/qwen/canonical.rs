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
    QwenContentBlock, QwenNativeRecord, QwenToolFields, extract_qwen_native_records,
    is_known_qwen_discriminator,
};
use crate::parser::ParseError;

#[derive(Clone)]
pub(crate) struct QwenCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
}

impl QwenCanonicalOptions {
    pub(crate) fn new(observed_at: ObservedAt) -> Self {
        Self { observed_at }
    }
}

pub(crate) enum QwenCanonicalError {
    Source(ParseError),
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl QwenCanonicalError {
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

impl fmt::Debug for QwenCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("QwenCanonicalError::Source")
            }
            Self::Mapping { code, detail } => formatter
                .debug_struct("QwenCanonicalError::Mapping")
                .field("code", code)
                .field("detail", detail)
                .finish(),
            Self::Observation(error) => formatter
                .debug_struct("QwenCanonicalError::Observation")
                .field("code", &error.code())
                .finish(),
        }
    }
}

impl fmt::Display for QwenCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("Qwen source could not be parsed")
            }
            Self::Mapping { code, detail } => {
                write!(
                    formatter,
                    "Qwen canonical mapping failed ({code}): {detail}"
                )
            }
            Self::Observation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for QwenCanonicalError {}

impl From<ParseError> for QwenCanonicalError {
    fn from(error: ParseError) -> Self {
        Self::Source(error)
    }
}

impl From<ObservationError> for QwenCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

pub(crate) fn project_qwen_canonical_observations(
    source: &Source,
    options: QwenCanonicalOptions,
) -> Result<Vec<CanonicalObservationV2>, QwenCanonicalError> {
    if source.client != ClientId::Qwen || source.source_id != "qwen.projects" {
        return Err(mapping(
            "unsupported_source_identity",
            "canonical projection requires the Qwen projects source",
        ));
    }
    if source.kind != SourceKind::Jsonl {
        return Err(mapping(
            "unsupported_source_kind",
            "canonical projection requires JSONL input",
        ));
    }

    let records = extract_qwen_native_records(source)?;
    let mut observations = Vec::new();
    for record in records {
        project_record(&record, &options, &mut observations)?;
    }
    Ok(observations)
}

fn project_record(
    record: &QwenNativeRecord,
    options: &QwenCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), QwenCanonicalError> {
    if record
        .discriminator
        .as_deref()
        .is_some_and(|kind| !is_known_qwen_discriminator(kind))
    {
        return Err(mapping(
            "unknown_discriminator",
            "explicit Qwen record discriminator is not supported",
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
            "Qwen payload message has no supported content or tool fact",
        ));
    }

    let mut child_ordinal = 0;
    if let Some(blocks) = record.blocks.as_deref() {
        if blocks
            .iter()
            .any(|block| matches!(block, QwenContentBlock::Unknown))
        {
            return Err(mapping(
                "unknown_content_block",
                "Qwen content block type is not supported",
            ));
        }

        let message_record = record
            .discriminator
            .as_deref()
            .is_some_and(is_message_discriminator);
        let has_message_content = blocks.iter().any(|block| {
            matches!(
                block,
                QwenContentBlock::Text { .. } | QwenContentBlock::ToolUse { .. }
            )
        });
        let message_required = message_record && (blocks.is_empty() || has_message_content);
        let mut message_emitted = false;

        for block in blocks {
            if message_required
                && !message_emitted
                && !matches!(block, QwenContentBlock::ToolResult { .. })
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
                    "Qwen record does not describe a supported message or tool",
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

fn canonical_role(record: &QwenNativeRecord) -> Result<MessageRole, QwenCanonicalError> {
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
            "Qwen record role is not a user or assistant role",
        )),
        None => Err(mapping(
            "missing_role",
            "Qwen conversational record has no role",
        )),
    }
}

fn build_message_body(
    record: &QwenNativeRecord,
    role: MessageRole,
    blocks: &[QwenContentBlock],
) -> Result<MessageObservation, QwenCanonicalError> {
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
    record: &QwenNativeRecord,
    options: &QwenCanonicalOptions,
    role: MessageRole,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), QwenCanonicalError> {
    let body = build_message_body(record, role, &[])?;
    emit_message_body(record, options, body, child_ordinal, observations)
}

fn emit_message_body(
    record: &QwenNativeRecord,
    options: &QwenCanonicalOptions,
    body: MessageObservation,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), QwenCanonicalError> {
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

fn content_part(block: &QwenContentBlock) -> Result<ContentPart, QwenCanonicalError> {
    match block {
        QwenContentBlock::Text { text } => {
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
        QwenContentBlock::ToolUse {
            call_id,
            name,
            input,
            input_present,
        } => {
            let mut fields = Vec::new();
            if let Some(call_id) = call_id {
                fields.push(("id".to_owned(), JsonValue::string(call_id)));
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
        QwenContentBlock::ToolResult {
            tool_call_id,
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
            if let Some(tool_call_id) = tool_call_id {
                fields.push(("tool_call_id".to_owned(), JsonValue::string(tool_call_id)));
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
        QwenContentBlock::Unknown => Err(mapping(
            "unknown_content_block",
            "Qwen content block type is not supported",
        )),
    }
}

fn block_tool(
    block: &QwenContentBlock,
) -> Result<Option<(QwenToolFields, ObservationStage)>, QwenCanonicalError> {
    match block {
        QwenContentBlock::ToolUse {
            call_id,
            name,
            input,
            input_present,
        } => Ok(Some((
            QwenToolFields {
                name: name.clone(),
                arguments: input.clone(),
                arguments_present: *input_present,
                call_id: call_id.clone(),
                ..QwenToolFields::default()
            },
            ObservationStage::ToolRequested,
        ))),
        QwenContentBlock::ToolResult {
            tool_call_id,
            result,
            result_present,
            is_error,
            is_error_present,
        } => Ok(Some((
            QwenToolFields {
                call_id: tool_call_id.clone(),
                result: result.clone(),
                result_present: *result_present,
                is_error: *is_error,
                is_error_present: *is_error_present,
                ..QwenToolFields::default()
            },
            ObservationStage::ToolResultReturned,
        ))),
        QwenContentBlock::Text { .. } => Ok(None),
        QwenContentBlock::Unknown => Err(mapping(
            "unknown_content_block",
            "Qwen content block type is not supported",
        )),
    }
}

fn emit_generic_tool(
    record: &QwenNativeRecord,
    options: &QwenCanonicalOptions,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), QwenCanonicalError> {
    let fields = &record.tool;
    let has_request = fields.name.is_some() || fields.arguments_present;
    let has_result = fields.result_present || fields.error_present || fields.is_error.is_some();
    if !has_request && !has_result {
        return Err(mapping(
            "unsupported_record",
            "Qwen tool snapshot has no direct request or result fact",
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
    record: &QwenNativeRecord,
    options: &QwenCanonicalOptions,
    fields: QwenToolFields,
    stage: ObservationStage,
    child_ordinal: &mut usize,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), QwenCanonicalError> {
    if fields.is_error_present && fields.is_error.is_none() {
        return Err(mapping(
            "invalid_tool_result",
            "Qwen tool error state is not boolean",
        ));
    }

    let result = fields.result.as_ref().or(fields.error.as_ref());
    let has_result = fields.result_present || fields.error_present;
    if stage == ObservationStage::ToolResultReturned && !has_result && fields.is_error.is_none() {
        return Err(mapping(
            "invalid_tool_result",
            "Qwen tool result has no returned value or error state",
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
            "Qwen tool record has no canonical tool fact",
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

fn tool_correlation(call_id: Option<&str>) -> Result<Option<CorrelationIds>, QwenCanonicalError> {
    let Some(call_id) = call_id else {
        return Ok(None);
    };
    Ok(Some(
        CorrelationIds::new().with_call_id(CorrelationId::source_reported(call_id)?),
    ))
}

fn common_builder(
    record: &QwenNativeRecord,
    options: &QwenCanonicalOptions,
    body: ObservationBody,
    stage: ObservationStage,
    correlation: Option<CorrelationIds>,
    child_ordinal: usize,
) -> Result<ObservationBuilder, QwenCanonicalError> {
    let mut source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "qwen",
        "qwen.projects",
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

fn normal_reported() -> Result<FactMetadata, QwenCanonicalError> {
    normal(FactProvenance::Reported)
}

fn normal(provenance: FactProvenance) -> Result<FactMetadata, QwenCanonicalError> {
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

fn value_to_json(value: &serde_json::Value) -> Result<JsonValue, QwenCanonicalError> {
    Ok(JsonValue::try_from_source_value(value)?)
}

fn mapping(code: &'static str, detail: &'static str) -> QwenCanonicalError {
    QwenCanonicalError::Mapping { code, detail }
}
