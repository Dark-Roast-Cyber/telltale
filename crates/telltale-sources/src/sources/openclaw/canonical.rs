//! Maps native OpenClaw records to Canonical Observation v2. Reached only
//! through the acquisition router.

use std::fmt;

use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId, ContentPart,
    ContentPartKind, CorrelationId, CorrelationIds, FactMetadata, FactProvenance, Fidelity,
    IngestionMode, JsonValue, MessageObservation, MessageRole, ObservationBody, ObservationBuilder,
    ObservationError, ObservationStage, ObservedAt, SemanticFacet, Sensitivity, SourceProvenance,
    SourceTimestamp, ToolObservation,
};

use crate::tool_operation::{
    ResultText, ValueBounds, build_fitted, declare, replaced_arguments, with_declared_arguments,
    with_source_result,
};

use super::native::{
    OpenClawContentBlock, OpenClawNativeRecord, OpenClawToolFields, is_known_openclaw_discriminator,
};

#[derive(Clone)]
pub(crate) struct OpenClawCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
    pub(crate) scale: telltale_schema::observation::SourceScale,
}

impl OpenClawCanonicalOptions {
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

pub(crate) enum OpenClawCanonicalError {
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl OpenClawCanonicalError {
    #[cfg(test)]
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Mapping { code, .. } => code,
            Self::Observation(error) => error.code(),
        }
    }
}

impl fmt::Debug for OpenClawCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

impl From<ObservationError> for OpenClawCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

pub(crate) fn project_openclaw_native_records(
    records: &[OpenClawNativeRecord],
    options: &OpenClawCanonicalOptions,
) -> Result<Vec<CanonicalObservationV2>, OpenClawCanonicalError> {
    let mut observations = crate::acquisition::CanonicalCollector::scaled(options.scale);
    for record in records {
        project_record(record, options, &mut observations)?;
    }
    Ok(observations.finish())
}

fn project_record(
    record: &OpenClawNativeRecord,
    options: &OpenClawCanonicalOptions,
    observations: &mut crate::acquisition::CanonicalCollector,
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

    if record.discriminator.as_deref() == Some("session_meta") {
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
            body = body.with_content(JsonValue::try_from_source_message_content(content)?);
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
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), OpenClawCanonicalError> {
    let body = build_message_body(record, role, &[])?;
    emit_message_body(record, options, body, child_ordinal, observations)
}

fn emit_message_body(
    record: &OpenClawNativeRecord,
    options: &OpenClawCanonicalOptions,
    body: MessageObservation,
    child_ordinal: &mut usize,
    observations: &mut crate::acquisition::CanonicalCollector,
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
        builder = builder.fact_metadata(path, FactMetadata::reported()?);
    }
    observations.push(builder.build()?)?;
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
                JsonValue::try_from_source_message_text(text)?,
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
    observations: &mut crate::acquisition::CanonicalCollector,
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
    observations: &mut crate::acquisition::CanonicalCollector,
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

    let observation = build_fitted(ValueBounds::Replace, value_bound, |bounds| {
        let mut body = ToolObservation::new();
        let mut metadata = Vec::new();
        if let Some(name) = &fields.name {
            body = body.with_name(name)?;
            metadata.push(("tool.name", FactProvenance::Reported));
        }
        if let Some(arguments) = &fields.arguments {
            body = with_declared_arguments(
                telltale_schema::observation::ArgumentText::new(),
                body,
                arguments,
                bounds,
            )?;
            metadata.push(("tool.arguments", FactProvenance::Reported));
        }
        if let Some(result) = result {
            body = with_source_result(body, result, ResultText::Structured, bounds)?;
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

        // No facet is built from an argument that was replaced.
        let replaced = replaced_arguments(&body, &["command", "cmd", "file_path", "path"]);
        let admitted = |key: &str| !replaced.contains(&key);
        let mut builder = common_builder(
            record,
            options,
            ObservationBody::Tool(declare(super::tools::TOOLS, body)),
            stage,
            tool_correlation(fields.call_id.as_deref())?,
            *child_ordinal,
        )?;
        for (path, provenance) in metadata {
            builder =
                builder.fact_metadata(path, FactMetadata::new(provenance, Sensitivity::Normal)?);
        }

        if let Some(arguments) = fields.arguments.as_ref().and_then(parsed_argument_view) {
            if let Some(command) = argument_string(arguments, "command")
                .filter(|_| admitted("command"))
                .or_else(|| argument_string(arguments, "cmd").filter(|_| admitted("cmd")))
            {
                builder = builder
                    .facet(
                        "command.text",
                        SemanticFacet::new(JsonValue::string(command)),
                    )?
                    .fact_metadata("command.text", FactMetadata::parsed()?);
            }
            if let Some(path) = argument_string(arguments, "file_path")
                .filter(|_| admitted("file_path"))
                .or_else(|| argument_string(arguments, "path").filter(|_| admitted("path")))
            {
                builder = builder
                    .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
                    .fact_metadata("resource.path", FactMetadata::parsed()?);
            }
        }

        Ok(builder.build()?)
    })?;
    observations.push(observation)?;
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

/// A failure of a call's observation on a value bound: [`build_fitted`] then
/// builds it again with the call's values fitted.
fn value_bound(error: &OpenClawCanonicalError) -> bool {
    matches!(error, OpenClawCanonicalError::Observation(error) if error.bound_dimension().is_some())
}

#[cfg(test)]
mod tests;
