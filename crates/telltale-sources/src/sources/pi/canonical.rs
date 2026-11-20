//! Maps native Pi entries to Canonical Observation v2. Reached only through
//! the acquisition router.

use std::fmt;

use serde_json::Value;
use telltale_schema::observation::{
    CanonicalBoundContext, CanonicalFieldCategory, CanonicalObservationV2, CapabilityAvailability,
    CapabilityContext, CapabilityId, ContentPart, ContentPartKind, CorrelationId, CorrelationIds,
    FactMetadata, FactProvenance, Fidelity, IngestionMode, JsonValue, MessageObservation,
    MessageRole, ObservationBody, ObservationBuilder, ObservationError, ObservationStage,
    ObservedAt, SemanticFacet, SourceProvenance, SourceTimestamp, ToolKind, ToolObservation,
    ToolOperation,
};

use telltale_schema::observation::BoundedTarget;

use crate::tool_operation::{
    BoundedRecord, ResultText, ValueBounds, bounded_records, build_fitted, declare_in,
    with_source_arguments, with_source_result,
};

use super::native::{
    METADATA_ENTRY_TYPES, METADATA_MESSAGE_ROLES, PiBashExecution, PiContentBlock, PiNativeRecord,
    PiToolResult,
};

const ADAPTER_TYPE: &str = "pi";
const SOURCE_ID: &str = "pi.sessions";

#[derive(Clone)]
pub(crate) struct PiCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
    pub(crate) scale: telltale_schema::observation::SourceScale,
}

impl PiCanonicalOptions {
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

pub(crate) enum PiCanonicalError {
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl fmt::Debug for PiCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping { code, detail } => formatter
                .debug_struct("PiCanonicalError::Mapping")
                .field("code", code)
                .field("detail", detail)
                .finish(),
            Self::Observation(error) => formatter
                .debug_struct("PiCanonicalError::Observation")
                .field("code", &error.code())
                .finish(),
        }
    }
}

impl fmt::Display for PiCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping { code, detail } => {
                write!(formatter, "Pi canonical mapping failed ({code}): {detail}")
            }
            Self::Observation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PiCanonicalError {}

impl From<ObservationError> for PiCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

#[derive(Debug)]
pub(crate) struct PiProjection {
    pub(crate) observations: Vec<CanonicalObservationV2>,
    /// Records left out by themselves; every other record was still mapped.
    pub(crate) quarantined: Vec<PiQuarantinedRecord>,
    /// Records mapped with over-bound tool values replaced; never quarantined.
    pub(crate) bounded: Vec<BoundedRecord>,
}

/// Coordinates of a record excluded from projection, never its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PiQuarantinedRecord {
    pub(crate) source_sequence: u64,
    pub(crate) code: &'static str,
    pub(crate) bound: Option<CanonicalBoundContext>,
}

/// Map each entry on its own. An entry whose type, message role or content
/// block this adapter does not know, or whose own values exceed a canonical
/// bound, is quarantined so one entry cannot blind the whole session.
/// Integrity failures and the source-wide retained budget still fail the
/// source.
pub(crate) fn project_pi_native_records(
    records: &[PiNativeRecord],
    options: &PiCanonicalOptions,
) -> Result<PiProjection, PiCanonicalError> {
    let mut observations = crate::acquisition::CanonicalCollector::scaled(options.scale);
    let mut quarantined = Vec::new();
    let mut bounded = Vec::new();
    for record in records {
        let mut unit = crate::acquisition::CanonicalCollector::default();
        match project_record(record, options, &mut unit) {
            Ok(()) => {
                let unit = unit.finish();
                bounded.extend(bounded_records(record.source_sequence, &unit));
                for observation in unit {
                    observations.push(observation)?;
                }
            }
            Err(error) => match quarantine_code(&error) {
                Some(code) => quarantined.push(PiQuarantinedRecord {
                    source_sequence: record.source_sequence,
                    code,
                    bound: match &error {
                        PiCanonicalError::Observation(error) => error.bound_context(),
                        PiCanonicalError::Mapping { .. } => None,
                    },
                }),
                None => return Err(error),
            },
        }
    }
    Ok(PiProjection {
        observations: observations.finish(),
        quarantined,
        bounded,
    })
}

fn quarantine_code(error: &PiCanonicalError) -> Option<&'static str> {
    match error {
        PiCanonicalError::Mapping { code, .. }
            if matches!(*code, "unknown_discriminator" | "unknown_content_block") =>
        {
            Some(code)
        }
        PiCanonicalError::Observation(error) if error.code() == "unbounded_value" => {
            Some("unbounded_value")
        }
        _ => None,
    }
}

fn project_record(
    record: &PiNativeRecord,
    options: &PiCanonicalOptions,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), PiCanonicalError> {
    match record.discriminator.as_deref() {
        Some("message") => {}
        Some(kind) if METADATA_ENTRY_TYPES.contains(&kind) => return Ok(()),
        _ => {
            return Err(mapping(
                "unknown_discriminator",
                "Pi entry type is not supported",
            ));
        }
    }
    let mut child_ordinal = 0;
    match record.role.as_deref() {
        Some("user") => emit_message(
            record,
            options,
            MessageRole::User,
            &mut child_ordinal,
            observations,
        ),
        Some("assistant") => {
            emit_message(
                record,
                options,
                MessageRole::Assistant,
                &mut child_ordinal,
                observations,
            )?;
            for block in record.blocks.iter().flatten() {
                if let PiContentBlock::ToolCall {
                    id,
                    name,
                    arguments,
                    namespace,
                } = block
                {
                    emit_tool_call(
                        record,
                        options,
                        ToolCall {
                            id: id.as_deref(),
                            name: name.as_deref(),
                            arguments: arguments.as_ref(),
                            namespace: namespace.as_deref(),
                        },
                        &mut child_ordinal,
                        observations,
                    )?;
                }
            }
            Ok(())
        }
        Some("toolResult") => emit_tool_result(
            record,
            options,
            record.tool_result.as_ref().expect("toolResult role"),
            &mut child_ordinal,
            observations,
        ),
        Some("bashExecution") => emit_bash_execution(
            record,
            options,
            record.bash.as_ref().expect("bashExecution role"),
            &mut child_ordinal,
            observations,
        ),
        Some(role) if METADATA_MESSAGE_ROLES.contains(&role) => Ok(()),
        _ => Err(mapping(
            "unknown_discriminator",
            "Pi message role is not supported",
        )),
    }
}

fn emit_message(
    record: &PiNativeRecord,
    options: &PiCanonicalOptions,
    role: MessageRole,
    child_ordinal: &mut usize,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), PiCanonicalError> {
    let mut body = MessageObservation::new(role);
    if let Some(blocks) = &record.blocks {
        if blocks
            .iter()
            .any(|block| matches!(block, PiContentBlock::Unknown))
            || role == MessageRole::User
                && blocks
                    .iter()
                    .any(|block| matches!(block, PiContentBlock::ToolCall { .. }))
        {
            return Err(mapping(
                "unknown_content_block",
                "Pi content block type is not supported",
            ));
        }
        for block in blocks {
            if let Some(part) = content_part(block)? {
                body = body.with_content_part(part);
            }
        }
    } else if let Some(content) = &record.message_content {
        body =
            body.with_content(JsonValue::try_from_source_message_content(content).map_err(
                |error| error.with_bound_category(CanonicalFieldCategory::MessageContent),
            )?);
    } else {
        return Err(mapping(
            "invalid_message",
            "Pi message has no string or array content",
        ));
    }
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
        builder = builder.fact_metadata(path, normal(FactProvenance::Reported)?);
    }
    observations.push(builder.build()?)?;
    *child_ordinal += 1;
    Ok(())
}

fn content_part(block: &PiContentBlock) -> Result<Option<ContentPart>, PiCanonicalError> {
    match block {
        PiContentBlock::Text { text } => {
            let text = text.as_deref().ok_or_else(|| {
                mapping(
                    "invalid_content_block",
                    "text content block has no text value",
                )
            })?;
            Ok(Some(ContentPart::new(
                ContentPartKind::Text,
                JsonValue::try_from_source_message_text(text).map_err(|error| {
                    error.with_bound_category(CanonicalFieldCategory::MessageContentParts)
                })?,
            )))
        }
        // A tool part references its lifecycle by call id. Arguments live
        // once, on the linked tool observation, so a message never repeats
        // them under the tighter nested-value bounds.
        PiContentBlock::ToolCall { id, name, .. } => {
            let mut fields = Vec::new();
            if let Some(id) = id {
                fields.push(("id".to_owned(), JsonValue::string(id)));
            }
            if let Some(name) = name {
                fields.push(("name".to_owned(), JsonValue::string(name)));
            }
            Ok(Some(ContentPart::new(
                ContentPartKind::ToolUse,
                JsonValue::object(fields)?,
            )))
        }
        PiContentBlock::Ignored => Ok(None),
        PiContentBlock::Unknown => Err(mapping(
            "unknown_content_block",
            "Pi content block type is not supported",
        )),
    }
}

struct ToolCall<'a> {
    id: Option<&'a str>,
    name: Option<&'a str>,
    arguments: Option<&'a Value>,
    namespace: Option<&'a str>,
}

fn emit_tool_call(
    record: &PiNativeRecord,
    options: &PiCanonicalOptions,
    call: ToolCall<'_>,
    child_ordinal: &mut usize,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), PiCanonicalError> {
    let observation = build_fitted(ValueBounds::Replace, value_bound, |bounds| {
        let mut body = ToolObservation::new();
        let mut paths = Vec::new();
        if let Some(name) = call.name {
            body = body.with_name(name)?;
            paths.push(("tool.name", FactProvenance::Reported));
        }
        if let Some(arguments) = call.arguments {
            body = with_source_arguments(super::tools::TOOLS, call.name, body, arguments, bounds)?;
            paths.push(("tool.arguments", FactProvenance::Reported));
        }
        if paths.is_empty() {
            return Err(mapping(
                "invalid_tool_request",
                "Pi tool call has no name or arguments",
            ));
        }
        let body = declare_in(super::tools::TOOLS, body, call.namespace);
        // Facets are never built from an argument that was replaced.
        let admitted = |key: &str| !body.bounded_member(BoundedTarget::Arguments, key);
        let (command_admitted, path_admitted) = (admitted("command"), admitted("path"));
        let mut builder = common_builder(
            record,
            options,
            ObservationBody::Tool(body),
            ObservationStage::ToolRequested,
            tool_correlation(call.id)?,
            *child_ordinal,
        )?;
        for (path, provenance) in paths {
            builder = builder.fact_metadata(path, normal(provenance)?);
        }
        if let Some(arguments) = call.arguments.and_then(Value::as_object) {
            if let Some(command) = arguments
                .get("command")
                .and_then(Value::as_str)
                .filter(|_| command_admitted)
            {
                builder = builder
                    .facet(
                        "command.text",
                        SemanticFacet::new(JsonValue::string(command)),
                    )?
                    .fact_metadata("command.text", normal(FactProvenance::Parsed)?);
            }
            if let Some(path) = arguments
                .get("path")
                .and_then(Value::as_str)
                .filter(|_| path_admitted)
            {
                builder = builder
                    .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
                    .fact_metadata("resource.path", normal(FactProvenance::Parsed)?);
            }
        }
        Ok(builder.build()?)
    })?;
    observations.push(observation)?;
    *child_ordinal += 1;
    Ok(())
}

fn emit_tool_result(
    record: &PiNativeRecord,
    options: &PiCanonicalOptions,
    result: &PiToolResult,
    child_ordinal: &mut usize,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), PiCanonicalError> {
    if result.is_error_present && result.is_error.is_none() {
        return Err(mapping(
            "invalid_tool_result",
            "Pi tool result error state is not boolean",
        ));
    }
    if result.content.is_none() && result.is_error.is_none() {
        return Err(mapping(
            "invalid_tool_result",
            "Pi tool result has no returned value or error state",
        ));
    }
    let observation = build_fitted(ValueBounds::Replace, value_bound, |bounds| {
        let mut body = ToolObservation::new();
        let mut paths = Vec::new();
        if let Some(name) = &result.name {
            body = body.with_name(name)?;
            paths.push(("tool.name", FactProvenance::Reported));
        }
        if let Some(content) = &result.content {
            body = with_tool_result(body, content, bounds)?;
            paths.push(("tool.result", FactProvenance::Reported));
        }
        if let Some(is_error) = result.is_error {
            body = body.with_is_error(is_error);
            paths.push(("tool.is_error", FactProvenance::Reported));
        }
        let mut builder = common_builder(
            record,
            options,
            ObservationBody::Tool(body),
            ObservationStage::ToolResultReturned,
            tool_correlation(result.call_id.as_deref())?,
            *child_ordinal,
        )?;
        for (path, provenance) in paths {
            builder = builder.fact_metadata(path, normal(provenance)?);
        }
        Ok(builder.build()?)
    })?;
    observations.push(observation)?;
    *child_ordinal += 1;
    Ok(())
}

/// A `!` command the user ran in the session. Like a Codex completed command
/// it is one reported shell result: no model request precedes it, so it has no
/// tool name or call ID, and the command is a reported facet.
fn emit_bash_execution(
    record: &PiNativeRecord,
    options: &PiCanonicalOptions,
    bash: &PiBashExecution,
    child_ordinal: &mut usize,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), PiCanonicalError> {
    let Some(command) = &bash.command else {
        return Err(mapping(
            "invalid_tool_result",
            "Pi shell execution has no command",
        ));
    };
    if bash.exit_code_present && bash.exit_code.is_none() {
        return Err(mapping(
            "invalid_tool_result",
            "Pi shell execution exit code is not an integer",
        ));
    }
    let observation = build_fitted(ValueBounds::Replace, value_bound, |bounds| {
        let mut body = ToolObservation::new().with_operation(ToolOperation::new(ToolKind::Shell));
        let mut paths = Vec::new();
        if let Some(output) = &bash.output {
            body = with_tool_result(body, output, bounds)?;
            paths.push(("tool.result", FactProvenance::Reported));
        }
        if let Some(exit_code) = bash.exit_code {
            body = body.with_exit_code(exit_code);
            paths.push(("tool.exit_code", FactProvenance::Reported));
        }
        let mut builder = common_builder(
            record,
            options,
            ObservationBody::Tool(body),
            ObservationStage::ToolResultReturned,
            None,
            *child_ordinal,
        )?;
        for (path, provenance) in paths {
            builder = builder.fact_metadata(path, normal(provenance)?);
        }
        builder = builder
            .facet(
                "command.text",
                SemanticFacet::new(JsonValue::string(command)),
            )?
            .fact_metadata("command.text", normal(FactProvenance::Reported)?);
        Ok(builder.build()?)
    })?;
    observations.push(observation)?;
    *child_ordinal += 1;
    Ok(())
}

/// Direct output text gets the tool-result text budget. Pi stores a tool's
/// result as `[{"type":"text","text":...}]`; an all-text array is joined into
/// one direct string, and any other shape keeps ordinary structured conversion.
fn with_tool_result(
    body: ToolObservation,
    result: &Value,
    bounds: ValueBounds,
) -> Result<ToolObservation, PiCanonicalError> {
    let joined = result.as_array().and_then(|items| {
        let texts = items
            .iter()
            .map(|item| match item.get("type").and_then(Value::as_str) {
                Some("text") => item.get("text").and_then(Value::as_str),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        (!texts.is_empty()).then(|| Value::String(texts.join("\n")))
    });
    Ok(with_source_result(
        body,
        joined.as_ref().unwrap_or(result),
        ResultText::Direct,
        bounds,
    )?)
}

/// A failure of a call's observation on a value bound: [`build_fitted`] then
/// builds it again with the call's values fitted.
fn value_bound(error: &PiCanonicalError) -> bool {
    matches!(error, PiCanonicalError::Observation(error) if error.bound_dimension().is_some())
}

fn tool_correlation(call_id: Option<&str>) -> Result<Option<CorrelationIds>, PiCanonicalError> {
    let Some(call_id) = call_id else {
        return Ok(None);
    };
    Ok(Some(
        CorrelationIds::new().with_call_id(CorrelationId::source_reported(call_id)?),
    ))
}

fn common_builder(
    record: &PiNativeRecord,
    options: &PiCanonicalOptions,
    body: ObservationBody,
    stage: ObservationStage,
    correlation: Option<CorrelationIds>,
    child_ordinal: usize,
) -> Result<ObservationBuilder, PiCanonicalError> {
    let mut source = SourceProvenance::new(
        IngestionMode::SessionStore,
        ADAPTER_TYPE,
        SOURCE_ID,
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
    if let Some(timestamp) = &record.timestamp
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

fn normal(provenance: FactProvenance) -> Result<FactMetadata, PiCanonicalError> {
    Ok(match provenance {
        FactProvenance::Reported => FactMetadata::reported()?,
        FactProvenance::Parsed => FactMetadata::parsed()?,
        _ => FactMetadata::new(
            provenance,
            telltale_schema::observation::Sensitivity::Normal,
        )?,
    })
}

fn mapping(code: &'static str, detail: &'static str) -> PiCanonicalError {
    PiCanonicalError::Mapping { code, detail }
}
