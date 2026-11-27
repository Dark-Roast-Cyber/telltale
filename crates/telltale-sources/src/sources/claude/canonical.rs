//! Maps native Claude Code records to Canonical Observation v2, including
//! per-unit quarantine and replacement of over-bound tool values. Reached only
//! through the acquisition router.

use std::fmt;

use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId, ContentPart,
    ContentPartKind, CorrelationId, CorrelationIds, FactMetadata, FactProvenance, Fidelity,
    IngestionMode, JsonValue, MessageObservation, MessageRole, ObservationBody, ObservationBuilder,
    ObservationError, ObservationStage, ObservedAt, SemanticFacet, Sensitivity, SourceProvenance,
    SourceTimestamp, ToolObservation,
};

use telltale_schema::observation::CanonicalBoundContext;

use crate::tool_operation::{
    BoundedRecord, ResultText, ToolSpec, ValueBounds, bounded_records, build_fitted, declare,
    table, with_source_arguments, with_source_result,
};
use telltale_schema::observation::BoundedTarget;

use super::native::{ClaudeContentBlock, ClaudeNativeRecord, is_known_claude_discriminator};

#[derive(Clone)]
pub(crate) struct ClaudeCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
    pub(crate) scale: telltale_schema::observation::SourceScale,
    /// The adapter type and source ID stamped on every observation.
    pub(crate) adapter: (&'static str, &'static str),
    /// The tool table that declares each tool call.
    pub(crate) tools: &'static [ToolSpec],
    /// What a tool call's over-bound values do.
    pub(crate) value_bounds: ValueBounds,
}

impl ClaudeCanonicalOptions {
    pub(crate) fn new(observed_at: ObservedAt) -> Self {
        Self {
            observed_at,
            scale: telltale_schema::observation::SourceScale::FLOOR,
            adapter: ("claude_code", "claude.projects"),
            tools: super::tools::TOOLS,
            value_bounds: ValueBounds::Replace,
        }
    }

    /// Quarantines a record whose tool values exceed a bound instead of
    /// replacing them, as every record did before replacement existed.
    pub(crate) fn with_strict_values(self) -> Self {
        Self {
            value_bounds: ValueBounds::Strict,
            ..self
        }
    }

    /// Stamps the identity the source was acquired under: the hook journal
    /// of any client is read here, so it carries its own.
    pub(crate) fn with_adapter(self, adapter_type: &'static str, source_id: &'static str) -> Self {
        Self {
            adapter: (adapter_type, source_id),
            ..self
        }
    }

    /// Declares tool calls with the table of `client`'s harness: a hook journal
    /// holds the calls of the client whose hooks wrote it, in the shape that
    /// harness reported them. A client with no table declares nothing.
    pub(crate) fn with_tool_table(self, client: telltale_schema::clients::ClientId) -> Self {
        Self {
            tools: table(client).unwrap_or(&[]),
            ..self
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
    /// Records mapped with over-bound tool values replaced; never quarantined.
    pub(crate) bounded: Vec<BoundedRecord>,
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
        bounded,
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

/// Elements Claude Code writes when it stores the output of a shell escape, a
/// local command or a background task as a user record.
const HARNESS_OUTPUT_ELEMENTS: [&str; 5] = [
    "bash-stdout",
    "bash-stderr",
    "local-command-stdout",
    "local-command-stderr",
    "task-notification",
];

/// Whether a projected Claude user message holds harness output rather than
/// only a prompt: one of [`HARNESS_OUTPUT_ELEMENTS`], by the transcript's
/// shared element rule. `text` is the message text a transcript shows.
pub(crate) fn is_harness_output_message(observation: &CanonicalObservationV2, text: &str) -> bool {
    crate::acquisition::transcript::user_message_holds_element(
        observation,
        text,
        &HARNESS_OUTPUT_ELEMENTS,
    )
}

fn project_record(
    record: &ClaudeNativeRecord,
    options: &ClaudeCanonicalOptions,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), ClaudeCanonicalError> {
    if record.is_bookkeeping {
        return Ok(());
    }
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
        builder = builder.fact_metadata(path, FactMetadata::reported()?);
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
    let observation = build_fitted(
        options.value_bounds,
        |error| matches!(error, ClaudeCanonicalError::Observation(error) if error.bound_dimension().is_some()),
        |bounds| tool_observation(record, options, block, *child_ordinal, bounds),
    )?;
    observations.push(observation)?;
    *child_ordinal += 1;
    Ok(())
}

fn tool_observation(
    record: &ClaudeNativeRecord,
    options: &ClaudeCanonicalOptions,
    block: &ClaudeContentBlock,
    child_ordinal: usize,
    bounds: ValueBounds,
) -> Result<CanonicalObservationV2, ClaudeCanonicalError> {
    let ToolBody {
        body,
        facts,
        resource_path,
    } = tool_body(block, options, bounds)?;
    // A command whose argument was replaced is not built from the source.
    let admitted = |key: &str| !body.bounded_member(BoundedTarget::Arguments, key);
    let (command_admitted, cmd_admitted) = (admitted("command"), admitted("cmd"));
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
        child_ordinal,
    )?;
    for (path, provenance) in facts {
        builder = builder.fact_metadata(path, FactMetadata::new(provenance, Sensitivity::Normal)?);
    }
    if let ClaudeContentBlock::ToolUse {
        input: Some(serde_json::Value::Object(input)),
        ..
    } = block
        && let Some(command) = input
            .get("command")
            .and_then(serde_json::Value::as_str)
            .filter(|_| command_admitted)
            .or_else(|| {
                input
                    .get("cmd")
                    .and_then(serde_json::Value::as_str)
                    .filter(|_| cmd_admitted)
            })
    {
        builder = builder
            .facet(
                "command.text",
                SemanticFacet::new(JsonValue::string(command)),
            )?
            .fact_metadata("command.text", FactMetadata::parsed()?);
    }
    if let Some(path) = resource_path {
        builder = builder
            .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
            .fact_metadata("resource.path", FactMetadata::parsed()?);
    }
    Ok(builder.build()?)
}

struct ToolBody {
    body: ToolObservation,
    facts: Vec<(&'static str, FactProvenance)>,
    resource_path: Option<String>,
}

fn tool_body(
    block: &ClaudeContentBlock,
    options: &ClaudeCanonicalOptions,
    bounds: ValueBounds,
) -> Result<ToolBody, ClaudeCanonicalError> {
    match block {
        ClaudeContentBlock::ToolUse { id: _, name, input } => {
            let name = name
                .as_deref()
                .ok_or_else(|| mapping("missing_tool_name", "tool_use block has no tool name"))?;
            let mut body = ToolObservation::new().with_name(name)?;
            let mut paths = vec![("tool.name", FactProvenance::Reported)];
            let mut facet = None;
            if let Some(input) = input {
                body = with_source_arguments(options.tools, Some(name), body, input, bounds)?;
                facet = body
                    .arguments()
                    .and_then(resource_path)
                    .map(ToOwned::to_owned);
                paths.push(("tool.arguments", FactProvenance::Reported));
            }
            Ok(ToolBody {
                body: declare(options.tools, body),
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
                body = with_source_result(
                    body,
                    joined.as_ref().unwrap_or(content),
                    ResultText::Direct,
                    bounds,
                )?;
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
        options.adapter.0,
        options.adapter.1,
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
mod tests;
