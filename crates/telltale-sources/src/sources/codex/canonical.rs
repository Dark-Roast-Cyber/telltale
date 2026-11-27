//! Maps native Codex records to Canonical Observation v2. Reached only through
//! the acquisition router.

use std::fmt;

use serde_json::Value;
use telltale_schema::observation::{
    CanonicalFieldCategory, CanonicalObservationV2, CapabilityAvailability, CapabilityContext,
    CapabilityId, ContentPart, ContentPartKind, CorrelationId, CorrelationIds, FactMetadata,
    FactProvenance, Fidelity, IngestionMode, JsonValue, MessageObservation, MessageRole,
    ObservationBody, ObservationBuilder, ObservationError, ObservationStage, ObservedAt,
    SemanticFacet, Sensitivity, SourceProvenance, SourceTimestamp, ToolKind, ToolObservation,
    ToolOperation, ToolStatus,
};

use telltale_schema::observation::{BoundedTarget, CanonicalBoundContext};

use crate::tool_operation::{
    BoundedRecord, ResultText, ValueBounds, bounded_records, build_fitted, declare_in,
    with_searchable_text, with_source_arguments, with_source_result,
};

use super::native::{
    CodexContentBlock, CodexNativeRecord, CodexToolFields, is_known_codex_discriminator,
    legacy_message_group,
};

#[derive(Clone)]
pub(crate) struct CodexCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
    pub(crate) scale: telltale_schema::observation::SourceScale,
}

impl CodexCanonicalOptions {
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

pub(crate) enum CodexCanonicalError {
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl CodexCanonicalError {
    #[cfg(test)]
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Mapping { code, .. } => code,
            Self::Observation(error) => error.code(),
        }
    }
}

impl fmt::Debug for CodexCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping { code, detail } => formatter
                .debug_struct("CodexCanonicalError::Mapping")
                .field("code", code)
                .field("detail", detail)
                .finish(),
            Self::Observation(error) => formatter
                .debug_struct("CodexCanonicalError::Observation")
                .field("code", &error.code())
                .field("bound_context", &error.bound_context())
                .finish(),
        }
    }
}

impl fmt::Display for CodexCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

impl From<ObservationError> for CodexCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

#[derive(Debug)]
pub(crate) struct CodexProjection {
    pub(crate) observations: Vec<CanonicalObservationV2>,
    /// Records left out by themselves; every other record was still mapped.
    pub(crate) quarantined: Vec<CodexQuarantinedRecord>,
    /// Records mapped with over-bound tool values replaced; never quarantined.
    pub(crate) bounded: Vec<BoundedRecord>,
}

/// Coordinates of a record excluded from projection, never its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodexQuarantinedRecord {
    pub(crate) source_sequence: u64,
    pub(crate) code: &'static str,
    pub(crate) bound: Option<CanonicalBoundContext>,
}

/// Map each record on its own. A record whose type, completed item or content
/// part this adapter does not map, or whose own values exceed a canonical
/// bound, is quarantined so one record cannot blind the whole session.
/// Integrity failures and the source-wide retained budget still fail the
/// source.
pub(crate) fn project_codex_native_records(
    records: &[CodexNativeRecord],
    options: &CodexCanonicalOptions,
) -> Result<CodexProjection, CodexCanonicalError> {
    let mut observations = crate::acquisition::CanonicalCollector::scaled(options.scale);
    let mut quarantined = Vec::new();
    let mut bounded = Vec::new();
    let mut index = 0;
    while index < records.len() {
        if let Some((raw, end)) = legacy_message_group(records, index) {
            if !project_unit(
                &records[raw],
                options,
                &mut observations,
                &mut quarantined,
                &mut bounded,
            )? {
                // A quarantined raw message cannot hide usable legacy text.
                for (offset, record) in records[index..end].iter().enumerate() {
                    if index + offset != raw {
                        project_unit(
                            record,
                            options,
                            &mut observations,
                            &mut quarantined,
                            &mut bounded,
                        )?;
                    }
                }
            }
            index = end;
        } else {
            // An unmatched event run is visited once, not rescanned for every
            // event while looking for an adjacent raw response.
            let end = if records[index].is_legacy_agent_message() {
                index
                    + records[index..]
                        .iter()
                        .take_while(|record| record.is_legacy_agent_message())
                        .count()
            } else {
                index + 1
            };
            for record in &records[index..end] {
                project_unit(
                    record,
                    options,
                    &mut observations,
                    &mut quarantined,
                    &mut bounded,
                )?;
            }
            index = end;
        }
    }
    quarantined.sort_by_key(|record| record.source_sequence);
    bounded.sort_by_key(|record| record.source_sequence);
    Ok(CodexProjection {
        observations: observations.finish(),
        quarantined,
        bounded,
    })
}

fn project_unit(
    record: &CodexNativeRecord,
    options: &CodexCanonicalOptions,
    observations: &mut crate::acquisition::CanonicalCollector,
    quarantined: &mut Vec<CodexQuarantinedRecord>,
    bounded: &mut Vec<BoundedRecord>,
) -> Result<bool, CodexCanonicalError> {
    let mut unit = crate::acquisition::CanonicalCollector::default();
    match project_record(record, options, &mut unit) {
        Ok(()) => {
            let unit = unit.finish();
            bounded.extend(bounded_records(record.source_sequence, &unit));
            for observation in unit {
                observations.push(observation)?;
            }
            Ok(true)
        }
        Err(error) => match quarantine_code(&error) {
            Some(code) => {
                quarantined.push(CodexQuarantinedRecord {
                    source_sequence: record.source_sequence,
                    code,
                    bound: match &error {
                        CodexCanonicalError::Observation(error) => error.bound_context(),
                        CodexCanonicalError::Mapping { .. } => None,
                    },
                });
                Ok(false)
            }
            None => Err(error),
        },
    }
}

fn quarantine_code(error: &CodexCanonicalError) -> Option<&'static str> {
    match error {
        CodexCanonicalError::Mapping { code, .. }
            if matches!(
                *code,
                "unknown_discriminator"
                    | "unknown_content_block"
                    | "unsupported_completed_item"
                    | "foreign_thread_item"
            ) =>
        {
            Some(code)
        }
        CodexCanonicalError::Observation(error) if error.code() == "unbounded_value" => {
            Some("unbounded_value")
        }
        _ => None,
    }
}

fn project_record(
    record: &CodexNativeRecord,
    options: &CodexCanonicalOptions,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), CodexCanonicalError> {
    if record.auxiliary || record.mirrored {
        return Ok(());
    }
    if let Some(code) = record.quarantine {
        return Err(mapping(
            code,
            "Codex record is recognized but not mapped by this adapter",
        ));
    }
    if record.discriminator.as_deref().is_some_and(|kind| {
        !(is_known_codex_discriminator(kind)
            || is_known_canonical_discriminator(kind)
            || kind == "plan" && record.completed.is_some())
    }) {
        return Err(mapping(
            "unknown_discriminator",
            "explicit Codex record discriminator is not supported",
        ));
    }

    if record.session_metadata {
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
            "user_message" | "user" | "agent_message" | "assistant_message" | "assistant"
            | "gemini" | "model" | "text" | "message" | "plan",
        ) => {
            let body = build_message_body(record, canonical_role(record)?, &[])?;
            emit_message_body(record, options, body, &mut child_ordinal, observations)
        }
        Some("tool_call" | "custom_tool_call" | "function_call" | "web_search_call") => emit_tool(
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
                | "agent_message"
                | "assistant"
                | "gemini"
                | "model"
                | "text"
                | "message"
                | "plan"
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

/// The element Codex wraps a command the user ran from the prompt in, with
/// its output, when it stores the pair as a user message.
const HARNESS_OUTPUT_ELEMENTS: [&str; 1] = ["user_shell_command"];

/// Whether a projected Codex user message holds harness output rather than
/// only a prompt: one of [`HARNESS_OUTPUT_ELEMENTS`], by the transcript's
/// shared element rule. `text` is the message text a transcript shows.
pub(crate) fn is_harness_output_message(observation: &CanonicalObservationV2, text: &str) -> bool {
    crate::acquisition::transcript::user_message_holds_element(
        observation,
        text,
        &HARNESS_OUTPUT_ELEMENTS,
    )
}

fn canonical_role(record: &CodexNativeRecord) -> Result<MessageRole, CodexCanonicalError> {
    let role = record.role.as_deref().or_else(|| {
        record.discriminator.as_deref().and_then(|kind| match kind {
            "user_message" | "user" => Some("user"),
            "agent_message" | "assistant_message" | "assistant" | "gemini" | "model" => {
                Some("assistant")
            }
            _ => None,
        })
    });
    match role {
        Some("system") => Ok(MessageRole::System),
        Some("developer") => Ok(MessageRole::Developer),
        Some("user") => Ok(MessageRole::User),
        Some("assistant" | "model") => Ok(MessageRole::Assistant),
        Some(_) => Err(mapping(
            "unsupported_role",
            "Codex record role is not a supported message role",
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
            body = body.with_content(JsonValue::try_from_source_message_content(content).map_err(
                |error| error.with_bound_category(CanonicalFieldCategory::MessageContent),
            )?);
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
                JsonValue::try_from_source_message_text(text).map_err(|error| {
                    error.with_bound_category(
                        telltale_schema::observation::CanonicalFieldCategory::MessageContentParts,
                    )
                })?,
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
                fields.push((
                    "input".to_owned(),
                    value_to_json(input, CanonicalFieldCategory::MessageContentParts)?,
                ));
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
                fields.push((
                    "content".to_owned(),
                    value_to_json(result, CanonicalFieldCategory::MessageContentParts)?,
                ));
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
            id, name, input, ..
        } => Ok(Some((
            CodexToolFields {
                name: name.clone(),
                arguments: input.clone(),
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
    observations: &mut crate::acquisition::CanonicalCollector,
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
        builder = builder.fact_metadata(path, FactMetadata::reported()?);
    }
    observations.push(builder.build()?)?;
    *child_ordinal += 1;
    Ok(())
}

fn emit_tool(
    record: &CodexNativeRecord,
    options: &CodexCanonicalOptions,
    fields: CodexToolFields,
    stage: ObservationStage,
    child_ordinal: &mut usize,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), CodexCanonicalError> {
    let observation = build_fitted(
        ValueBounds::Replace,
        |error| matches!(error, CodexCanonicalError::Observation(error) if error.bound_dimension().is_some()),
        |bounds| tool_observation(record, options, &fields, stage, *child_ordinal, bounds),
    )?;
    observations.push(observation)?;
    *child_ordinal += 1;
    Ok(())
}

fn tool_observation(
    record: &CodexNativeRecord,
    options: &CodexCanonicalOptions,
    fields: &CodexToolFields,
    stage: ObservationStage,
    child_ordinal: usize,
    bounds: ValueBounds,
) -> Result<CanonicalObservationV2, CodexCanonicalError> {
    if fields.is_error_present && fields.is_error.is_none() {
        return Err(mapping(
            "invalid_tool_result",
            "tool error state is not boolean",
        ));
    }

    let generic = record.discriminator.as_deref() == Some("tool");
    let hosted_search = record.discriminator.as_deref() == Some("web_search_call");
    let source_error =
        !hosted_search && (fields.error_present || fields.status.as_deref() == Some("error"));
    let has_result = fields.result_present || fields.error_present;
    let has_explicit_body = fields.name.is_some()
        || fields.arguments.is_some()
        || fields.result.is_some()
        || fields.is_error.is_some();

    if stage == ObservationStage::ToolResultReturned
        && !has_result
        && !generic
        && !fields.completed_command
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
        paths.push((
            "tool.name",
            if hosted_search {
                FactProvenance::Parsed
            } else {
                FactProvenance::Reported
            },
        ));
    }
    if let Some(arguments) = &fields.arguments {
        body = with_source_arguments(
            super::tools::TOOLS,
            fields.name.as_deref(),
            body,
            arguments,
            bounds,
        )?;
        paths.push(("tool.arguments", FactProvenance::Reported));
    }
    if let Some(result) = &fields.result {
        body = with_tool_result(body, result, bounds)?;
        let searchable = body
            .result()
            .filter(|_| fields.completed_file_change)
            .filter(|_| !replaced_in(&body, BoundedTarget::Result))
            .and_then(file_change_searchable_result);
        if let Some(text) = searchable {
            body = with_searchable_text(body, BoundedTarget::SearchableResult, &text, bounds)?;
            if body.searchable_result().is_some() {
                paths.push(("tool.searchable_result", FactProvenance::Parsed));
            }
        }
        paths.push(("tool.result", FactProvenance::Reported));
    } else if let Some(error) = &fields.error {
        body = with_source_result(body, error, ResultText::Structured, bounds)?;
        paths.push(("tool.result", FactProvenance::Reported));
    }
    // Searchable text is derived from validated values, never from a field
    // with replaced values; fitting the result can replace arguments too. A
    // text over its own bound is omitted and recorded.
    if hosted_search
        && !replaced_in(&body, BoundedTarget::Arguments)
        && let Some(text) = body.arguments().and_then(web_search_searchable_arguments)
    {
        body = with_searchable_text(body, BoundedTarget::SearchableArguments, &text, bounds)?;
        if body.searchable_arguments().is_some() {
            paths.push(("tool.searchable_arguments", FactProvenance::Parsed));
        }
    }
    if let Some(is_error) = fields.is_error {
        body = body.with_is_error(is_error);
        paths.push(("tool.is_error", FactProvenance::Reported));
    }
    if let Some(exit_code) = fields.exit_code {
        body = body.with_exit_code(exit_code);
        paths.push(("tool.exit_code", FactProvenance::Reported));
    }
    if fields.completed_command || fields.completed_file_change && fields.status.is_some() {
        body = body.with_reported_status(match fields.status.as_deref() {
            Some("completed") => ToolStatus::Succeeded,
            Some("failed") => ToolStatus::Failed,
            Some("declined") => ToolStatus::Denied,
            _ => {
                return Err(mapping(
                    "invalid_command_status",
                    "completed tool requires terminal status",
                ));
            }
        });
        paths.push(("tool.reported_status", FactProvenance::Reported));
    } else if source_error {
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

    // Completed commands and file changes carry no tool name; their records
    // say what they are. Their operands are in the facets and the result.
    let body = if fields.completed_command {
        body.with_operation(ToolOperation::new(ToolKind::Shell))
    } else if fields.completed_file_change {
        body.with_operation(ToolOperation::new(ToolKind::FileWrite))
    } else {
        declare_in(super::tools::TOOLS, body, fields.namespace.as_deref())
    };
    // Facets are never built from an argument that was replaced.
    let admitted = |key: &str| !body.bounded_member(BoundedTarget::Arguments, key);
    let admitted_keys = ["command", "cmd"].map(|key| (key, admitted(key)));
    let path_admitted = admitted("file_path");
    let arguments_whole = !body
        .bounded_values()
        .iter()
        .any(|value| value.target() == BoundedTarget::Arguments);
    let mut builder = common_builder(
        record,
        options,
        ObservationBody::Tool(body),
        stage,
        tool_correlation(fields.call_id.as_deref())?,
        child_ordinal,
    )?;
    for (path, provenance) in paths {
        builder = builder.fact_metadata(path, FactMetadata::new(provenance, Sensitivity::Normal)?);
    }

    if fields.completed_command {
        builder = builder
            .facet(
                "tool.source_status",
                SemanticFacet::new(JsonValue::string(
                    fields.status.as_deref().expect("validated status"),
                )),
            )?
            .fact_metadata("tool.source_status", FactMetadata::reported()?)
            .facet(
                "tool.output_fidelity",
                SemanticFacet::new(JsonValue::string(
                    fields.output_fidelity.expect("native output fidelity"),
                )),
            )?
            .fact_metadata("tool.output_fidelity", FactMetadata::parsed()?);
        if let Some(cwd) = &fields.cwd {
            builder = builder
                .facet("resource.path", SemanticFacet::new(JsonValue::string(cwd)))?
                .fact_metadata("resource.path", FactMetadata::reported()?);
        }
    }

    if (fields.completed_file_change || hosted_search)
        && let Some(status) = &fields.status
    {
        builder = builder
            .facet(
                "tool.source_status",
                SemanticFacet::new(JsonValue::string(status)),
            )?
            .fact_metadata("tool.source_status", FactMetadata::reported()?);
    }

    let argument_view = fields.arguments.as_ref().and_then(parsed_argument_view);
    let command = fields.command.clone().or_else(|| {
        argument_command(fields.arguments.as_ref(), argument_view.as_ref(), |key| {
            admitted_keys.contains(&(key, true))
        })
    });
    let has_command = command.is_some();
    if let Some(command) = command {
        builder = builder
            .facet(
                "command.text",
                SemanticFacet::new(JsonValue::string(command)),
            )?
            .fact_metadata("command.text", FactMetadata::parsed()?);
    }
    if let Some(path) = argument_view
        .as_ref()
        .filter(|_| path_admitted)
        .and_then(|arguments| argument_string(arguments, "file_path"))
    {
        builder = builder
            .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
            .fact_metadata("resource.path", FactMetadata::parsed()?);
    }

    // Completed commands report argv only. A shell-quoted rendering gives
    // command selectors a view of it; argv stays structured, and a rendering
    // that does not fit the bounds is omitted rather than rejecting the result.
    let derived = if fields.completed_command && !has_command && arguments_whole {
        fields
            .arguments
            .as_ref()
            .and_then(shell_quoted_argv)
            .and_then(|text| {
                builder
                    .clone()
                    .facet("command.text", SemanticFacet::new(JsonValue::string(text)))
                    .ok()
            })
    } else {
        None
    };
    Ok(match derived {
        Some(with_command) => match with_command
            .fact_metadata(
                "command.text",
                FactMetadata::new(FactProvenance::Derived, Sensitivity::Normal)?,
            )
            .build()
        {
            Ok(observation) => observation,
            Err(error) if error.bound_dimension().is_some() => builder.build()?,
            Err(error) => return Err(error.into()),
        },
        None => builder.build()?,
    })
}

/// POSIX shell quoting: safe words unchanged, the empty word as `''`, and any
/// other word single-quoted with each embedded quote written as `'\''`.
fn shell_quoted_argv(arguments: &Value) -> Option<String> {
    let words = arguments
        .as_array()?
        .iter()
        .map(|word| word.as_str().map(shell_quote))
        .collect::<Option<Vec<_>>>()?;
    (!words.is_empty()).then(|| words.join(" "))
}

fn shell_quote(word: &str) -> String {
    if word.is_empty() {
        "''".to_owned()
    } else if word
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte))
    {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// Whether a bounded conversion replaced any value of `target`.
fn replaced_in(body: &ToolObservation, target: BoundedTarget) -> bool {
    body.bounded_values()
        .iter()
        .any(|value| value.target() == target)
}

fn web_search_searchable_arguments(action: &JsonValue) -> Option<String> {
    let JsonValue::Object(action) = action else {
        unreachable!("validated web search action")
    };
    let mut text = String::new();
    for key in ["query", "queries", "url", "pattern"] {
        let values: &[JsonValue] = match action.get(key) {
            Some(JsonValue::Array(values)) => values,
            Some(value @ JsonValue::String(_)) => std::slice::from_ref(value),
            _ => continue,
        };
        for value in values {
            let JsonValue::String(value) = value else {
                unreachable!("validated search text")
            };
            text.push_str(key);
            text.push('\n');
            text.push_str(value);
            text.push('\n');
        }
    }
    (!text.is_empty()).then(|| text.replace(['\r', '\n'], " "))
}

/// Only the closed native patch fields become text. Deletion content and both
/// sides of a diff remain reported patch evidence, never newly written content.
fn file_change_searchable_result(result: &JsonValue) -> Option<String> {
    let JsonValue::Object(result) = result else {
        unreachable!("validated file change")
    };
    let JsonValue::Object(changes) = &result["changes"] else {
        unreachable!("validated changes")
    };
    let mut text = String::new();
    for (path, change) in changes {
        let JsonValue::Object(change) = change else {
            unreachable!("validated change")
        };
        let JsonValue::String(kind) = &change["type"] else {
            unreachable!("validated kind")
        };
        text.push_str("path\n");
        text.push_str(path);
        text.push('\n');
        for key in ["content", "unified_diff", "move_path"] {
            if let Some(JsonValue::String(value)) = change.get(key) {
                text.push_str(kind);
                text.push('.');
                text.push_str(key);
                text.push('\n');
                text.push_str(value);
                text.push('\n');
            }
        }
    }
    for key in ["stdout", "stderr"] {
        if let Some(JsonValue::String(value)) = result.get(key) {
            text.push_str(key);
            text.push('\n');
            text.push_str(value);
            text.push('\n');
        }
    }
    // Searchable Tool fields are single-line by contract. The structured result
    // above retains exact patch text; only this parsed search view folds CR/LF.
    (!text.is_empty()).then(|| text.replace(['\r', '\n'], " "))
}

fn tool_correlation(call_id: Option<&str>) -> Result<Option<CorrelationIds>, CodexCanonicalError> {
    let Some(value) = call_id else {
        return Ok(None);
    };
    Ok(Some(
        CorrelationIds::new().with_call_id(CorrelationId::source_reported(value)?),
    ))
}

fn common_builder(
    record: &CodexNativeRecord,
    options: &CodexCanonicalOptions,
    body: ObservationBody,
    stage: ObservationStage,
    correlation: Option<CorrelationIds>,
    child_ordinal: usize,
) -> Result<ObservationBuilder, CodexCanonicalError> {
    let mut source_provenance = SourceProvenance::new(
        if record.external_import {
            IngestionMode::Import
        } else {
            IngestionMode::SessionStore
        },
        "codex",
        &record.adapter_id,
        Fidelity::PartialStructured,
    )?
    .with_source_sequence(record.source_sequence);
    if let Some(coords) = &record.completed {
        source_provenance = source_provenance.with_native_id(
            serde_json::to_string(&[
                record
                    .effective_session_id
                    .as_deref()
                    .expect("completed owner"),
                &coords.turn_id,
                &coords.item_id,
            ])
            .expect("string coordinates"),
        )?;
    } else if let Some(session_id) = &record.effective_session_id {
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
    if let Some(session_id) = &record.effective_session_id {
        builder = builder.session_id(CorrelationId::source_reported(session_id)?);
    }
    let mut correlation = correlation.unwrap_or_default();
    if let Some(coords) = &record.completed {
        correlation = correlation.with_turn_id(CorrelationId::source_reported(&coords.turn_id)?);
        if !record.tool.completed_command {
            correlation =
                correlation.with_response_id(CorrelationId::source_reported(&coords.item_id)?);
        }
    } else if record.discriminator.as_deref() == Some("web_search_call")
        && let Some(id) = &record.response_id
    {
        correlation = correlation.with_response_id(CorrelationId::source_reported(id)?);
    }
    builder = builder.correlation(correlation);
    if let Some(root_id) = &record.root_session_id {
        builder = builder
            .facet(
                "session.root_id",
                SemanticFacet::new(JsonValue::string(root_id)),
            )?
            .fact_metadata("session.root_id", FactMetadata::reported()?);
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

fn parsed_argument_view(value: &Value) -> Option<Value> {
    match value {
        Value::String(value) => serde_json::from_str(value).ok(),
        Value::Object(_) => Some(value.clone()),
        _ => None,
    }
}

/// The command among the arguments, `command` before `cmd`, skipping a key
/// whose value was replaced.
fn argument_command(
    arguments: Option<&Value>,
    parsed: Option<&Value>,
    admitted: impl Fn(&str) -> bool,
) -> Option<String> {
    let command = |value: Option<&Value>, key| {
        value
            .filter(|_| admitted(key))
            .and_then(|value| argument_string(value, key))
    };
    command(parsed, "command")
        .or_else(|| command(parsed, "cmd"))
        .or_else(|| command(arguments, "command"))
        .or_else(|| command(arguments, "cmd"))
}

fn argument_string(value: &Value, key: &str) -> Option<String> {
    value
        .as_object()?
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn value_to_json(
    value: &Value,
    category: CanonicalFieldCategory,
) -> Result<JsonValue, CodexCanonicalError> {
    Ok(JsonValue::try_from_source_value(value)
        .map_err(|error| error.with_bound_category(category))?)
}

/// Direct output text gets the tool-result text budget. Codex stores custom
/// tool output as `[{"type":"input_text","text":...}]`; an all-text array is
/// joined into one direct string, and any other shape keeps ordinary
/// structured conversion.
fn with_tool_result(
    body: ToolObservation,
    result: &Value,
    bounds: ValueBounds,
) -> Result<ToolObservation, CodexCanonicalError> {
    let joined = joined_text_result(result);
    Ok(with_source_result(
        body,
        joined.as_ref().unwrap_or(result),
        ResultText::Direct,
        bounds,
    )?)
}

fn joined_text_result(result: &Value) -> Option<Value> {
    let items = result.as_array()?;
    let texts = items
        .iter()
        .map(|item| match item.get("type").and_then(Value::as_str) {
            Some("input_text" | "output_text" | "text") => item.get("text").and_then(Value::as_str),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    (!texts.is_empty()).then(|| Value::String(texts.join("\n")))
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
mod tests;
