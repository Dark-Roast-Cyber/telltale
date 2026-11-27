//! Maps native Copilot process-log events to Canonical Observation v2.
//! Reached only through the acquisition router.

use std::fmt;

use serde_json::Value;
use telltale_schema::observation::{
    BoundedTarget, CanonicalFieldCategory, CanonicalObservationV2, CapabilityAvailability,
    CapabilityContext, CapabilityId, ContentPart, ContentPartKind, CorrelationId, CorrelationIds,
    FactMetadata, FactProvenance, Fidelity, IngestionMode, JsonValue, MessageObservation,
    MessageRole, ObservationBody, ObservationBuilder, ObservationError, ObservationStage,
    ObservedAt, SemanticFacet, Sensitivity, SourceProvenance, SourceTimestamp, ToolObservation,
};

use crate::tool_operation::{
    ResultText, ValueBounds, build_fitted, declare, replaced_arguments, with_declared_arguments,
    with_searchable_text, with_source_result,
};

use super::native::{CopilotContentBlock, CopilotNativeEvent, CopilotOutputItem};

#[derive(Clone)]
pub(crate) struct CopilotCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
}

impl CopilotCanonicalOptions {
    pub(crate) fn new(observed_at: ObservedAt) -> Self {
        Self { observed_at }
    }
}

pub(crate) enum CopilotCanonicalError {
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl CopilotCanonicalError {
    #[cfg(test)]
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Mapping { code, .. } => code,
            Self::Observation(error) => error.code(),
        }
    }
}

impl fmt::Debug for CopilotCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping { code, detail } => formatter
                .debug_struct("CopilotCanonicalError::Mapping")
                .field("code", code)
                .field("detail", detail)
                .finish(),
            Self::Observation(error) => formatter
                .debug_struct("CopilotCanonicalError::Observation")
                .field("code", &error.code())
                .finish(),
        }
    }
}

impl fmt::Display for CopilotCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping { code, detail } => {
                write!(
                    formatter,
                    "Copilot canonical mapping failed ({code}): {detail}"
                )
            }
            Self::Observation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CopilotCanonicalError {}

impl From<ObservationError> for CopilotCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

pub(crate) fn project_copilot_native_events(
    events: &[CopilotNativeEvent],
    options: &CopilotCanonicalOptions,
) -> Result<Vec<CanonicalObservationV2>, CopilotCanonicalError> {
    let mut observations = crate::acquisition::CanonicalCollector::default();
    for event in events {
        match event {
            CopilotNativeEvent::WorkspaceInitialized { .. }
            | CopilotNativeEvent::SessionCompleted => {}
            CopilotNativeEvent::MalformedStructuredOutput {
                canonical_session_id,
            } => {
                if canonical_session_id.is_none() {
                    return Err(mapping(
                        "replay_unverifiable",
                        "accumulated output has no active source session",
                    ));
                }
                return Err(mapping(
                    "malformed_structured_output",
                    "accumulated output is not a valid array",
                ));
            }
            CopilotNativeEvent::AccumulatedOutputItem {
                canonical_session_id,
                ordinal,
                timestamp,
                item,
                ..
            } => {
                let session_id = canonical_session_id.as_deref().ok_or_else(|| {
                    mapping(
                        "replay_unverifiable",
                        "accumulated output has no active source session",
                    )
                })?;
                let ordinal = (*ordinal).ok_or_else(|| {
                    mapping(
                        "replay_unverifiable",
                        "accumulated output has no source session ordinal",
                    )
                })?;
                project_item(
                    session_id,
                    ordinal,
                    timestamp.as_deref(),
                    item,
                    options,
                    &mut observations,
                )?;
            }
        }
    }
    Ok(observations.finish())
}

fn project_item(
    session_id: &str,
    ordinal: u64,
    timestamp: Option<&str>,
    item: &CopilotOutputItem,
    options: &CopilotCanonicalOptions,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), CopilotCanonicalError> {
    match item.item_type.as_deref() {
        None | Some("") | Some("reasoning") => Ok(()),
        Some("function_call") => {
            project_function_call(session_id, ordinal, timestamp, item, options, observations)
        }
        Some("message") => {
            project_message(session_id, ordinal, timestamp, item, options, observations)
        }
        Some(_) => Err(mapping(
            "unknown_output_item_type",
            "Copilot output item type is not supported",
        )),
    }
}

fn project_function_call(
    session_id: &str,
    ordinal: u64,
    timestamp: Option<&str>,
    item: &CopilotOutputItem,
    options: &CopilotCanonicalOptions,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), CopilotCanonicalError> {
    let has_name = item.name.as_deref().is_some_and(|value| !value.is_empty());
    let has_arguments = item
        .arguments
        .as_deref()
        .is_some_and(|value| !value.is_empty());
    if !has_name && !has_arguments {
        return Err(mapping(
            "invalid_tool_request",
            "Copilot function call has no meaningful tool fact",
        ));
    }

    let observation = build_fitted(ValueBounds::Replace, value_bound, |bounds| {
        let mut body = ToolObservation::new();
        let mut metadata = Vec::new();
        if has_name {
            body = body.with_name(item.name.as_deref().expect("checked"))?;
            metadata.push(("tool.name", FactProvenance::Reported));
        }
        if has_arguments {
            let arguments = item.arguments.as_deref().expect("checked");
            if let Ok(value) = serde_json::from_str::<Value>(arguments) {
                body = with_declared_arguments(
                    telltale_schema::observation::ArgumentText::new(),
                    body,
                    &value,
                    bounds,
                )?;
                metadata.push(("tool.arguments", FactProvenance::Parsed));
            } else {
                // Request text that is no JSON is one string value, kept
                // whole or replaced whole.
                body = with_declared_arguments(
                    telltale_schema::observation::ArgumentText::new(),
                    body,
                    &normalized(arguments),
                    bounds,
                )?;
                metadata.push(("tool.arguments", FactProvenance::Reported));
            }
            // Searchable text is the raw request; it is never kept beside
            // arguments whose values were replaced, and is omitted (and
            // recorded) when it alone is over its bound.
            if body.bounded_values().is_empty() {
                body = with_searchable_text(
                    body,
                    BoundedTarget::SearchableArguments,
                    arguments,
                    bounds,
                )?;
                if body.searchable_arguments().is_some() {
                    metadata.push(("tool.searchable_arguments", FactProvenance::Reported));
                }
            }
        }

        // No facet is built from an argument that was replaced.
        let replaced = replaced_arguments(&body, &["command", "cmd", "path", "file_path"]);
        let mut builder = common_builder(
            session_id,
            ordinal,
            timestamp,
            ObservationBody::Tool(declare(super::tools::TOOLS, body)),
            ObservationStage::ToolRequested,
            0,
            item.call_id.as_deref(),
            options,
        )?;
        for (path, provenance) in metadata {
            builder =
                builder.fact_metadata(path, FactMetadata::new(provenance, Sensitivity::Normal)?);
        }
        add_argument_facets(&mut builder, item.arguments.as_deref(), &replaced)?;
        Ok(builder.build()?)
    })?;
    observations.push(observation)?;

    if item
        .message
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        let message = normalized(item.message.as_deref().expect("checked"));
        let observation = build_fitted(ValueBounds::Replace, value_bound, |bounds| {
            let body =
                with_source_result(ToolObservation::new(), &message, ResultText::Direct, bounds)?;
            let builder = common_builder(
                session_id,
                ordinal,
                timestamp,
                ObservationBody::Tool(body),
                ObservationStage::ToolResultReturned,
                1,
                item.call_id.as_deref(),
                options,
            )?;
            Ok(builder
                .fact_metadata("tool.result", FactMetadata::reported()?)
                .build()?)
        })?;
        observations.push(observation)?;
    }
    Ok(())
}

/// A Copilot text the observation stores whole, normalized as it stores it,
/// so its bound is decided on the normalized text.
fn normalized(text: &str) -> Value {
    match JsonValue::string(text) {
        JsonValue::String(text) => Value::String(text),
        _ => unreachable!("a string stays a string"),
    }
}

fn project_message(
    session_id: &str,
    ordinal: u64,
    timestamp: Option<&str>,
    item: &CopilotOutputItem,
    options: &CopilotCanonicalOptions,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), CopilotCanonicalError> {
    if item.role.as_deref() != Some("assistant") {
        return Err(mapping(
            "unsupported_role",
            "Copilot message role is not assistant",
        ));
    }
    if !item.content_present {
        return Err(mapping(
            "missing_message_content",
            "Copilot assistant message has no content parts",
        ));
    }
    let blocks = item.content.as_deref().ok_or_else(|| {
        mapping(
            "unsupported_message_content",
            "Copilot assistant message content is not structured",
        )
    })?;
    let mut body = MessageObservation::new(MessageRole::Assistant);
    for block in blocks {
        let CopilotContentBlock::OutputText { text } = block else {
            return Err(mapping(
                "unknown_content_block",
                "Copilot message content block is not output text",
            ));
        };
        let text = text.as_deref().ok_or_else(|| {
            mapping(
                "invalid_content_block",
                "Copilot output text block has no text value",
            )
        })?;
        body = body.with_content_part(ContentPart::new(
            ContentPartKind::Text,
            JsonValue::try_from_source_message_text(text).map_err(|error| {
                error.with_bound_category(CanonicalFieldCategory::MessageContentParts)
            })?,
        ));
    }
    let mut builder = common_builder(
        session_id,
        ordinal,
        timestamp,
        ObservationBody::Message(body),
        ObservationStage::MessageObserved,
        0,
        None,
        options,
    )?;
    builder = builder
        .fact_metadata("message.role", FactMetadata::reported()?)
        .fact_metadata("message.content_parts", FactMetadata::reported()?);
    observations.push(builder.build()?)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn common_builder(
    session_id: &str,
    ordinal: u64,
    timestamp: Option<&str>,
    body: ObservationBody,
    stage: ObservationStage,
    child_ordinal: u32,
    call_id: Option<&str>,
    options: &CopilotCanonicalOptions,
) -> Result<ObservationBuilder, CopilotCanonicalError> {
    let source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "copilot",
        "copilot.process_log",
        Fidelity::PartialStructured,
    )?
    .with_identity_source_sequence(session_id, ordinal)?;
    let mut builder =
        CanonicalObservationV2::builder(body, stage, options.observed_at.clone(), source)
            .sequence(ordinal)
            .capability_context(capabilities())
            .session_id(CorrelationId::source_reported(session_id)?);
    if let Some(call_id) = call_id {
        builder = builder.correlation(
            CorrelationIds::new().with_call_id(CorrelationId::source_reported(call_id)?),
        );
    }
    if let Some(timestamp) = timestamp.and_then(|value| SourceTimestamp::new(value).ok()) {
        builder = builder.occurred_at(timestamp);
    }
    Ok(builder.child_ordinal(child_ordinal))
}

fn add_argument_facets(
    builder: &mut ObservationBuilder,
    arguments: Option<&str>,
    replaced: &[&str],
) -> Result<(), CopilotCanonicalError> {
    let Some(arguments) = arguments else {
        return Ok(());
    };
    let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(arguments) else {
        return Ok(());
    };
    if let Some(command) = fields
        .get("command")
        .filter(|_| !replaced.contains(&"command"))
        .or_else(|| fields.get("cmd").filter(|_| !replaced.contains(&"cmd")))
        .and_then(Value::as_str)
    {
        *builder = builder
            .clone()
            .facet(
                "command.text",
                SemanticFacet::new(JsonValue::string(command)),
            )?
            .fact_metadata("command.text", FactMetadata::parsed()?);
    }
    if let Some(path) = fields
        .get("path")
        .filter(|_| !replaced.contains(&"path"))
        .or_else(|| {
            fields
                .get("file_path")
                .filter(|_| !replaced.contains(&"file_path"))
        })
        .and_then(Value::as_str)
    {
        *builder = builder
            .clone()
            .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
            .fact_metadata("resource.path", FactMetadata::parsed()?);
    }
    Ok(())
}

fn capabilities() -> CapabilityContext {
    CapabilityContext::new()
        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported)
        .with_override(
            CapabilityId::UserContext,
            CapabilityAvailability::Unsupported,
        )
        .with_override(CapabilityId::ToolExecution, CapabilityAvailability::Unknown)
}

fn mapping(code: &'static str, detail: &'static str) -> CopilotCanonicalError {
    CopilotCanonicalError::Mapping { code, detail }
}

/// A failure of a call's observation on a value bound: [`build_fitted`] then
/// builds it again with the call's values fitted.
fn value_bound(error: &CopilotCanonicalError) -> bool {
    matches!(error, CopilotCanonicalError::Observation(error) if error.bound_dimension().is_some())
}

#[cfg(test)]
mod tests;
