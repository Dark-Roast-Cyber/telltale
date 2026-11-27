//! Maps native OpenCode records to Canonical Observation v2. Reached only
//! through the acquisition router.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::Value;
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId, FactMetadata,
    FactProvenance, Fidelity, IngestionMode, JsonValue, MessageObservation, MessageRole,
    ObservationBody, ObservationBuilder, ObservationError, ObservationStage, ObservedAt,
    SemanticFacet, Sensitivity, SourceProvenance, SourceTimestamp, ToolObservation, ToolStatus,
};

use crate::tool_operation::{
    ResultText, ValueBounds, build_fitted, declare, replaced_arguments, with_source_arguments,
    with_source_result,
};

use super::native::{
    OpenCodeMessageContext, OpenCodeMessageNativeRecord, OpenCodeSqliteNativeRecord,
    OpenCodeTextPartNativeRecord, OpenCodeToolPartNativeRecord, OpenCodeToolState,
};

pub(crate) enum OpenCodeCanonicalError {
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl OpenCodeCanonicalError {
    #[cfg(test)]
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Mapping { code, .. } => code,
            Self::Observation(error) => error.code(),
        }
    }
}

impl fmt::Debug for OpenCodeCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping { code, detail } => formatter
                .debug_struct("OpenCodeCanonicalError::Mapping")
                .field("code", code)
                .field("detail", detail)
                .finish(),
            Self::Observation(error) => formatter
                .debug_struct("OpenCodeCanonicalError::Observation")
                .field("code", &error.code())
                .finish(),
        }
    }
}

impl fmt::Display for OpenCodeCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping { code, detail } => {
                write!(
                    formatter,
                    "OpenCode canonical mapping failed ({code}): {detail}"
                )
            }
            Self::Observation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for OpenCodeCanonicalError {}

impl From<ObservationError> for OpenCodeCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

pub(crate) fn project_opencode_native_records(
    records: &[OpenCodeSqliteNativeRecord],
    observed_at: &ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, OpenCodeCanonicalError> {
    let part_message_ids = records
        .iter()
        .filter_map(|record| match record {
            OpenCodeSqliteNativeRecord::Text(record) => record.message_id.as_deref(),
            OpenCodeSqliteNativeRecord::Tool(record) => record.message_id.as_deref(),
            OpenCodeSqliteNativeRecord::Message(_) => None,
        })
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    let mut observations = crate::acquisition::CanonicalCollector::default();
    for record in records {
        match record {
            OpenCodeSqliteNativeRecord::Message(record)
                if record
                    .source_id
                    .as_deref()
                    .is_some_and(|id| part_message_ids.contains(id)) => {}
            OpenCodeSqliteNativeRecord::Message(record) => {
                require_source_id(record.source_id.as_deref())?;
                project_message(record, observed_at, &mut observations)?;
            }
            OpenCodeSqliteNativeRecord::Text(record) => {
                require_source_id(record.source_id.as_deref())?;
                project_text_part(record, observed_at, &mut observations)?;
            }
            OpenCodeSqliteNativeRecord::Tool(record) => {
                require_source_id(record.source_id.as_deref())?;
                project_tool_part(record, observed_at, &mut observations)?;
            }
        }
    }
    Ok(observations.finish())
}

fn project_message(
    record: &OpenCodeMessageNativeRecord,
    observed_at: &ObservedAt,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), OpenCodeCanonicalError> {
    let message_type = record.message_type.as_deref();
    if matches!(message_type, Some("tool" | "tool_call" | "tool_result")) {
        if record.tool_state_invalid {
            return Err(mapping(
                "invalid_tool_state",
                "OpenCode tool state is not an object",
            ));
        }
        let result = record.result.clone().or_else(|| {
            (message_type == Some("tool_result"))
                .then(|| record.content.clone())
                .flatten()
        });
        let stage = if message_type == Some("tool_call") && record.tool_state.is_none() {
            Some(ObservationStage::ToolRequested)
        } else if message_type == Some("tool_result") {
            Some(ObservationStage::ToolResultReturned)
        } else {
            None
        };
        return project_tool(
            record.source_sequence,
            record.source_id.as_deref(),
            &record.context,
            record.tool_name.as_deref(),
            record.call_id.as_deref(),
            record.tool_state.as_ref(),
            record.arguments.as_ref(),
            record.arguments_present,
            result.as_ref(),
            record.result_present || result.is_some(),
            record.error.as_ref(),
            record.error_present,
            stage,
            observed_at,
            observations,
        );
    }

    if message_type.is_some_and(|kind| !is_message_type(kind)) {
        return Err(mapping(
            "unknown_message_variant",
            "OpenCode message variant is not supported",
        ));
    }
    if record.content.is_none() {
        return Ok(());
    }

    let role = canonical_role(&record.context)?;
    let mut body = MessageObservation::new(role);
    body = body.with_content(JsonValue::try_from_source_message_content(
        record.content.as_ref().expect("checked"),
    )?);
    let mut builder = common_builder(
        record.source_sequence,
        record.source_id.as_deref(),
        &record.context,
        record.context.occurrence_time.as_deref(),
        ObservationBody::Message(body),
        ObservationStage::MessageObserved,
        observed_at,
    )?;
    builder = builder.fact_metadata("message.role", FactMetadata::reported()?);
    builder = builder.fact_metadata("message.content", FactMetadata::reported()?);
    observations.push(builder.build()?)?;
    Ok(())
}

fn project_text_part(
    record: &OpenCodeTextPartNativeRecord,
    observed_at: &ObservedAt,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), OpenCodeCanonicalError> {
    let text = record
        .text
        .as_deref()
        .ok_or_else(|| mapping("invalid_text_part", "OpenCode text part has no text value"))?;
    let role = canonical_role(&record.context)?;
    let body =
        MessageObservation::new(role).with_content(JsonValue::try_from_source_message_text(text)?);
    let mut builder = common_builder(
        record.source_rowid as u64,
        record.source_id.as_deref(),
        &record.context,
        record.occurrence_time.as_deref(),
        ObservationBody::Message(body),
        ObservationStage::MessageObserved,
        observed_at,
    )?;
    builder = builder.fact_metadata("message.role", FactMetadata::reported()?);
    builder = builder.fact_metadata("message.content", FactMetadata::reported()?);
    observations.push(builder.build()?)?;
    Ok(())
}

fn project_tool_part(
    record: &OpenCodeToolPartNativeRecord,
    observed_at: &ObservedAt,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), OpenCodeCanonicalError> {
    if record.tool_state_invalid {
        return Err(mapping(
            "invalid_tool_state",
            "OpenCode tool state is not an object",
        ));
    }
    project_tool(
        record.source_rowid as u64,
        record.source_id.as_deref(),
        &record.context,
        record.tool_name.as_deref(),
        record.call_id.as_deref(),
        Some(&record.state),
        None,
        false,
        None,
        false,
        None,
        false,
        None,
        observed_at,
        observations,
    )
}

#[allow(clippy::too_many_arguments)]
fn project_tool(
    source_sequence: u64,
    source_id: Option<&str>,
    context: &OpenCodeMessageContext,
    tool_name: Option<&str>,
    call_id: Option<&str>,
    state: Option<&OpenCodeToolState>,
    fallback_arguments: Option<&Value>,
    fallback_arguments_present: bool,
    fallback_result: Option<&Value>,
    fallback_result_present: bool,
    fallback_error: Option<&Value>,
    fallback_error_present: bool,
    message_stage: Option<ObservationStage>,
    observed_at: &ObservedAt,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), OpenCodeCanonicalError> {
    let empty_state;
    let state = match state {
        Some(state) => state,
        None => {
            empty_state = OpenCodeToolState {
                status: None,
                status_present: false,
                input: None,
                input_present: false,
                output: None,
                output_present: false,
                error: None,
                error_present: false,
                is_error: None,
                is_error_present: false,
                start_time: None,
                end_time: None,
            };
            &empty_state
        }
    };
    if state.status_present && state.status.is_none() {
        return Err(mapping(
            "invalid_tool_state",
            "OpenCode tool status is not a string",
        ));
    }
    if state.is_error_present && state.is_error.is_none() {
        return Err(mapping(
            "invalid_tool_state",
            "OpenCode tool error state is not boolean",
        ));
    }

    let arguments = state.input.as_ref().or(fallback_arguments);
    let has_arguments = state.input_present || fallback_arguments_present;
    let output = state.output.as_ref().or(fallback_result);
    let has_output = state.output_present || fallback_result_present;
    let error = state.error.as_ref().or(fallback_error);
    let has_error = state.error_present || fallback_error_present;
    let result = output.or(error);
    let has_result = has_output || has_error;
    let explicit_failure =
        state.is_error == Some(true) || state.status.as_deref() == Some("error") || has_error;

    let stages = if let Some(stage) = message_stage {
        vec![stage]
    } else {
        match state.status.as_deref() {
            Some("pending") => vec![ObservationStage::ToolRequested],
            Some("running") => vec![ObservationStage::ToolExecutionStarted],
            Some("completed" | "error" | "cancelled" | "denied") => {
                vec![ObservationStage::ToolExecutionCompleted]
            }
            Some(_) => {
                return Err(mapping(
                    "unknown_tool_status",
                    "OpenCode tool lifecycle status is not supported",
                ));
            }
            None if has_result => vec![ObservationStage::ToolResultReturned],
            None => Vec::new(),
        }
    };

    let mut terminal_stage_emitted = false;
    for stage in stages {
        emit_tool_observation(
            source_sequence,
            source_id,
            context,
            tool_name,
            call_id,
            state,
            arguments,
            has_arguments,
            result,
            has_result,
            explicit_failure,
            stage,
            observed_at,
            observations,
        )?;
        terminal_stage_emitted |= stage == ObservationStage::ToolExecutionCompleted;
    }

    if message_stage.is_none()
        && terminal_stage_emitted
        && has_result
        && matches!(
            state.status.as_deref(),
            Some("completed" | "error" | "cancelled" | "denied")
        )
    {
        emit_tool_observation(
            source_sequence,
            source_id,
            context,
            tool_name,
            call_id,
            state,
            arguments,
            has_arguments,
            result,
            has_result,
            explicit_failure,
            ObservationStage::ToolResultReturned,
            observed_at,
            observations,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_tool_observation(
    source_sequence: u64,
    source_id: Option<&str>,
    context: &OpenCodeMessageContext,
    tool_name: Option<&str>,
    call_id: Option<&str>,
    state: &OpenCodeToolState,
    arguments: Option<&Value>,
    has_arguments: bool,
    result: Option<&Value>,
    has_result: bool,
    explicit_failure: bool,
    stage: ObservationStage,
    observed_at: &ObservedAt,
    observations: &mut crate::acquisition::CanonicalCollector,
) -> Result<(), OpenCodeCanonicalError> {
    let observation = build_fitted(
        ValueBounds::Replace,
        |error| matches!(error, OpenCodeCanonicalError::Observation(error) if error.bound_dimension().is_some()),
        |bounds| {
            tool_observation(
                source_sequence,
                source_id,
                context,
                tool_name,
                call_id,
                state,
                arguments,
                has_arguments,
                result,
                has_result,
                explicit_failure,
                stage,
                observed_at,
                bounds,
            )
        },
    )?;
    observations.push(observation)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn tool_observation(
    source_sequence: u64,
    source_id: Option<&str>,
    context: &OpenCodeMessageContext,
    tool_name: Option<&str>,
    call_id: Option<&str>,
    state: &OpenCodeToolState,
    arguments: Option<&Value>,
    has_arguments: bool,
    result: Option<&Value>,
    has_result: bool,
    explicit_failure: bool,
    stage: ObservationStage,
    observed_at: &ObservedAt,
    bounds: ValueBounds,
) -> Result<CanonicalObservationV2, OpenCodeCanonicalError> {
    let mut body = ToolObservation::new();
    let mut metadata = Vec::new();
    if let Some(name) = tool_name {
        body = body.with_name(name)?;
        metadata.push(("tool.name", FactProvenance::Reported));
    }
    if has_arguments && let Some(arguments) = arguments {
        body = with_source_arguments(super::tools::TOOLS, tool_name, body, arguments, bounds)?;
        metadata.push(("tool.arguments", FactProvenance::Reported));
    }
    if has_result && let Some(result) = result {
        body = with_source_result(body, result, ResultText::Direct, bounds)?;
        metadata.push(("tool.result", FactProvenance::Reported));
    }
    if let Some(is_error) = state.is_error {
        body = body.with_is_error(is_error);
        metadata.push(("tool.is_error", FactProvenance::Reported));
    }

    let status = match state.status.as_deref() {
        Some("error") => Some((ToolStatus::Failed, FactProvenance::Reported)),
        Some("cancelled") => Some((ToolStatus::Cancelled, FactProvenance::Reported)),
        Some("denied") => Some((ToolStatus::Denied, FactProvenance::Reported)),
        Some("completed") if explicit_failure => {
            Some((ToolStatus::Failed, FactProvenance::Reported))
        }
        Some("pending" | "running" | "completed") => None,
        None if explicit_failure => Some((ToolStatus::Failed, FactProvenance::Reported)),
        None => None,
        Some(_) => None,
    };
    if let Some((status, provenance)) = status {
        body = body.with_reported_status(status);
        metadata.push(("tool.reported_status", provenance));
    }

    if stage == ObservationStage::ToolExecutionCompleted
        && state.status.as_deref() == Some("completed")
        && !has_result
        && state.is_error.is_none()
    {
        body = body.with_reported_status(ToolStatus::Unknown);
        metadata.push(("tool.reported_status", FactProvenance::Parsed));
    }
    if matches!(
        stage,
        ObservationStage::ToolRequested | ObservationStage::ToolExecutionStarted
    ) && metadata.is_empty()
    {
        body = body.with_reported_status(ToolStatus::Unknown);
        metadata.push(("tool.reported_status", FactProvenance::Parsed));
    }
    if metadata.is_empty() {
        return Err(mapping(
            "invalid_tool_part",
            "OpenCode tool part has no canonical fact",
        ));
    }

    let occurrence_time = match stage {
        ObservationStage::ToolRequested | ObservationStage::ToolExecutionStarted => state
            .start_time
            .as_deref()
            .or(context.occurrence_time.as_deref()),
        ObservationStage::ToolExecutionCompleted | ObservationStage::ToolResultReturned => state
            .end_time
            .as_deref()
            .or(context.occurrence_time.as_deref()),
        _ => context.occurrence_time.as_deref(),
    };
    // No facet is built from an argument that was replaced.
    let replaced = replaced_arguments(&body, &["command", "cmd", "file_path"]);
    let mut builder = common_builder(
        source_sequence,
        source_id,
        context,
        occurrence_time,
        ObservationBody::Tool(declare(super::tools::TOOLS, body)),
        stage,
        observed_at,
    )?;
    for (path, provenance) in metadata {
        builder = builder.fact_metadata(path, FactMetadata::new(provenance, Sensitivity::Normal)?);
    }

    if let Some(arguments) = arguments {
        builder = with_argument_facets(builder, arguments, &replaced)?;
    }

    if let Some(call_id) = call_id {
        builder = builder.correlation(
            telltale_schema::observation::CorrelationIds::new().with_call_id(
                telltale_schema::observation::CorrelationId::source_reported(call_id)?,
            ),
        );
    }
    Ok(builder.build()?)
}

/// Clear command and file-path arguments become Parsed facets; they never
/// produce File, Process, or Network observations.
pub(super) fn with_argument_facets(
    mut builder: ObservationBuilder,
    arguments: &Value,
    replaced: &[&str],
) -> Result<ObservationBuilder, OpenCodeCanonicalError> {
    let parsed = parsed_argument_view(arguments);
    let view = parsed.as_ref().or(Some(arguments));
    let admitted = |key: &str| !replaced.contains(&key);
    if let Some(command) = argument_string(view, "command")
        .filter(|_| admitted("command"))
        .or_else(|| argument_string(view, "cmd").filter(|_| admitted("cmd")))
    {
        builder = builder
            .facet(
                "command.text",
                SemanticFacet::new(JsonValue::string(command)),
            )?
            .fact_metadata("command.text", FactMetadata::parsed()?);
    }
    if let Some(path) = argument_string(view, "file_path").filter(|_| admitted("file_path")) {
        builder = builder
            .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
            .fact_metadata("resource.path", FactMetadata::parsed()?);
    }
    Ok(builder)
}

fn common_builder(
    source_sequence: u64,
    source_id: Option<&str>,
    context: &OpenCodeMessageContext,
    occurrence_time: Option<&str>,
    body: ObservationBody,
    stage: ObservationStage,
    observed_at: &ObservedAt,
) -> Result<ObservationBuilder, OpenCodeCanonicalError> {
    let mut source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "opencode",
        "opencode.sqlite",
        Fidelity::PartialStructured,
    )?
    .with_source_sequence(source_sequence);
    if let Some(source_id) = source_id {
        source = source.with_native_id(source_id)?;
    }
    let mut builder = CanonicalObservationV2::builder(body, stage, observed_at.clone(), source)
        .sequence(source_sequence)
        .capability_context(capabilities());
    if let Some(session_id) = &context.session_id {
        builder = builder
            .session_id(telltale_schema::observation::CorrelationId::source_reported(session_id)?);
    }
    if let Some(timestamp) = occurrence_time
        && let Ok(timestamp) = SourceTimestamp::new(timestamp)
    {
        builder = builder.occurred_at(timestamp);
    }
    Ok(builder.child_ordinal(0))
}

fn canonical_role(context: &OpenCodeMessageContext) -> Result<MessageRole, OpenCodeCanonicalError> {
    match context.role.as_deref() {
        Some("user") => Ok(MessageRole::User),
        Some("assistant" | "model") => Ok(MessageRole::Assistant),
        Some(_) => Err(mapping(
            "unsupported_role",
            "OpenCode record role is not a user or assistant role",
        )),
        None => Err(mapping(
            "missing_role",
            "OpenCode conversational record has no role",
        )),
    }
}

fn capabilities() -> CapabilityContext {
    CapabilityContext::new()
        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported)
        .with_override(
            CapabilityId::ToolExecution,
            CapabilityAvailability::Supported,
        )
        .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported)
}

fn parsed_argument_view(value: &Value) -> Option<Value> {
    match value {
        Value::Object(_) => Some(value.clone()),
        _ => None,
    }
}

fn argument_string(value: Option<&Value>, key: &str) -> Option<String> {
    value?
        .as_object()?
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn is_message_type(kind: &str) -> bool {
    matches!(
        kind,
        "user" | "assistant" | "user_message" | "assistant_message" | "text" | "gemini" | "model"
    )
}

pub(super) fn mapping(code: &'static str, detail: &'static str) -> OpenCodeCanonicalError {
    OpenCodeCanonicalError::Mapping { code, detail }
}

pub(super) fn require_source_id(value: Option<&str>) -> Result<&str, OpenCodeCanonicalError> {
    value.ok_or_else(|| {
        mapping(
            "replay_unverifiable",
            "OpenCode source identity is unavailable",
        )
    })
}

#[cfg(test)]
mod tests;
