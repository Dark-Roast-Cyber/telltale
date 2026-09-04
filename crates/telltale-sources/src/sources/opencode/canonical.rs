#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fmt;

use serde_json::Value;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId, FactMetadata,
    FactProvenance, Fidelity, IngestionMode, JsonValue, MessageObservation, MessageRole,
    ObservationBody, ObservationBuilder, ObservationError, ObservationStage, ObservedAt,
    SemanticFacet, SourceProvenance, SourceTimestamp, ToolObservation, ToolStatus,
};
use telltale_schema::source::Source;

use super::native::{
    OpenCodeMessageContext, OpenCodeMessageNativeRecord, OpenCodeSqliteNativeRecord,
    OpenCodeTextPartNativeRecord, OpenCodeToolPartNativeRecord, OpenCodeToolState,
    extract_sqlite_native_source,
};
use crate::parser::{ParseError, ParseOptions};

#[derive(Clone)]
pub(crate) struct OpenCodeCanonicalOptions {
    pub(crate) observed_at: ObservedAt,
    pub(crate) parse_options: ParseOptions,
}

impl OpenCodeCanonicalOptions {
    pub(crate) fn new(observed_at: ObservedAt) -> Self {
        Self {
            observed_at,
            parse_options: ParseOptions::default(),
        }
    }

    pub(crate) fn with_parse_options(mut self, parse_options: ParseOptions) -> Self {
        self.parse_options = parse_options;
        self
    }
}

pub(crate) enum OpenCodeCanonicalError {
    Source(ParseError),
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl OpenCodeCanonicalError {
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

impl fmt::Debug for OpenCodeCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("OpenCodeCanonicalError::Source")
            }
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
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("OpenCode source could not be parsed")
            }
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

impl From<ParseError> for OpenCodeCanonicalError {
    fn from(error: ParseError) -> Self {
        Self::Source(error)
    }
}

impl From<ObservationError> for OpenCodeCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

pub(crate) fn project_opencode_canonical_observations(
    source: &Source,
    options: OpenCodeCanonicalOptions,
) -> Result<Vec<CanonicalObservationV2>, OpenCodeCanonicalError> {
    if source.client != ClientId::OpenCode || source.source_id != "opencode.sqlite" {
        return Err(mapping(
            "unsupported_source_identity",
            "canonical projection requires the OpenCode SQLite source",
        ));
    }
    if source.kind != SourceKind::Sqlite {
        return Err(mapping(
            "unsupported_source_kind",
            "canonical projection requires SQLite input",
        ));
    }

    let extraction = extract_sqlite_native_source(source, options.parse_options)?;
    let part_message_ids = extraction
        .records
        .iter()
        .filter_map(|record| match record {
            OpenCodeSqliteNativeRecord::Text(record) => record.message_id.as_deref(),
            OpenCodeSqliteNativeRecord::Tool(record) => record.message_id.as_deref(),
            OpenCodeSqliteNativeRecord::Message(_) => None,
        })
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    let mut observations = Vec::new();
    for record in &extraction.records {
        match record {
            OpenCodeSqliteNativeRecord::Message(record)
                if record
                    .source_id
                    .as_deref()
                    .is_some_and(|id| part_message_ids.contains(id)) => {}
            OpenCodeSqliteNativeRecord::Message(record) => {
                require_source_id(record.source_id.as_deref())?;
                project_message(record, &options, &mut observations)?;
            }
            OpenCodeSqliteNativeRecord::Text(record) => {
                require_source_id(record.source_id.as_deref())?;
                project_text_part(record, &options, &mut observations)?;
            }
            OpenCodeSqliteNativeRecord::Tool(record) => {
                require_source_id(record.source_id.as_deref())?;
                project_tool_part(record, &options, &mut observations)?;
            }
        }
    }
    Ok(observations)
}

fn project_message(
    record: &OpenCodeMessageNativeRecord,
    options: &OpenCodeCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
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
            options,
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
    body = body.with_content(value_to_json(record.content.as_ref().expect("checked"))?);
    let mut builder = common_builder(
        record.source_sequence,
        record.source_id.as_deref(),
        &record.context,
        record.context.occurrence_time.as_deref(),
        ObservationBody::Message(body),
        ObservationStage::MessageObserved,
        options,
    )?;
    builder = builder.fact_metadata("message.role", normal_reported()?);
    builder = builder.fact_metadata("message.content", normal_reported()?);
    observations.push(builder.build()?);
    Ok(())
}

fn project_text_part(
    record: &OpenCodeTextPartNativeRecord,
    options: &OpenCodeCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), OpenCodeCanonicalError> {
    let text = record
        .text
        .as_deref()
        .ok_or_else(|| mapping("invalid_text_part", "OpenCode text part has no text value"))?;
    let role = canonical_role(&record.context)?;
    let body = MessageObservation::new(role).with_content(JsonValue::string(text));
    let mut builder = common_builder(
        record.source_rowid as u64,
        record.source_id.as_deref(),
        &record.context,
        record.occurrence_time.as_deref(),
        ObservationBody::Message(body),
        ObservationStage::MessageObserved,
        options,
    )?;
    builder = builder.fact_metadata("message.role", normal_reported()?);
    builder = builder.fact_metadata("message.content", normal_reported()?);
    observations.push(builder.build()?);
    Ok(())
}

fn project_tool_part(
    record: &OpenCodeToolPartNativeRecord,
    options: &OpenCodeCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
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
        options,
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
    options: &OpenCodeCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
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
            options,
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
            options,
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
    options: &OpenCodeCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), OpenCodeCanonicalError> {
    let mut body = ToolObservation::new();
    let mut metadata = Vec::new();
    if let Some(name) = tool_name {
        body = body.with_name(name)?;
        metadata.push(("tool.name", FactProvenance::Reported));
    }
    if has_arguments && let Some(arguments) = arguments {
        body = body.with_arguments(value_to_json(arguments)?);
        metadata.push(("tool.arguments", FactProvenance::Reported));
    }
    if has_result && let Some(result) = result {
        body = body.with_result(value_to_json(result)?);
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
    let mut builder = common_builder(
        source_sequence,
        source_id,
        context,
        occurrence_time,
        ObservationBody::Tool(body),
        stage,
        options,
    )?;
    for (path, provenance) in metadata {
        builder = builder.fact_metadata(path, normal(provenance)?);
    }

    if let Some(arguments) = arguments {
        let parsed = parsed_argument_view(arguments);
        if let Some(command) = argument_string(parsed.as_ref().or(Some(arguments)), "command")
            .or_else(|| argument_string(parsed.as_ref().or(Some(arguments)), "cmd"))
        {
            builder = builder
                .facet(
                    "command.text",
                    SemanticFacet::new(JsonValue::string(command)),
                )?
                .fact_metadata("command.text", normal(FactProvenance::Parsed)?);
        }
        if let Some(path) = argument_string(parsed.as_ref().or(Some(arguments)), "file_path") {
            builder = builder
                .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
                .fact_metadata("resource.path", normal(FactProvenance::Parsed)?);
        }
    }

    if let Some(call_id) = call_id {
        builder = builder.correlation(
            telltale_schema::observation::CorrelationIds::new().with_call_id(
                telltale_schema::observation::CorrelationId::source_reported(call_id)?,
            ),
        );
    }
    observations.push(builder.build()?);
    Ok(())
}

fn common_builder(
    source_sequence: u64,
    source_id: Option<&str>,
    context: &OpenCodeMessageContext,
    occurrence_time: Option<&str>,
    body: ObservationBody,
    stage: ObservationStage,
    options: &OpenCodeCanonicalOptions,
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
    let mut builder =
        CanonicalObservationV2::builder(body, stage, options.observed_at.clone(), source)
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

fn normal_reported() -> Result<FactMetadata, OpenCodeCanonicalError> {
    normal(FactProvenance::Reported)
}

fn normal(provenance: FactProvenance) -> Result<FactMetadata, OpenCodeCanonicalError> {
    Ok(match provenance {
        FactProvenance::Reported => FactMetadata::reported()?,
        FactProvenance::Parsed => FactMetadata::parsed()?,
        _ => FactMetadata::new(
            provenance,
            telltale_schema::observation::Sensitivity::Normal,
        )?,
    })
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

fn value_to_json(value: &Value) -> Result<JsonValue, OpenCodeCanonicalError> {
    Ok(JsonValue::try_from_source_value(value)?)
}

fn is_message_type(kind: &str) -> bool {
    matches!(
        kind,
        "user" | "assistant" | "user_message" | "assistant_message" | "text" | "gemini" | "model"
    )
}

fn mapping(code: &'static str, detail: &'static str) -> OpenCodeCanonicalError {
    OpenCodeCanonicalError::Mapping { code, detail }
}

fn require_source_id(value: Option<&str>) -> Result<&str, OpenCodeCanonicalError> {
    value.ok_or_else(|| {
        mapping(
            "replay_unverifiable",
            "OpenCode source identity is unavailable",
        )
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::{
        CapabilityAvailability, CapabilityId, Fidelity, IngestionMode, JsonValue, MessageRole,
        ObservationBody, ObservationFamily, ObservationStage, ObservedAt, ToolStatus,
    };
    use telltale_schema::source::Source;
    use tempfile::tempdir;

    use super::{OpenCodeCanonicalOptions, project_opencode_canonical_observations};
    use crate::parser::{ParseOptions, parse_source_records};

    const OBSERVED_AT: &str = "2026-09-03T12:00:00Z";

    fn source(path: std::path::PathBuf) -> Source {
        Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_owned(),
            path,
        }
    }

    fn project(
        path: std::path::PathBuf,
    ) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
        project_opencode_canonical_observations(
            &source(path),
            OpenCodeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect("canonical observations")
    }

    fn database(schema: &str) -> (tempfile::TempDir, Connection, Source) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("synthetic-opencode.db");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(schema).unwrap();
        let source = source(path);
        (directory, connection, source)
    }

    fn message_schema() -> &'static str {
        "create table message (id text, session_id text, time_created integer, time_updated integer, data text);"
    }

    fn part_schema() -> &'static str {
        "create table message (id text, session_id text, time_created integer, time_updated integer, data text);
         create table part (id text, message_id text, session_id text, time_created integer, time_updated integer, data text);"
    }

    fn insert_part(
        connection: &Connection,
        id: &str,
        message_id: &str,
        updated: i64,
        data: serde_json::Value,
    ) {
        connection
            .execute(
                "insert into part (id, message_id, session_id, time_created, time_updated, data) values (?1, ?2, ?3, ?4, ?5, ?6)",
                (id, message_id, "sqlite-test-session", updated, updated, data.to_string()),
            )
            .unwrap();
    }

    #[test]
    fn text_parts_use_joined_role_without_an_envelope_duplicate() {
        let (_directory, connection, source) = database(part_schema());
        connection
            .execute(
                "insert into message values (?1, ?2, ?3, ?4, ?5)",
                (
                    "message-text",
                    "sqlite-session",
                    1_000_i64,
                    9_999_i64,
                    r#"{"role":"assistant","modelID":"fixture-model"}"#,
                ),
            )
            .unwrap();
        insert_part(
            &connection,
            "part-text",
            "message-text",
            2_000,
            serde_json::json!({"type":"text","text":"Synthetic text","time":{"start":1775000000000_i64}}),
        );
        let observations = project(source.path);
        assert_eq!(observations.len(), 1);
        let ObservationBody::Message(message) = observations[0].body() else {
            panic!("expected message")
        };
        assert_eq!(message.role(), Some(MessageRole::Assistant));
        assert_eq!(
            message.content(),
            Some(&JsonValue::string("Synthetic text"))
        );
        assert_eq!(observations[0].identity_basis().child_ordinal(), 0);
        assert_eq!(observations[0].source().native_id(), Some("part-text"));
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "sqlite-test-session"
        );
        assert_eq!(
            observations[0].occurred_at().unwrap().as_str(),
            "2026-03-31T23:33:20Z"
        );
    }

    #[test]
    fn canonical_projection_preserves_part_cursor_and_limit() {
        let (_directory, connection, source) = database(part_schema());
        connection
            .execute(
                "insert into message values (?1, ?2, ?3, ?4, ?5)",
                (
                    "message-cursor",
                    "sqlite-session",
                    1_000_i64,
                    1_000_i64,
                    r#"{"role":"assistant"}"#,
                ),
            )
            .unwrap();
        insert_part(
            &connection,
            "part-old",
            "message-cursor",
            1_000,
            serde_json::json!({"type":"text","text":"old"}),
        );
        insert_part(
            &connection,
            "part-new",
            "message-cursor",
            2_000,
            serde_json::json!({"type":"text","text":"new"}),
        );

        let observations = project_opencode_canonical_observations(
            &source,
            OpenCodeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap())
                .with_parse_options(ParseOptions {
                    sqlite_part_min_time_updated: Some(1_001),
                    sqlite_part_limit: 1,
                }),
        )
        .unwrap();
        assert_eq!(observations.len(), 1);
        let ObservationBody::Message(message) = observations[0].body() else {
            panic!("expected message")
        };
        assert_eq!(message.content(), Some(&JsonValue::string("new")));
        assert_eq!(observations[0].source().native_id(), Some("part-new"));
    }

    #[test]
    fn native_ids_ignore_content_path_rowid_and_cursor_time() {
        let (_first_dir, first, first_source) = database(part_schema());
        let (_second_dir, second, second_source) = database(part_schema());
        for connection in [&first, &second] {
            connection
                .execute(
                    "insert into message values (?1, ?2, ?3, ?4, ?5)",
                    (
                        "message-context",
                        "sqlite-test-session",
                        1_000_i64,
                        1_000_i64,
                        r#"{"role":"assistant"}"#,
                    ),
                )
                .unwrap();
        }
        for (connection, id, text, updated) in [
            (&first, "part-stable", "first content", 10_i64),
            (&second, "part-stable", "changed content", 20_i64),
        ] {
            insert_part(
                connection,
                id,
                "message-context",
                updated,
                serde_json::json!({"type":"text","text":text}),
            );
        }
        let left = project(first_source.path);
        let right = project(second_source.path);
        assert_eq!(left[0].observation_id(), right[0].observation_id());
        assert_ne!(
            left[0]
                .semantic_comparison()
                .compare(right[0].semantic_comparison()),
            telltale_schema::observation::SemanticReplayVerdict::Equivalent
        );
        assert_eq!(left[0].source().native_id(), Some("part-stable"));
        assert_eq!(right[0].source().native_id(), Some("part-stable"));
        assert_eq!(left[0].identity_basis().child_ordinal(), 0);
        assert_eq!(right[0].identity_basis().child_ordinal(), 0);
    }

    #[test]
    fn missing_part_id_fails_closed_without_content_substitution() {
        let (_directory, connection, source) = database(part_schema());
        connection
            .execute(
                "insert into message values (?1, ?2, ?3, ?4, ?5)",
                (
                    "message-context",
                    "sqlite-test-session",
                    1_000_i64,
                    1_000_i64,
                    r#"{"role":"assistant"}"#,
                ),
            )
            .unwrap();
        insert_part(
            &connection,
            "",
            "message-context",
            1,
            serde_json::json!({"type":"text","text":"Synthetic secret marker"}),
        );
        let error = project_opencode_canonical_observations(
            &source,
            OpenCodeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "replay_unverifiable");
        assert!(!error.to_string().contains("Synthetic secret marker"));
        assert!(parse_source_records(&source).is_ok());
    }

    #[test]
    fn tool_states_emit_only_the_directly_reported_lifecycle() {
        let (_directory, connection, source) = database(part_schema());
        for (id, status, extra) in [
            (
                "part-pending",
                "pending",
                serde_json::json!({"input":{"command":"echo pending"}}),
            ),
            (
                "part-running",
                "running",
                serde_json::json!({"input":{"command":"echo running"},"time":{"start":1775000000000_i64}}),
            ),
            (
                "part-completed",
                "completed",
                serde_json::json!({"input":{"command":"echo complete"},"output":{"ok":true},"time":{"start":1775000000000_i64,"end":1775000001000_i64}}),
            ),
            (
                "part-error",
                "error",
                serde_json::json!({"error":{"message":"Synthetic failure"}}),
            ),
        ] {
            insert_part(
                &connection,
                id,
                "missing-message",
                id.len() as i64,
                serde_json::Value::Object(serde_json::json!({"type":"tool","tool":"shell","callID":id,"state":{"status":status}}).as_object().unwrap().iter().chain(extra.as_object().unwrap().iter()).map(|(k,v)| (k.clone(),v.clone())).collect::<serde_json::Map<_,_>>()),
            );
        }
        let observations = project(source.path);
        assert_eq!(
            observations
                .iter()
                .filter(|item| item.stage() == ObservationStage::ToolRequested)
                .count(),
            1
        );
        assert_eq!(
            observations
                .iter()
                .filter(|item| item.stage() == ObservationStage::ToolExecutionStarted)
                .count(),
            1
        );
        assert_eq!(
            observations
                .iter()
                .filter(|item| item.stage() == ObservationStage::ToolExecutionCompleted)
                .count(),
            2
        );
        assert_eq!(
            observations
                .iter()
                .filter(|item| item.stage() == ObservationStage::ToolResultReturned)
                .count(),
            2
        );
        assert!(
            observations
                .iter()
                .all(|item| item.stage() != ObservationStage::ToolProposed)
        );
        assert!(observations.iter().all(|item| item.stage()
            != ObservationStage::ToolExecutionCompleted
            || item.body().kind() == ObservationFamily::Tool));
        let completed = observations
            .iter()
            .find(|item| {
                item.source().native_id() == Some("part-completed")
                    && item.stage() == ObservationStage::ToolExecutionCompleted
            })
            .unwrap();
        let ObservationBody::Tool(tool) = completed.body() else {
            panic!("expected tool")
        };
        assert_eq!(tool.reported_status(), None);
        assert_eq!(
            tool.result(),
            Some(&JsonValue::object([(String::from("ok"), JsonValue::Bool(true))]).unwrap())
        );
        let error = observations
            .iter()
            .find(|item| {
                item.source().native_id() == Some("part-error")
                    && item.stage() == ObservationStage::ToolExecutionCompleted
            })
            .unwrap();
        let ObservationBody::Tool(tool) = error.body() else {
            panic!("expected tool")
        };
        assert_eq!(tool.reported_status(), Some(ToolStatus::Failed));
        assert_eq!(
            tool.result(),
            Some(
                &JsonValue::object([(
                    String::from("message"),
                    JsonValue::string("Synthetic failure")
                )])
                .unwrap()
            )
        );
    }

    #[test]
    fn source_json_string_arguments_remain_strings_without_parsed_facets() {
        let (_directory, connection, source) = database(part_schema());
        let encoded_arguments = r#"{"command":"printf synthetic","file_path":"synthetic.txt","url":"https://example.invalid"}"#;
        insert_part(
            &connection,
            "part-string-arguments",
            "missing-message",
            1,
            serde_json::json!({
                "type": "tool",
                "tool": "shell",
                "state": {"status": "pending", "input": encoded_arguments}
            }),
        );

        let observations = project(source.path);
        assert_eq!(observations.len(), 1);
        let ObservationBody::Tool(tool) = observations[0].body() else {
            panic!("expected tool observation")
        };
        assert_eq!(
            tool.arguments(),
            Some(&JsonValue::string(encoded_arguments))
        );
        assert!(!observations[0].facets().contains_key("command.text"));
        assert!(!observations[0].facets().contains_key("resource.path"));
        assert!(!observations[0].facets().contains_key("network.destination"));
        assert!(
            observations
                .iter()
                .all(|item| item.kind() != ObservationFamily::Network)
        );
    }

    #[test]
    fn missing_tool_status_does_not_fabricate_a_request() {
        let (_directory, connection, source) = database(part_schema());
        insert_part(
            &connection,
            "part-missing-status",
            "missing-message",
            1,
            serde_json::json!({
                "type": "tool",
                "tool": "shell",
                "state": {"input": {"command": "printf synthetic"}}
            }),
        );

        let observations = project(source.path);
        assert!(observations.is_empty());
    }

    #[test]
    fn empty_or_ambiguous_tool_status_fails_closed_without_a_request() {
        for (index, status) in ["", "queued"].into_iter().enumerate() {
            let (_directory, connection, source) = database(part_schema());
            insert_part(
                &connection,
                &format!("part-invalid-status-{index}"),
                "missing-message",
                index as i64 + 1,
                serde_json::json!({
                    "type": "tool",
                    "tool": "shell",
                    "state": {"status": status}
                }),
            );

            let error = project_opencode_canonical_observations(
                &source,
                OpenCodeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
            )
            .unwrap_err();
            assert_eq!(error.code(), "unknown_tool_status");
        }
    }

    #[test]
    fn malformed_tool_state_fails_closed_without_leaking_source_values() {
        let (_directory, connection, source) = database(part_schema());
        insert_part(
            &connection,
            "part-invalid-state",
            "missing-message",
            1,
            serde_json::json!({
                "type":"tool",
                "tool":"shell",
                "state":"Synthetic malformed state"
            }),
        );

        let error = project_opencode_canonical_observations(
            &source,
            OpenCodeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "invalid_tool_state");
        assert!(!error.to_string().contains("Synthetic malformed state"));
    }

    #[test]
    fn terminal_pair_reuses_native_id_and_child_zero_with_structured_values_and_facets() {
        let (_directory, connection, source) = database(part_schema());
        insert_part(
            &connection,
            "part-terminal",
            "missing-message",
            1,
            serde_json::json!({
                "type":"tool","tool":"shell","callID":"call-terminal",
                "state":{"status":"completed","input":{"command":"git status","file_path":"synthetic.txt"},"output":{"status":"ok"}}
            }),
        );
        let observations = project(source.path);
        assert_eq!(observations.len(), 2);
        assert_ne!(
            observations[0].observation_id(),
            observations[1].observation_id()
        );
        assert_eq!(observations[0].source().native_id(), Some("part-terminal"));
        assert_eq!(observations[1].source().native_id(), Some("part-terminal"));
        assert_eq!(observations[0].identity_basis().child_ordinal(), 0);
        assert_eq!(observations[1].identity_basis().child_ordinal(), 0);
        assert_eq!(
            observations[0].correlation().call_id().unwrap().value(),
            "call-terminal"
        );
        assert_eq!(
            observations[1].correlation().call_id().unwrap().origin(),
            telltale_schema::observation::CorrelationOrigin::SourceReported
        );
        assert_eq!(
            observations[0].facets()["command.text"].value(),
            &JsonValue::string("git status")
        );
        assert_eq!(
            observations[0].facets()["resource.path"].value(),
            &JsonValue::string("synthetic.txt")
        );
        assert!(observations.iter().all(|item| !matches!(
            item.kind(),
            ObservationFamily::File | ObservationFamily::Process | ObservationFamily::Network
        )));
    }

    #[test]
    fn message_only_rows_map_content_and_keep_session_source_reported() {
        let (_directory, connection, source) = database(message_schema());
        connection
            .execute(
                "insert into message values (?1, ?2, ?3, ?4, ?5)",
                (
                    "message-only",
                    "message-session",
                    1_000_i64,
                    50_000_i64,
                    r#"{"type":"user","time":"2026-04-27T12:00:00Z","content":"Synthetic prompt"}"#,
                ),
            )
            .unwrap();
        let observations = project(source.path);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].source().native_id(), Some("message-only"));
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "message-session"
        );
        assert_eq!(observations[0].observed_at().as_str(), OBSERVED_AT);
        assert_eq!(
            observations[0].occurred_at().unwrap().as_str(),
            "2026-04-27T12:00:00Z"
        );
    }

    #[test]
    fn provenance_capabilities_and_missing_call_id_are_explicit() {
        let (_directory, connection, source) = database(part_schema());
        insert_part(
            &connection,
            "part-no-call",
            "missing-message",
            1,
            serde_json::json!({"type":"tool","tool":"shell","state":{"status":"pending","input":{"command":"printf synthetic"}}}),
        );
        let observations = project(source.path);
        let observation = &observations[0];
        assert_eq!(observation.correlation().call_id(), None);
        assert_eq!(
            observation.source().ingestion_mode(),
            IngestionMode::SessionStore
        );
        assert_eq!(observation.source().adapter_type(), "opencode");
        assert_eq!(observation.source().adapter_id(), "opencode.sqlite");
        assert_eq!(observation.source().adapter_version(), None);
        assert_eq!(observation.source().source_path_hash(), None);
        assert_eq!(observation.source().fidelity(), Fidelity::PartialStructured);
        let capabilities = observation.capability_context().unwrap();
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
            CapabilityAvailability::Supported
        );
    }

    #[test]
    fn empty_source_session_is_omitted_instead_of_reported() {
        let (_directory, connection, source) = database(part_schema());
        connection
            .execute(
                "insert into part values (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    "part-empty-session",
                    "missing-message",
                    "",
                    1_i64,
                    1_i64,
                    serde_json::json!({
                        "type":"tool",
                        "tool":"shell",
                        "state":{"status":"pending"}
                    })
                    .to_string(),
                ),
            )
            .unwrap();

        let observations = project(source.path);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].session_id(), None);
    }
}
