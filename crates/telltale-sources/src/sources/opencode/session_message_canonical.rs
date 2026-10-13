//! Canonical Observation v2 mapping for OpenCode v2 `session_message` rows.
//!
//! Observation identity is the row's `id` (`source.native_id`) and, inside an
//! assistant message, the entry's `content` index (`child_ordinal`). Neither
//! rowid, `seq`, `time_updated`, path nor content enters identity, so a message
//! and its tool children keep their identities across relocation, vacuum and
//! in-place lifecycle updates.

use std::collections::BTreeSet;

use serde_json::Value;
use telltale_schema::observation::{
    CanonicalFieldCategory, CanonicalObservationV2, CapabilityAvailability, CapabilityContext,
    CapabilityId, CorrelationId, CorrelationIds, FactProvenance, Fidelity, IngestionMode,
    JsonValue, MessageObservation, MessageRole, ObservationBody, ObservationBuilder,
    ObservationStage, ObservedAt, SemanticFacet, SourceProvenance, SourceTimestamp,
    ToolObservation, ToolStatus,
};

use super::canonical::{
    OpenCodeCanonicalError, mapping, normal, normal_reported, require_source_id,
    with_argument_facets,
};
use super::session_message::{
    OpenCodeAssistantContent, OpenCodeAssistantTool, OpenCodeSessionMessageBody,
    OpenCodeSessionMessageRecord, OpenCodeShell, OpenCodeShellStatus, OpenCodeToolStatus,
    SHELL_TOOL_NAME,
};
use crate::acquisition::CanonicalCollector;

pub(crate) fn project_opencode_session_messages(
    records: &[OpenCodeSessionMessageRecord],
    observed_at: &ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, OpenCodeCanonicalError> {
    let mut identities = BTreeSet::new();
    let mut observations = CanonicalCollector::default();
    for record in records {
        let id = require_source_id(record.source_id.as_deref())?;
        if !identities.insert(id) {
            return Err(mapping(
                "ambiguous_source_identity",
                "OpenCode session message identity is not unique",
            ));
        }
        let context = Context {
            record,
            id,
            session: record.session_id.as_deref().ok_or_else(|| {
                mapping(
                    "missing_session_id",
                    "OpenCode session message has no source session",
                )
            })?,
            observed_at,
        };
        match &record.body {
            OpenCodeSessionMessageBody::User { text } => {
                context.message(MessageRole::User, text.as_deref(), 0, &mut observations)?;
            }
            OpenCodeSessionMessageBody::Assistant { content } => {
                let content = content.as_deref().ok_or_else(|| {
                    mapping(
                        "invalid_assistant_content",
                        "OpenCode assistant content is not an array",
                    )
                })?;
                for (index, entry) in content.iter().enumerate() {
                    let child = u32::try_from(index).map_err(|_| {
                        mapping(
                            "child_ordinal_overflow",
                            "too many observations in OpenCode message",
                        )
                    })?;
                    match entry {
                        OpenCodeAssistantContent::Text(text) => context.message(
                            MessageRole::Assistant,
                            text.as_deref(),
                            child,
                            &mut observations,
                        )?,
                        OpenCodeAssistantContent::Reasoning => {}
                        OpenCodeAssistantContent::Tool(tool) => {
                            context.tool(tool, child, &mut observations)?;
                        }
                        OpenCodeAssistantContent::Unsupported => {
                            return Err(mapping(
                                "unknown_content_variant",
                                "OpenCode assistant content variant is not supported",
                            ));
                        }
                    }
                }
            }
            OpenCodeSessionMessageBody::Shell(shell) => context.shell(shell, &mut observations)?,
            OpenCodeSessionMessageBody::Auxiliary(_) => {}
            OpenCodeSessionMessageBody::Unsupported => {
                return Err(mapping(
                    "unknown_message_variant",
                    "OpenCode message variant is not supported",
                ));
            }
        }
    }
    Ok(observations.finish())
}

struct Context<'a> {
    record: &'a OpenCodeSessionMessageRecord,
    id: &'a str,
    session: &'a str,
    observed_at: &'a ObservedAt,
}

impl Context<'_> {
    fn message(
        &self,
        role: MessageRole,
        text: Option<&str>,
        child: u32,
        observations: &mut CanonicalCollector,
    ) -> Result<(), OpenCodeCanonicalError> {
        let text = text.ok_or_else(|| {
            mapping(
                "invalid_message_text",
                "OpenCode message text is not a string",
            )
        })?;
        let body = MessageObservation::new(role)
            .with_content(JsonValue::try_from_source_message_text(text)?);
        let builder = self
            .builder(
                ObservationBody::Message(body),
                ObservationStage::MessageObserved,
                child,
                self.record.occurrence_time.as_deref(),
                CapabilityAvailability::Unknown,
            )?
            .fact_metadata("message.role", normal_reported()?)
            .fact_metadata("message.content", normal_reported()?);
        observations.push(builder.build()?)?;
        Ok(())
    }

    /// One content entry records the model's tool request and, once terminal,
    /// its outcome. The request is always its own observation; the outcome is
    /// `ToolResultReturned`. Execution stages need source evidence: the entry
    /// reports `executed: true`, or a completed `shell` tool reports how its
    /// command settled. `executed: false` and absence make no claim by
    /// themselves, and error or running entries never gain one from metadata.
    fn tool(
        &self,
        tool: &OpenCodeAssistantTool,
        child: u32,
        observations: &mut CanonicalCollector,
    ) -> Result<(), OpenCodeCanonicalError> {
        let call_id = tool
            .id
            .as_deref()
            .ok_or_else(|| mapping("missing_tool_id", "OpenCode tool entry has no source id"))?;
        let name = tool
            .name
            .as_deref()
            .ok_or_else(|| mapping("missing_tool_name", "OpenCode tool entry has no name"))?;
        if tool.malformed {
            return Err(mapping(
                "invalid_tool_state",
                "OpenCode tool entry state is malformed",
            ));
        }
        if tool.status == OpenCodeToolStatus::Unsupported {
            return Err(mapping(
                "unknown_tool_status",
                "OpenCode tool lifecycle status is not supported",
            ));
        }
        let mut stages = vec![(ObservationStage::ToolRequested, tool.created.as_deref())];
        let reported_completion =
            tool.executed == Some(true) && tool.status.is_terminal() && tool.ran.is_some();
        if tool.executed == Some(true) && tool.status == OpenCodeToolStatus::Running {
            stages.push((ObservationStage::ToolExecutionStarted, tool.ran.as_deref()));
        } else if reported_completion || tool.shell_settlement.is_some() {
            stages.push((
                ObservationStage::ToolExecutionCompleted,
                tool.completed.as_deref(),
            ));
        }
        if tool.status.is_terminal() {
            stages.push((
                ObservationStage::ToolResultReturned,
                tool.completed.as_deref(),
            ));
        }
        for (stage, occurred_at) in stages {
            let outcome = matches!(
                stage,
                ObservationStage::ToolExecutionCompleted | ObservationStage::ToolResultReturned
            );
            let mut body = ToolObservation::new().with_name(name)?;
            let mut metadata = vec![("tool.name", FactProvenance::Reported)];
            if let Some(input) = &tool.input {
                body = body.with_arguments(arguments(Some(name), input)?);
                metadata.push(("tool.arguments", FactProvenance::Reported));
            }
            if outcome && let Some(result) = &tool.result {
                body = body.with_result(tool_result(result)?);
                metadata.push(("tool.result", FactProvenance::Reported));
            }
            let settlement = tool.shell_settlement.as_ref().filter(|_| outcome);
            if let Some(exit) = settlement.and_then(|settlement| settlement.exit) {
                body = body.with_exit_code(exit);
                metadata.push(("tool.exit_code", FactProvenance::Reported));
            }
            // An exit code alone is neither success nor failure; a reported
            // timeout fails the call like a timed-out user shell command.
            if outcome
                && (tool.status == OpenCodeToolStatus::Error
                    || settlement.is_some_and(|settlement| settlement.timeout))
            {
                body = body.with_reported_status(ToolStatus::Failed);
                metadata.push(("tool.reported_status", FactProvenance::Reported));
            }
            let mut builder = self.builder(
                ObservationBody::Tool(body),
                stage,
                child,
                occurred_at,
                CapabilityAvailability::Unknown,
            )?;
            for (path, provenance) in metadata {
                builder = builder.fact_metadata(path, normal(provenance)?);
            }
            if let Some(Value::Object(_)) = &tool.input {
                builder = with_argument_facets(builder, tool.input.as_ref().expect("checked"))?;
            }
            if let Some(executed) = tool.executed {
                builder = builder
                    .facet(
                        "tool.executed",
                        SemanticFacet::new(JsonValue::Bool(executed)),
                    )?
                    .fact_metadata("tool.executed", normal_reported()?);
            }
            if let Some(signal) = settlement.and_then(|settlement| settlement.signal.as_deref()) {
                builder = builder
                    .facet("tool.signal", SemanticFacet::new(JsonValue::string(signal)))?
                    .fact_metadata("tool.signal", normal_reported()?);
            }
            builder = builder.correlation(
                CorrelationIds::new().with_call_id(CorrelationId::source_reported(call_id)?),
            );
            observations.push(builder.build()?)?;
        }
        Ok(())
    }

    /// A user-initiated harness shell command. OpenCode's shell service reports
    /// its start, status, exit code and output; no process, file or network
    /// observation is derived from them.
    fn shell(
        &self,
        shell: &OpenCodeShell,
        observations: &mut CanonicalCollector,
    ) -> Result<(), OpenCodeCanonicalError> {
        if shell.malformed {
            return Err(mapping(
                "invalid_shell_state",
                "OpenCode shell message is malformed",
            ));
        }
        let status = match shell.status {
            OpenCodeShellStatus::Running | OpenCodeShellStatus::Exited => None,
            OpenCodeShellStatus::Timeout => Some(ToolStatus::Failed),
            OpenCodeShellStatus::Killed => Some(ToolStatus::Cancelled),
            OpenCodeShellStatus::Unsupported => {
                return Err(mapping(
                    "unknown_shell_status",
                    "OpenCode shell status is not supported",
                ));
            }
        };
        let command = shell.command.as_deref().expect("malformed without command");
        let mut stages = vec![(
            ObservationStage::ToolExecutionStarted,
            shell.created.as_deref(),
        )];
        if shell.is_terminal() {
            stages.push((
                ObservationStage::ToolExecutionCompleted,
                shell.completed.as_deref(),
            ));
            if shell.output.is_some() {
                stages.push((
                    ObservationStage::ToolResultReturned,
                    shell.completed.as_deref(),
                ));
            }
        }
        for (stage, occurred_at) in stages {
            let outcome = stage != ObservationStage::ToolExecutionStarted;
            let mut body = ToolObservation::new()
                .with_name(SHELL_TOOL_NAME)?
                .with_arguments(arguments(
                    Some(SHELL_TOOL_NAME),
                    &Value::String(command.to_owned()),
                )?);
            let mut metadata = vec![
                ("tool.name", FactProvenance::Parsed),
                ("tool.arguments", FactProvenance::Reported),
            ];
            if outcome {
                if let Some(output) = &shell.output {
                    body = body.with_result(tool_result(&Value::String(output.clone()))?);
                    metadata.push(("tool.result", FactProvenance::Reported));
                }
                if let Some(exit) = shell.exit {
                    body = body.with_exit_code(exit);
                    metadata.push(("tool.exit_code", FactProvenance::Reported));
                }
                if let Some(status) = status {
                    body = body.with_reported_status(status);
                    metadata.push(("tool.reported_status", FactProvenance::Reported));
                }
            }
            let mut builder = self.builder(
                ObservationBody::Tool(body),
                stage,
                0,
                occurred_at,
                CapabilityAvailability::Supported,
            )?;
            for (path, provenance) in metadata {
                builder = builder.fact_metadata(path, normal(provenance)?);
            }
            builder = builder
                .facet(
                    "command.text",
                    SemanticFacet::new(JsonValue::string(command)),
                )?
                .fact_metadata("command.text", normal_reported()?);
            if let Some(shell_id) = &shell.shell_id {
                builder = builder.correlation(
                    CorrelationIds::new().with_call_id(CorrelationId::source_reported(shell_id)?),
                );
            }
            observations.push(builder.build()?)?;
        }
        Ok(())
    }

    fn builder(
        &self,
        body: ObservationBody,
        stage: ObservationStage,
        child: u32,
        occurred_at: Option<&str>,
        tool_execution: CapabilityAvailability,
    ) -> Result<ObservationBuilder, OpenCodeCanonicalError> {
        let source = SourceProvenance::new(
            IngestionMode::SessionStore,
            "opencode",
            "opencode.sqlite",
            Fidelity::PartialStructured,
        )?
        .with_source_sequence(self.record.seq)
        .with_native_id(self.id)?;
        let mut builder =
            CanonicalObservationV2::builder(body, stage, self.observed_at.clone(), source)
                .sequence(self.record.seq)
                .capability_context(
                    CapabilityContext::new()
                        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported)
                        .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported)
                        .with_override(CapabilityId::ToolExecution, tool_execution),
                )
                .session_id(CorrelationId::source_reported(self.session)?);
        if let Some(timestamp) = occurred_at
            && let Ok(timestamp) = SourceTimestamp::new(timestamp)
        {
            builder = builder.occurred_at(timestamp);
        }
        Ok(builder.child_ordinal(child))
    }
}

fn arguments(name: Option<&str>, value: &Value) -> Result<JsonValue, OpenCodeCanonicalError> {
    Ok(JsonValue::try_from_source_tool_arguments(name, value)
        .map_err(|error| error.with_bound_category(CanonicalFieldCategory::ToolArguments))?)
}

fn tool_result(value: &Value) -> Result<JsonValue, OpenCodeCanonicalError> {
    Ok(JsonValue::try_from_source_tool_result(value)
        .map_err(|error| error.with_bound_category(CanonicalFieldCategory::ToolResult))?)
}
