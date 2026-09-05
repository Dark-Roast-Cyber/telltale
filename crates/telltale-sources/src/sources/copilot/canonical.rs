#![allow(dead_code)]

use std::fmt;

use serde_json::Value;
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
    CopilotContentBlock, CopilotNativeEvent, CopilotOutputItem, extract_copilot_native_events,
};
use crate::parser::ParseError;

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
    Source(ParseError),
    Mapping {
        code: &'static str,
        detail: &'static str,
    },
    Observation(ObservationError),
}

impl CopilotCanonicalError {
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

impl fmt::Debug for CopilotCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("CopilotCanonicalError::Source")
            }
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
            Self::Source(error) => {
                let _ = error;
                formatter.write_str("Copilot source could not be parsed")
            }
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

impl From<ParseError> for CopilotCanonicalError {
    fn from(error: ParseError) -> Self {
        Self::Source(error)
    }
}

impl From<ObservationError> for CopilotCanonicalError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

pub(crate) fn project_copilot_canonical_observations(
    source: &Source,
    options: CopilotCanonicalOptions,
) -> Result<Vec<CanonicalObservationV2>, CopilotCanonicalError> {
    if source.client != ClientId::Copilot || source.source_id != "copilot.process_log" {
        return Err(mapping(
            "unsupported_source_identity",
            "canonical projection requires the Copilot process log source",
        ));
    }
    if source.kind != SourceKind::CopilotProcessLog {
        return Err(mapping(
            "unsupported_source_kind",
            "canonical projection requires Copilot process-log input",
        ));
    }

    let events = extract_copilot_native_events(source)?;
    let mut observations = Vec::new();
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
                let ordinal = ordinal.ok_or_else(|| {
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
                    &options,
                    &mut observations,
                )?;
            }
        }
    }
    Ok(observations)
}

fn project_item(
    session_id: &str,
    ordinal: u64,
    timestamp: Option<&str>,
    item: Box<CopilotOutputItem>,
    options: &CopilotCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
) -> Result<(), CopilotCanonicalError> {
    match item.item_type.as_deref() {
        None | Some("") | Some("reasoning") => Ok(()),
        Some("function_call") => {
            project_function_call(session_id, ordinal, timestamp, &item, options, observations)
        }
        Some("message") => {
            project_message(session_id, ordinal, timestamp, &item, options, observations)
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
    observations: &mut Vec<CanonicalObservationV2>,
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

    let mut body = ToolObservation::new();
    let mut metadata = Vec::new();
    if has_name {
        body = body.with_name(item.name.as_deref().expect("checked"))?;
        metadata.push(("tool.name", FactProvenance::Reported));
    }
    if has_arguments {
        let arguments = item.arguments.as_deref().expect("checked");
        if let Ok(value) = serde_json::from_str::<Value>(arguments) {
            body = body.with_arguments(value_to_json(&value)?);
            metadata.push(("tool.arguments", FactProvenance::Parsed));
        } else {
            body = body.with_arguments(JsonValue::string(arguments));
            metadata.push(("tool.arguments", FactProvenance::Reported));
        }
        body = body.with_searchable_arguments(arguments)?;
        metadata.push(("tool.searchable_arguments", FactProvenance::Reported));
    }

    let mut builder = common_builder(
        session_id,
        ordinal,
        timestamp,
        ObservationBody::Tool(body),
        ObservationStage::ToolRequested,
        0,
        item.call_id.as_deref(),
        options,
    )?;
    for (path, provenance) in metadata {
        builder = builder.fact_metadata(path, normal(provenance)?);
    }
    add_argument_facets(&mut builder, item.arguments.as_deref())?;
    observations.push(builder.build()?);

    if item
        .message
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        let body = ToolObservation::new()
            .with_result(JsonValue::string(item.message.as_deref().expect("checked")));
        let mut builder = common_builder(
            session_id,
            ordinal,
            timestamp,
            ObservationBody::Tool(body),
            ObservationStage::ToolResultReturned,
            1,
            item.call_id.as_deref(),
            options,
        )?;
        builder = builder.fact_metadata("tool.result", normal_reported()?);
        observations.push(builder.build()?);
    }
    Ok(())
}

fn project_message(
    session_id: &str,
    ordinal: u64,
    timestamp: Option<&str>,
    item: &CopilotOutputItem,
    options: &CopilotCanonicalOptions,
    observations: &mut Vec<CanonicalObservationV2>,
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
            JsonValue::string(text),
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
        .fact_metadata("message.role", normal_reported()?)
        .fact_metadata("message.content_parts", normal_reported()?);
    observations.push(builder.build()?);
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
) -> Result<(), CopilotCanonicalError> {
    let Some(arguments) = arguments else {
        return Ok(());
    };
    let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(arguments) else {
        return Ok(());
    };
    if let Some(command) = fields
        .get("command")
        .or_else(|| fields.get("cmd"))
        .and_then(Value::as_str)
    {
        *builder = builder
            .clone()
            .facet(
                "command.text",
                SemanticFacet::new(JsonValue::string(command)),
            )?
            .fact_metadata("command.text", normal(FactProvenance::Parsed)?);
    }
    if let Some(path) = fields
        .get("path")
        .or_else(|| fields.get("file_path"))
        .and_then(Value::as_str)
    {
        *builder = builder
            .clone()
            .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))?
            .fact_metadata("resource.path", normal(FactProvenance::Parsed)?);
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

fn normal_reported() -> Result<FactMetadata, CopilotCanonicalError> {
    normal(FactProvenance::Reported)
}

fn normal(provenance: FactProvenance) -> Result<FactMetadata, CopilotCanonicalError> {
    Ok(match provenance {
        FactProvenance::Reported => FactMetadata::reported()?,
        FactProvenance::Parsed => FactMetadata::parsed()?,
        _ => FactMetadata::new(
            provenance,
            telltale_schema::observation::Sensitivity::Normal,
        )?,
    })
}

fn value_to_json(value: &Value) -> Result<JsonValue, CopilotCanonicalError> {
    Ok(JsonValue::try_from_source_value(value)?)
}

fn mapping(code: &'static str, detail: &'static str) -> CopilotCanonicalError {
    CopilotCanonicalError::Mapping { code, detail }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::{
        CapabilityAvailability, CapabilityId, ContentPartKind, Fidelity, IngestionMode, JsonValue,
        ObservationBody, ObservationFamily, ObservationStage, ObservedAt,
    };
    use telltale_schema::record::RecordKind;
    use telltale_schema::source::Source;
    use tempfile::tempdir;

    use super::{CopilotCanonicalOptions, project_copilot_canonical_observations};
    use crate::parser::parse_source_records;
    use crate::sources::copilot::native::{CopilotNativeEvent, extract_copilot_native_events};

    const OBSERVED_AT: &str = "2026-09-04T12:00:00Z";

    fn source(path: std::path::PathBuf) -> Source {
        Source {
            client: ClientId::Copilot,
            kind: SourceKind::CopilotProcessLog,
            source_id: "copilot.process_log".to_owned(),
            path,
        }
    }

    fn project(
        path: std::path::PathBuf,
    ) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
        project_copilot_canonical_observations(
            &source(path),
            CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect("Copilot canonical observations")
    }

    #[test]
    fn mixed_fixture_preserves_assistant_parts_and_legacy_omits_them() {
        let path = crate::test_fixture_path("session_stores/copilot/process-mixed-format.log");
        let observations = project(path.clone());
        assert_eq!(observations.len(), 4);
        assert!(observations.iter().all(|observation| {
            observation.source().ingestion_mode() == IngestionMode::SessionStore
                && observation.source().adapter_type() == "copilot"
                && observation.source().adapter_id() == "copilot.process_log"
                && observation.source().fidelity() == Fidelity::PartialStructured
                && observation
                    .capability_context()
                    .unwrap()
                    .resolve(CapabilityId::ToolCall)
                    == CapabilityAvailability::Supported
                && observation
                    .capability_context()
                    .unwrap()
                    .resolve(CapabilityId::UserContext)
                    == CapabilityAvailability::Unsupported
                && observation
                    .capability_context()
                    .unwrap()
                    .resolve(CapabilityId::ToolExecution)
                    == CapabilityAvailability::Unknown
        }));
        let ObservationBody::Message(message) = observations[0].body() else {
            panic!("expected assistant message")
        };
        assert_eq!(message.content_parts().len(), 1);
        assert_eq!(message.content_parts()[0].kind(), ContentPartKind::Text);
        assert_eq!(
            message.content_parts()[0].value(),
            &JsonValue::string("I will inspect synthetic files.")
        );
        assert_eq!(observations[0].stage(), ObservationStage::MessageObserved);
        assert_eq!(
            observations[0].occurred_at().unwrap().as_str(),
            "2026-04-27T16:17:17.990Z"
        );
        assert_eq!(observations[1].source().source_sequence(), Some(2));
        assert_eq!(observations[1].identity_basis().child_ordinal(), 0);
        assert_eq!(observations[2].identity_basis().child_ordinal(), 0);
        assert_eq!(observations[3].identity_basis().child_ordinal(), 1);
        assert_ne!(
            observations[2].observation_id(),
            observations[3].observation_id()
        );

        let legacy = parse_source_records(&source(path)).expect("legacy records");
        assert_eq!(legacy.len(), 4);
        assert!(legacy.iter().all(|record| {
            record.kind != RecordKind::AssistantMessage
                && !record.content.contains("I will inspect synthetic files")
        }));
    }

    #[test]
    fn multi_session_boundaries_and_reactivation_use_truthful_ordinals() {
        let path = crate::test_fixture_path("session_stores/copilot/process-multi-session.log");
        let observations = project(path);
        assert_eq!(observations.len(), 2);
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "copilot-multi-session-a"
        );
        assert_eq!(
            observations[1].session_id().unwrap().value(),
            "copilot-multi-session-b"
        );
        assert_eq!(observations[0].sequence(), Some(0));
        assert_eq!(observations[1].sequence(), Some(0));
        assert_ne!(
            observations[0].observation_id(),
            observations[1].observation_id()
        );

        let directory = tempdir().unwrap();
        let repeated = directory.path().join("repeated.log");
        fs::write(
            &repeated,
            "Workspace initialized: repeated-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"reasoning\"}]\nSession completed.\nWorkspace initialized: repeated-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();
        let observations = project(repeated);
        assert_eq!(observations[0].sequence(), Some(1));
    }

    #[test]
    fn tool_identity_is_coordinate_only_and_call_ids_are_optional_correlations() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("first.log");
        let second = directory.path().join("renamed.log");
        let line = "2026-04-27T16:17:17Z [INFO] Workspace initialized: identity-session (checkpoints: 0)\n2026-04-27T16:17:18Z [INFO] Accumulated output items (1): [{\"arguments\":\"{\\\"path\\\":\\\"synthetic-a.txt\\\"}\",\"call_id\":\"call-a\",\"id\":\"c1\",\"name\":\"view\",\"type\":\"function_call\"}]\n";
        fs::write(&first, line).unwrap();
        fs::write(
            &second,
            line.replace("synthetic-a.txt", "synthetic-b.txt")
                .replace("call-a", "call-b"),
        )
        .unwrap();
        let left = project(first);
        let right = project(second);
        assert_eq!(left[0].observation_id(), right[0].observation_id());
        assert_eq!(left[0].identity_basis().child_ordinal(), 0);
        assert_eq!(left[0].source().native_id(), None);
        assert_eq!(left[0].correlation().call_id().unwrap().value(), "call-a");
        let ObservationBody::Tool(tool) = left[0].body() else {
            panic!("expected tool")
        };
        assert_eq!(
            tool.arguments(),
            Some(
                &JsonValue::object([("path".to_owned(), JsonValue::string("synthetic-a.txt"))])
                    .unwrap()
            )
        );
        assert_eq!(
            tool.searchable_arguments(),
            Some("{\"path\":\"synthetic-a.txt\"}")
        );
        assert_eq!(
            left[0].facets()["resource.path"].value(),
            &JsonValue::string("synthetic-a.txt")
        );

        let missing = directory.path().join("missing-call.log");
        fs::write(
            &missing,
            "Workspace initialized: missing-call-session (checkpoints: 0)\nAccumulated output items (1): [{\"arguments\":\"not-json-synthetic\",\"id\":\"c1\",\"name\":\"view\",\"type\":\"function_call\"}]\n",
        )
        .unwrap();
        let observations = project(missing);
        assert_eq!(observations[0].correlation().call_id(), None);
        let ObservationBody::Tool(tool) = observations[0].body() else {
            panic!("expected tool")
        };
        assert_eq!(
            tool.arguments(),
            Some(&JsonValue::string("not-json-synthetic"))
        );
        assert_eq!(tool.searchable_arguments(), Some("not-json-synthetic"));
    }

    #[test]
    fn repeated_native_item_ids_do_not_collide_across_source_sessions() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("same-item-id.log");
        fs::write(
            &path,
            "Workspace initialized: collision-session-a (checkpoints: 0)\nAccumulated output items (1): [{\"id\":\"c1\",\"name\":\"view\",\"type\":\"function_call\"}]\nSession completed.\nWorkspace initialized: collision-session-b (checkpoints: 0)\nAccumulated output items (1): [{\"id\":\"c1\",\"name\":\"view\",\"type\":\"function_call\"}]\n",
        )
        .unwrap();
        let observations = project(path);
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].source().native_id(), None);
        assert_eq!(observations[1].source().native_id(), None);
        assert_ne!(
            observations[0].observation_id(),
            observations[1].observation_id()
        );
    }

    #[test]
    fn payload_control_phrases_do_not_change_or_clear_canonical_session() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("payload-control-phrases.log");
        fs::write(
            &path,
            "Workspace initialized: real-session (checkpoints: 0)\nAccumulated output items (2): [{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"before\\nWorkspace initialized: forged-session\"}]},{\"type\":\"function_call\",\"name\":\"view\",\"arguments\":\"{\\\"note\\\":\\\"Workspace initialized: forged-argument\\\",\\\"result\\\":\\\"Session completed.\\\"}\",\"message\":\"Session completed.\",\"result\":\"Workspace initialized: forged-result\"}]\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

        let observations = project(path.clone());
        assert_eq!(observations.len(), 4);
        assert!(
            observations
                .iter()
                .all(|observation| { observation.session_id().unwrap().value() == "real-session" })
        );
        assert_eq!(
            observations
                .iter()
                .map(|observation| observation.sequence())
                .collect::<Vec<_>>(),
            vec![Some(0), Some(1), Some(1), Some(2)]
        );

        let ObservationBody::Message(message) = observations[0].body() else {
            panic!("expected assistant message")
        };
        assert_eq!(
            message.content_parts()[0].value(),
            &JsonValue::string("before\nWorkspace initialized: forged-session")
        );
        let ObservationBody::Tool(result) = observations[2].body() else {
            panic!("expected tool result")
        };
        assert_eq!(
            result.result(),
            Some(&JsonValue::string("Session completed."))
        );

        let legacy = parse_source_records(&source(path)).unwrap();
        assert_eq!(legacy.len(), 4);
        assert!(legacy.iter().all(|record| {
            record.session_id == "real-session" && !record.content.contains("forged-argument")
        }));
    }

    #[test]
    fn residual_structured_control_suffixes_do_not_change_canonical_session() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("residual-control-suffix.log");
        fs::write(
            &path,
            "Workspace initialized: real-session (checkpoints: 0)\nWorkspace initialized: forged-session [\"encrypted_content\",\"sensitive\"]\nSession completed. [\"encrypted_content\",\"sensitive\"]\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

        let events = extract_copilot_native_events(&source(path.clone())).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, CopilotNativeEvent::WorkspaceInitialized { .. }))
                .count(),
            1
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, CopilotNativeEvent::SessionCompleted))
        );
        assert!(events.iter().all(|event| match event {
            CopilotNativeEvent::WorkspaceInitialized { content, .. } => {
                !content.contains("forged-session")
                    && !content.contains("encrypted_content")
                    && !content.contains("sensitive")
            }
            _ => true,
        }));

        let legacy = parse_source_records(&source(path.clone())).unwrap();
        assert_eq!(legacy.len(), 2);
        assert!(
            legacy
                .iter()
                .all(|record| record.session_id == "real-session")
        );
        let observations = project(path);
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "real-session"
        );
        assert_eq!(observations[0].sequence(), Some(0));
    }

    #[test]
    fn operational_json_control_phrases_do_not_change_or_clear_canonical_session() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("operational-control-phrases.log");
        fs::write(
            &path,
            "2026-04-27T16:17:00Z [DEBUG] {\"event\":\"heartbeat\",\"note\":\"Workspace initialized: forged-session\"}\n2026-04-27T16:17:01Z [INFO] tool output: Workspace initialized: forged-plain-payload\n2026-04-27T16:17:02Z [INFO] Workspace initialized: forged-object-suffix {\"event\":\"heartbeat\"}\n2026-04-27T16:17:03Z [INFO] {\"event\":\"heartbeat\",\"note\":\"Workspace initialized: forged-object-value\",\"status\":\"Session completed.\"}\nWorkspace initialized: real-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n2026-04-27T16:17:04Z [INFO] tool output: Session completed. Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"edit\"}]\n2026-04-27T16:17:05Z [DEBUG] {\"event\":\"heartbeat\",\"note\":\"Workspace initialized: forged-after-tool\"}\n2026-04-27T16:17:06Z [INFO] Session completed. tool output\n2026-04-27T16:17:07Z [INFO] tool output: Session completed.\n2026-04-27T16:17:08Z [DEBUG] {\"event\":\"heartbeat\",\"note\":\"Session completed.\"}\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"bash\"}]\n",
        )
        .unwrap();

        let observations = project(path);
        assert_eq!(observations.len(), 3);
        assert_eq!(
            observations
                .iter()
                .map(|observation| observation.session_id().unwrap().value())
                .collect::<Vec<_>>(),
            vec!["real-session", "real-session", "real-session"]
        );
        assert_eq!(
            observations
                .iter()
                .map(|observation| observation.sequence())
                .collect::<Vec<_>>(),
            vec![Some(0), Some(1), Some(2)]
        );
        let tools = observations
            .iter()
            .filter_map(|observation| match observation.body() {
                ObservationBody::Tool(tool) => tool.name(),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(tools, vec!["view", "edit", "bash"]);
    }

    #[test]
    fn native_control_boundary_is_shared_with_legacy_and_canonical_projections() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("combined-control-output.log");
        fs::write(
            &path,
            "Workspace initialized: combined-session (checkpoints: 0) Accumulated output items (2): [{\"type\":\"reasoning\",\"encrypted_content\":\"fixture-encrypted-reasoning\"},{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

        let events = extract_copilot_native_events(&source(path.clone())).unwrap();
        let CopilotNativeEvent::WorkspaceInitialized { content, .. } = &events[0] else {
            panic!("expected workspace event")
        };
        assert_eq!(
            content,
            "Workspace initialized: combined-session (checkpoints: 0)"
        );
        assert!(!content.contains("encrypted_content"));
        assert!(!content.contains("fixture-encrypted-reasoning"));

        let legacy = parse_source_records(&source(path.clone())).unwrap();
        assert_eq!(legacy[0].content, content.as_str());
        let observations = project(path);
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "combined-session"
        );
    }

    #[test]
    fn completion_line_items_project_before_canonical_session_clear() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("completion-with-output.log");
        fs::write(
            &path,
            "Workspace initialized: completion-line-session (checkpoints: 0)\nSession completed. Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

        let observations = project(path);
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].session_id().unwrap().value(),
            "completion-line-session"
        );
        assert_eq!(observations[0].sequence(), Some(0));
        assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
    }

    #[test]
    fn unsupported_message_shapes_and_completed_status_fail_or_remain_non_results() {
        let directory = tempdir().unwrap();
        let message = directory.path().join("message-shapes.log");
        fs::write(
            &message,
            "Workspace initialized: message-shapes-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"unknown_block\",\"text\":\"secret-marker\"}]}]\n",
        )
        .unwrap();
        let error = project_copilot_canonical_observations(
            &source(message),
            CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "unknown_content_block");
        assert!(!format!("{error} {error:?}").contains("secret-marker"));

        let role = directory.path().join("message-role.log");
        fs::write(
            &role,
            "Workspace initialized: message-role-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"message\",\"role\":\"user\",\"content\":[]}]\n",
        )
        .unwrap();
        let error = project_copilot_canonical_observations(
            &source(role),
            CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "unsupported_role");

        let completed = directory.path().join("completed.log");
        fs::write(
            &completed,
            "Workspace initialized: completed-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\",\"status\":\"completed\"}]\n",
        )
        .unwrap();
        let observations = project(completed);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
    }

    #[test]
    fn malformed_unknown_and_unscoped_output_fail_without_payloads() {
        let directory = tempdir().unwrap();
        let malformed = directory.path().join("malformed.log");
        fs::write(
            &malformed,
            "Workspace initialized: malformed-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\"}\n",
        )
        .unwrap();
        let error = project_copilot_canonical_observations(
            &source(malformed),
            CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "malformed_structured_output");
        assert!(!format!("{error:?}").contains("malformed-session"));

        let non_array = directory.path().join("non-array.log");
        fs::write(
            &non_array,
            "Workspace initialized: non-array-session (checkpoints: 0)\nAccumulated output items (1): {\"type\":\"function_call\"}\n",
        )
        .unwrap();
        let error = project_copilot_canonical_observations(
            &source(non_array),
            CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "malformed_structured_output");

        let unknown = directory.path().join("unknown.log");
        fs::write(
            &unknown,
            "Workspace initialized: unknown-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"future_variant_secret_marker\",\"encrypted_content\":\"fixture-encrypted-reasoning\"}]\n",
        )
        .unwrap();
        let error = project_copilot_canonical_observations(
            &source(unknown.clone()),
            CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "unknown_output_item_type");
        let rendered = format!("{error} {error:?}");
        for forbidden in [
            "future_variant_secret_marker",
            "fixture-encrypted-reasoning",
            "unknown-session",
        ] {
            assert!(!rendered.contains(forbidden));
        }
        assert_eq!(
            parse_source_records(&source(unknown)).unwrap()[1].content,
            "unknown Copilot accumulated output item"
        );

        let unscoped = directory.path().join("unscoped.log");
        fs::write(
            &unscoped,
            "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();
        let error = project_copilot_canonical_observations(
            &source(unscoped),
            CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "replay_unverifiable");
    }

    #[test]
    fn canonical_rejects_wrong_kind_before_reading_and_preserves_observed_at() {
        let source_path = std::path::PathBuf::from("does-not-exist-process.log");
        let mut wrong = source(source_path);
        wrong.kind = SourceKind::Jsonl;
        let error = project_copilot_canonical_observations(
            &wrong,
            CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "unsupported_source_kind");

        let observations = project(crate::test_fixture_path(
            "session_stores/copilot/process-uc001.log",
        ));
        assert!(
            observations
                .iter()
                .all(|observation| observation.observed_at().as_str() == OBSERVED_AT)
        );
    }

    #[test]
    fn no_activity_families_or_execution_lifecycle_are_fabricated() {
        let observations = project(crate::test_fixture_path(
            "session_stores/copilot/process-uc001.log",
        ));
        assert!(observations.iter().all(|observation| {
            observation.kind() != ObservationFamily::Process
                && observation.kind() != ObservationFamily::File
                && observation.kind() != ObservationFamily::Network
                && observation.kind() != ObservationFamily::Inference
                && !matches!(
                    observation.stage(),
                    ObservationStage::ToolProposed
                        | ObservationStage::ToolExecutionStarted
                        | ObservationStage::ToolExecutionCompleted
                )
        }));
    }
}
