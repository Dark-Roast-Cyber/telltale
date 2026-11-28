use std::collections::{BTreeMap, BTreeSet};

use telltale_rules::process_chain::{
    ProcessChainContext, load_default_process_chain_rules, load_process_chain_rules,
};
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId, CorrelationId,
    FactMetadata, FactProvenance, Fidelity, IngestionMode, JsonValue, MessageObservation,
    MessageRole, ObservationBody, ObservationFamily, ObservationStage, ObservedAt,
    ProcessObservation as CanonicalProcess, SemanticFacet, SourceProvenance, ToolObservation,
    ToolStatus,
};

use super::*;
use crate::v2::{FindingKind, NonEvaluationReason};

const OBSERVED_AT: &str = "2026-09-17T12:00:00Z";

fn source(native_id: &str) -> SourceProvenance {
    SourceProvenance::new(
        IngestionMode::Harness,
        "synthetic",
        "process-chain-v2-tests",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id(native_id)
    .unwrap()
}

fn metadata(provenance: FactProvenance) -> FactMetadata {
    FactMetadata::new(
        provenance,
        telltale_schema::observation::Sensitivity::Normal,
    )
    .unwrap()
}

fn tool(
    stage: ObservationStage,
    command_text: Option<&str>,
    searchable_arguments: Option<&str>,
    arguments: Option<JsonValue>,
    tool_name: &str,
    native_id: &str,
) -> CanonicalObservationV2 {
    tool_with_session_and_time(
        stage,
        command_text,
        searchable_arguments,
        arguments,
        tool_name,
        native_id,
        Some("session:process-v2"),
        None,
    )
}

fn timed_command(
    command: &str,
    native_id: &str,
    session_id: Option<&str>,
    occurred_at: Option<&str>,
) -> CanonicalObservationV2 {
    tool_with_session_and_time(
        ObservationStage::ToolRequested,
        Some(command),
        None,
        None,
        "shell",
        native_id,
        session_id,
        occurred_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn tool_with_session_and_time(
    stage: ObservationStage,
    command_text: Option<&str>,
    searchable_arguments: Option<&str>,
    arguments: Option<JsonValue>,
    tool_name: &str,
    native_id: &str,
    session_id: Option<&str>,
    occurred_at: Option<&str>,
) -> CanonicalObservationV2 {
    tool_with_session_time_and_capability(
        stage,
        command_text,
        searchable_arguments,
        arguments,
        tool_name,
        native_id,
        session_id,
        occurred_at,
        CapabilityAvailability::Supported,
    )
}

#[allow(clippy::too_many_arguments)]
fn tool_with_session_time_and_capability(
    stage: ObservationStage,
    command_text: Option<&str>,
    searchable_arguments: Option<&str>,
    arguments: Option<JsonValue>,
    tool_name: &str,
    native_id: &str,
    session_id: Option<&str>,
    occurred_at: Option<&str>,
    tool_call_capability: CapabilityAvailability,
) -> CanonicalObservationV2 {
    let has_arguments = arguments.is_some();
    let mut body = ToolObservation::new().with_name(tool_name).unwrap();
    if let Some(arguments) = arguments {
        body = body.with_arguments(arguments);
    }
    if let Some(searchable) = searchable_arguments {
        body = body.with_searchable_arguments(searchable).unwrap();
    }
    if stage == ObservationStage::ToolExecutionCompleted {
        body = body.with_reported_status(ToolStatus::Succeeded);
    }
    if stage == ObservationStage::ToolResultReturned {
        body = body.with_result(JsonValue::string("synthetic result"));
    }

    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(body),
        stage,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(native_id),
    );
    if let Some(session_id) = session_id {
        builder = builder.session_id(CorrelationId::source_reported(session_id).unwrap());
    }
    if let Some(occurred_at) = occurred_at {
        builder = builder
            .occurred_at(telltale_schema::observation::SourceTimestamp::new(occurred_at).unwrap());
    }
    let mut builder = builder
        .capability_context(
            CapabilityContext::new().with_override(CapabilityId::ToolCall, tool_call_capability),
        )
        .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    if has_arguments {
        builder = builder.fact_metadata("tool.arguments", metadata(FactProvenance::Reported));
    }
    if searchable_arguments.is_some() {
        builder = builder.fact_metadata(
            "tool.searchable_arguments",
            metadata(FactProvenance::Reported),
        );
    }
    if stage == ObservationStage::ToolExecutionCompleted {
        builder = builder.fact_metadata("tool.reported_status", metadata(FactProvenance::Reported));
    }
    if stage == ObservationStage::ToolResultReturned {
        builder = builder.fact_metadata("tool.result", metadata(FactProvenance::Reported));
    }
    if let Some(command_text) = command_text {
        builder = builder
            .facet(
                "command.text",
                SemanticFacet::new(JsonValue::string(command_text)),
            )
            .unwrap()
            .fact_metadata("command.text", metadata(FactProvenance::Parsed));
    }
    builder.build().unwrap()
}

fn requested_command(command: &str, native_id: &str) -> CanonicalObservationV2 {
    tool(
        ObservationStage::ToolRequested,
        Some(command),
        None,
        None,
        "shell",
        native_id,
    )
}

fn default_results(command: &str, native_id: &str) -> Vec<DetectorResult> {
    evaluate_tool_process_chains(
        &load_default_process_chain_rules().unwrap(),
        &requested_command(command, native_id),
        &ProcessChainContext::default(),
    )
    .unwrap()
}

fn result<'a>(results: &'a [DetectorResult], id: &str) -> &'a DetectorResult {
    results
        .iter()
        .find(|result| result.detector().id() == id)
        .unwrap_or_else(|| panic!("missing {id}"))
}

mod command_eligibility;
mod correlation;
mod matching;
mod repeat_suppression;
mod rule_normalization;
