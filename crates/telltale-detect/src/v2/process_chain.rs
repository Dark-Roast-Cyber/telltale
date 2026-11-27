//! Process-chain evaluation over canonical Tool evidence.
//!
//! Parsed command relationships stay private matcher working state. This
//! module never constructs canonical Process observations.

use std::collections::{BTreeMap, BTreeSet};

use sha2::Digest;
use telltale_rules::process_chain::{
    CompiledCorrelationRule, CompiledProcessChainRules, ProcessChainContext, ProcessChainDetection,
    ProcessObservation,
};
use telltale_schema::observation::{
    CanonicalObservationV2, FactProvenance, JsonValue, ObservationBody, ObservationStage,
    canonical_identity_json,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::classification::finding_kind_for_detection_class;
use super::{
    Confidence, CorrelationScope, DetectionError, DetectorIdentity, DetectorKind, DetectorResult,
    EvaluationStatus, FindingKind, FindingMetadata, Severity,
};
use crate::process_chain_session::{
    ProcessChainOccurrenceId, ProcessChainSessionCandidate, ProcessChainSessionConfig,
    try_evaluate_process_chain_session,
};

const ELIGIBLE_TOOL_STAGES: [ObservationStage; 4] = [
    ObservationStage::ToolProposed,
    ObservationStage::ToolRequested,
    ObservationStage::ToolExecutionStarted,
    ObservationStage::ToolExecutionCompleted,
];

/// Evaluates command-bearing canonical Tool evidence without source access,
/// lifecycle suppression, correlation, or Event projection.
pub(crate) fn evaluate_tool_process_chains(
    rules: &CompiledProcessChainRules,
    observation: &CanonicalObservationV2,
    context: &ProcessChainContext,
) -> Result<Vec<DetectorResult>, DetectionError> {
    let mut budget = super::session::RetentionBudget::new();
    let matches = evaluate_tool_process_chain_matches(rules, observation, context, 0, &mut budget)?;
    Ok(normalize_atomic_results(&matches))
}

#[derive(Clone)]
struct ProcessChainWorkingMatch {
    result: DetectorResult,
    child: String,
    occurred_at: Option<OffsetDateTime>,
    observation_index: usize,
    projection: super::event3::ProcessProjection,
}

fn evaluate_tool_process_chain_matches(
    rules: &CompiledProcessChainRules,
    observation: &CanonicalObservationV2,
    context: &ProcessChainContext,
    observation_index: usize,
    budget: &mut super::session::RetentionBudget,
) -> Result<Vec<ProcessChainWorkingMatch>, DetectionError> {
    let mut matches = Vec::new();
    budget
        .charge(observation.retained_byte_len().saturating_mul(4))
        .map_err(|_| DetectionError::InvalidBounds)?;
    for command in command_candidates(observation) {
        budget
            .charge(command.len().saturating_mul(64))
            .map_err(|_| DetectionError::InvalidBounds)?;
    }
    for process_input in command_derived_process_matcher_inputs(observation) {
        for detection in rules
            .try_evaluate_with_context(&process_input, context, &mut |bytes| budget.charge(bytes))
            .map_err(|_| DetectionError::InvalidBounds)?
        {
            matches.push(ProcessChainWorkingMatch {
                result: normalize_match(&detection, observation)?,
                child: process_input.child.normalized_name(),
                occurred_at: occurred_at(observation),
                observation_index,
                projection: super::event3::ProcessProjection::atomic(
                    &process_input,
                    &detection,
                    observation,
                    observation_index,
                    budget,
                )?,
            });
            if matches.len() > budget.bounds.projection_items {
                return Err(DetectionError::InvalidBounds);
            }
        }
    }
    Ok(matches)
}

fn normalize_atomic_results<'a>(
    matches: impl IntoIterator<Item = &'a ProcessChainWorkingMatch>,
) -> Vec<DetectorResult> {
    let mut results = matches
        .into_iter()
        .map(|matched| matched.result.clone())
        .collect::<Vec<_>>();
    // Outward atomic presentation is detector-ordered and duplicate-free.
    // Private session semantics use the untouched parser-ordered matches.
    results.sort_by(|left, right| {
        left.detector()
            .id()
            .cmp(right.detector().id())
            .then_with(|| left.observation_ids().cmp(right.observation_ids()))
            .then_with(|| left.dedupe_key().cmp(&right.dedupe_key()))
    });
    results.dedup_by(|left, right| {
        left.detector().id() == right.detector().id()
            && left.observation_ids() == right.observation_ids()
            && left.dedupe_key() == right.dedupe_key()
    });
    results
}

/// Private session result retained by the caller-defined evaluator. Repeat
/// counts belong to the Event3 projection rather than the common
/// DetectorResult/Signal/Finding types.
#[derive(Clone)]
pub(crate) struct ProcessChainSessionEvaluation {
    results: Vec<DetectorResult>,
    detailed_results: Option<Vec<DetectorResult>>,
    /// Test observable for suppression semantics; production does not read it.
    #[cfg(test)]
    suppressed_count: usize,
    pub(crate) projection:
        BTreeMap<super::event3::ProcessResultKey, super::event3::ProcessProjection>,
}

impl ProcessChainSessionEvaluation {
    pub(crate) fn results(&self) -> &[DetectorResult] {
        &self.results
    }
    pub(crate) fn detailed_results(&self) -> &[DetectorResult] {
        self.detailed_results.as_deref().unwrap_or(&self.results)
    }

    #[cfg(test)]
    pub(crate) fn suppressed_count(&self) -> usize {
        self.suppressed_count
    }
}

/// Evaluates a caller-grouped set of canonical Tool observations.  Source
/// discovery and session grouping remain caller responsibilities.
pub(crate) fn evaluate_tool_process_chain_session(
    rules: &CompiledProcessChainRules,
    observations: &[&CanonicalObservationV2],
    context: &ProcessChainContext,
    config: &ProcessChainSessionConfig,
) -> Result<ProcessChainSessionEvaluation, DetectionError> {
    let mut budget = super::session::RetentionBudget::new();
    evaluate_tool_process_chain_session_with_budget(
        rules,
        observations,
        context,
        config,
        &mut budget,
    )
}

pub(crate) fn evaluate_tool_process_chain_session_with_budget(
    rules: &CompiledProcessChainRules,
    observations: &[&CanonicalObservationV2],
    context: &ProcessChainContext,
    config: &ProcessChainSessionConfig,
    budget: &mut super::session::RetentionBudget,
) -> Result<ProcessChainSessionEvaluation, DetectionError> {
    evaluate_tool_process_chain_views(rules, observations, context, config, budget, false)
}

pub(crate) fn evaluate_tool_process_chain_views(
    rules: &CompiledProcessChainRules,
    observations: &[&CanonicalObservationV2],
    context: &ProcessChainContext,
    config: &ProcessChainSessionConfig,
    budget: &mut super::session::RetentionBudget,
    detailed: bool,
) -> Result<ProcessChainSessionEvaluation, DetectionError> {
    let mut matches = Vec::new();
    for (observation_index, observation) in observations.iter().enumerate() {
        matches.extend(evaluate_tool_process_chain_matches(
            rules,
            observation,
            context,
            observation_index,
            budget,
        )?);
        if matches.len() > budget.bounds.projection_items {
            return Err(DetectionError::InvalidBounds);
        }
    }
    // Timed session semantics are chronological. `sort_by` is stable, so equal
    // occurred_at values retain caller order. Untimed matches remain atomic but
    // are placed after timed candidates and can never join timed semantics.
    matches.sort_by(|left, right| match (left.occurred_at, right.occurred_at) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    let mut output = finish_process_matches(rules, &matches, observations, config, budget)?;
    if detailed
        && observations.iter().any(|o| {
            o.source().ingestion_mode() == telltale_schema::observation::IngestionMode::Import
        })
    {
        let filtered = matches
            .into_iter()
            .filter(|m| {
                observations[m.observation_index].source().ingestion_mode()
                    != telltale_schema::observation::IngestionMode::Import
            })
            .collect::<Vec<_>>();
        output.detailed_results =
            Some(finish_process_matches(rules, &filtered, observations, config, budget)?.results);
    }
    Ok(output)
}

fn finish_process_matches(
    rules: &CompiledProcessChainRules,
    matches: &[ProcessChainWorkingMatch],
    observations: &[&CanonicalObservationV2],
    config: &ProcessChainSessionConfig,
    budget: &mut super::session::RetentionBudget,
) -> Result<ProcessChainSessionEvaluation, DetectionError> {
    let mut occurrence_ids = BTreeMap::new();
    let mut next_occurrence_id = 0;
    let candidates = matches
        .iter()
        .map(|matched| {
            budget
                .charge(
                    matched
                        .result
                        .detector()
                        .id()
                        .len()
                        .saturating_add(matched.result.category().len())
                        .saturating_add(matched.child.len())
                        .saturating_add(matched.result.dedupe_key().map_or(0, str::len)),
                )
                .map_err(|_| DetectionError::InvalidBounds)?;
            let dedupe_key = matched
                .result
                .dedupe_key()
                .ok_or(DetectionError::RuntimeEvaluation)?;
            let occurrence_key = (
                matched.result.observation_ids().to_vec(),
                matched.result.detector().id().to_owned(),
                dedupe_key.to_owned(),
            );
            let occurrence_id = *occurrence_ids.entry(occurrence_key).or_insert_with(|| {
                let occurrence_id = ProcessChainOccurrenceId::new(next_occurrence_id);
                next_occurrence_id += 1;
                occurrence_id
            });
            Ok(ProcessChainSessionCandidate {
                occurrence_id,
                rule_id: matched.result.detector().id().to_owned(),
                category: matched.result.category().to_owned(),
                child: matched.child.clone(),
                dedupe_key: dedupe_key.to_owned(),
                entity: matched.result.session_id().map(str::to_owned),
                occurred_at: matched.occurred_at,
            })
        })
        .collect::<Result<Vec<_>, DetectionError>>()?;
    let semantics = try_evaluate_process_chain_session(&candidates, rules, config, &mut |bytes| {
        budget.charge(bytes)
    })
    .map_err(|_| DetectionError::InvalidBounds)?;

    let retained_matches = semantics
        .suppression
        .retained
        .iter()
        .filter_map(|index| matches.get(*index));
    let mut results = normalize_atomic_results(retained_matches);
    let mut projection: BTreeMap<
        super::event3::ProcessResultKey,
        super::event3::ProcessProjection,
    > = BTreeMap::new();
    for index in &semantics.suppression.retained {
        let matched = &matches[*index];
        let entry = projection.entry(super::event3::process_result_key(&matched.result));
        match entry {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry
                    .get_mut()
                    .retain_variant(&matched.projection, budget)?;
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                matched.projection.consume_clone_budget(budget)?;
                entry.insert(matched.projection.clone());
            }
        }
    }
    for (index, count) in semantics.suppression.repeat_counts {
        let Some(matched) = matches.get(index) else {
            continue;
        };
        if matched.result.observation_ids().is_empty() {
            continue;
        }
        if let Some(context) =
            projection.get_mut(&super::event3::process_result_key(&matched.result))
        {
            context.repeat_count = Some(count);
        }
    }

    for decision in semantics.correlations {
        let rule = &rules.correlations()[decision.rule_index];
        let matched = decision
            .candidate_indexes
            .iter()
            .filter_map(|index| matches.get(*index))
            .collect::<Vec<_>>();
        if matched.len() != decision.candidate_indexes.len() {
            continue;
        }
        let result = correlation_result(
            rule,
            &matched,
            observations,
            decision.effective_score,
            decision.risk_capped,
        )?;
        let supporting = matched
            .iter()
            .map(|m| (super::event3::process_result_key(&m.result), &m.projection))
            .collect::<Vec<_>>();
        projection.insert(
            super::event3::process_result_key(&result),
            super::event3::ProcessProjection::correlation(
                rule,
                &supporting,
                decision.risk_capped,
                budget,
            )?,
        );
        results.push(result);
        if results.len() > budget.bounds.projection_items {
            return Err(DetectionError::InvalidBounds);
        }
    }

    let mut seen = BTreeSet::new();
    results.retain(|result| {
        seen.insert((
            result.detector().id().to_owned(),
            result.observation_ids().to_vec(),
            result.dedupe_key().map(str::to_owned),
        ))
    });

    Ok(ProcessChainSessionEvaluation {
        results,
        detailed_results: None,
        #[cfg(test)]
        suppressed_count: semantics.suppression.suppressed_count,
        projection,
    })
}

/// Adapts Tool command text to the existing matcher's input type. Returned
/// values are derived interpretation only, not canonical observations or
/// directly observed operating-system process facts.
fn command_derived_process_matcher_inputs(
    observation: &CanonicalObservationV2,
) -> Vec<ProcessObservation> {
    use crate::process_chain::observations_from_command_line;
    // A statement is the same one with or without the comment after it.
    fn statement(line: &str) -> &str {
        line.split(" #").next().unwrap_or(line).trim()
    }
    let mut inputs = Vec::new();
    for command in command_candidates(observation) {
        let mut found = observations_from_command_line(command);
        // That split takes a quote in a comment or a here-document for a real
        // one and hides what follows it. The shell reader's stages do not.
        let mut seen = found
            .iter()
            .filter_map(|input| input.child.command_line.as_deref())
            .map(|line| statement(line).to_owned())
            .collect::<BTreeSet<_>>();
        let shell = super::shell_text::read(command);
        for stage in shell.stages.iter().chain(&shell.inner_commands) {
            for input in observations_from_command_line(&shell.code[stage.clone()]) {
                let line = input.child.command_line.as_deref().unwrap_or_default();
                if seen.insert(statement(line).to_owned()) {
                    found.push(input);
                }
            }
        }
        inputs.append(&mut found);
    }
    inputs
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

    // A call whose declaration gives its arguments a role has no argument text
    // to read as a command line, and no command where its command member has one.
    let by_role = super::tool_arguments::reads_by_role(tool);
    let command_by_role = super::tool_arguments::command_member_has_role(tool);
    add_candidate(
        &mut seen,
        &mut candidates,
        observation
            .facets()
            .get("command.text")
            .filter(|_| !command_by_role)
            .and_then(|facet| match facet.value() {
                JsonValue::String(value) => Some(value.as_str()),
                _ => None,
            }),
    );
    add_candidate(
        &mut seen,
        &mut candidates,
        tool.searchable_arguments().filter(|_| {
            !by_role
                && observation
                    .fact_metadata()
                    .get("tool.searchable_arguments")
                    .is_some_and(|metadata| metadata.provenance() == FactProvenance::Reported)
        }),
    );
    add_candidate(
        &mut seen,
        &mut candidates,
        match tool.arguments() {
            Some(JsonValue::String(value)) if !by_role => Some(value.as_str()),
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
    .with_dedupe_key(if detection.signal_type == "atomic" {
        atomic_dedupe_key(&detection.dedup_key)
    } else {
        detection.dedup_key.clone()
    })?;

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

fn occurred_at(observation: &CanonicalObservationV2) -> Option<OffsetDateTime> {
    observation
        .occurred_at()
        .and_then(|timestamp| OffsetDateTime::parse(timestamp.as_str(), &Rfc3339).ok())
}

fn atomic_dedupe_key(reported: &str) -> String {
    if super::types::bounded_opaque(reported, super::types::MAX_ID_BYTES).is_ok() {
        return reported.to_owned();
    }
    // Matcher keys can include a normalized executable basename containing
    // spaces. Preserve that identity without putting unsafe text in an opaque
    // detector key or dropping the source's otherwise valid findings.
    let mut digest = sha2::Sha256::new();
    digest.update(b"telltale:process-atomic-dedupe:v1\0");
    digest.update(reported.as_bytes());
    format!("process:sha256:{}", hex::encode(digest.finalize()))
}

fn correlation_result(
    rule: &CompiledCorrelationRule,
    matched: &[&ProcessChainWorkingMatch],
    observations: &[&CanonicalObservationV2],
    score: u64,
    risk_capped: bool,
) -> Result<DetectorResult, DetectionError> {
    let detector =
        DetectorIdentity::new(DetectorKind::ProcessChain, &rule.id)?.with_rule_version(1)?;
    let authored_severity = severity(&rule.severity)?;
    let effective_severity = if risk_capped {
        Severity::Informational
    } else {
        authored_severity
    };
    let techniques = rule
        .mitre_attack_techniques
        .iter()
        .map(|value| normalize_attack_technique(value))
        .collect::<Result<Vec<_>, _>>()?;
    let session_scope = matched
        .first()
        .and_then(|candidate| candidate.result.session_id())
        .ok_or(DetectionError::RuntimeEvaluation)?;
    let dedupe_key = correlation_dedupe_key(&rule.id, session_scope)?;
    let mut tags = vec!["process_chain", "correlation", rule.category.as_str()];
    if risk_capped {
        tags.push("risk_capped");
    }
    let mut metadata =
        FindingMetadata::new(FindingKind::Correlation, &rule.category, effective_severity)?
            .with_risk_points(score)?
            .with_confidence(confidence(&rule.confidence)?);
    metadata = metadata
        .with_techniques(techniques)?
        .with_tags(tags)?
        .with_correlation_scope(CorrelationScope::Sequence)
        .with_dedupe_key(&dedupe_key)?;

    let anchor = matched
        .first()
        .and_then(|candidate| observations.get(candidate.observation_index).copied())
        .ok_or(DetectionError::RuntimeEvaluation)?;
    if let Some(session_id) = anchor.session_id() {
        metadata = metadata.with_session_id(session_id.value())?;
    }
    let observation_ids = matched
        .iter()
        .flat_map(|candidate| {
            candidate
                .result
                .observation_ids()
                .iter()
                .map(String::as_str)
        })
        .collect::<Vec<_>>();
    if observation_ids.is_empty() {
        return Err(DetectionError::MissingObservationId);
    }
    DetectorResult::evaluated_with_observation_ids(
        detector,
        EvaluationStatus::EvaluatedMatch,
        None,
        observation_ids,
        metadata,
        None,
        Vec::new(),
    )
}

fn correlation_dedupe_key(rule_id: &str, session_scope: &str) -> Result<String, DetectionError> {
    let identity = JsonValue::Array(vec![
        JsonValue::string("telltale:process-correlation-dedupe"),
        JsonValue::Unsigned(1),
        JsonValue::string(rule_id),
        JsonValue::string(session_scope),
    ]);
    let bytes =
        canonical_identity_json(&identity).map_err(|_| DetectionError::RuntimeEvaluation)?;
    let digest = sha2::Sha256::digest(bytes);
    Ok(format!("correlation:sha256:{}", hex::encode(digest)))
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
mod tests;
