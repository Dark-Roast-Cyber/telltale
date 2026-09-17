//! Rule v1 compatibility compiler.
//!
//! This compiler consumes the effective compiled-rule view.  It intentionally
//! does not parse YAML and does not carry the legacy allowlist or evaluator into
//! Detection v2.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;
use telltale_rules::{RuleV1CompatibilityExport, RuleV1CompatibilityRule};
use telltale_schema::event::redact_sensitive_text;
use telltale_schema::observation::{CapabilityId, JsonValue, ObservationFamily, ObservationStage};
use telltale_schema::scoring::{
    RiskAccountingError, RiskContribution, RiskContributionType, canonicalize_contributions,
    checked_risk_sum,
};

use super::matcher::{MatcherOperator, MatcherSpec};
use super::observation_match::{CompiledObservationMatchDetector, ObservationMatchSpec};
use super::types::{
    DetectionError, DetectorIdentity, DetectorKind, EvaluationStatus, FindingKind, FindingMetadata,
    Severity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleV1CompileError {
    InvalidRule,
    UnknownTarget,
    UnmappableDetectionClass,
    InvalidSeverity,
    ScoreOutOfRange,
    InvalidMetadata,
}

impl RuleV1CompileError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidRule => "invalid_rule",
            Self::UnknownTarget => "unknown_target",
            Self::UnmappableDetectionClass => "unmappable_detection_class",
            Self::InvalidSeverity => "invalid_severity",
            Self::ScoreOutOfRange => "score_out_of_range",
            Self::InvalidMetadata => "invalid_metadata",
        }
    }
}

impl fmt::Display for RuleV1CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for RuleV1CompileError {}

#[derive(Debug, Clone)]
pub struct RuleV1CompatibilityPlan {
    export: RuleV1CompatibilityExport,
    detectors: Vec<CompiledObservationMatchDetector>,
}

impl RuleV1CompatibilityPlan {
    pub fn policy_name(&self) -> Option<&str> {
        self.export.policy_name()
    }
    pub fn detectors(&self) -> &[CompiledObservationMatchDetector] {
        &self.detectors
    }
}

/// Session-level Rule v1 compatibility outcome after applying deterministic
/// status precedence.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleV1DetectorOutcome {
    Match,
    Error,
    Indeterminate,
    NoMatch,
    #[default]
    NotApplicable,
}

impl RuleV1DetectorOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Error => "error",
            Self::Indeterminate => "indeterminate",
            Self::NoMatch => "no_match",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Bounded aggregate for one Rule v1 compatibility detector in one session.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(crate) struct RuleV1DetectorSessionEvaluation {
    detector_id: String,
    outcome: RuleV1DetectorOutcome,
    evaluated_match_count: u64,
    evaluated_no_match_count: u64,
    not_evaluated_count: u64,
    not_applicable_count: u64,
    detector_error_count: u64,
    non_evaluation_reason_counts: BTreeMap<String, u64>,
    matched_selector_paths: Vec<String>,
}

impl RuleV1DetectorSessionEvaluation {
    pub(crate) fn detector_id(&self) -> &str {
        &self.detector_id
    }
    pub(crate) fn outcome(&self) -> RuleV1DetectorOutcome {
        self.outcome
    }
    #[cfg(test)]
    pub(crate) fn evaluated_match_count(&self) -> u64 {
        self.evaluated_match_count
    }
    #[cfg(test)]
    pub(crate) fn evaluated_no_match_count(&self) -> u64 {
        self.evaluated_no_match_count
    }
    #[cfg(test)]
    pub(crate) fn not_evaluated_count(&self) -> u64 {
        self.not_evaluated_count
    }
    #[cfg(test)]
    pub(crate) fn not_applicable_count(&self) -> u64 {
        self.not_applicable_count
    }
    #[cfg(test)]
    pub(crate) fn detector_error_count(&self) -> u64 {
        self.detector_error_count
    }
    pub(crate) fn non_evaluation_reason_counts(&self) -> &BTreeMap<String, u64> {
        &self.non_evaluation_reason_counts
    }
    pub(crate) fn matched_selector_paths(&self) -> &[String] {
        &self.matched_selector_paths
    }
}

/// Rule v1 metadata reconstructed from matched atomic rules and triggered
/// modifiers. This is compatibility metadata, not native Detection v2 output.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(crate) struct RuleV1CompatibilityMetadata {
    categories: Vec<String>,
    detection_classes: Vec<String>,
    signal_types: Vec<String>,
    analytic_intents: Vec<String>,
    atlas_tags: Vec<String>,
    tags: Vec<String>,
}

impl RuleV1CompatibilityMetadata {
    pub(crate) fn categories(&self) -> &[String] {
        &self.categories
    }
    pub(crate) fn detection_classes(&self) -> &[String] {
        &self.detection_classes
    }
    pub(crate) fn signal_types(&self) -> &[String] {
        &self.signal_types
    }
    pub(crate) fn analytic_intents(&self) -> &[String] {
        &self.analytic_intents
    }
    pub(crate) fn atlas_tags(&self) -> &[String] {
        &self.atlas_tags
    }
    pub(crate) fn tags(&self) -> &[String] {
        &self.tags
    }
}

/// Complete Rule v1 compatibility semantics for one caller-defined canonical
/// session. No individual observation results or raw evidence are retained.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RuleV1SessionEvaluation {
    detectors: Vec<RuleV1DetectorSessionEvaluation>,
    matched_atomic_rule_ids: Vec<String>,
    triggered_modifier_ids: Vec<String>,
    effective_rule_ids: Vec<String>,
    compatibility_contributions: Vec<RiskContribution>,
    compatibility_score: u64,
    compatibility_metadata: RuleV1CompatibilityMetadata,
}

impl RuleV1SessionEvaluation {
    pub(crate) fn detectors(&self) -> &[RuleV1DetectorSessionEvaluation] {
        &self.detectors
    }
    #[cfg(test)]
    pub(crate) fn matched_atomic_rule_ids(&self) -> &[String] {
        &self.matched_atomic_rule_ids
    }
    pub(crate) fn triggered_modifier_ids(&self) -> &[String] {
        &self.triggered_modifier_ids
    }
    pub(crate) fn effective_rule_ids(&self) -> &[String] {
        &self.effective_rule_ids
    }
    pub(crate) fn compatibility_contributions(&self) -> &[RiskContribution] {
        &self.compatibility_contributions
    }
    pub(crate) fn compatibility_score(&self) -> u64 {
        self.compatibility_score
    }
    pub(crate) fn compatibility_metadata(&self) -> &RuleV1CompatibilityMetadata {
        &self.compatibility_metadata
    }
}

/// Compile every effective Rule v1 rule to an observation matcher.  A single
/// compatibility detector may apply to Message and Tool observations because
/// legacy targets span those two canonical families. Each compiled detector
/// still evaluates one observation at a time; `evaluate_rule_v1_session`
/// provides the bounded compatibility aggregation.
pub fn compile_rule_v1(
    rules: &RuleV1CompatibilityExport,
) -> Result<RuleV1CompatibilityPlan, RuleV1CompileError> {
    let detectors = rules
        .rules()
        .iter()
        .map(compile_rule)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RuleV1CompatibilityPlan {
        export: rules.clone(),
        detectors,
    })
}

/// Evaluate Rule v1 compatibility semantics for one caller-defined canonical
/// session. Session grouping, identity, source access, and production behavior
/// remain outside this non-production boundary.
pub(crate) fn evaluate_rule_v1_session(
    plan: &RuleV1CompatibilityPlan,
    observations: &[&telltale_schema::observation::CanonicalObservationV2],
) -> Result<RuleV1SessionEvaluation, RiskAccountingError> {
    let mut detectors = Vec::with_capacity(plan.detectors.len());
    let mut matched_atomic_rule_ids = BTreeSet::new();
    for detector in &plan.detectors {
        let aggregate = aggregate_detector_session(detector, observations);
        if aggregate.outcome == RuleV1DetectorOutcome::Match {
            matched_atomic_rule_ids.insert(aggregate.detector_id.clone());
        }
        detectors.push(aggregate);
    }

    let export = &plan.export;
    let matched_categories = export
        .rules()
        .iter()
        .filter(|rule| matched_atomic_rule_ids.contains(&rule.id))
        .map(|rule| rule.category.as_str())
        .collect::<BTreeSet<_>>();
    let triggered_modifier_ids = export
        .modifiers()
        .iter()
        .filter(|modifier| {
            let has_conditions =
                !modifier.when_all_categories.is_empty() || !modifier.when_all_rule_ids.is_empty();
            has_conditions
                && modifier
                    .when_all_categories
                    .iter()
                    .all(|category| matched_categories.contains(category.as_str()))
                && modifier
                    .when_all_rule_ids
                    .iter()
                    .all(|rule_id| matched_atomic_rule_ids.contains(rule_id))
        })
        .map(|modifier| modifier.id.clone())
        .collect::<BTreeSet<_>>();

    let contributions = export
        .rules()
        .iter()
        .filter(|rule| matched_atomic_rule_ids.contains(&rule.id) && rule.score > 0)
        .map(|rule| {
            RiskContribution::new(
                &rule.id,
                RiskContributionType::DeterministicRule,
                rule.score,
                redact_sensitive_text(&rule.explanation),
            )
        })
        .chain(
            export
                .modifiers()
                .iter()
                .filter(|modifier| {
                    triggered_modifier_ids.contains(&modifier.id) && modifier.score > 0
                })
                .map(|modifier| {
                    RiskContribution::new(
                        &modifier.id,
                        RiskContributionType::ChainModifier,
                        modifier.score,
                        redact_sensitive_text(&modifier.explanation),
                    )
                }),
        )
        .collect::<Result<Vec<_>, _>>()?;
    let compatibility_contributions = canonicalize_contributions(contributions)?;
    let compatibility_score = checked_risk_sum(&compatibility_contributions)?;
    let compatibility_metadata =
        compatibility_metadata(&matched_atomic_rule_ids, &triggered_modifier_ids, export);
    let effective_rule_ids = matched_atomic_rule_ids
        .iter()
        .chain(triggered_modifier_ids.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    Ok(RuleV1SessionEvaluation {
        detectors,
        matched_atomic_rule_ids: matched_atomic_rule_ids.into_iter().collect(),
        triggered_modifier_ids: triggered_modifier_ids.into_iter().collect(),
        effective_rule_ids,
        compatibility_contributions,
        compatibility_score,
        compatibility_metadata,
    })
}

fn aggregate_detector_session(
    detector: &CompiledObservationMatchDetector,
    observations: &[&telltale_schema::observation::CanonicalObservationV2],
) -> RuleV1DetectorSessionEvaluation {
    let mut aggregate = RuleV1DetectorSessionEvaluation {
        detector_id: detector.detector().id().to_owned(),
        ..RuleV1DetectorSessionEvaluation::default()
    };
    for observation in observations {
        add_detector_result(&mut aggregate, detector.evaluate(observation));
    }
    aggregate.matched_selector_paths.sort();
    aggregate.matched_selector_paths.dedup();
    aggregate
}

fn add_detector_result(
    aggregate: &mut RuleV1DetectorSessionEvaluation,
    result: super::types::DetectorResult,
) {
    match result.evaluation_status() {
        EvaluationStatus::EvaluatedMatch => {
            aggregate.evaluated_match_count += 1;
            aggregate.outcome = max_outcome(aggregate.outcome, RuleV1DetectorOutcome::Match);
            aggregate
                .matched_selector_paths
                .extend(result.matched_selector_paths().iter().cloned());
        }
        EvaluationStatus::EvaluatedNoMatch => {
            aggregate.evaluated_no_match_count += 1;
            aggregate.outcome = max_outcome(aggregate.outcome, RuleV1DetectorOutcome::NoMatch);
        }
        EvaluationStatus::NotEvaluated => {
            aggregate.not_evaluated_count += 1;
            aggregate.outcome =
                max_outcome(aggregate.outcome, RuleV1DetectorOutcome::Indeterminate);
            if let Some(reason) = result.non_evaluation_reason() {
                *aggregate
                    .non_evaluation_reason_counts
                    .entry(reason.as_str().to_owned())
                    .or_default() += 1;
            }
        }
        EvaluationStatus::NotApplicable => aggregate.not_applicable_count += 1,
        EvaluationStatus::DetectorError => {
            aggregate.detector_error_count += 1;
            aggregate.outcome = max_outcome(aggregate.outcome, RuleV1DetectorOutcome::Error);
        }
    }
}

fn max_outcome(left: RuleV1DetectorOutcome, right: RuleV1DetectorOutcome) -> RuleV1DetectorOutcome {
    if outcome_rank(right) > outcome_rank(left) {
        right
    } else {
        left
    }
}

fn outcome_rank(outcome: RuleV1DetectorOutcome) -> u8 {
    match outcome {
        RuleV1DetectorOutcome::NotApplicable => 0,
        RuleV1DetectorOutcome::NoMatch => 1,
        RuleV1DetectorOutcome::Indeterminate => 2,
        RuleV1DetectorOutcome::Error => 3,
        RuleV1DetectorOutcome::Match => 4,
    }
}

fn compatibility_metadata(
    atomic_ids: &BTreeSet<String>,
    modifier_ids: &BTreeSet<String>,
    export: &RuleV1CompatibilityExport,
) -> RuleV1CompatibilityMetadata {
    let mut metadata = RuleV1CompatibilityMetadata::default();
    for rule in export
        .rules()
        .iter()
        .filter(|rule| atomic_ids.contains(&rule.id))
    {
        metadata.categories.push(rule.category.clone());
        metadata
            .detection_classes
            .push(rule.detection_class.clone());
        metadata.signal_types.push(rule.signal_type.clone());
        metadata.analytic_intents.push(rule.analytic_intent.clone());
        metadata.atlas_tags.extend(rule.atlas_tags.iter().cloned());
        metadata.tags.extend(rule.tags.iter().cloned());
    }
    for modifier in export
        .modifiers()
        .iter()
        .filter(|modifier| modifier_ids.contains(&modifier.id))
    {
        metadata
            .detection_classes
            .push(modifier.detection_class.clone());
        metadata.signal_types.push(modifier.signal_type.clone());
        metadata
            .analytic_intents
            .push(modifier.analytic_intent.clone());
        metadata
            .atlas_tags
            .extend(modifier.atlas_tags.iter().cloned());
    }
    metadata.categories = sorted_unique(metadata.categories);
    metadata.detection_classes = sorted_unique(metadata.detection_classes);
    metadata.signal_types = sorted_unique(metadata.signal_types);
    metadata.analytic_intents = sorted_unique(metadata.analytic_intents);
    metadata.atlas_tags = sorted_unique(metadata.atlas_tags);
    metadata.tags = sorted_unique(metadata.tags);
    metadata
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn compile_rule(
    rule: &RuleV1CompatibilityRule,
) -> Result<CompiledObservationMatchDetector, RuleV1CompileError> {
    if rule.signal_type != "atomic" {
        return Err(RuleV1CompileError::InvalidMetadata);
    }
    let finding_kind = finding_kind(&rule.detection_class)?;
    let severity = severity(&rule.severity)?;
    if rule.score > 100 {
        return Err(RuleV1CompileError::ScoreOutOfRange);
    }
    let tags = rule.tags.iter().map(String::as_str).collect::<Vec<_>>();
    let techniques = rule
        .atlas_tags
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let metadata = FindingMetadata::new(finding_kind, &rule.category, severity)
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?
        .with_risk_points(rule.score)
        .map_err(|_| RuleV1CompileError::ScoreOutOfRange)?
        .with_tags(tags)
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?
        .with_techniques(techniques)
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?;

    if rule.matchers.is_empty() {
        return Err(RuleV1CompileError::InvalidRule);
    }
    let mut clauses = Vec::new();
    let mut families = Vec::new();
    for matcher in &rule.matchers {
        let selector = compat_selector(&matcher.target)?;
        for family in selector_families(&matcher.target) {
            if !families.contains(&family) {
                families.push(family);
            }
        }
        clauses.push(MatcherSpec::predicate(
            selector,
            MatcherOperator::Regex,
            Some(JsonValue::string(&matcher.regex)),
        ));
    }
    let matcher = MatcherSpec::any(clauses);
    let identity = DetectorIdentity::new(DetectorKind::ObservationMatch, &rule.id)
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?
        .with_version("1")
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?
        .with_rule_version(1)
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?;
    let stages = families
        .iter()
        .flat_map(|family| family_stages(*family).iter().copied())
        .collect::<Vec<_>>();
    ObservationMatchSpec::new_for_families(identity, families, stages, matcher, metadata)
        .with_required_capabilities(required_capabilities(rule))
        .compile()
        .map_err(|error| match error {
            DetectionError::InvalidSelector => RuleV1CompileError::UnknownTarget,
            DetectionError::ScoreOutOfRange => RuleV1CompileError::ScoreOutOfRange,
            _ => RuleV1CompileError::InvalidMetadata,
        })
}

fn compat_selector(target: &str) -> Result<String, RuleV1CompileError> {
    match target {
        "arguments" | "assistant_context" | "command" | "file_path" | "tool_name"
        | "tool_result" | "url" | "user_context" => Ok(format!("compat.v1.{target}")),
        _ => Err(RuleV1CompileError::UnknownTarget),
    }
}

fn selector_families(target: &str) -> [ObservationFamily; 1] {
    match target {
        "assistant_context" | "user_context" => [ObservationFamily::Message],
        _ => [ObservationFamily::Tool],
    }
}

fn family_stages(family: ObservationFamily) -> &'static [ObservationStage] {
    const MESSAGE: &[ObservationStage] = &[ObservationStage::MessageObserved];
    const TOOL: &[ObservationStage] = &[
        ObservationStage::ToolProposed,
        ObservationStage::ToolRequested,
        ObservationStage::ToolExecutionStarted,
        ObservationStage::ToolExecutionCompleted,
        ObservationStage::ToolResultReturned,
    ];
    match family {
        ObservationFamily::Message => MESSAGE,
        ObservationFamily::Tool => TOOL,
        _ => &[],
    }
}

fn required_capabilities(rule: &RuleV1CompatibilityRule) -> Vec<CapabilityId> {
    let mut capabilities = BTreeSet::new();
    for matcher in &rule.matchers {
        match matcher.target.as_str() {
            "assistant_context" | "user_context" => {
                capabilities.insert(CapabilityId::UserContext);
            }
            _ => {
                capabilities.insert(CapabilityId::ToolCall);
            }
        }
    }
    capabilities.into_iter().collect()
}

fn finding_kind(class: &str) -> Result<FindingKind, RuleV1CompileError> {
    match class {
        "security_detection" => Ok(FindingKind::SecurityDetection),
        "policy_violation" => Ok(FindingKind::PolicyViolation),
        "threat_hunting" => Ok(FindingKind::ThreatHunt),
        "compliance_observation" => Ok(FindingKind::ComplianceObservation),
        "baseline_deviation" => Ok(FindingKind::BehavioralDeviation),
        // Operational health is not a truthful security meaning for an atomic
        // Rule v1 observation match.  Do not silently map it to informational.
        "operational_health" => Err(RuleV1CompileError::UnmappableDetectionClass),
        _ => Err(RuleV1CompileError::UnmappableDetectionClass),
    }
}

fn severity(value: &str) -> Result<Severity, RuleV1CompileError> {
    match value {
        "informational" => Ok(Severity::Informational),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(RuleV1CompileError::InvalidSeverity),
    }
}

#[cfg(test)]
mod tests {
    use telltale_schema::observation::ObservationId;

    use super::*;
    use crate::v2::{DetectorResult, Diagnostic, DiagnosticKind, NonEvaluationReason};

    fn identity() -> DetectorIdentity {
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.aggregate").unwrap()
    }

    fn metadata() -> FindingMetadata {
        FindingMetadata::new(FindingKind::SecurityDetection, "synthetic", Severity::Low).unwrap()
    }

    #[test]
    fn detector_session_precedence_retains_counts_and_reasons() {
        let mut aggregate = RuleV1DetectorSessionEvaluation {
            detector_id: "synthetic.aggregate".to_owned(),
            ..RuleV1DetectorSessionEvaluation::default()
        };
        add_detector_result(
            &mut aggregate,
            DetectorResult::new(identity(), EvaluationStatus::NotApplicable, metadata()).unwrap(),
        );
        assert_eq!(aggregate.outcome(), RuleV1DetectorOutcome::NotApplicable);
        add_detector_result(
            &mut aggregate,
            DetectorResult::new(identity(), EvaluationStatus::EvaluatedNoMatch, metadata())
                .unwrap(),
        );
        assert_eq!(aggregate.outcome(), RuleV1DetectorOutcome::NoMatch);
        for reason in [
            NonEvaluationReason::TypeMismatch,
            NonEvaluationReason::RequiredCapabilityUnknown,
        ] {
            add_detector_result(
                &mut aggregate,
                DetectorResult::not_evaluated(identity(), reason, metadata()).unwrap(),
            );
        }
        assert_eq!(aggregate.outcome(), RuleV1DetectorOutcome::Indeterminate);
        add_detector_result(
            &mut aggregate,
            DetectorResult::detector_error(
                identity(),
                metadata(),
                Diagnostic::new(DiagnosticKind::RuntimeDetectorError, "synthetic_error").unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(aggregate.outcome(), RuleV1DetectorOutcome::Error);
        let observation_id = ObservationId::new(
            "obs:v2:sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        add_detector_result(
            &mut aggregate,
            DetectorResult::evaluated_match(identity(), &[observation_id], metadata())
                .unwrap()
                .with_matched_selector_paths(vec!["compat.v1.command".to_owned()])
                .unwrap(),
        );

        assert_eq!(aggregate.outcome(), RuleV1DetectorOutcome::Match);
        assert_eq!(aggregate.evaluated_match_count(), 1);
        assert_eq!(aggregate.evaluated_no_match_count(), 1);
        assert_eq!(aggregate.not_evaluated_count(), 2);
        assert_eq!(aggregate.not_applicable_count(), 1);
        assert_eq!(aggregate.detector_error_count(), 1);
        assert_eq!(
            aggregate.non_evaluation_reason_counts(),
            &BTreeMap::from([
                ("required_capability_unknown".to_owned(), 1),
                ("type_mismatch".to_owned(), 1),
            ])
        );
    }
}
