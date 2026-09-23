//! Rule v1 compatibility compiler.
//!
//! This compiler consumes the effective compiled-rule view.  It intentionally
//! does not parse YAML and does not carry the legacy allowlist or evaluator into
//! Detection v2.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;
use telltale_rules::{RuleV1CompatibilityExport, RuleV1CompatibilityRule, RuleV1ContentMatcher};
use telltale_schema::event::{Evidence, evidence_hash, redact_sensitive_text};
use telltale_schema::observation::{CapabilityId, JsonValue, ObservationFamily, ObservationStage};
use telltale_schema::scoring::{RiskAccountingError, RiskContribution};

use super::classification::finding_kind_for_detection_class;
use super::matcher::{MAX_PATTERN_BYTES, MatchState, MatcherSpec};
use super::observation_match::{CompiledObservationMatchDetector, ObservationMatchSpec};
use super::selector::SelectorPresence;
use super::types::{
    DetectionError, DetectorIdentity, DetectorKind, EvaluationStatus, FindingMetadata,
    NonEvaluationReason, Severity,
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

#[derive(Debug)]
pub(crate) enum RuleV1SessionError {
    Bounds,
    Accounting,
}

impl RuleV1SessionError {
    pub(crate) fn processing_error(&self) -> super::session::ProcessingError {
        match self {
            Self::Bounds => super::session::ProcessingError::Bounds,
            Self::Accounting => super::session::ProcessingError::Evaluation,
        }
    }
}

impl From<RiskAccountingError> for RuleV1SessionError {
    fn from(_: RiskAccountingError) -> Self {
        Self::Accounting
    }
}

impl RuleV1CompatibilityPlan {
    pub fn policy_name(&self) -> Option<&str> {
        self.export.policy_name()
    }
    pub fn detectors(&self) -> &[CompiledObservationMatchDetector] {
        &self.detectors
    }
    pub(crate) fn has_unavailable_url_visibility(&self) -> bool {
        self.export
            .rules()
            .iter()
            .any(|rule| rule.matchers.iter().any(|matcher| matcher.target == "url"))
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
pub struct RuleV1DetectorSessionEvaluation {
    detector_id: String,
    outcome: RuleV1DetectorOutcome,
    evaluated_match_count: u64,
    evaluated_no_match_count: u64,
    not_evaluated_count: u64,
    not_applicable_count: u64,
    detector_error_count: u64,
    non_evaluation_reason_counts: BTreeMap<String, u64>,
    matched_selector_paths: Vec<String>,
    projection: Vec<RuleV1MatchEvidence>,
}

/// Bounded, already-redacted compatibility evidence; no source observation is
/// copied. Dropped with the session result after projection.
#[derive(Clone)]
pub(crate) struct RuleV1MatchEvidence {
    pub(crate) observation_id: String,
    pub(crate) occurrence: usize,
    pub(crate) evidence: Evidence,
}

impl PartialEq for RuleV1MatchEvidence {
    fn eq(&self, other: &Self) -> bool {
        self.observation_id == other.observation_id
            && self.occurrence == other.occurrence
            && self.evidence.field == other.evidence.field
            && self.evidence.redacted_value == other.evidence.redacted_value
            && self.evidence.hash == other.evidence.hash
            && self.evidence.rule_id == other.evidence.rule_id
    }
}
impl Eq for RuleV1MatchEvidence {}

impl fmt::Debug for RuleV1MatchEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleV1MatchEvidence")
            .field("occurrence", &self.occurrence)
            .finish_non_exhaustive()
    }
}

impl RuleV1DetectorSessionEvaluation {
    pub fn detector_id(&self) -> &str {
        &self.detector_id
    }
    pub fn outcome(&self) -> RuleV1DetectorOutcome {
        self.outcome
    }
    pub fn evaluated_match_count(&self) -> u64 {
        self.evaluated_match_count
    }
    pub fn evaluated_no_match_count(&self) -> u64 {
        self.evaluated_no_match_count
    }
    pub fn not_evaluated_count(&self) -> u64 {
        self.not_evaluated_count
    }
    pub fn not_applicable_count(&self) -> u64 {
        self.not_applicable_count
    }
    pub fn detector_error_count(&self) -> u64 {
        self.detector_error_count
    }
    pub fn non_evaluation_reason_counts(&self) -> &BTreeMap<String, u64> {
        &self.non_evaluation_reason_counts
    }
    #[cfg(test)]
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
/// session. Only bounded redacted evidence and occurrence references are retained.
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
    pub(crate) fn projection(&self) -> impl Iterator<Item = &RuleV1MatchEvidence> {
        self.detectors
            .iter()
            .flat_map(|detector| detector.projection.iter())
    }
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
/// still evaluates one observation at a time; session evaluation provides
/// bounded compatibility aggregation.
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

pub(crate) fn evaluate_rule_v1_session_with_budget(
    plan: &RuleV1CompatibilityPlan,
    observations: &[&telltale_schema::observation::CanonicalObservationV2],
    budget: &mut super::session::RetentionBudget,
) -> Result<RuleV1SessionEvaluation, RuleV1SessionError> {
    let mut detectors = Vec::with_capacity(plan.detectors.len());
    let mut matched_atomic_rule_ids = BTreeSet::new();
    for detector in &plan.detectors {
        let aggregate = aggregate_detector_session(detector, observations, budget)?;
        if aggregate.outcome == RuleV1DetectorOutcome::Match {
            retain_text(budget, &aggregate.detector_id)?;
            matched_atomic_rule_ids.insert(aggregate.detector_id.clone());
        }
        detectors.push(aggregate);
    }

    let selected = matched_atomic_rule_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for rule in plan
        .export
        .rules()
        .iter()
        .filter(|rule| selected.contains(rule.id.as_str()) && rule.score > 0)
    {
        super::session::RetentionBudget::validate_text(&rule.explanation)
            .map_err(|_| RuleV1SessionError::Bounds)?;
    }
    for modifier in plan
        .export
        .triggered_modifiers(&selected)
        .into_iter()
        .filter(|modifier| modifier.score > 0)
    {
        super::session::RetentionBudget::validate_text(&modifier.explanation)
            .map_err(|_| RuleV1SessionError::Bounds)?;
    }
    let content = plan.export.evaluate_matched(&selected)?;
    let (
        triggered_modifier_ids,
        effective_rule_ids,
        compatibility_contributions,
        compatibility_score,
        compatibility_metadata,
    ) = if let Some(matches) = content {
        let triggered_modifier_ids = plan
            .export
            .modifiers()
            .iter()
            .filter(|modifier| matches.rule_ids.contains(&modifier.id))
            .map(|modifier| modifier.id.clone())
            .collect::<Vec<_>>();
        for rule_id in &triggered_modifier_ids {
            retain_text(budget, rule_id)?;
        }
        for contribution in &matches.contributions {
            retain_text(budget, contribution.id())?;
            retain_text(budget, contribution.rationale())?;
        }
        let metadata = RuleV1CompatibilityMetadata {
            categories: retain_values(budget, matches.categories)?,
            detection_classes: retain_values(budget, matches.detection_classes)?,
            signal_types: retain_values(budget, matches.signal_types)?,
            analytic_intents: retain_values(budget, matches.analytic_intents)?,
            atlas_tags: retain_values(budget, matches.atlas_tags)?,
            tags: retain_values(budget, matches.tags)?,
        };
        let ids = retain_values(budget, matches.rule_ids)?;
        (
            triggered_modifier_ids,
            ids,
            matches.contributions,
            matches.score,
            metadata,
        )
    } else {
        (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            RuleV1CompatibilityMetadata::default(),
        )
    };
    let mut effective_rule_ids = effective_rule_ids;
    effective_rule_ids.sort();
    effective_rule_ids.dedup();
    let mut triggered_modifier_ids = triggered_modifier_ids;
    triggered_modifier_ids.sort();
    triggered_modifier_ids.dedup();

    Ok(RuleV1SessionEvaluation {
        detectors,
        matched_atomic_rule_ids: matched_atomic_rule_ids.into_iter().collect(),
        triggered_modifier_ids,
        effective_rule_ids,
        compatibility_contributions,
        compatibility_score,
        compatibility_metadata,
    })
}

fn aggregate_detector_session(
    detector: &CompiledObservationMatchDetector,
    observations: &[&telltale_schema::observation::CanonicalObservationV2],
    budget: &mut super::session::RetentionBudget,
) -> Result<RuleV1DetectorSessionEvaluation, RuleV1SessionError> {
    retain_text(budget, detector.detector().id())?;
    let mut aggregate = RuleV1DetectorSessionEvaluation {
        detector_id: detector.detector().id().to_owned(),
        ..RuleV1DetectorSessionEvaluation::default()
    };
    for (occurrence, observation) in observations.iter().enumerate() {
        let result = detector.evaluate(observation);
        if result.evaluation_status() == EvaluationStatus::EvaluatedMatch {
            for path in result.matched_selector_paths() {
                if aggregate.projection.len() >= super::session::MAX_PROJECTION_ITEMS {
                    return Err(RuleV1SessionError::Bounds);
                }
                let selector =
                    super::SelectorId::parse(path).map_err(|_| RuleV1SessionError::Bounds)?;
                let resolution = super::SelectorRegistry::new().resolve(selector, observation);
                let Some(JsonValue::String(value)) = resolution.value() else {
                    continue;
                };
                super::session::RetentionBudget::validate_text(value)
                    .map_err(|_| RuleV1SessionError::Bounds)?;
                let field = path.strip_prefix("compat.v1.").unwrap_or(path);
                let redacted_value = redact_sensitive_text(value);
                let retained_bytes = observation
                    .observation_id()
                    .len()
                    .checked_add(field.len())
                    .and_then(|bytes| bytes.checked_add(redacted_value.len()))
                    .and_then(|bytes| bytes.checked_add(64))
                    .and_then(|bytes| bytes.checked_add(detector.detector().id().len()))
                    .ok_or(RuleV1SessionError::Bounds)?;
                budget
                    .consume(1, retained_bytes)
                    .map_err(|_| RuleV1SessionError::Bounds)?;
                aggregate.projection.push(RuleV1MatchEvidence {
                    observation_id: observation.observation_id().to_owned(),
                    occurrence,
                    evidence: Evidence {
                        field: field.to_owned(),
                        redacted_value,
                        hash: Some(evidence_hash(value)),
                        rule_id: Some(detector.detector().id().to_owned()),
                    },
                });
            }
        }
        add_detector_result(&mut aggregate, result);
    }
    aggregate.matched_selector_paths.sort();
    aggregate.matched_selector_paths.dedup();
    Ok(aggregate)
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

fn retain_values(
    budget: &mut super::session::RetentionBudget,
    values: Vec<String>,
) -> Result<Vec<String>, RuleV1SessionError> {
    for value in &values {
        retain_text(budget, value)?;
    }
    Ok(values)
}

fn retain_text(
    budget: &mut super::session::RetentionBudget,
    value: &str,
) -> Result<(), RuleV1SessionError> {
    budget
        .retain_text(value)
        .map_err(|_| RuleV1SessionError::Bounds)
}

fn compile_rule(
    rule: &RuleV1CompatibilityRule,
) -> Result<CompiledObservationMatchDetector, RuleV1CompileError> {
    if rule.signal_type != "atomic" {
        return Err(RuleV1CompileError::InvalidMetadata);
    }
    let finding_kind = finding_kind_for_detection_class(&rule.detection_class)
        .map_err(|_| RuleV1CompileError::UnmappableDetectionClass)?;
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
    for matcher in &rule.matchers {
        if matcher.regex.len() > MAX_PATTERN_BYTES
            || matcher
                .exclusion_regex
                .as_ref()
                .is_some_and(|regex| regex.len() > MAX_PATTERN_BYTES)
        {
            return Err(RuleV1CompileError::InvalidMetadata);
        }
    }
    let content = rule
        .compile_content_matcher()
        .map_err(|_| RuleV1CompileError::InvalidMetadata)?;
    let mut clauses = Vec::new();
    let mut targets = Vec::new();
    let mut families = Vec::new();
    // URL has no truthful COv2 compatibility value. In a mixed-target Rule v1
    // detector, evaluate only the available alternatives and report the source
    // visibility limitation separately. A URL-only detector retains its URL
    // predicate so it becomes explicitly indeterminate rather than NoMatch.
    let has_available_target = rule.matchers.iter().any(|matcher| matcher.target != "url");
    for matcher in rule
        .matchers
        .iter()
        .filter(|matcher| matcher.target != "url" || !has_available_target)
    {
        let selector = compat_selector(&matcher.target)?;
        targets.push(matcher.target.clone());
        for family in selector_families(&matcher.target) {
            if !families.contains(&family) {
                families.push(family);
            }
        }
        clauses.push(MatcherSpec::exists(selector));
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
        .map(|detector| detector.with_rule_v1_content(content, targets))
}

/// The canonical adapter resolves only truthful compatibility selectors. Rule
/// predicates (including exclusions) run in the I/O-free Rule v1 content owner.
pub(super) fn evaluate_content_matcher(
    matcher: &RuleV1ContentMatcher,
    targets: &[String],
    observation: &telltale_schema::observation::CanonicalObservationV2,
) -> (MatchState, Vec<String>) {
    let registry = super::SelectorRegistry::new();
    let mut resolutions = Vec::new();
    let mut unknown = Vec::new();
    for target in targets {
        let selector = super::SelectorId::parse(&format!("compat.v1.{target}"))
            .expect("validated Rule v1 target");
        resolutions.push(registry.resolve(selector, observation));
    }
    let mut fields = Vec::new();
    for (target, resolution) in targets.iter().zip(&resolutions) {
        match resolution.presence() {
            SelectorPresence::UnavailableVisibility => {
                unknown.push(NonEvaluationReason::InsufficientVisibility)
            }
            SelectorPresence::MetadataMissing => unknown.push(NonEvaluationReason::IneligibleInput),
            SelectorPresence::Present => match resolution.value() {
                Some(JsonValue::String(value)) => fields.push((target.as_str(), value.as_str())),
                _ => unknown.push(NonEvaluationReason::TypeMismatch),
            },
            SelectorPresence::Absent => {}
        }
    }
    let mut paths = matcher
        .matching_fields(&fields)
        .iter()
        .map(|(name, _)| format!("compat.v1.{name}"))
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    if !paths.is_empty() {
        (MatchState::Match, paths)
    } else if let Some(reason) = unknown.into_iter().min() {
        (MatchState::NotEvaluated(reason), Vec::new())
    } else {
        (MatchState::NoMatch, Vec::new())
    }
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
    use crate::v2::{DetectorResult, Diagnostic, DiagnosticKind, FindingKind, NonEvaluationReason};

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
