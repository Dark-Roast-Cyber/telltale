//! Deterministic, I/O-free Detection v2 shadow comparison.
//!
//! This experimental module is for fixture measurement only. It is not wired
//! into scanning or watching, does not emit Event 3/Event 4, and deliberately
//! has no dependency on `telltale-sources`.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest, Sha256};
use telltale_rules::{CompiledRuleSet, MatchResult, RuleV1CompatibilityExport};
use telltale_schema::observation::{CanonicalObservationV2, CapabilityId, CorrelationOrigin};
use telltale_schema::record::NormalizedRecord;
use telltale_schema::scoring::RiskContributionType;

use crate::detection::{evaluate_session_matches, legacy_evaluation_fields};
use crate::v2::{
    DetectorResult, EvaluationStatus, NonEvaluationReason, RuleV1CompatibilityPlan,
    RuleV1CompileError, compile_rule_v1,
};

const SESSION_HASH_DOMAIN: &str = "telltale:detection-v2-shadow-session-v1:";

/// A comparison failure is intentionally code-only. It cannot contain source
/// paths, session content, or legacy evidence values.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ShadowComparisonError {
    CompatibilityCompilation,
    LegacyEvaluation,
}

impl ShadowComparisonError {
    pub fn code(self) -> &'static str {
        match self {
            Self::CompatibilityCompilation => "compatibility_compilation",
            Self::LegacyEvaluation => "legacy_evaluation",
        }
    }
}

impl std::fmt::Display for ShadowComparisonError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ShadowComparisonError {}

impl From<RuleV1CompileError> for ShadowComparisonError {
    fn from(_: RuleV1CompileError) -> Self {
        Self::CompatibilityCompilation
    }
}

/// Session-level result after applying the deterministic status precedence.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionDetectorOutcome {
    Match,
    Error,
    Indeterminate,
    NoMatch,
    #[default]
    NotApplicable,
}

impl SessionDetectorOutcome {
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

/// Atomic relation between a legacy session result and its v2 session result.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicRelation {
    BothMatch,
    BothNoMatch,
    LegacyOnly,
    V2Only,
    V2Indeterminate,
    V2Error,
    V2NotApplicable,
}

impl AtomicRelation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BothMatch => "both_match",
            Self::BothNoMatch => "both_no_match",
            Self::LegacyOnly => "legacy_only",
            Self::V2Only => "v2_only",
            Self::V2Indeterminate => "v2_indeterminate",
            Self::V2Error => "v2_error",
            Self::V2NotApplicable => "v2_not_applicable",
        }
    }
}

/// Evidence-backed mismatch class. Unknown differences remain unexpected.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchClassification {
    VisibilityGap,
    LegacyFlatteningDifference,
    V2SemanticExpansion,
    LegacyPostFilterDifference,
    ModifierDifference,
    RiskDifference,
    MetadataDifference,
    SessionAlignmentGap,
    UnexpectedSemanticDifference,
    DetectorError,
}

impl MismatchClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VisibilityGap => "visibility_gap",
            Self::LegacyFlatteningDifference => "legacy_flattening_difference",
            Self::V2SemanticExpansion => "v2_semantic_expansion",
            Self::LegacyPostFilterDifference => "legacy_post_filter_difference",
            Self::ModifierDifference => "modifier_difference",
            Self::RiskDifference => "risk_difference",
            Self::MetadataDifference => "metadata_difference",
            Self::SessionAlignmentGap => "session_alignment_gap",
            Self::UnexpectedSemanticDifference => "unexpected_semantic_difference",
            Self::DetectorError => "detector_error",
        }
    }
}

/// Counts of each per-observation status for one detector/session.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize)]
pub struct DetectorSessionAggregate {
    pub outcome: SessionDetectorOutcome,
    pub matched_observations: u64,
    pub evaluated_no_match_observations: u64,
    pub not_evaluated_observations: u64,
    pub not_applicable_observations: u64,
    pub detector_error_observations: u64,
    pub non_evaluation_reason_counts: BTreeMap<String, u64>,
    pub matched_selector_paths: Vec<String>,
}

impl DetectorSessionAggregate {
    pub fn outcome(&self) -> SessionDetectorOutcome {
        self.outcome
    }

    pub fn reason_counts(&self) -> &BTreeMap<String, u64> {
        &self.non_evaluation_reason_counts
    }
}

/// Aggregate independent detector results with match > error > indeterminate
/// > no-match > not-applicable precedence.
pub fn aggregate_detector_results(results: &[DetectorResult]) -> DetectorSessionAggregate {
    let mut aggregate = DetectorSessionAggregate::default();
    for result in results {
        match result.evaluation_status() {
            EvaluationStatus::EvaluatedMatch => {
                aggregate.matched_observations += 1;
                aggregate.outcome = max_outcome(aggregate.outcome, SessionDetectorOutcome::Match);
                aggregate
                    .matched_selector_paths
                    .extend(result.matched_selector_paths().iter().cloned());
            }
            EvaluationStatus::EvaluatedNoMatch => {
                aggregate.evaluated_no_match_observations += 1;
                aggregate.outcome = max_outcome(aggregate.outcome, SessionDetectorOutcome::NoMatch);
            }
            EvaluationStatus::NotEvaluated => {
                aggregate.not_evaluated_observations += 1;
                aggregate.outcome =
                    max_outcome(aggregate.outcome, SessionDetectorOutcome::Indeterminate);
                if let Some(reason) = result.non_evaluation_reason() {
                    *aggregate
                        .non_evaluation_reason_counts
                        .entry(reason.as_str().to_owned())
                        .or_default() += 1;
                }
            }
            EvaluationStatus::NotApplicable => {
                aggregate.not_applicable_observations += 1;
            }
            EvaluationStatus::DetectorError => {
                aggregate.detector_error_observations += 1;
                aggregate.outcome = max_outcome(aggregate.outcome, SessionDetectorOutcome::Error);
            }
        }
    }
    aggregate.matched_selector_paths.sort();
    aggregate.matched_selector_paths.dedup();
    aggregate
}

fn max_outcome(
    left: SessionDetectorOutcome,
    right: SessionDetectorOutcome,
) -> SessionDetectorOutcome {
    if outcome_rank(right) > outcome_rank(left) {
        right
    } else {
        left
    }
}

fn outcome_rank(outcome: SessionDetectorOutcome) -> u8 {
    match outcome {
        SessionDetectorOutcome::NotApplicable => 0,
        SessionDetectorOutcome::NoMatch => 1,
        SessionDetectorOutcome::Indeterminate => 2,
        SessionDetectorOutcome::Error => 3,
        SessionDetectorOutcome::Match => 4,
    }
}

/// A privacy-safe risk ledger entry. Rationale is intentionally absent.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct ShadowContribution {
    pub id: String,
    #[serde(rename = "type")]
    pub contribution_type: RiskContributionType,
    pub points: u64,
}

/// Metadata fields that are reconstructable from the effective Rule v1 export.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize)]
pub struct MetadataSnapshot {
    pub categories: Vec<String>,
    pub detection_classes: Vec<String>,
    pub signal_types: Vec<String>,
    pub analytic_intents: Vec<String>,
    pub atlas_tags: Vec<String>,
    pub tags: Vec<String>,
}

/// A single detector/session comparison. All identity-bearing values are
/// bounded IDs or session fingerprints; no evidence values are retained.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AtomicComparison {
    pub session_reference: Option<String>,
    pub detector_id: String,
    pub legacy_matched: bool,
    pub relation: AtomicRelation,
    pub classification: Option<MismatchClassification>,
    pub reason_code: Option<String>,
    pub legacy_matched_target: Option<String>,
    pub v2_outcome: SessionDetectorOutcome,
    pub v2_non_evaluation_reasons: BTreeMap<String, u64>,
    pub v2_matched_selector_paths: Vec<String>,
    pub canonical_family_counts: BTreeMap<String, u64>,
    pub canonical_stage_counts: BTreeMap<String, u64>,
    pub capability_availability: BTreeMap<String, BTreeMap<String, u64>>,
}

impl AtomicComparison {
    /// Whether this relation represents an actionable equivalence mismatch.
    /// A detector that was not applicable to any canonical observation is not
    /// a semantic no-match, but it is also not a mismatch when legacy did not
    /// match. The separate atomic count retains that denominator information.
    pub fn is_mismatch(&self) -> bool {
        match self.relation {
            AtomicRelation::BothMatch | AtomicRelation::BothNoMatch => false,
            AtomicRelation::V2NotApplicable => self.legacy_matched,
            AtomicRelation::LegacyOnly
            | AtomicRelation::V2Only
            | AtomicRelation::V2Indeterminate
            | AtomicRelation::V2Error => true,
        }
    }
}

/// One aligned or explicitly unaligned session view.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct SessionComparison {
    pub session_reference: Option<String>,
    pub legacy_record_count: u64,
    pub canonical_observation_count: u64,
    pub canonical_family_counts: BTreeMap<String, u64>,
    pub canonical_stage_counts: BTreeMap<String, u64>,
    pub capability_availability: BTreeMap<String, BTreeMap<String, u64>>,
    pub detectors: Vec<AtomicComparison>,
    pub v2_compat_modifier_ids: Vec<String>,
    pub v2_compat_effective_rule_ids: Vec<String>,
    pub v2_compat_contribution_ledger: Vec<ShadowContribution>,
    pub v2_compat_score: u64,
    pub modifier_ids_legacy: Vec<String>,
    pub legacy_contribution_ledger: Vec<ShadowContribution>,
    pub legacy_score: u64,
    pub modifier_equivalent: bool,
    pub risk_equivalent: bool,
    pub metadata_equivalent: bool,
}

/// Atomic relation totals. `v2_not_applicable` is separate so it cannot be
/// mistaken for an evaluated no-match.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize)]
pub struct AtomicEquivalenceCounts {
    pub both_match: u64,
    pub both_no_match: u64,
    pub legacy_only: u64,
    pub v2_only: u64,
    pub v2_indeterminate: u64,
    pub v2_error: u64,
    pub v2_not_applicable: u64,
}

/// Equality totals for compatibility post-processing surfaces.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize)]
pub struct EquivalenceCounts {
    pub equal: u64,
    pub legacy_only: u64,
    pub v2_only: u64,
    pub different: u64,
}

/// Bounded health counts, separate from equivalence results.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize)]
pub struct ShadowHealth {
    pub total_detector_session_evaluations: u64,
    pub fully_evaluable: u64,
    pub indeterminate: u64,
    pub capability_unsupported: u64,
    pub capability_unknown: u64,
    pub provenance_ineligible: u64,
    pub type_mismatch: u64,
    pub session_alignment_gaps: u64,
    pub canonical_projection_errors: u64,
}

/// Complete source-free comparison result.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize)]
pub struct ShadowComparison {
    pub schema_version: String,
    pub sessions: Vec<SessionComparison>,
    pub atomic_equivalence: AtomicEquivalenceCounts,
    pub modifier_equivalence: EquivalenceCounts,
    pub risk_equivalence: EquivalenceCounts,
    pub metadata_equivalence: EquivalenceCounts,
    pub non_evaluation_reason_counts: BTreeMap<String, u64>,
    pub mismatch_class_counts: BTreeMap<String, u64>,
    pub unaligned_legacy_session_references: Vec<String>,
    pub unaligned_canonical_session_references: Vec<String>,
    pub unscoped_observation_count: u64,
    pub health: ShadowHealth,
}

/// Versioned report envelope suitable for fixture tooling. The comparator has
/// no source or case context, so those breakdowns are supplied by the harness.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ShadowReport {
    pub schema_version: String,
    pub reference_source_ids: Vec<String>,
    pub case_count: u64,
    pub session_count: u64,
    pub atomic_equivalence: AtomicEquivalenceCounts,
    pub modifier_equivalence: EquivalenceCounts,
    pub risk_equivalence: EquivalenceCounts,
    pub metadata_equivalence: EquivalenceCounts,
    pub non_evaluation_reason_counts: BTreeMap<String, u64>,
    pub mismatch_class_counts: BTreeMap<String, u64>,
    pub source_breakdown: BTreeMap<String, BTreeMap<String, u64>>,
    pub target_breakdown: BTreeMap<String, BTreeMap<String, u64>>,
    pub rule_breakdown: BTreeMap<String, BTreeMap<String, u64>>,
    pub reviewed_exceptions: Vec<ReviewedException>,
    pub health: ShadowHealth,
    pub unaligned_legacy_session_references: Vec<String>,
    pub unaligned_canonical_session_references: Vec<String>,
    pub unscoped_observation_count: u64,
    pub mismatches: Vec<AtomicComparison>,
}

/// A report-only reviewed ledger entry. Fixture harnesses may populate it from
/// a checked expectation file; it is never used to suppress comparison output.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ReviewedException {
    pub case_id: String,
    /// A `sha256:` session fingerprint, or `unscoped` when no truthful scope exists.
    pub session_reference: String,
    pub rule_id: String,
    pub expected_relation: AtomicRelation,
    pub classification: MismatchClassification,
    pub reason_code: String,
}

impl ShadowComparison {
    /// Render this comparison as a versioned development report.
    pub fn to_report(
        &self,
        mut reference_source_ids: Vec<String>,
        case_count: u64,
    ) -> ShadowReport {
        reference_source_ids.sort();
        reference_source_ids.dedup();
        let mismatches = self
            .sessions
            .iter()
            .flat_map(|session| session.detectors.iter())
            .filter(|comparison| comparison.is_mismatch())
            .cloned()
            .collect::<Vec<_>>();
        ShadowReport {
            schema_version: "detection-v2-shadow-report.v1".to_owned(),
            reference_source_ids,
            case_count,
            session_count: self.sessions.len() as u64,
            atomic_equivalence: self.atomic_equivalence.clone(),
            modifier_equivalence: self.modifier_equivalence.clone(),
            risk_equivalence: self.risk_equivalence.clone(),
            metadata_equivalence: self.metadata_equivalence.clone(),
            non_evaluation_reason_counts: self.non_evaluation_reason_counts.clone(),
            mismatch_class_counts: self.mismatch_class_counts.clone(),
            source_breakdown: BTreeMap::new(),
            target_breakdown: BTreeMap::new(),
            rule_breakdown: BTreeMap::new(),
            reviewed_exceptions: Vec::new(),
            health: self.health.clone(),
            unaligned_legacy_session_references: self.unaligned_legacy_session_references.clone(),
            unaligned_canonical_session_references: self
                .unaligned_canonical_session_references
                .clone(),
            unscoped_observation_count: self.unscoped_observation_count,
            mismatches,
        }
    }
}

/// Compare the current Rule v1 session evaluation with the v2 compatibility
/// path using one effective rule set. Inputs are already in memory; this
/// function performs no source reads.
pub fn compare_sessions(
    rule_set: &CompiledRuleSet,
    legacy_records: &[NormalizedRecord],
    observations: &[CanonicalObservationV2],
) -> Result<ShadowComparison, ShadowComparisonError> {
    let export = rule_set.compatibility_export();
    let plan = compile_rule_v1(&export)?;
    let legacy_sessions = group_legacy_records(legacy_records);
    let (canonical_sessions, unscoped) = group_canonical_observations(observations);

    let mut comparison = ShadowComparison {
        schema_version: "detection-v2-shadow-comparison.v1".to_owned(),
        ..ShadowComparison::default()
    };
    let legacy_ids = legacy_sessions.keys().cloned().collect::<BTreeSet<_>>();
    let canonical_ids = canonical_sessions.keys().cloned().collect::<BTreeSet<_>>();

    for session_id in legacy_ids.intersection(&canonical_ids) {
        // The legacy "unknown" value is a parser fallback, never a truthful
        // alignment key. Canonical observations with that literal source ID
        // are also kept unaligned to avoid accidental fallback joins.
        if session_id == "unknown" {
            continue;
        }
        let records = legacy_sessions.get(session_id).expect("legacy session");
        let canonical = canonical_sessions
            .get(session_id)
            .expect("canonical session");
        comparison.sessions.push(compare_one_session(
            Some(session_id),
            records,
            canonical,
            &plan,
            &export,
            rule_set,
        )?);
    }

    for (session_id, records) in &legacy_sessions {
        if session_id != "unknown" && canonical_ids.contains(session_id) {
            continue;
        }
        comparison
            .unaligned_legacy_session_references
            .push(session_reference(session_id));
        comparison.sessions.push(compare_one_session(
            None,
            records,
            &[],
            &plan,
            &export,
            rule_set,
        )?);
    }

    for (session_id, canonical) in &canonical_sessions {
        if session_id != "unknown" && legacy_ids.contains(session_id) {
            continue;
        }
        comparison
            .unaligned_canonical_session_references
            .push(session_reference(session_id));
        comparison.sessions.push(compare_one_session(
            Some(session_id),
            &[],
            canonical,
            &plan,
            &export,
            rule_set,
        )?);
    }

    if !unscoped.is_empty() {
        comparison.unscoped_observation_count = unscoped.len() as u64;
        comparison.health.session_alignment_gaps += unscoped.len() as u64;
        comparison.sessions.push(compare_one_session(
            None,
            &[],
            &unscoped,
            &plan,
            &export,
            rule_set,
        )?);
    }

    comparison.unaligned_legacy_session_references.sort();
    comparison.unaligned_canonical_session_references.sort();
    comparison.health.session_alignment_gaps += comparison.unaligned_legacy_session_references.len()
        as u64
        + comparison.unaligned_canonical_session_references.len() as u64;
    comparison.sessions.sort_by(|left, right| {
        left.session_reference
            .cmp(&right.session_reference)
            .then_with(|| left.legacy_record_count.cmp(&right.legacy_record_count))
    });
    Ok(finalize_totals(comparison))
}

fn group_legacy_records(records: &[NormalizedRecord]) -> BTreeMap<String, Vec<&NormalizedRecord>> {
    let mut grouped = BTreeMap::new();
    for record in records {
        grouped
            .entry(record.session_id.clone())
            .or_insert_with(Vec::new)
            .push(record);
    }
    grouped
}

fn group_canonical_observations(
    observations: &[CanonicalObservationV2],
) -> (
    BTreeMap<String, Vec<&CanonicalObservationV2>>,
    Vec<&CanonicalObservationV2>,
) {
    let mut grouped = BTreeMap::new();
    let mut unscoped = Vec::new();
    for observation in observations {
        match observation.session_id() {
            Some(session)
                if session.origin() == CorrelationOrigin::SourceReported
                    && session.value() != "unknown" =>
            {
                grouped
                    .entry(session.value().to_owned())
                    .or_insert_with(Vec::new)
                    .push(observation)
            }
            _ => unscoped.push(observation),
        }
    }
    (grouped, unscoped)
}

fn compare_one_session(
    session_id: Option<&str>,
    legacy_records: &[&NormalizedRecord],
    canonical: &[&CanonicalObservationV2],
    plan: &RuleV1CompatibilityPlan,
    export: &RuleV1CompatibilityExport,
    rule_set: &CompiledRuleSet,
) -> Result<SessionComparison, ShadowComparisonError> {
    let session_reference = session_id.map(session_reference);
    let owned_legacy_records = legacy_records
        .iter()
        .map(|record| (*record).clone())
        .collect::<Vec<_>>();
    let fields = legacy_evaluation_fields(&owned_legacy_records);
    let legacy_filtered = rule_set
        .legacy_filtered_rule_ids(&fields)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let legacy_match = evaluate_session_matches(rule_set, &owned_legacy_records)
        .map_err(|_| ShadowComparisonError::LegacyEvaluation)?;
    let legacy_atomic_ids = legacy_match
        .as_ref()
        .map(|result| atomic_ids(result, export))
        .unwrap_or_default();
    let legacy_modifier_ids = legacy_match
        .as_ref()
        .map(|result| modifier_ids(result, plan))
        .unwrap_or_default();
    let legacy_ledger = legacy_match
        .as_ref()
        .map(contributions_from_result)
        .map(normalize_contributions)
        .unwrap_or_default();
    let legacy_score = legacy_match.as_ref().map_or(0, |result| result.score);
    let legacy_metadata = legacy_metadata(legacy_match.as_ref());

    let (family_counts, stage_counts, capability_availability) = canonical_shape(canonical);
    let mut detectors = Vec::with_capacity(plan.detectors().len());
    let mut v2_atomic_ids = BTreeSet::new();
    for detector in plan.detectors() {
        let results = canonical
            .iter()
            .map(|observation| detector.evaluate(observation))
            .collect::<Vec<_>>();
        let aggregate = aggregate_detector_results(&results);
        if aggregate.outcome == SessionDetectorOutcome::Match {
            v2_atomic_ids.insert(detector.detector().id().to_owned());
        }
        detectors.push(AtomicComparison {
            session_reference: session_reference.clone(),
            detector_id: detector.detector().id().to_owned(),
            legacy_matched: legacy_atomic_ids.contains(detector.detector().id()),
            relation: relation(
                legacy_atomic_ids.contains(detector.detector().id()),
                aggregate.outcome,
            ),
            classification: None,
            reason_code: None,
            legacy_matched_target: legacy_evidence_target(
                legacy_match.as_ref(),
                detector.detector().id(),
            ),
            v2_outcome: aggregate.outcome,
            v2_non_evaluation_reasons: aggregate.non_evaluation_reason_counts,
            v2_matched_selector_paths: aggregate.matched_selector_paths,
            canonical_family_counts: family_counts.clone(),
            canonical_stage_counts: stage_counts.clone(),
            capability_availability: capability_availability.clone(),
        });
    }

    let v2_modifier_id_set = triggered_modifier_ids(&v2_atomic_ids, export, plan);
    let v2_effective_ids = v2_atomic_ids
        .iter()
        .cloned()
        .chain(v2_modifier_id_set.iter().cloned())
        .collect::<BTreeSet<_>>();
    let v2_ledger = normalize_contributions(compatibility_ledger(
        &v2_atomic_ids,
        &v2_modifier_id_set,
        export,
    ));
    let v2_score = checked_shadow_score(&v2_ledger)?;
    let v2_metadata = v2_metadata(&v2_atomic_ids, &v2_modifier_id_set, export);

    for detector in &mut detectors {
        if !detector.is_mismatch() {
            continue;
        }
        let (classification, reason_code) =
            classify_difference(detector, &legacy_filtered, canonical, legacy_records);
        detector.classification = classification;
        detector.reason_code = reason_code;
    }

    let modifier_ids_legacy = sorted_unique(legacy_modifier_ids.into_iter().collect());
    let v2_modifier_ids = sorted_unique(v2_modifier_id_set.into_iter().collect());
    let modifier_equivalent = modifier_ids_legacy == v2_modifier_ids;
    let risk_equivalent = legacy_ledger == v2_ledger && legacy_score == v2_score;
    let metadata_equivalent = legacy_metadata == v2_metadata;
    Ok(SessionComparison {
        session_reference,
        legacy_record_count: legacy_records.len() as u64,
        canonical_observation_count: canonical.len() as u64,
        canonical_family_counts: family_counts,
        canonical_stage_counts: stage_counts,
        capability_availability,
        detectors,
        v2_compat_modifier_ids: v2_modifier_ids,
        v2_compat_effective_rule_ids: v2_effective_ids.into_iter().collect(),
        v2_compat_contribution_ledger: v2_ledger,
        v2_compat_score: v2_score,
        modifier_ids_legacy,
        legacy_contribution_ledger: legacy_ledger,
        legacy_score,
        modifier_equivalent,
        risk_equivalent,
        metadata_equivalent,
    })
}

fn atomic_ids(result: &MatchResult, export: &RuleV1CompatibilityExport) -> BTreeSet<String> {
    let atomic = export
        .rules()
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<BTreeSet<_>>();
    result
        .rule_ids
        .iter()
        .filter(|id| atomic.contains(id.as_str()))
        .cloned()
        .collect()
}

fn modifier_ids(result: &MatchResult, plan: &RuleV1CompatibilityPlan) -> BTreeSet<String> {
    let modifiers = plan
        .modifiers()
        .iter()
        .map(|modifier| modifier.id())
        .collect::<BTreeSet<_>>();
    result
        .rule_ids
        .iter()
        .filter(|id| modifiers.contains(id.as_str()))
        .cloned()
        .collect()
}

fn contributions_from_result(result: &MatchResult) -> Vec<ShadowContribution> {
    result
        .contributions
        .iter()
        .map(|contribution| ShadowContribution {
            id: contribution.id().to_owned(),
            contribution_type: contribution.contribution_type(),
            points: contribution.points(),
        })
        .collect()
}

/// Canonicalize contribution order without deduplicating entries, so equality
/// remains sensitive to contribution multiplicity as well as ID, type, and points.
fn normalize_contributions(mut contributions: Vec<ShadowContribution>) -> Vec<ShadowContribution> {
    contributions.sort();
    contributions
}

fn checked_shadow_score(
    contributions: &[ShadowContribution],
) -> Result<u64, ShadowComparisonError> {
    contributions.iter().try_fold(0_u64, |total, contribution| {
        total
            .checked_add(contribution.points)
            .ok_or(ShadowComparisonError::LegacyEvaluation)
    })
}

fn legacy_metadata(result: Option<&MatchResult>) -> MetadataSnapshot {
    let Some(result) = result else {
        return MetadataSnapshot::default();
    };
    MetadataSnapshot {
        categories: sorted_unique(result.categories.clone()),
        detection_classes: sorted_unique(result.detection_classes.clone()),
        signal_types: sorted_unique(result.signal_types.clone()),
        analytic_intents: sorted_unique(result.analytic_intents.clone()),
        atlas_tags: sorted_unique(result.atlas_tags.clone()),
        tags: sorted_unique(result.tags.clone()),
    }
}

fn v2_metadata(
    atomic_ids: &BTreeSet<String>,
    modifier_ids: &BTreeSet<String>,
    export: &RuleV1CompatibilityExport,
) -> MetadataSnapshot {
    let mut snapshot = MetadataSnapshot::default();
    for rule in export
        .rules()
        .iter()
        .filter(|rule| atomic_ids.contains(&rule.id))
    {
        snapshot.categories.push(rule.category.clone());
        snapshot
            .detection_classes
            .push(rule.detection_class.clone());
        snapshot.signal_types.push(rule.signal_type.clone());
        snapshot.analytic_intents.push(rule.analytic_intent.clone());
        snapshot.atlas_tags.extend(rule.atlas_tags.iter().cloned());
        snapshot.tags.extend(rule.tags.iter().cloned());
    }
    for modifier in export
        .modifiers()
        .iter()
        .filter(|modifier| modifier_ids.contains(&modifier.id))
    {
        snapshot
            .detection_classes
            .push(modifier.detection_class.clone());
        snapshot.signal_types.push(modifier.signal_type.clone());
        snapshot
            .analytic_intents
            .push(modifier.analytic_intent.clone());
        snapshot
            .atlas_tags
            .extend(modifier.atlas_tags.iter().cloned());
    }
    snapshot.categories = sorted_unique(snapshot.categories);
    snapshot.detection_classes = sorted_unique(snapshot.detection_classes);
    snapshot.signal_types = sorted_unique(snapshot.signal_types);
    snapshot.analytic_intents = sorted_unique(snapshot.analytic_intents);
    snapshot.atlas_tags = sorted_unique(snapshot.atlas_tags);
    snapshot.tags = sorted_unique(snapshot.tags);
    snapshot
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn triggered_modifier_ids(
    atomic_ids: &BTreeSet<String>,
    export: &RuleV1CompatibilityExport,
    plan: &RuleV1CompatibilityPlan,
) -> BTreeSet<String> {
    let categories = export
        .rules()
        .iter()
        .filter(|rule| atomic_ids.contains(&rule.id))
        .map(|rule| rule.category.as_str())
        .collect::<BTreeSet<_>>();
    plan.modifiers()
        .iter()
        .filter(|modifier| {
            let category_match = modifier
                .when_all_categories()
                .iter()
                .all(|category| categories.contains(category.as_str()));
            let rule_match = modifier
                .when_all_rule_ids()
                .iter()
                .all(|rule_id| atomic_ids.contains(rule_id));
            !(modifier.when_all_categories().is_empty() && modifier.when_all_rule_ids().is_empty())
                && category_match
                && rule_match
        })
        .map(|modifier| modifier.id().to_owned())
        .collect()
}

fn compatibility_ledger(
    atomic_ids: &BTreeSet<String>,
    modifier_ids: &BTreeSet<String>,
    export: &RuleV1CompatibilityExport,
) -> Vec<ShadowContribution> {
    let mut contributions = export
        .rules()
        .iter()
        .filter(|rule| atomic_ids.contains(&rule.id) && rule.score > 0)
        .map(|rule| ShadowContribution {
            id: rule.id.clone(),
            contribution_type: RiskContributionType::DeterministicRule,
            points: rule.score,
        })
        .chain(
            export
                .modifiers()
                .iter()
                .filter(|modifier| modifier_ids.contains(&modifier.id) && modifier.score > 0)
                .map(|modifier| ShadowContribution {
                    id: modifier.id.clone(),
                    contribution_type: RiskContributionType::ChainModifier,
                    points: modifier.score,
                }),
        )
        .collect::<Vec<_>>();
    contributions.sort();
    contributions
}

fn relation(legacy_matched: bool, v2_outcome: SessionDetectorOutcome) -> AtomicRelation {
    match (legacy_matched, v2_outcome) {
        (true, SessionDetectorOutcome::Match) => AtomicRelation::BothMatch,
        (false, SessionDetectorOutcome::NoMatch) => AtomicRelation::BothNoMatch,
        (true, SessionDetectorOutcome::NoMatch) => AtomicRelation::LegacyOnly,
        (false, SessionDetectorOutcome::Match) => AtomicRelation::V2Only,
        (_, SessionDetectorOutcome::Indeterminate) => AtomicRelation::V2Indeterminate,
        (_, SessionDetectorOutcome::Error) => AtomicRelation::V2Error,
        (_, SessionDetectorOutcome::NotApplicable) => AtomicRelation::V2NotApplicable,
    }
}

fn classify_difference(
    comparison: &AtomicComparison,
    legacy_filtered: &BTreeSet<String>,
    canonical: &[&CanonicalObservationV2],
    legacy_records: &[&NormalizedRecord],
) -> (Option<MismatchClassification>, Option<String>) {
    if comparison.relation == AtomicRelation::V2Error {
        return (
            Some(MismatchClassification::DetectorError),
            Some("detector_error".to_owned()),
        );
    }
    if comparison.relation == AtomicRelation::V2Indeterminate {
        if comparison
            .v2_non_evaluation_reasons
            .contains_key(NonEvaluationReason::RequiredCapabilityUnsupported.as_str())
        {
            return (
                Some(MismatchClassification::VisibilityGap),
                Some("canonical_capability_unsupported".to_owned()),
            );
        }
        if comparison
            .v2_non_evaluation_reasons
            .contains_key(NonEvaluationReason::RequiredCapabilityUnknown.as_str())
        {
            return (
                Some(MismatchClassification::VisibilityGap),
                Some("canonical_capability_unknown".to_owned()),
            );
        }
        if comparison
            .v2_non_evaluation_reasons
            .contains_key(NonEvaluationReason::IneligibleInput.as_str())
        {
            return (
                Some(MismatchClassification::VisibilityGap),
                Some("canonical_provenance_ineligible".to_owned()),
            );
        }
    }
    if comparison.session_reference.is_none() {
        return (
            Some(MismatchClassification::SessionAlignmentGap),
            Some("session_identity_unavailable".to_owned()),
        );
    }
    if legacy_records.is_empty() && comparison.relation != AtomicRelation::BothNoMatch {
        return (
            Some(MismatchClassification::SessionAlignmentGap),
            Some("session_identity_unavailable".to_owned()),
        );
    }
    if comparison.relation == AtomicRelation::V2Only
        && legacy_filtered.contains(&comparison.detector_id)
    {
        return (
            Some(MismatchClassification::LegacyPostFilterDifference),
            Some("legacy_post_match_filter".to_owned()),
        );
    }
    if comparison.relation == AtomicRelation::LegacyOnly {
        let target = comparison.legacy_matched_target.as_deref();
        if target == Some("url") {
            return (
                Some(MismatchClassification::LegacyFlatteningDifference),
                Some("compat_v1_url_unavailable".to_owned()),
            );
        }
        if target == Some("file_path")
            && !canonical
                .iter()
                .any(|observation| observation.facets().contains_key("resource.path"))
        {
            return (
                Some(MismatchClassification::LegacyFlatteningDifference),
                Some("legacy_tool_content_file_path_broadening".to_owned()),
            );
        }
        if target == Some("command")
            && !canonical
                .iter()
                .any(|observation| observation.facets().contains_key("command.text"))
        {
            return (
                Some(MismatchClassification::LegacyFlatteningDifference),
                Some("legacy_tool_content_command_broadening".to_owned()),
            );
        }
    }
    (
        Some(MismatchClassification::UnexpectedSemanticDifference),
        None,
    )
}

fn legacy_evidence_target(result: Option<&MatchResult>, rule_id: &str) -> Option<String> {
    result
        .into_iter()
        .flat_map(|result| result.evidence.iter())
        .find(|evidence| evidence.rule_id.as_deref() == Some(rule_id))
        .map(|evidence| evidence.field.clone())
        .filter(|field| {
            matches!(
                field.as_str(),
                "arguments"
                    | "assistant_context"
                    | "command"
                    | "file_path"
                    | "tool_name"
                    | "tool_result"
                    | "url"
                    | "user_context"
            )
        })
}

type CanonicalShape = (
    BTreeMap<String, u64>,
    BTreeMap<String, u64>,
    BTreeMap<String, BTreeMap<String, u64>>,
);

fn canonical_shape(observations: &[&CanonicalObservationV2]) -> CanonicalShape {
    let mut families = BTreeMap::new();
    let mut stages = BTreeMap::new();
    let mut capabilities = BTreeMap::new();
    for observation in observations {
        *families
            .entry(observation.kind().as_str().to_owned())
            .or_default() += 1;
        *stages
            .entry(observation.stage().as_str().to_owned())
            .or_default() += 1;
        if let Some(context) = observation.capability_context() {
            for capability in [
                CapabilityId::ToolCall,
                CapabilityId::ToolExecution,
                CapabilityId::UserContext,
            ] {
                *capabilities
                    .entry(capability.as_str().to_owned())
                    .or_insert_with(BTreeMap::new)
                    .entry(context.resolve(capability).as_str().to_owned())
                    .or_default() += 1;
            }
        }
    }
    (families, stages, capabilities)
}

fn session_reference(value: &str) -> String {
    let digest = Sha256::digest(format!("{SESSION_HASH_DOMAIN}{value}").as_bytes());
    format!("sha256:{digest:x}")
}

fn add_relation(counts: &mut AtomicEquivalenceCounts, relation: AtomicRelation) {
    match relation {
        AtomicRelation::BothMatch => counts.both_match += 1,
        AtomicRelation::BothNoMatch => counts.both_no_match += 1,
        AtomicRelation::LegacyOnly => counts.legacy_only += 1,
        AtomicRelation::V2Only => counts.v2_only += 1,
        AtomicRelation::V2Indeterminate => counts.v2_indeterminate += 1,
        AtomicRelation::V2Error => counts.v2_error += 1,
        AtomicRelation::V2NotApplicable => counts.v2_not_applicable += 1,
    }
}

fn add_equivalence(
    counts: &mut EquivalenceCounts,
    legacy_nonempty: bool,
    v2_nonempty: bool,
    equal: bool,
) {
    if equal {
        counts.equal += 1;
    } else if legacy_nonempty && !v2_nonempty {
        counts.legacy_only += 1;
    } else if !legacy_nonempty && v2_nonempty {
        counts.v2_only += 1;
    } else {
        counts.different += 1;
    }
}

fn update_totals(comparison: &mut ShadowComparison) {
    comparison.atomic_equivalence = AtomicEquivalenceCounts::default();
    comparison.modifier_equivalence = EquivalenceCounts::default();
    comparison.risk_equivalence = EquivalenceCounts::default();
    comparison.metadata_equivalence = EquivalenceCounts::default();
    comparison.non_evaluation_reason_counts.clear();
    comparison.mismatch_class_counts.clear();
    comparison.health.total_detector_session_evaluations = 0;
    comparison.health.fully_evaluable = 0;
    comparison.health.indeterminate = 0;
    comparison.health.capability_unsupported = 0;
    comparison.health.capability_unknown = 0;
    comparison.health.provenance_ineligible = 0;
    comparison.health.type_mismatch = 0;
    for session in &comparison.sessions {
        add_equivalence(
            &mut comparison.modifier_equivalence,
            !session.modifier_ids_legacy.is_empty(),
            !session.v2_compat_modifier_ids.is_empty(),
            session.modifier_equivalent,
        );
        add_equivalence(
            &mut comparison.risk_equivalence,
            !session.legacy_contribution_ledger.is_empty(),
            !session.v2_compat_contribution_ledger.is_empty(),
            session.risk_equivalent,
        );
        add_equivalence(
            &mut comparison.metadata_equivalence,
            session
                .detectors
                .iter()
                .any(|detector| detector.legacy_matched)
                || !session.modifier_ids_legacy.is_empty()
                || session.legacy_score != 0,
            !session.v2_compat_effective_rule_ids.is_empty(),
            session.metadata_equivalent,
        );
        for detector in &session.detectors {
            add_relation(&mut comparison.atomic_equivalence, detector.relation);
            if let Some(classification) = detector.classification {
                *comparison
                    .mismatch_class_counts
                    .entry(classification.as_str().to_owned())
                    .or_default() += 1;
            }
            for (reason, count) in &detector.v2_non_evaluation_reasons {
                *comparison
                    .non_evaluation_reason_counts
                    .entry(reason.clone())
                    .or_default() += count;
                match reason.as_str() {
                    "required_capability_unsupported" => {
                        comparison.health.capability_unsupported += count
                    }
                    "required_capability_unknown" => comparison.health.capability_unknown += count,
                    "ineligible_input" => comparison.health.provenance_ineligible += count,
                    "type_mismatch" => comparison.health.type_mismatch += count,
                    _ => {}
                }
            }
            comparison.health.total_detector_session_evaluations += 1;
            match detector.v2_outcome {
                SessionDetectorOutcome::Match | SessionDetectorOutcome::NoMatch => {
                    comparison.health.fully_evaluable += 1
                }
                SessionDetectorOutcome::Indeterminate => comparison.health.indeterminate += 1,
                SessionDetectorOutcome::Error | SessionDetectorOutcome::NotApplicable => {}
            }
        }
    }
}

// Keep the aggregation totals in one place and make the public comparison
// construction above easy to audit.
fn finalize_totals(mut comparison: ShadowComparison) -> ShadowComparison {
    update_totals(&mut comparison);
    comparison
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use telltale_rules::load_rule_set_from_documents;
    use telltale_schema::observation::{
        CapabilityAvailability, CapabilityContext, FactMetadata, Fidelity, IngestionMode,
        JsonValue, MessageObservation, MessageRole, ObservationBody, ObservationStage, ObservedAt,
        SourceProvenance, ToolObservation,
    };
    use telltale_schema::record::RecordKind;

    const OBSERVED_AT: &str = "2026-09-04T00:00:00Z";

    fn rules(yaml: &str) -> telltale_rules::CompiledRuleSet {
        load_rule_set_from_documents(&[yaml], None).expect("rules")
    }

    fn record(
        session: &str,
        kind: telltale_schema::record::RecordKind,
        content: &str,
    ) -> NormalizedRecord {
        NormalizedRecord {
            session_id: session.to_owned(),
            client: "synthetic".to_owned(),
            agent: None,
            model: None,
            provider: None,
            timestamp: None,
            kind,
            tool_name: None,
            arguments: None,
            content: content.to_owned(),
        }
    }

    fn observation(
        session: Option<(&str, CorrelationOrigin)>,
        body: ObservationBody,
        family_stage: ObservationStage,
        capabilities: CapabilityContext,
    ) -> CanonicalObservationV2 {
        let source_namespace = session
            .map(|(value, _)| value)
            .unwrap_or("synthetic-shadow");
        let source = SourceProvenance::new(
            IngestionMode::SessionStore,
            "synthetic",
            "synthetic.shadow",
            Fidelity::FullNative,
        )
        .unwrap()
        .with_identity_source_sequence(source_namespace, 1)
        .unwrap();
        let metadata_paths = match &body {
            ObservationBody::Message(message) => {
                let mut paths = vec!["message.role"];
                if message.content().is_some() {
                    paths.push("message.content");
                }
                if !message.content_parts().is_empty() {
                    paths.push("message.content_parts");
                }
                paths
            }
            ObservationBody::Tool(tool) => {
                let mut paths = Vec::new();
                if tool.name().is_some() {
                    paths.push("tool.name");
                }
                if tool.arguments().is_some() {
                    paths.push("tool.arguments");
                }
                if tool.searchable_arguments().is_some() {
                    paths.push("tool.searchable_arguments");
                }
                if tool.result().is_some() {
                    paths.push("tool.result");
                }
                if tool.searchable_result().is_some() {
                    paths.push("tool.searchable_result");
                }
                if tool.reported_status().is_some() {
                    paths.push("tool.reported_status");
                }
                if tool.is_error().is_some() {
                    paths.push("tool.is_error");
                }
                if tool.exit_code().is_some() {
                    paths.push("tool.exit_code");
                }
                paths
            }
            _ => Vec::new(),
        };
        let facets = match &body {
            ObservationBody::Tool(tool) => match tool.arguments() {
                Some(JsonValue::Object(fields)) => [
                    ("command.text", fields.get("command")),
                    ("resource.path", fields.get("file_path")),
                ]
                .into_iter()
                .filter_map(|(name, value)| match value {
                    Some(JsonValue::String(value)) => Some((name, value.clone())),
                    _ => None,
                })
                .collect::<Vec<_>>(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };
        let mut builder = CanonicalObservationV2::builder(
            body,
            family_stage,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            source,
        )
        .sequence(1)
        .capability_context(capabilities)
        .child_ordinal(0);
        for path in metadata_paths {
            builder = builder.fact_metadata(path, FactMetadata::reported().unwrap());
        }
        for (name, value) in facets {
            builder = builder
                .facet(
                    name,
                    telltale_schema::observation::SemanticFacet::new(JsonValue::string(value)),
                )
                .unwrap()
                .fact_metadata(name, FactMetadata::parsed().unwrap());
        }
        if let Some((value, origin)) = session {
            builder = builder.session_id(
                telltale_schema::observation::CorrelationId::new(value, origin).unwrap(),
            );
        }
        builder.build().unwrap()
    }

    fn message(session: &str, role: MessageRole, text: &str) -> CanonicalObservationV2 {
        observation(
            Some((session, CorrelationOrigin::SourceReported)),
            ObservationBody::Message(
                MessageObservation::new(role).with_content(JsonValue::string(text)),
            ),
            ObservationStage::MessageObserved,
            CapabilityContext::new()
                .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported),
        )
    }

    fn tool(session: &str, name: &str, args: JsonValue) -> CanonicalObservationV2 {
        let body = ToolObservation::new()
            .with_name(name)
            .unwrap()
            .with_arguments(args);
        observation(
            Some((session, CorrelationOrigin::SourceReported)),
            ObservationBody::Tool(body),
            ObservationStage::ToolRequested,
            CapabilityContext::new()
                .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported)
                .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported),
        )
    }

    fn target_rule(id: &str, target: &str, regex: &str) -> String {
        format!(
            "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: {id}\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 7\n    targets: [{target}]\n    regex: '{regex}'\n    tags: []\n    explanation: synthetic\nmodifiers: []\n"
        )
    }

    #[test]
    fn all_eight_targets_use_explicit_legacy_and_canonical_inputs() {
        type TargetCase = (
            &'static str,
            RecordKind,
            &'static str,
            fn() -> CanonicalObservationV2,
        );
        let targets: [TargetCase; 8] = [
            ("arguments", RecordKind::ToolCall, "needle", || {
                tool("session", "run", JsonValue::string("needle"))
            }),
            (
                "assistant_context",
                RecordKind::AssistantMessage,
                "needle",
                || message("session", MessageRole::Assistant, "needle"),
            ),
            ("command", RecordKind::ToolCall, "needle", || {
                tool(
                    "session",
                    "run",
                    JsonValue::object([(String::from("command"), JsonValue::string("needle"))])
                        .unwrap(),
                )
            }),
            ("file_path", RecordKind::ToolCall, "needle", || {
                tool(
                    "session",
                    "run",
                    JsonValue::object([(String::from("file_path"), JsonValue::string("needle"))])
                        .unwrap(),
                )
            }),
            ("tool_name", RecordKind::ToolCall, "needle", || {
                tool("session", "needle", JsonValue::string("other"))
            }),
            ("tool_result", RecordKind::ToolResult, "needle", || {
                observation(
                    Some(("session", CorrelationOrigin::SourceReported)),
                    ObservationBody::Tool(
                        ToolObservation::new().with_result(JsonValue::string("needle")),
                    ),
                    ObservationStage::ToolResultReturned,
                    CapabilityContext::new()
                        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
                )
            }),
            ("url", RecordKind::ToolCall, "needle", || {
                tool("session", "run", JsonValue::string("needle"))
            }),
            ("user_context", RecordKind::UserMessage, "needle", || {
                message("session", MessageRole::User, "needle")
            }),
        ];
        for (target, kind, value, canonical) in targets {
            let rule = rules(&target_rule(&format!("synthetic.{target}"), target, value));
            let legacy_content = if target == "tool_name" {
                "other"
            } else {
                value
            };
            let legacy = record("session", kind, legacy_content);
            let legacy = if target == "arguments" {
                NormalizedRecord {
                    arguments: Some(value.to_owned()),
                    ..legacy
                }
            } else if target == "tool_name" {
                NormalizedRecord {
                    tool_name: Some(value.to_owned()),
                    ..legacy
                }
            } else {
                legacy
            };
            let canonical = canonical();
            let result = compare_sessions(&rule, &[legacy], &[canonical]).unwrap();
            if target == "url" {
                assert_eq!(result.atomic_equivalence.legacy_only, 1, "{target}");
            } else {
                assert_eq!(result.atomic_equivalence.both_match, 1, "{target}");
            }
        }
    }

    #[test]
    fn url_is_truthfully_absent_and_reports_flattening_gap() {
        let rule = rules(&target_rule("synthetic.url", "url", "needle"));
        let legacy = record("session", RecordKind::ToolCall, "needle");
        let canonical = tool("session", "run", JsonValue::string("other"));
        let result = compare_sessions(&rule, &[legacy], &[canonical]).unwrap();
        let detector = &result.sessions[0].detectors[0];
        assert_eq!(detector.relation, AtomicRelation::LegacyOnly);
        assert_eq!(
            detector.reason_code.as_deref(),
            Some("compat_v1_url_unavailable")
        );
    }

    #[test]
    fn command_flattening_requires_missing_canonical_command_facet() {
        let rule = rules(&target_rule("synthetic.command", "command", "bash"));

        let legacy = record("session", RecordKind::ToolCall, "bash synthetic");
        let canonical_without_command = tool("session", "run", JsonValue::string("other"));
        let result = compare_sessions(
            &rule,
            std::slice::from_ref(&legacy),
            &[canonical_without_command],
        )
        .unwrap();
        let detector = &result.sessions[0].detectors[0];
        assert_eq!(detector.relation, AtomicRelation::LegacyOnly);
        assert_eq!(
            detector.reason_code.as_deref(),
            Some("legacy_tool_content_command_broadening")
        );

        let canonical_with_command = tool(
            "session",
            "run",
            JsonValue::object([(String::from("command"), JsonValue::string("other"))]).unwrap(),
        );
        let result = compare_sessions(
            &rule,
            std::slice::from_ref(&legacy),
            &[canonical_with_command],
        )
        .unwrap();
        let detector = &result.sessions[0].detectors[0];
        assert_eq!(detector.relation, AtomicRelation::LegacyOnly);
        assert_eq!(
            detector.classification,
            Some(MismatchClassification::UnexpectedSemanticDifference)
        );
        assert_eq!(detector.reason_code, None);
    }

    #[test]
    fn all_eight_targets_have_evaluated_negative_vectors() {
        type TargetCase = (&'static str, RecordKind, fn() -> CanonicalObservationV2);
        let targets: [TargetCase; 8] = [
            ("arguments", RecordKind::ToolCall, || {
                tool("session", "run", JsonValue::string("different"))
            }),
            ("assistant_context", RecordKind::AssistantMessage, || {
                message("session", MessageRole::Assistant, "different")
            }),
            ("command", RecordKind::ToolCall, || {
                tool(
                    "session",
                    "run",
                    JsonValue::object([(String::from("command"), JsonValue::string("different"))])
                        .unwrap(),
                )
            }),
            ("file_path", RecordKind::ToolCall, || {
                tool(
                    "session",
                    "run",
                    JsonValue::object([(
                        String::from("file_path"),
                        JsonValue::string("different"),
                    )])
                    .unwrap(),
                )
            }),
            ("tool_name", RecordKind::ToolCall, || {
                tool("session", "different", JsonValue::string("other"))
            }),
            ("tool_result", RecordKind::ToolResult, || {
                observation(
                    Some(("session", CorrelationOrigin::SourceReported)),
                    ObservationBody::Tool(
                        ToolObservation::new().with_result(JsonValue::string("different")),
                    ),
                    ObservationStage::ToolResultReturned,
                    CapabilityContext::new()
                        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
                )
            }),
            ("url", RecordKind::ToolCall, || {
                tool("session", "run", JsonValue::string("different"))
            }),
            ("user_context", RecordKind::UserMessage, || {
                message("session", MessageRole::User, "different")
            }),
        ];

        for (target, kind, canonical) in targets {
            let rule = rules(&target_rule(
                &format!("synthetic.{target}"),
                target,
                "needle",
            ));
            let legacy = if target == "arguments" {
                NormalizedRecord {
                    arguments: Some("different".to_owned()),
                    ..record("session", kind, "different")
                }
            } else if target == "tool_name" {
                NormalizedRecord {
                    tool_name: Some("different".to_owned()),
                    ..record("session", kind, "different")
                }
            } else {
                record("session", kind, "different")
            };
            let result = compare_sessions(&rule, &[legacy], &[canonical()]).unwrap();
            let detector = &result.sessions[0].detectors[0];
            assert_eq!(detector.relation, AtomicRelation::BothNoMatch, "{target}");
            assert_eq!(
                detector.v2_outcome,
                SessionDetectorOutcome::NoMatch,
                "{target}"
            );
        }
    }

    #[test]
    fn not_applicable_without_legacy_match_is_not_a_semantic_mismatch() {
        let rule = rules(&target_rule("synthetic.command", "command", "needle"));
        let canonical = message("session", MessageRole::User, "other");
        let result = compare_sessions(&rule, &[], &[canonical]).unwrap();
        let detector = &result.sessions[0].detectors[0];
        assert_eq!(detector.relation, AtomicRelation::V2NotApplicable);
        assert!(!detector.is_mismatch());
    }

    #[test]
    fn not_applicable_with_legacy_match_remains_a_mismatch() {
        let rule = rules(&target_rule("synthetic.command", "command", "needle"));
        let legacy = record("session", RecordKind::ToolCall, "needle");
        let canonical = message("session", MessageRole::User, "other");
        let result = compare_sessions(&rule, &[legacy], &[canonical]).unwrap();
        let detector = &result.sessions[0].detectors[0];
        assert_eq!(detector.relation, AtomicRelation::V2NotApplicable);
        assert!(detector.is_mismatch());
    }

    #[test]
    fn precedence_and_indeterminate_are_preserved() {
        let rule = rules(&target_rule(
            "synthetic.message",
            "assistant_context",
            "needle",
        ));
        let matching = message("session", MessageRole::Assistant, "needle");
        let no_match = message("session", MessageRole::Assistant, "other");
        let result = compare_sessions(&rule, &[], &[no_match, matching]).unwrap();
        assert_eq!(
            result.sessions[0].detectors[0].v2_outcome,
            SessionDetectorOutcome::Match
        );
        assert_eq!(
            result.sessions[0].detectors[0].v2_non_evaluation_reasons,
            BTreeMap::new()
        );
        let aggregate = aggregate_detector_results(&[
            result_for(EvaluationStatus::EvaluatedNoMatch),
            result_for(EvaluationStatus::NotEvaluated),
        ]);
        assert_eq!(aggregate.outcome, SessionDetectorOutcome::Indeterminate);
        assert_eq!(aggregate.evaluated_no_match_observations, 1);
        assert_eq!(aggregate.not_evaluated_observations, 1);

        let aggregate = aggregate_detector_results(&[
            result_for(EvaluationStatus::NotEvaluated),
            result_for(EvaluationStatus::DetectorError),
        ]);
        assert_eq!(aggregate.outcome, SessionDetectorOutcome::Error);
    }

    fn result_for(status: EvaluationStatus) -> DetectorResult {
        let identity = crate::v2::DetectorIdentity::new(
            crate::v2::DetectorKind::ObservationMatch,
            "synthetic.result",
        )
        .unwrap();
        let metadata = crate::v2::FindingMetadata::new(
            crate::v2::FindingKind::SecurityDetection,
            "synthetic",
            crate::v2::Severity::Low,
        )
        .unwrap();
        match status {
            EvaluationStatus::NotEvaluated => {
                DetectorResult::not_evaluated(identity, NonEvaluationReason::TypeMismatch, metadata)
                    .unwrap()
            }
            EvaluationStatus::DetectorError => DetectorResult::detector_error(
                identity,
                metadata,
                crate::v2::Diagnostic::new(
                    crate::v2::DiagnosticKind::RuntimeDetectorError,
                    "synthetic_error",
                )
                .unwrap(),
            )
            .unwrap(),
            _ => DetectorResult::new(identity, status, metadata).unwrap(),
        }
    }

    #[test]
    fn truthful_alignment_hashes_ids_and_keeps_unscoped_separate_from_unknown() {
        let rule = rules(&target_rule("synthetic.user", "user_context", "needle"));
        let legacy = record("unknown", RecordKind::UserMessage, "needle");
        let unscoped = observation(
            Some(("source-session", CorrelationOrigin::TelltaleOriginated)),
            ObservationBody::Message(
                MessageObservation::new(MessageRole::User)
                    .with_content(JsonValue::string("needle")),
            ),
            ObservationStage::MessageObserved,
            CapabilityContext::new()
                .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported),
        );
        let result = compare_sessions(&rule, &[legacy], &[unscoped]).unwrap();
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("source-session"));
        assert_eq!(result.unscoped_observation_count, 1);
        assert_eq!(result.atomic_equivalence.v2_only, 1);
        assert_eq!(result.atomic_equivalence.v2_not_applicable, 1);
    }

    #[test]
    fn source_reported_unknown_session_remains_unscoped() {
        let rule = rules(&target_rule("synthetic.user", "user_context", "needle"));
        let result = compare_sessions(
            &rule,
            &[
                record("unknown", RecordKind::UserMessage, "needle"),
                record("ordinary-session", RecordKind::UserMessage, "needle"),
            ],
            &[
                message("unknown", MessageRole::User, "needle"),
                message("ordinary-session", MessageRole::User, "needle"),
            ],
        )
        .unwrap();

        let unknown_reference = session_reference("unknown");
        let ordinary_reference = session_reference("ordinary-session");
        assert_eq!(result.unscoped_observation_count, 1);
        assert_eq!(result.unaligned_legacy_session_references.len(), 1);
        assert!(result.unaligned_canonical_session_references.is_empty());
        assert_eq!(result.sessions.len(), 3);
        assert_eq!(
            result
                .sessions
                .iter()
                .filter(|session| {
                    session.legacy_record_count == 1 && session.canonical_observation_count == 1
                })
                .count(),
            1
        );
        assert!(!result.sessions.iter().any(
            |session| session.session_reference.as_deref() == Some(unknown_reference.as_str())
        ));
        let ordinary = result
            .sessions
            .iter()
            .find(|session| {
                session.session_reference.as_deref() == Some(ordinary_reference.as_str())
            })
            .expect("ordinary source-reported session remains aligned");
        assert_eq!(ordinary.legacy_record_count, 1);
        assert_eq!(ordinary.canonical_observation_count, 1);
    }

    #[test]
    fn modifiers_are_aggregated_once_and_never_become_detectors() {
        let yaml = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.atomic\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 7\n    targets: [assistant_context]\n    regex: needle\n    tags: []\n    explanation: synthetic\nmodifiers:\n  - id: synthetic.modifier\n    score: 9\n    detection_class: security_detection\n    signal_type: chain\n    analytic_intent: alert\n    atlas_tags: []\n    when_all_rule_ids: [synthetic.atomic]\n    explanation: synthetic\n";
        let rule = rules(yaml);
        let canonical = vec![
            message("session", MessageRole::Assistant, "needle"),
            message("session", MessageRole::Assistant, "needle"),
        ];
        let legacy = vec![
            record("session", RecordKind::AssistantMessage, "needle"),
            record("session", RecordKind::AssistantMessage, "needle"),
        ];
        let result = compare_sessions(&rule, &legacy, &canonical).unwrap();
        let session = &result.sessions[0];
        assert_eq!(session.v2_compat_modifier_ids, ["synthetic.modifier"]);
        assert_eq!(session.modifier_ids_legacy, ["synthetic.modifier"]);
        assert_eq!(session.v2_compat_score, 16);
        assert_eq!(session.legacy_score, 16);
        assert_eq!(session.v2_compat_contribution_ledger.len(), 2);
        assert_eq!(session.legacy_contribution_ledger.len(), 2);
        for ledger in [
            &session.v2_compat_contribution_ledger,
            &session.legacy_contribution_ledger,
        ] {
            assert_eq!(
                ledger
                    .iter()
                    .filter(|entry| entry.id == "synthetic.atomic")
                    .count(),
                1
            );
            assert_eq!(
                ledger
                    .iter()
                    .filter(|entry| entry.id == "synthetic.modifier")
                    .count(),
                1
            );
        }
        assert!(session.risk_equivalent);
        assert!(
            session
                .detectors
                .iter()
                .all(|detector| detector.detector_id != "synthetic.modifier")
        );
    }

    #[test]
    fn contribution_and_risk_equality_ignore_legacy_evaluation_order() {
        let yaml = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.atomic\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 7\n    targets: [user_context]\n    regex: needle\n    tags: []\n    explanation: synthetic\nmodifiers:\n  - id: chain.synthetic\n    score: 9\n    detection_class: security_detection\n    signal_type: chain\n    analytic_intent: alert\n    atlas_tags: []\n    when_all_rule_ids: [synthetic.atomic]\n    explanation: synthetic\n";
        let rule = rules(yaml);
        let result = compare_sessions(
            &rule,
            &[record("session", RecordKind::UserMessage, "needle")],
            &[message("session", MessageRole::User, "needle")],
        )
        .unwrap();
        let session = &result.sessions[0];
        assert_eq!(session.legacy_score, 16);
        assert_eq!(session.v2_compat_score, 16);
        assert_eq!(
            session.legacy_contribution_ledger,
            session.v2_compat_contribution_ledger
        );
        assert_eq!(
            session.legacy_contribution_ledger,
            [
                ShadowContribution {
                    id: "chain.synthetic".to_owned(),
                    contribution_type: RiskContributionType::ChainModifier,
                    points: 9,
                },
                ShadowContribution {
                    id: "synthetic.atomic".to_owned(),
                    contribution_type: RiskContributionType::DeterministicRule,
                    points: 7,
                },
            ]
        );
        assert!(session.risk_equivalent);
        assert_eq!(result.risk_equivalence.equal, 1);
    }

    #[test]
    fn modifier_equality_ignores_path_specific_id_order() {
        let yaml = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.atomic\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 7\n    targets: [user_context]\n    regex: needle\n    tags: []\n    explanation: synthetic\nmodifiers:\n  - id: chain.z\n    score: 9\n    detection_class: security_detection\n    signal_type: chain\n    analytic_intent: alert\n    atlas_tags: []\n    when_all_rule_ids: [synthetic.atomic]\n    explanation: synthetic\n  - id: chain.a\n    score: 11\n    detection_class: security_detection\n    signal_type: chain\n    analytic_intent: alert\n    atlas_tags: []\n    when_all_rule_ids: [synthetic.atomic]\n    explanation: synthetic\n";
        let rule = rules(yaml);
        let result = compare_sessions(
            &rule,
            &[record("session", RecordKind::UserMessage, "needle")],
            &[message("session", MessageRole::User, "needle")],
        )
        .unwrap();
        let session = &result.sessions[0];
        assert_eq!(session.modifier_ids_legacy, ["chain.a", "chain.z"]);
        assert_eq!(session.v2_compat_modifier_ids, ["chain.a", "chain.z"]);
        assert!(session.modifier_equivalent);
        assert_eq!(result.modifier_equivalence.equal, 1);
    }

    #[test]
    fn compatibility_score_overflow_uses_existing_shadow_error() {
        let contributions = [
            ShadowContribution {
                id: "synthetic.first".to_owned(),
                contribution_type: RiskContributionType::DeterministicRule,
                points: u64::MAX,
            },
            ShadowContribution {
                id: "synthetic.second".to_owned(),
                contribution_type: RiskContributionType::DeterministicRule,
                points: 1,
            },
        ];
        assert_eq!(
            checked_shadow_score(&contributions),
            Err(ShadowComparisonError::LegacyEvaluation)
        );
    }

    #[test]
    fn modifier_requires_every_category_condition() {
        let yaml = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.atomic\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 7\n    targets: [assistant_context]\n    regex: needle\n    tags: []\n    explanation: synthetic\nmodifiers:\n  - id: synthetic.category_modifier\n    score: 9\n    detection_class: security_detection\n    signal_type: chain\n    analytic_intent: alert\n    atlas_tags: []\n    when_all_categories: [other]\n    explanation: synthetic\n";
        let rule = rules(yaml);
        let result = compare_sessions(
            &rule,
            &[record("session", RecordKind::AssistantMessage, "needle")],
            &[message("session", MessageRole::Assistant, "needle")],
        )
        .unwrap();
        assert!(result.sessions[0].v2_compat_modifier_ids.is_empty());
        assert!(result.sessions[0].modifier_equivalent);
    }

    #[test]
    fn modifier_requires_every_rule_id_condition() {
        let yaml = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.atomic\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 7\n    targets: [assistant_context]\n    regex: needle\n    tags: []\n    explanation: synthetic\nmodifiers:\n  - id: synthetic.rule_modifier\n    score: 9\n    detection_class: security_detection\n    signal_type: chain\n    analytic_intent: alert\n    atlas_tags: []\n    when_all_rule_ids: [synthetic.missing]\n    explanation: synthetic\n";
        let rule = rules(yaml);
        let result = compare_sessions(
            &rule,
            &[record("session", RecordKind::AssistantMessage, "needle")],
            &[message("session", MessageRole::Assistant, "needle")],
        )
        .unwrap();
        assert!(result.sessions[0].v2_compat_modifier_ids.is_empty());
        assert!(result.sessions[0].modifier_equivalent);
    }

    #[test]
    fn post_match_filter_is_reported_for_approval_context() {
        let rule = rules(&target_rule(
            "approval.bypass.context",
            "assistant_context",
            "bypass approval",
        ));
        let text = "Documentation quoted example: bypass approval should not be treated as an instruction.";
        let result = compare_sessions(
            &rule,
            &[record("session", RecordKind::AssistantMessage, text)],
            &[message("session", MessageRole::Assistant, text)],
        )
        .unwrap();
        let detector = &result.sessions[0].detectors[0];
        assert_eq!(detector.relation, AtomicRelation::V2Only);
        assert_eq!(
            detector.classification,
            Some(MismatchClassification::LegacyPostFilterDifference)
        );
        assert_eq!(
            detector.reason_code.as_deref(),
            Some("legacy_post_match_filter")
        );
    }

    #[test]
    fn post_match_filter_is_reported_for_negated_secret_context() {
        let rule = rules(&target_rule(
            "secret.env.read",
            "assistant_context",
            "\\.env",
        ));
        let text = "Assistant instruction: do not read .env during this synthetic test.";
        let result = compare_sessions(
            &rule,
            &[record("session", RecordKind::AssistantMessage, text)],
            &[message("session", MessageRole::Assistant, text)],
        )
        .unwrap();
        let detector = &result.sessions[0].detectors[0];
        assert_eq!(detector.relation, AtomicRelation::V2Only);
        assert_eq!(
            detector.classification,
            Some(MismatchClassification::LegacyPostFilterDifference)
        );
        assert_eq!(
            detector.reason_code.as_deref(),
            Some("legacy_post_match_filter")
        );
    }

    #[test]
    fn policy_disabled_rule_is_absent_from_both_paths() {
        let document = target_rule("synthetic.disabled", "user_context", "needle");
        let policy = "version: 1\ndisabled_rules: [synthetic.disabled]\n";
        let rule = load_rule_set_from_documents(&[&document], Some(policy)).expect("rules");
        let result = compare_sessions(
            &rule,
            &[record("session", RecordKind::UserMessage, "needle")],
            &[message("session", MessageRole::User, "needle")],
        )
        .unwrap();
        let session = &result.sessions[0];
        assert!(session.detectors.is_empty());
        assert_eq!(session.legacy_score, 0);
        assert_eq!(session.v2_compat_score, 0);
        assert!(session.v2_compat_effective_rule_ids.is_empty());
    }

    #[test]
    fn score_override_is_reflected_in_legacy_and_v2_ledgers() {
        let document = target_rule("synthetic.score", "user_context", "needle");
        let mut rule_set: telltale_rules::RuleSet = serde_yaml::from_str(&document).unwrap();
        let override_yaml = "version: 1\noverrides:\n  - rule_id: synthetic.score\n    reason: synthetic score review\n    score: 31\n";
        let override_document: telltale_rules::RuleOverrideDocument =
            serde_yaml::from_str(override_yaml).unwrap();
        telltale_rules::apply_rule_override_document(
            &mut rule_set,
            &override_document,
            Path::new("synthetic-overrides.yaml"),
        )
        .unwrap();
        let rule = rule_set.compile(None).unwrap();
        let result = compare_sessions(
            &rule,
            &[record("session", RecordKind::UserMessage, "needle")],
            &[message("session", MessageRole::User, "needle")],
        )
        .unwrap();
        let session = &result.sessions[0];
        assert_eq!(session.legacy_score, 31);
        assert_eq!(session.v2_compat_score, 31);
        assert_eq!(
            session.legacy_contribution_ledger,
            session.v2_compat_contribution_ledger
        );
        assert!(session.risk_equivalent);
    }

    #[test]
    fn distinct_truthful_sessions_are_compared_without_mixing() {
        let rule = rules(&target_rule("synthetic.user", "user_context", "needle"));
        let result = compare_sessions(
            &rule,
            &[
                record("session-a", RecordKind::UserMessage, "needle"),
                record("session-b", RecordKind::UserMessage, "needle"),
            ],
            &[
                message("session-a", MessageRole::User, "needle"),
                message("session-b", MessageRole::User, "needle"),
            ],
        )
        .unwrap();
        assert_eq!(result.sessions.len(), 2);
        assert!(
            result
                .sessions
                .iter()
                .all(|session| session.legacy_record_count == 1
                    && session.canonical_observation_count == 1)
        );
        assert_ne!(
            result.sessions[0].session_reference,
            result.sessions[1].session_reference
        );
    }

    #[test]
    fn case_insensitive_effective_regex_and_disabled_rule_share_one_plan() {
        let yaml = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: true\n  enabled: true\nrules:\n  - id: synthetic.enabled\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 7\n    targets: [user_context]\n    regex: needle\n    tags: []\n    explanation: synthetic\n  - id: synthetic.disabled\n    enabled: false\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 7\n    targets: [user_context]\n    regex: needle\n    tags: []\n    explanation: synthetic\nmodifiers: []\n";
        let rule = rules(yaml);
        let result = compare_sessions(
            &rule,
            &[record("session", RecordKind::UserMessage, "NEEDLE")],
            &[message("session", MessageRole::User, "NEEDLE")],
        )
        .unwrap();
        assert_eq!(result.atomic_equivalence.both_match, 1);
        assert!(
            result
                .sessions
                .iter()
                .flat_map(|session| session.detectors.iter())
                .all(|detector| detector.detector_id != "synthetic.disabled")
        );
    }

    #[test]
    fn report_is_byte_deterministic_and_contains_no_raw_values() {
        let rule = rules(&target_rule("synthetic.user", "user_context", "needle"));
        let legacy = record("private-session", RecordKind::UserMessage, "needle");
        let canonical = message("private-session", MessageRole::User, "needle");
        let left = serde_json::to_vec(
            &compare_sessions(
                &rule,
                std::slice::from_ref(&legacy),
                std::slice::from_ref(&canonical),
            )
            .unwrap()
            .to_report(vec!["synthetic.source".to_owned()], 1),
        )
        .unwrap();
        let right = serde_json::to_vec(
            &compare_sessions(&rule, &[legacy], &[canonical])
                .unwrap()
                .to_report(vec!["synthetic.source".to_owned()], 1),
        )
        .unwrap();
        assert_eq!(left, right);
        let text = String::from_utf8(left).unwrap();
        assert!(!text.contains("private-session"));
        assert!(!text.contains("needle"));
    }

    #[test]
    fn metadata_snapshot_serialization_excludes_compatibility_risk_score() {
        let snapshot = MetadataSnapshot::default();
        let serialized = serde_json::to_string(&snapshot).unwrap();

        assert!(!serialized.contains("score"));
        assert!(!serialized.contains("rule_ids"));
    }
}
