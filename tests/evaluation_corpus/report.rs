use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

use crate::evaluate::{
    CANONICAL_EVALUATION_THRESHOLDS, CaseEvaluation, Contribution, Evaluation, RuleCoverage,
    SourceCoverage, VisibilityCounts,
};
use crate::manifest::{
    Disposition, ExpectedSecurityReview, Manifest, RuleExpectationKind, manifest_sha256,
};

#[derive(Serialize)]
struct Report {
    metadata: Metadata,
    corpus: Corpus,
    conformance: Conformance,
    characterization: Characterization,
    efficacy: Efficacy,
    rule_coverage: Coverage,
    modifier_coverage: Coverage,
    rule_match_confusion: BTreeMap<String, Confusion>,
    contribution_conformance: ContributionConformance,
    source_coverage: SourceCoverageReport,
    process_chain: ProcessChainCoverageReport,
    cases: Vec<CaseReport>,
}

#[derive(Serialize)]
struct Metadata {
    schema: String,
    version: u32,
    manifest_version: u32,
    manifest_sha256: String,
    synthetic: bool,
    characterization_purpose: String,
    efficacy_purpose: String,
    primary_efficacy_decision_boundary: String,
    canonical_thresholds: CanonicalThresholds,
}

#[derive(Clone, Copy, Serialize)]
struct CanonicalThresholds {
    low: u32,
    medium: u32,
    high: u32,
    critical: u32,
}

#[derive(Serialize)]
struct Corpus {
    total_cases: u64,
    characterization_cases: u64,
    source_conformance_case_count: u64,
    efficacy_case_count: u64,
    overlap_case_count: u64,
    by_eventfulness: BTreeMap<String, u64>,
    by_disposition: BTreeMap<String, u64>,
    efficacy_scored_cases: u64,
    efficacy_not_scored_cases: u64,
}

#[derive(Serialize)]
struct Conformance {
    pass: bool,
    fail: u64,
    failure_case_ids: Vec<String>,
    note: String,
}

#[derive(Serialize)]
struct Characterization {
    note: String,
    positive_risk: Rate,
    non_informational: Rate,
    review_or_higher: Rate,
    security_review_required: Rate,
    critical: Rate,
    severity_distribution: BTreeMap<String, u64>,
}

#[derive(Serialize)]
struct Efficacy {
    decision_boundary: String,
    canonical_thresholds: CanonicalThresholds,
    scored_efficacy_cases: u64,
    not_scored_cases: u64,
    session_security_review_confusion: SessionAlertConfusion,
    benign_signal_ladder: BenignLadder,
}

#[derive(Clone, Copy, Default, Serialize)]
struct Confusion {
    tp: u64,
    fp: u64,
    tn: u64,
    #[serde(rename = "fn")]
    false_negative: u64,
}

#[derive(Serialize)]
struct SessionAlertConfusion {
    tp: u64,
    fp: u64,
    tn: u64,
    #[serde(rename = "fn")]
    false_negative: u64,
    precision: Rate,
    recall: Rate,
}

#[derive(Serialize)]
struct Rate {
    numerator: u64,
    denominator: u64,
    value: Option<f64>,
}

#[derive(Serialize)]
struct BenignLadder {
    scored_denominator: u64,
    benign_positive_risk_rate: Rate,
    benign_non_informational_rate: Rate,
    benign_review_or_higher_rate: Rate,
    benign_security_review_rate: Rate,
    benign_critical_rate: Rate,
}

#[derive(Serialize)]
struct Coverage {
    enabled_count: u64,
    enabled_ids: Vec<String>,
    positive_covered: BTreeMap<String, Vec<String>>,
    benign_confounder_covered: BTreeMap<String, Vec<String>>,
    unsupported_observability: BTreeMap<String, String>,
    uncovered: Vec<String>,
}

#[derive(Serialize)]
struct ContributionConformance {
    exact_expected_total_checks: u64,
    contribution_id_point_checks: u64,
    failures: Vec<String>,
}

#[derive(Serialize)]
struct SourceCoverageReport {
    supported_expected: Vec<String>,
    supported_represented: Vec<String>,
    candidates_represented: Vec<String>,
    source_conformance_case_count: u64,
    efficacy_case_count: u64,
    overlap_case_count: u64,
    client_source_counts: BTreeMap<String, u64>,
    visibility_field_coverage: BTreeMap<String, VisibilityCountReport>,
}

#[derive(Serialize)]
struct VisibilityCountReport {
    required: u64,
    optional: u64,
    unavailable: u64,
}

#[derive(Serialize)]
struct ProcessChainCoverageReport {
    note: String,
    enabled_chain_count: u64,
    enabled_standalone_count: u64,
    enabled_correlation_count: u64,
    enabled_total_count: u64,
    definition_conformance_covered: u64,
    independent_scenario_efficacy_count: u64,
    independent_benign_scenario_count: u64,
    uncovered_ids: Vec<String>,
    rationales: BTreeMap<String, String>,
    evaluator_path: String,
    pipeline_integration: String,
}

#[derive(Serialize)]
struct CaseReport {
    id: String,
    eventfulness: String,
    disposition: String,
    expected_security_review: String,
    label_rationale: String,
    observed_security_review: bool,
    observed_severity: String,
    score: u64,
    matched_rule_ids: Vec<String>,
    contributions: Vec<Contribution>,
    efficacy_result: String,
    conformance_failures: Vec<String>,
}

pub fn render_report(
    manifest: &Manifest,
    evaluation: &Evaluation,
    repo_root: &Path,
) -> Result<Vec<u8>, String> {
    let thresholds = CanonicalThresholds {
        low: CANONICAL_EVALUATION_THRESHOLDS.low,
        medium: CANONICAL_EVALUATION_THRESHOLDS.medium,
        high: CANONICAL_EVALUATION_THRESHOLDS.high,
        critical: CANONICAL_EVALUATION_THRESHOLDS.critical,
    };
    let purpose = purpose_counts(manifest);
    let report = Report {
        metadata: Metadata {
            schema: "telltale.evaluation.baseline".to_string(),
            version: 1,
            manifest_version: manifest.version,
            manifest_sha256: manifest_sha256(&repo_root.join("tests/evaluation/manifest.yaml"))?,
            synthetic: true,
            characterization_purpose:
                "What does the current deterministic detector do on this synthetic corpus?"
                    .to_string(),
            efficacy_purpose: "Against independently authored scenario expectations, does the current detector require security review for the scenarios we intend to escalate while avoiding security-review escalation for the benign scenarios we intend not to escalate?".to_string(),
            primary_efficacy_decision_boundary:
                "security_review_required when MatchResult.score >= 70 using fixed canonical thresholds"
                    .to_string(),
            canonical_thresholds: thresholds,
        },
        corpus: corpus(manifest, &purpose),
        conformance: conformance(&evaluation.cases),
        characterization: characterization(manifest, &evaluation.cases),
        efficacy: efficacy(manifest, &evaluation.cases, thresholds),
        rule_coverage: coverage(&evaluation.rule_coverage),
        modifier_coverage: coverage(&evaluation.modifier_coverage),
        rule_match_confusion: rule_match_confusion(manifest, &evaluation.cases),
        contribution_conformance: contribution_conformance(manifest, &evaluation.cases),
        source_coverage: source_coverage(&evaluation.source_coverage, &purpose),
        process_chain: process_chain_coverage(&evaluation.process_chain_coverage),
        cases: evaluation.cases.iter().map(|case| {
            let expected = manifest
                .cases
                .iter()
                .find(|item| item.id == case.id)
                .expect("evaluated case came from manifest");
            case_report(case, expected)
        }).collect(),
    };
    let mut bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

struct PurposeCounts {
    source_conformance: u64,
    efficacy: u64,
    overlap: u64,
}

fn purpose_counts(manifest: &Manifest) -> PurposeCounts {
    let mut source_conformance = 0;
    let mut efficacy = 0;
    let mut overlap = 0;
    for case in &manifest.cases {
        let source = case.tags.iter().any(|tag| tag == "source_conformance");
        let scored = case.expected_security_review.is_scored();
        if source {
            source_conformance += 1;
        }
        if scored {
            efficacy += 1;
        }
        if source && scored {
            overlap += 1;
        }
    }
    PurposeCounts {
        source_conformance,
        efficacy,
        overlap,
    }
}

fn corpus(manifest: &Manifest, purpose: &PurposeCounts) -> Corpus {
    let mut by_eventfulness = BTreeMap::new();
    let mut by_disposition = BTreeMap::new();
    let mut efficacy_scored_cases = 0;
    let mut efficacy_not_scored_cases = 0;
    for case in &manifest.cases {
        *by_eventfulness
            .entry(case.eventfulness.as_str().to_string())
            .or_default() += 1;
        *by_disposition
            .entry(case.disposition.as_str().to_string())
            .or_default() += 1;
        if case.expected_security_review.is_scored() {
            efficacy_scored_cases += 1;
        } else {
            efficacy_not_scored_cases += 1;
        }
    }
    Corpus {
        total_cases: manifest.cases.len() as u64,
        characterization_cases: manifest.cases.len() as u64,
        source_conformance_case_count: purpose.source_conformance,
        efficacy_case_count: purpose.efficacy,
        overlap_case_count: purpose.overlap,
        by_eventfulness,
        by_disposition,
        efficacy_scored_cases,
        efficacy_not_scored_cases,
    }
}

fn conformance(cases: &[CaseEvaluation]) -> Conformance {
    let failure_case_ids = cases
        .iter()
        .filter(|case| !case.failures.is_empty())
        .map(|case| case.id.clone())
        .collect::<Vec<_>>();
    Conformance {
        pass: failure_case_ids.is_empty(),
        fail: failure_case_ids.len() as u64,
        failure_case_ids,
        note: "Conformance is characterization of current detector output (rules, scores, contributions, parser/visibility). It is not synthetic efficacy.".to_string(),
    }
}

fn characterization(manifest: &Manifest, evaluations: &[CaseEvaluation]) -> Characterization {
    let evaluations = by_id(evaluations);
    let total = manifest.cases.len() as u64;
    let mut positive_risk = 0;
    let mut non_informational = 0;
    let mut review_or_higher = 0;
    let mut security_review = 0;
    let mut critical = 0;
    let mut severity_distribution = BTreeMap::new();
    for case in &manifest.cases {
        let evaluation = evaluations[case.id.as_str()];
        *severity_distribution
            .entry(evaluation.observed_severity.clone())
            .or_default() += 1;
        if evaluation.observed_positive_risk {
            positive_risk += 1;
        }
        if evaluation.score >= u64::from(CANONICAL_EVALUATION_THRESHOLDS.low) {
            non_informational += 1;
        }
        if evaluation.score >= u64::from(CANONICAL_EVALUATION_THRESHOLDS.medium) {
            review_or_higher += 1;
        }
        if evaluation.observed_security_review {
            security_review += 1;
        }
        if evaluation.score >= u64::from(CANONICAL_EVALUATION_THRESHOLDS.critical) {
            critical += 1;
        }
    }
    Characterization {
        note: "Signal and severity characterization of current detector output. Positive-risk (score > 0) is not a false-positive rate and is not the primary efficacy classifier.".to_string(),
        positive_risk: rate(positive_risk, total),
        non_informational: rate(non_informational, total),
        review_or_higher: rate(review_or_higher, total),
        security_review_required: rate(security_review, total),
        critical: rate(critical, total),
        severity_distribution,
    }
}

fn efficacy(
    manifest: &Manifest,
    evaluations: &[CaseEvaluation],
    thresholds: CanonicalThresholds,
) -> Efficacy {
    let evaluations = by_id(evaluations);
    let mut confusion = Confusion::default();
    let mut scored = 0;
    let mut not_scored = 0;
    for case in &manifest.cases {
        let evaluation = evaluations[case.id.as_str()];
        match (
            case.expected_security_review,
            evaluation.observed_security_review,
        ) {
            (ExpectedSecurityReview::Required, true) => {
                scored += 1;
                confusion.tp += 1;
            }
            (ExpectedSecurityReview::NotRequired, true) => {
                scored += 1;
                confusion.fp += 1;
            }
            (ExpectedSecurityReview::NotRequired, false) => {
                scored += 1;
                confusion.tn += 1;
            }
            (ExpectedSecurityReview::Required, false) => {
                scored += 1;
                confusion.false_negative += 1;
            }
            (ExpectedSecurityReview::NotScored, _) => not_scored += 1,
        }
    }
    Efficacy {
        decision_boundary: "security_review_required".to_string(),
        canonical_thresholds: thresholds,
        scored_efficacy_cases: scored,
        not_scored_cases: not_scored,
        session_security_review_confusion: SessionAlertConfusion {
            tp: confusion.tp,
            fp: confusion.fp,
            tn: confusion.tn,
            false_negative: confusion.false_negative,
            precision: rate(confusion.tp, confusion.tp + confusion.fp),
            recall: rate(confusion.tp, confusion.tp + confusion.false_negative),
        },
        benign_signal_ladder: benign_ladder(manifest, &evaluations),
    }
}

fn benign_ladder(
    manifest: &Manifest,
    evaluations: &BTreeMap<&str, &CaseEvaluation>,
) -> BenignLadder {
    let mut denominator = 0;
    let mut positive_risk = 0;
    let mut non_informational = 0;
    let mut review_or_higher = 0;
    let mut security_review = 0;
    let mut critical = 0;
    for case in &manifest.cases {
        if case.disposition != Disposition::Benign || !case.expected_security_review.is_scored() {
            continue;
        }
        denominator += 1;
        let evaluation = evaluations[case.id.as_str()];
        if evaluation.observed_positive_risk {
            positive_risk += 1;
        }
        if evaluation.score >= u64::from(CANONICAL_EVALUATION_THRESHOLDS.low) {
            non_informational += 1;
        }
        if evaluation.score >= u64::from(CANONICAL_EVALUATION_THRESHOLDS.medium) {
            review_or_higher += 1;
        }
        if evaluation.observed_security_review {
            security_review += 1;
        }
        if evaluation.score >= u64::from(CANONICAL_EVALUATION_THRESHOLDS.critical) {
            critical += 1;
        }
    }
    BenignLadder {
        scored_denominator: denominator,
        benign_positive_risk_rate: rate(positive_risk, denominator),
        benign_non_informational_rate: rate(non_informational, denominator),
        benign_review_or_higher_rate: rate(review_or_higher, denominator),
        benign_security_review_rate: rate(security_review, denominator),
        benign_critical_rate: rate(critical, denominator),
    }
}

fn rate(numerator: u64, denominator: u64) -> Rate {
    Rate {
        numerator,
        denominator,
        value: (denominator != 0).then(|| numerator as f64 / denominator as f64),
    }
}

fn coverage(coverage: &RuleCoverage) -> Coverage {
    Coverage {
        enabled_count: coverage.enabled.len() as u64,
        enabled_ids: coverage.enabled.iter().cloned().collect(),
        positive_covered: map_case_sets(&coverage.positive_covered),
        benign_confounder_covered: map_case_sets(&coverage.benign_confounder_covered),
        unsupported_observability: coverage.unsupported_observability.clone(),
        uncovered: coverage.uncovered.clone(),
    }
}

fn map_case_sets(map: &BTreeMap<String, BTreeSet<String>>) -> BTreeMap<String, Vec<String>> {
    map.iter()
        .map(|(rule_id, case_ids)| (rule_id.clone(), case_ids.iter().cloned().collect()))
        .collect()
}

fn rule_match_confusion(
    manifest: &Manifest,
    evaluations: &[CaseEvaluation],
) -> BTreeMap<String, Confusion> {
    let evaluations = by_id(evaluations);
    let rule_set = telltale_rules::bundled_default_rule_set().expect("bundled rules");
    let enabled = rule_set
        .rules
        .iter()
        .filter(|rule| rule.enabled && rule_set.defaults.enabled)
        .map(|rule| rule.id.clone())
        .chain(
            rule_set
                .modifiers
                .iter()
                .filter(|modifier| modifier.enabled && rule_set.defaults.enabled)
                .map(|modifier| modifier.id.clone()),
        )
        .collect::<BTreeSet<_>>();
    let mut result = BTreeMap::<String, Confusion>::new();
    for case in &manifest.cases {
        let actual = evaluations[case.id.as_str()]
            .matched_rules
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let explicit = case
            .expected_detection
            .rule_expectations
            .iter()
            .map(|expectation| (expectation.rule_id.as_str(), expectation.expectation))
            .collect::<BTreeMap<_, _>>();
        for rule_id in &enabled {
            let expectation = explicit.get(rule_id.as_str()).copied().unwrap_or({
                if case.expected_detection.exact_rule_set {
                    RuleExpectationKind::ExpectedAbsent
                } else {
                    RuleExpectationKind::NotScored
                }
            });
            let Some(confusion) = (!matches!(expectation, RuleExpectationKind::NotScored))
                .then(|| result.entry(rule_id.clone()).or_default())
            else {
                continue;
            };
            match (expectation, actual.contains(rule_id)) {
                (RuleExpectationKind::ExpectedMatch, true) => confusion.tp += 1,
                (RuleExpectationKind::ExpectedMatch, false) => confusion.false_negative += 1,
                (RuleExpectationKind::ExpectedAbsent, true) => confusion.fp += 1,
                (RuleExpectationKind::ExpectedAbsent, false) => confusion.tn += 1,
                (RuleExpectationKind::NotScored, _) => {}
            }
        }
    }
    result
}

fn contribution_conformance(
    manifest: &Manifest,
    evaluations: &[CaseEvaluation],
) -> ContributionConformance {
    let evaluations = by_id(evaluations);
    let failures = manifest
        .cases
        .iter()
        .filter(|case| {
            let evaluation = evaluations[case.id.as_str()];
            evaluation.score != case.expected_detection.expected_score
                || contributions(evaluation) != expected_contributions(case)
        })
        .map(|case| case.id.clone())
        .collect();
    ContributionConformance {
        exact_expected_total_checks: manifest.cases.len() as u64,
        contribution_id_point_checks: manifest
            .cases
            .iter()
            .map(|case| case.expected_detection.expected_contributions.len() as u64)
            .sum(),
        failures,
    }
}

fn contributions(evaluation: &CaseEvaluation) -> Vec<Contribution> {
    evaluation.contributions.clone()
}

fn expected_contributions(case: &crate::manifest::Case) -> Vec<Contribution> {
    case.expected_detection
        .expected_contributions
        .iter()
        .map(|contribution| Contribution {
            id: contribution.id.clone(),
            contribution_type: contribution.contribution_type,
            points: contribution.points,
        })
        .collect()
}

fn source_coverage(coverage: &SourceCoverage, purpose: &PurposeCounts) -> SourceCoverageReport {
    SourceCoverageReport {
        supported_expected: coverage.supported_expected.iter().cloned().collect(),
        supported_represented: coverage.supported_represented.iter().cloned().collect(),
        candidates_represented: coverage.candidates_represented.iter().cloned().collect(),
        source_conformance_case_count: purpose.source_conformance,
        efficacy_case_count: purpose.efficacy,
        overlap_case_count: purpose.overlap,
        client_source_counts: coverage.client_source_counts.clone(),
        visibility_field_coverage: coverage
            .visibility_field_coverage
            .iter()
            .map(|(field, counts)| (field.clone(), visibility_counts(counts)))
            .collect(),
    }
}

fn visibility_counts(counts: &VisibilityCounts) -> VisibilityCountReport {
    VisibilityCountReport {
        required: counts.required,
        optional: counts.optional,
        unavailable: counts.unavailable,
    }
}

fn process_chain_coverage(
    coverage: &crate::process_chain::ProcessChainCoverage,
) -> ProcessChainCoverageReport {
    ProcessChainCoverageReport {
        note: "Definition-backed self-match conformance is not process-chain scenario efficacy and is not 100% process-chain detection performance.".to_string(),
        enabled_chain_count: coverage.enabled_chain_count as u64,
        enabled_standalone_count: coverage.enabled_standalone_count as u64,
        enabled_correlation_count: coverage.enabled_correlation_count as u64,
        enabled_total_count: (coverage.enabled_chain_count
            + coverage.enabled_standalone_count
            + coverage.enabled_correlation_count) as u64,
        definition_conformance_covered: coverage.covered_chain_and_standalone_ids.len() as u64
            + coverage.covered_correlation_ids.len() as u64,
        independent_scenario_efficacy_count: coverage.independent_scenario_tested_count as u64,
        independent_benign_scenario_count: coverage.independent_benign_scenario_count as u64,
        uncovered_ids: coverage.uncovered_ids.clone(),
        rationales: coverage.rationales.clone(),
        evaluator_path: coverage.evaluator_path.clone(),
        pipeline_integration: coverage.pipeline_integration.clone(),
    }
}

fn case_report(case: &CaseEvaluation, expected: &crate::manifest::Case) -> CaseReport {
    CaseReport {
        id: case.id.clone(),
        eventfulness: expected.eventfulness.as_str().to_string(),
        disposition: expected.disposition.as_str().to_string(),
        expected_security_review: case.expected_security_review.clone(),
        label_rationale: case.label_rationale.clone(),
        observed_security_review: case.observed_security_review,
        observed_severity: case.observed_severity.clone(),
        score: case.score,
        matched_rule_ids: case.matched_rules.clone(),
        contributions: case.contributions.clone(),
        efficacy_result: efficacy_result(
            expected.expected_security_review,
            case.observed_security_review,
        ),
        conformance_failures: case.failures.clone(),
    }
}

fn efficacy_result(expected: ExpectedSecurityReview, observed: bool) -> String {
    match (expected, observed) {
        (ExpectedSecurityReview::Required, true) => "tp",
        (ExpectedSecurityReview::NotRequired, true) => "fp",
        (ExpectedSecurityReview::NotRequired, false) => "tn",
        (ExpectedSecurityReview::Required, false) => "fn",
        (ExpectedSecurityReview::NotScored, _) => "not_scored",
    }
    .to_string()
}

fn by_id(evaluations: &[CaseEvaluation]) -> BTreeMap<&str, &CaseEvaluation> {
    evaluations
        .iter()
        .map(|evaluation| (evaluation.id.as_str(), evaluation))
        .collect()
}
