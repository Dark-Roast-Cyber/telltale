use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use telltale_detect::v2::{
    compile_rule_v1,
    session::{CanonicalSourceInput, evaluate_source},
};
use telltale_rules::bundled_default_rule_set;
use telltale_schema::observation::{
    CanonicalObservationV2, CorrelationId, MessageRole, ObservationBody, ObservationStage,
    ObservedAt,
};
use telltale_schema::scoring::{RiskContributionType, RiskThresholds, assess_risk_with_thresholds};
use telltale_schema::source::Source;
use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};

use crate::manifest::{
    Case, Client, Input, Manifest, RuleExpectationKind, VisibilityField, candidate_source_ids,
    fixture_path, supported_source_ids,
};

pub const CANONICAL_EVALUATION_THRESHOLDS: RiskThresholds = RiskThresholds {
    low: 20,
    medium: 50,
    high: 70,
    critical: 90,
};
use crate::process_chain::{ProcessChainCoverage, evaluate_process_chain_coverage};

struct FixtureDetection {
    score: u64,
    matched_rules: Vec<String>,
    contributions: Vec<Contribution>,
    failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Contribution {
    pub id: String,
    #[serde(rename = "type")]
    pub contribution_type: RiskContributionType,
    pub points: u64,
}

#[derive(Debug, Clone)]
pub struct CaseEvaluation {
    pub id: String,
    pub expected_security_review: String,
    pub label_rationale: String,
    pub observed_positive_risk: bool,
    pub observed_security_review: bool,
    pub observed_severity: String,
    pub score: u64,
    pub matched_rules: Vec<String>,
    pub contributions: Vec<Contribution>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuleCoverage {
    pub enabled: BTreeSet<String>,
    pub positive_covered: BTreeMap<String, BTreeSet<String>>,
    pub benign_confounder_covered: BTreeMap<String, BTreeSet<String>>,
    pub unsupported_observability: BTreeMap<String, String>,
    pub uncovered: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SourceCoverage {
    pub supported_expected: BTreeSet<String>,
    pub supported_represented: BTreeSet<String>,
    pub candidates_represented: BTreeSet<String>,
    pub client_source_counts: BTreeMap<String, u64>,
    pub visibility_field_coverage: BTreeMap<String, VisibilityCounts>,
}

#[derive(Debug, Clone, Default)]
pub struct VisibilityCounts {
    pub required: u64,
    pub optional: u64,
    pub unavailable: u64,
}

#[derive(Debug, Clone)]
pub struct Evaluation {
    pub cases: Vec<CaseEvaluation>,
    pub rule_coverage: RuleCoverage,
    pub modifier_coverage: RuleCoverage,
    pub source_coverage: SourceCoverage,
    pub process_chain_coverage: ProcessChainCoverage,
}

pub fn evaluate_manifest(manifest: &Manifest, repo_root: &Path) -> Result<Evaluation, String> {
    let rule_set = bundled_default_rule_set().map_err(|error| error.to_string())?;
    let canonical_rules = compile_rule_v1(
        &telltale_rules::load_default_rule_set()
            .map_err(|error| error.to_string())?
            .compatibility_export(),
    )
    .map_err(|error| error.to_string())?;
    let enabled_regex = rule_set
        .rules
        .iter()
        .filter(|rule| rule.enabled && rule_set.defaults.enabled)
        .map(|rule| rule.id.clone())
        .collect::<BTreeSet<_>>();
    let enabled_modifiers = rule_set
        .modifiers
        .iter()
        .filter(|modifier| modifier.enabled && rule_set.defaults.enabled)
        .map(|modifier| modifier.id.clone())
        .collect::<BTreeSet<_>>();
    let mut cases = manifest.cases.iter().collect::<Vec<_>>();
    cases.sort_by(|left, right| left.id.cmp(&right.id));
    let mut results = Vec::with_capacity(cases.len());
    let mut source_coverage = SourceCoverage {
        supported_expected: supported_source_ids(),
        supported_represented: BTreeSet::new(),
        candidates_represented: BTreeSet::new(),
        client_source_counts: BTreeMap::new(),
        visibility_field_coverage: BTreeMap::new(),
    };
    for case in cases {
        let result = evaluate_case(case, &canonical_rules, repo_root, &mut source_coverage)?;
        results.push(result);
    }
    let rule_coverage = coverage_for(&manifest.cases, &enabled_regex);
    let modifier_coverage = coverage_for(&manifest.cases, &enabled_modifiers);
    let process_chain_coverage = evaluate_process_chain_coverage()?;
    Ok(Evaluation {
        cases: results,
        rule_coverage,
        modifier_coverage,
        source_coverage,
        process_chain_coverage,
    })
}

fn evaluate_case(
    case: &Case,
    canonical_rules: &telltale_detect::v2::RuleV1CompatibilityPlan,
    repo_root: &Path,
    source_coverage: &mut SourceCoverage,
) -> Result<CaseEvaluation, String> {
    let FixtureDetection {
        score,
        matched_rules,
        contributions,
        mut failures,
    } = {
        // Every case is a native source fixture on the production canonical path.
        let Input::SourceFixture {
            fixture,
            client,
            source_id,
            source_kind,
        } = &case.input;
        let source = Source {
            client: client.client_id(),
            kind: source_kind.source_kind(),
            source_id: source_id.clone(),
            path: fixture_path(repo_root, fixture),
        };
        record_source_coverage(case, *client, source_id, source_coverage);
        evaluate_source_fixture(case, canonical_rules, &source)?
    };
    let assessment = assess_risk_with_thresholds(score, CANONICAL_EVALUATION_THRESHOLDS);
    let observed_positive_risk = score > 0;
    let observed_security_review = score >= u64::from(CANONICAL_EVALUATION_THRESHOLDS.high);
    if score != checked_risk_sum_from(&contributions)? {
        failures.push("score does not equal checked contribution sum".to_string());
    }
    let actual_rules = matched_rules.iter().cloned().collect::<BTreeSet<_>>();
    let expected_rules = case
        .expected_detection
        .rule_expectations
        .iter()
        .map(|expectation| (expectation.rule_id.as_str(), expectation.expectation))
        .collect::<BTreeMap<_, _>>();
    let enabled = enabled_rule_ids();
    for rule_id in enabled {
        let expectation = expected_rules.get(rule_id.as_str()).copied().unwrap_or({
            if case.expected_detection.exact_rule_set {
                RuleExpectationKind::ExpectedAbsent
            } else {
                RuleExpectationKind::NotScored
            }
        });
        match expectation {
            RuleExpectationKind::ExpectedMatch if !actual_rules.contains(&rule_id) => {
                failures.push(format!("required rule missing: {rule_id}"));
            }
            RuleExpectationKind::ExpectedAbsent if actual_rules.contains(&rule_id) => {
                failures.push(format!("forbidden rule matched: {rule_id}"));
            }
            RuleExpectationKind::ExpectedMatch
            | RuleExpectationKind::ExpectedAbsent
            | RuleExpectationKind::NotScored => {}
        }
    }
    if score != case.expected_detection.expected_score {
        failures.push(format!(
            "expected score {} but observed {score}",
            case.expected_detection.expected_score
        ));
    }
    let expected_contributions = case
        .expected_detection
        .expected_contributions
        .iter()
        .map(|contribution| Contribution {
            id: contribution.id.clone(),
            contribution_type: contribution.contribution_type,
            points: contribution.points,
        })
        .collect::<Vec<_>>();
    if expected_contributions != contributions {
        failures.push("expected contribution ledger differs".to_string());
    }
    Ok(CaseEvaluation {
        id: case.id.clone(),
        expected_security_review: case.expected_security_review.as_str().to_string(),
        label_rationale: case.label_rationale.clone(),
        observed_positive_risk,
        observed_security_review,
        observed_severity: assessment.severity.as_str().to_string(),
        score,
        matched_rules,
        contributions,
        failures,
    })
}

fn evaluate_source_fixture(
    case: &Case,
    rules: &telltale_detect::v2::RuleV1CompatibilityPlan,
    source: &Source,
) -> Result<FixtureDetection, String> {
    let observed_at = ObservedAt::new("2026-09-18T12:00:00Z").expect("fixed observed time");
    let batch = match acquire_source(source, AcquisitionOptions::new(observed_at)) {
        Ok(batch) => batch,
        Err(error) => {
            return Ok(FixtureDetection {
                score: 0,
                matched_rules: Vec::new(),
                contributions: Vec::new(),
                failures: vec![format!("canonical acquisition failure: {error}")],
            });
        }
    };
    if batch.observations.iter().any(|observation| {
        observation.source().adapter_id() != source.source_id
            || observation.source().adapter_type().is_empty()
    }) {
        return Err(format!(
            "case {} canonical provenance does not match {}",
            case.id, source.source_id
        ));
    }
    let instance = CorrelationId::source_reported(format!("evaluation:{}", case.id))
        .map_err(|error| format!("case {} evaluation instance: {error}", case.id))?;
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: source.client,
            source_id: &source.source_id,
            source_instance: Some(&instance),
            observations: &batch.observations,
        },
        rules,
        None,
    )
    .map_err(|error| format!("case {} detection failure: {error}", case.id))?;
    let mut score = 0_u64;
    let mut matched_rules = BTreeSet::new();
    let mut contributions = Vec::new();
    for session in evaluation.sessions() {
        score = score
            .checked_add(session.rule_score())
            .ok_or_else(|| format!("case {} score overflow", case.id))?;
        matched_rules.extend(session.rule_ids().iter().cloned());
        for contribution in session.risk_contributions() {
            contributions.push(Contribution {
                id: contribution.id().to_string(),
                contribution_type: contribution.contribution_type(),
                points: contribution.points(),
            });
        }
    }
    let failures = observation_visibility_failures(case, &batch.observations);
    Ok(FixtureDetection {
        score,
        matched_rules: matched_rules.into_iter().collect(),
        contributions,
        failures,
    })
}

fn observation_visibility_failures(
    case: &Case,
    observations: &[CanonicalObservationV2],
) -> Vec<String> {
    let mut failures = Vec::new();
    for required in &case.expected_visibility.required_record_kinds {
        if !observation_has_kind(required.as_str(), observations) {
            failures.push(format!(
                "required record kind unavailable: {}",
                required.as_str()
            ));
        }
    }
    for unavailable in &case.expected_visibility.unavailable_fields {
        if observation_field_available(*unavailable, observations) {
            failures.push(format!(
                "field declared unavailable is present: {}",
                unavailable.as_str()
            ));
        }
    }
    failures
}

fn observation_has_kind(kind: &str, observations: &[CanonicalObservationV2]) -> bool {
    observations.iter().any(|observation| match kind {
        "user_message" => matches!(
            observation.body(),
            ObservationBody::Message(message) if message.role() == Some(MessageRole::User)
        ),
        "assistant_message" => matches!(
            observation.body(),
            ObservationBody::Message(message) if message.role() == Some(MessageRole::Assistant)
        ),
        "tool_call" => {
            observation.stage() == ObservationStage::ToolRequested
                && matches!(observation.body(), ObservationBody::Tool(_))
        }
        "tool_result" => observation.stage() == ObservationStage::ToolResultReturned,
        "session_meta" => false,
        _ => false,
    })
}

fn observation_field_available(
    field: VisibilityField,
    observations: &[CanonicalObservationV2],
) -> bool {
    match field {
        VisibilityField::Pid | VisibilityField::ParentPid => false,
        VisibilityField::UserIntent => observation_has_kind("user_message", observations),
        VisibilityField::Timestamp => observations
            .iter()
            .any(|observation| observation.occurred_at().is_some()),
        VisibilityField::ToolName => observations.iter().any(|observation| {
            matches!(observation.body(), ObservationBody::Tool(tool) if tool.name().is_some())
        }),
        VisibilityField::Arguments => observations.iter().any(|observation| {
            matches!(
                observation.body(),
                ObservationBody::Tool(tool) if tool.arguments().is_some()
            )
        }),
        VisibilityField::Content => observations.iter().any(|observation| match observation.body() {
            ObservationBody::Message(message) => message.content().is_some(),
            ObservationBody::Tool(tool) => tool.arguments().is_some() || tool.result().is_some(),
            _ => false,
        }),
        VisibilityField::Agent | VisibilityField::Model | VisibilityField::Provider => false,
    }
}

fn checked_risk_sum_from(contributions: &[Contribution]) -> Result<u64, String> {
    contributions.iter().try_fold(0_u64, |total, contribution| {
        total
            .checked_add(contribution.points)
            .ok_or_else(|| "contribution total overflow".to_string())
    })
}

fn enabled_rule_ids() -> BTreeSet<String> {
    let rule_set = bundled_default_rule_set().expect("bundled rule set");
    rule_set
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
        .collect()
}

fn coverage_for(cases: &[Case], enabled: &BTreeSet<String>) -> RuleCoverage {
    let mut positive_covered = BTreeMap::<String, BTreeSet<String>>::new();
    let mut benign_confounder_covered = BTreeMap::<String, BTreeSet<String>>::new();
    for case in cases {
        for expectation in &case.expected_detection.rule_expectations {
            if !enabled.contains(&expectation.rule_id) {
                continue;
            }
            if case.tags.iter().any(|tag| tag == "benign_confounder")
                && expectation.expectation != RuleExpectationKind::NotScored
            {
                benign_confounder_covered
                    .entry(expectation.rule_id.clone())
                    .or_default()
                    .insert(case.id.clone());
            }
            if expectation.expectation != RuleExpectationKind::ExpectedMatch {
                continue;
            }
            positive_covered
                .entry(expectation.rule_id.clone())
                .or_default()
                .insert(case.id.clone());
        }
    }
    let unsupported_observability = BTreeMap::new();
    let uncovered = enabled
        .iter()
        .filter(|rule_id| !positive_covered.contains_key(*rule_id))
        .cloned()
        .collect();
    RuleCoverage {
        enabled: enabled.clone(),
        positive_covered,
        benign_confounder_covered,
        unsupported_observability,
        uncovered,
    }
}

fn record_source_coverage(
    case: &Case,
    client: Client,
    source_id: &str,
    coverage: &mut SourceCoverage,
) {
    if coverage.supported_expected.contains(source_id) {
        coverage.supported_represented.insert(source_id.to_string());
    }
    if candidate_source_ids().contains(source_id) {
        coverage
            .candidates_represented
            .insert(source_id.to_string());
    }
    *coverage
        .client_source_counts
        .entry(format!("{}.{}", client.client_id().as_str(), source_id))
        .or_default() += 1;
    for field in &case.expected_visibility.required_record_kinds {
        coverage
            .visibility_field_coverage
            .entry(format!("record_kind:{}", field.as_str()))
            .or_default()
            .required += 1;
    }
    for field in &case.expected_visibility.optional_fields {
        coverage
            .visibility_field_coverage
            .entry(field.as_str().to_string())
            .or_default()
            .optional += 1;
    }
    for field in &case.expected_visibility.unavailable_fields {
        coverage
            .visibility_field_coverage
            .entry(field.as_str().to_string())
            .or_default()
            .unavailable += 1;
    }
}
