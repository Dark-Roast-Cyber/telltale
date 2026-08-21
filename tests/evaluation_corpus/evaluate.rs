use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use telltale_core::Pipeline;
use telltale_rules::{MatchResult, bundled_default_rule_set};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::scoring::{RiskContributionType, RiskThresholds, assess_risk_with_thresholds};
use telltale_schema::source::Source;
use telltale_sources::parser::parse_source_records;

use crate::manifest::{
    Case, Client, Input, Manifest, RecordKindName, RuleExpectationKind, VisibilityField,
    candidate_source_ids, fixture_path, supported_source_ids,
};

pub const CANONICAL_EVALUATION_THRESHOLDS: RiskThresholds = RiskThresholds {
    low: 20,
    medium: 50,
    high: 70,
    critical: 90,
};
use crate::process_chain::{ProcessChainCoverage, evaluate_process_chain_coverage};

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
    let pipeline = Pipeline::builder()
        .build()
        .map_err(|error| error.to_string())?;
    let rule_set = bundled_default_rule_set().map_err(|error| error.to_string())?;
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
        let result = evaluate_case(case, &pipeline, repo_root, &mut source_coverage)?;
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
    pipeline: &Pipeline,
    repo_root: &Path,
    source_coverage: &mut SourceCoverage,
) -> Result<CaseEvaluation, String> {
    let (records, source_id, source_client) = match &case.input {
        Input::SourceFixture {
            fixture,
            client,
            source_id,
            source_kind,
        } => {
            let source = Source {
                client: client.client_id(),
                kind: source_kind.source_kind(),
                source_id: source_id.clone(),
                path: fixture_path(repo_root, fixture),
            };
            let records = parse_source_records(&source)
                .map_err(|error| format!("case {} parse failure: {error}", case.id))?;
            record_source_coverage(case, *client, source_id, source_coverage);
            (
                records,
                Some(source_id.clone()),
                Some(client.client_id().as_str().to_string()),
            )
        }
        Input::NormalizedRecords { client, records } => (
            records
                .iter()
                .map(|record| normalize_record(record, client.client_id().as_str()))
                .collect(),
            None,
            Some(client.client_id().as_str().to_string()),
        ),
    };
    let mut failures = visibility_failures(case, &records);
    if source_id.is_some()
        && records
            .iter()
            .any(|record| record.client != source_client.as_deref().unwrap_or_default())
    {
        failures.push("parsed record client differs from source client".to_string());
    }
    let matches = pipeline
        .evaluate_session(&records)
        .map_err(|error| format!("case {} evaluation failure: {error}", case.id))?;
    let (score, matched_rules, contributions) = match matches {
        Some(result) => match_result(result)?,
        None => (0, Vec::new(), Vec::new()),
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

fn normalize_record(record: &crate::manifest::RecordInput, client: &str) -> NormalizedRecord {
    NormalizedRecord {
        session_id: record.session_id.clone(),
        client: client.to_string(),
        agent: record.agent.clone(),
        model: record.model.clone(),
        provider: record.provider.clone(),
        timestamp: record.timestamp.clone(),
        kind: match record.kind {
            RecordKindName::UserMessage => RecordKind::UserMessage,
            RecordKindName::AssistantMessage => RecordKind::AssistantMessage,
            RecordKindName::ToolCall => RecordKind::ToolCall,
            RecordKindName::ToolResult => RecordKind::ToolResult,
            RecordKindName::SessionMeta => RecordKind::SessionMeta,
            RecordKindName::Other => RecordKind::Other,
        },
        tool_name: record.tool_name.clone(),
        arguments: record.arguments.clone(),
        content: record.content.clone(),
    }
}

fn match_result(result: MatchResult) -> Result<(u64, Vec<String>, Vec<Contribution>), String> {
    let score = result.score;
    let mut rule_ids = result.rule_ids;
    rule_ids.sort();
    rule_ids.dedup();
    let contributions = result
        .contributions
        .iter()
        .map(|contribution| Contribution {
            id: contribution.id().to_string(),
            contribution_type: contribution.contribution_type(),
            points: contribution.points(),
        })
        .collect::<Vec<_>>();
    let actual_sum = telltale_schema::scoring::checked_risk_sum(&result.contributions)
        .map_err(|error| error.to_string())?;
    if score != actual_sum {
        return Err(format!(
            "MatchResult score {score} does not equal {actual_sum}"
        ));
    }
    Ok((score, rule_ids, contributions))
}

fn checked_risk_sum_from(contributions: &[Contribution]) -> Result<u64, String> {
    contributions.iter().try_fold(0_u64, |total, contribution| {
        total
            .checked_add(contribution.points)
            .ok_or_else(|| "contribution total overflow".to_string())
    })
}

fn visibility_failures(case: &Case, records: &[NormalizedRecord]) -> Vec<String> {
    let kinds = record_kinds(records).into_iter().collect::<BTreeSet<_>>();
    let mut failures = Vec::new();
    for required in &case.expected_visibility.required_record_kinds {
        if !kinds.contains(required.as_str()) {
            failures.push(format!(
                "required record kind unavailable: {}",
                required.as_str()
            ));
        }
    }
    for unavailable in &case.expected_visibility.unavailable_fields {
        if field_is_available(*unavailable, records) {
            failures.push(format!(
                "field declared unavailable is present: {}",
                unavailable.as_str()
            ));
        }
    }
    failures
}

fn field_is_available(field: VisibilityField, records: &[NormalizedRecord]) -> bool {
    match field {
        VisibilityField::Pid | VisibilityField::ParentPid => false,
        VisibilityField::UserIntent => records
            .iter()
            .any(|record| record.kind == RecordKind::UserMessage),
        VisibilityField::Timestamp => records.iter().any(|record| record.timestamp.is_some()),
        VisibilityField::ToolName => records.iter().any(|record| record.tool_name.is_some()),
        VisibilityField::Arguments => records.iter().any(|record| record.arguments.is_some()),
        VisibilityField::Content => records.iter().any(|record| !record.content.is_empty()),
        VisibilityField::Agent => records.iter().any(|record| record.agent.is_some()),
        VisibilityField::Model => records.iter().any(|record| record.model.is_some()),
        VisibilityField::Provider => records.iter().any(|record| record.provider.is_some()),
    }
}

fn record_kinds(records: &[NormalizedRecord]) -> Vec<String> {
    records
        .iter()
        .map(|record| match record.kind {
            RecordKind::UserMessage => "user_message",
            RecordKind::AssistantMessage => "assistant_message",
            RecordKind::ToolCall => "tool_call",
            RecordKind::ToolResult => "tool_result",
            RecordKind::SessionMeta => "session_meta",
            RecordKind::Other => "other",
            _ => "other",
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect()
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
