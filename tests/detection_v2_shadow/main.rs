use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use telltale_detect::shadow_v2::{
    AtomicComparison, AtomicEquivalenceCounts, EquivalenceCounts, MismatchClassification,
    ShadowComparison, ShadowHealth, compare_sessions,
};
use telltale_rules::load_default_rule_set;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::ObservedAt;
use telltale_schema::source::Source;
use telltale_sources::canonical::{
    CanonicalProjectionOptions, project_source_canonical_observations,
};
use telltale_sources::parser::parse_source_records;

const OBSERVED_AT: &str = "2026-09-04T00:00:00Z";
const EXPECTATIONS_PATH: &str = "tests/evaluation/detection-v2-shadow-expectations.yaml";
const REPORT_ENV: &str = "TELLTALE_DETECTION_V2_SHADOW_REPORT";
const UNSCOPED_SESSION_REFERENCE: &str = "unscoped";

#[derive(Clone, Copy)]
struct CaseDefinition {
    id: &'static str,
    client: ClientId,
    source_id: &'static str,
    kind: SourceKind,
    fixture: &'static str,
}

const CASES: &[CaseDefinition] = &[
    CaseDefinition {
        id: "p13-claude-project-b",
        client: ClientId::Claude,
        source_id: "claude.projects",
        kind: SourceKind::Jsonl,
        fixture: "tests/fixtures/session_stores/claude/projects/project-b/session-tool-use.jsonl",
    },
    CaseDefinition {
        id: "p13-codex-sessions",
        client: ClientId::Codex,
        source_id: "codex.sessions",
        kind: SourceKind::Jsonl,
        fixture: "tests/fixtures/detection_v2_shadow/codex/command-content-broadening.jsonl",
    },
    CaseDefinition {
        id: "p13-claude-project-c",
        client: ClientId::Claude,
        source_id: "claude.projects",
        kind: SourceKind::Jsonl,
        fixture: "tests/fixtures/session_stores/claude/projects/project-c/uc001-claude-tool-result.jsonl",
    },
    CaseDefinition {
        id: "p13-codex-uc003-positive",
        client: ClientId::Codex,
        source_id: "codex.sessions",
        kind: SourceKind::Jsonl,
        fixture: "tests/fixtures/session_stores/codex/sessions/2026/04/uc003-positive-dns-exfil.jsonl",
    },
    CaseDefinition {
        id: "p13-codex-uc003-negative",
        client: ClientId::Codex,
        source_id: "codex.sessions",
        kind: SourceKind::Jsonl,
        fixture: "tests/fixtures/session_stores/codex/sessions/2026/04/uc003-negative-dns-troubleshooting.jsonl",
    },
    CaseDefinition {
        id: "p13-codex-archived",
        client: ClientId::Codex,
        source_id: "codex.archived_sessions",
        kind: SourceKind::ArchivedJsonl,
        fixture: "tests/fixtures/detection_v2_shadow/codex/archived_sessions/p13-shadow-archived.jsonl",
    },
    CaseDefinition {
        id: "p13-codex-headless",
        client: ClientId::Codex,
        source_id: "codex.headless_sessions",
        kind: SourceKind::HeadlessJsonl,
        fixture: "tests/fixtures/detection_v2_shadow/codex/headless/p13-shadow-headless.jsonl",
    },
    CaseDefinition {
        id: "p13-opencode-sqlite",
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite",
        kind: SourceKind::Sqlite,
        fixture: "tests/fixtures/session_stores/opencode/opencode.db",
    },
];

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ReviewedExpectation {
    case_id: String,
    session_reference: String,
    rule_id: String,
    expected_relation: String,
    classification: String,
    reason_code: String,
    rationale: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReviewedExceptionReport {
    case_id: String,
    session_reference: String,
    rule_id: String,
    expected_relation: String,
    classification: String,
    reason_code: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ExpectationDocument {
    version: u32,
    expectations: Vec<ReviewedExpectation>,
}

#[derive(Debug, Clone, Serialize)]
struct CaseReport {
    case_id: String,
    client: String,
    source_id: String,
    session_count: u64,
    canonical_observation_count: u64,
    atomic_equivalence: AtomicEquivalenceCounts,
    mismatches: u64,
}

#[derive(Debug, Clone, Serialize)]
struct MismatchReport {
    case_id: String,
    client: String,
    source_id: String,
    #[serde(flatten)]
    comparison: AtomicComparison,
}

#[derive(Debug, Clone, Serialize)]
struct ShadowReport {
    schema_version: String,
    reference_source_ids: Vec<String>,
    case_count: u64,
    session_count: u64,
    atomic_equivalence: AtomicEquivalenceCounts,
    modifier_equivalence: EquivalenceCounts,
    risk_equivalence: EquivalenceCounts,
    metadata_equivalence: EquivalenceCounts,
    non_evaluation_reason_counts: BTreeMap<String, u64>,
    mismatch_class_counts: BTreeMap<String, u64>,
    source_breakdown: BTreeMap<String, BTreeMap<String, u64>>,
    target_breakdown: BTreeMap<String, BTreeMap<String, u64>>,
    rule_breakdown: BTreeMap<String, BTreeMap<String, u64>>,
    reviewed_exceptions: Vec<ReviewedExceptionReport>,
    health: ShadowHealth,
    cases: Vec<CaseReport>,
    mismatches: Vec<MismatchReport>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source(root: &Path, case: CaseDefinition) -> Source {
    Source {
        client: case.client,
        kind: case.kind,
        source_id: case.source_id.to_owned(),
        path: root.join(case.fixture),
    }
}

fn load_expectations(root: &Path) -> ExpectationDocument {
    let path = root.join(EXPECTATIONS_PATH);
    let text = fs::read_to_string(path).expect("shadow expectation ledger");
    let document: ExpectationDocument =
        serde_yaml::from_str(&text).expect("shadow expectation YAML");
    assert_eq!(document.version, 1);
    for expectation in &document.expectations {
        assert!(!expectation.case_id.trim().is_empty());
        assert!(!expectation.rule_id.trim().is_empty());
        assert!(!expectation.case_id.contains('*') && !expectation.case_id.contains('?'));
        assert!(!expectation.rule_id.contains('*') && !expectation.rule_id.contains('?'));
        assert!(valid_session_reference(&expectation.session_reference));
        assert!(!expectation.reason_code.trim().is_empty());
        assert!(matches!(
            expectation.reason_code.as_str(),
            "compat_v1_url_unavailable"
                | "legacy_tool_content_file_path_broadening"
                | "legacy_tool_content_command_broadening"
                | "legacy_post_match_filter"
                | "canonical_capability_unknown"
                | "canonical_capability_unsupported"
                | "canonical_provenance_ineligible"
                | "session_identity_unavailable"
                | "candidate_source_characterization"
        ));
        assert!(!expectation.reason_code.contains("expected_difference"));
        assert!(!expectation.reason_code.contains("known_issue"));
        assert!(!expectation.reason_code.contains("other"));
        assert!(!expectation.rationale.trim().is_empty());
        assert!(matches!(
            expectation.expected_relation.as_str(),
            "both_match"
                | "both_no_match"
                | "legacy_only"
                | "v2_only"
                | "v2_indeterminate"
                | "v2_error"
                | "v2_not_applicable"
        ));
        assert!(matches!(
            expectation.classification.as_str(),
            "visibility_gap"
                | "legacy_flattening_difference"
                | "v2_semantic_expansion"
                | "legacy_post_filter_difference"
                | "modifier_difference"
                | "risk_difference"
                | "metadata_difference"
                | "session_alignment_gap"
                | "unexpected_semantic_difference"
                | "detector_error"
        ));
        assert_ne!(
            expectation.classification, "unexpected_semantic_difference",
            "ledger entries must use an evidence-backed mismatch class"
        );
    }
    document
}

fn evaluate_case(
    root: &Path,
    rules: &telltale_rules::CompiledRuleSet,
    case: CaseDefinition,
) -> ShadowComparison {
    let source = source(root, case);
    let legacy = parse_source_records(&source).expect("legacy fixture parse");
    let canonical = project_source_canonical_observations(
        &source,
        CanonicalProjectionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap_or_else(|error| panic!("{} projection failed: {error}", case.id));
    assert!(
        !canonical.is_empty(),
        "{} must project observations",
        case.id
    );
    compare_sessions(rules, &legacy, &canonical).expect("shadow comparison")
}

fn add_map(target: &mut BTreeMap<String, u64>, source: &BTreeMap<String, u64>) {
    for (key, value) in source {
        *target.entry(key.clone()).or_default() += value;
    }
}

fn add_equivalence(target: &mut EquivalenceCounts, source: &EquivalenceCounts) {
    target.equal += source.equal;
    target.legacy_only += source.legacy_only;
    target.v2_only += source.v2_only;
    target.different += source.different;
}

fn add_atomic(target: &mut AtomicEquivalenceCounts, source: &AtomicEquivalenceCounts) {
    target.both_match += source.both_match;
    target.both_no_match += source.both_no_match;
    target.legacy_only += source.legacy_only;
    target.v2_only += source.v2_only;
    target.v2_indeterminate += source.v2_indeterminate;
    target.v2_error += source.v2_error;
    target.v2_not_applicable += source.v2_not_applicable;
}

fn add_health(target: &mut ShadowHealth, source: &ShadowHealth) {
    target.total_detector_session_evaluations += source.total_detector_session_evaluations;
    target.fully_evaluable += source.fully_evaluable;
    target.indeterminate += source.indeterminate;
    target.capability_unsupported += source.capability_unsupported;
    target.capability_unknown += source.capability_unknown;
    target.provenance_ineligible += source.provenance_ineligible;
    target.type_mismatch += source.type_mismatch;
    target.session_alignment_gaps += source.session_alignment_gaps;
    target.canonical_projection_errors += source.canonical_projection_errors;
}

fn aggregate(
    root: &Path,
    rules: &telltale_rules::CompiledRuleSet,
) -> (ShadowReport, Vec<(CaseDefinition, ShadowComparison)>) {
    let mut atomic = AtomicEquivalenceCounts::default();
    let mut modifiers = EquivalenceCounts::default();
    let mut risks = EquivalenceCounts::default();
    let mut metadata = EquivalenceCounts::default();
    let mut reasons = BTreeMap::new();
    let mut classes = BTreeMap::new();
    let mut health = ShadowHealth::default();
    let mut sessions = 0;
    let mut source_breakdown = BTreeMap::new();
    let mut target_breakdown = BTreeMap::new();
    let mut rule_breakdown = BTreeMap::new();
    let mut cases = Vec::new();
    let mut mismatches = Vec::new();
    let mut evaluated = Vec::new();

    for case in CASES {
        let comparison = evaluate_case(root, rules, *case);
        add_atomic(&mut atomic, &comparison.atomic_equivalence);
        add_equivalence(&mut modifiers, &comparison.modifier_equivalence);
        add_equivalence(&mut risks, &comparison.risk_equivalence);
        add_equivalence(&mut metadata, &comparison.metadata_equivalence);
        add_map(&mut reasons, &comparison.non_evaluation_reason_counts);
        add_map(&mut classes, &comparison.mismatch_class_counts);
        add_health(&mut health, &comparison.health);
        sessions += comparison.sessions.len() as u64;
        let mut source_counts = BTreeMap::new();
        source_counts.insert("cases".to_owned(), 1);
        source_counts.insert("sessions".to_owned(), comparison.sessions.len() as u64);
        source_counts.insert(
            "canonical_observations".to_owned(),
            comparison
                .sessions
                .iter()
                .map(|session| session.canonical_observation_count)
                .sum(),
        );
        source_counts.insert(
            "mismatches".to_owned(),
            comparison
                .sessions
                .iter()
                .flat_map(|session| session.detectors.iter())
                .filter(|detector| detector.is_mismatch())
                .count() as u64,
        );
        add_map(
            source_breakdown
                .entry(case.source_id.to_owned())
                .or_insert_with(BTreeMap::new),
            &source_counts,
        );
        for session in &comparison.sessions {
            for detector in &session.detectors {
                let target = detector
                    .legacy_matched_target
                    .as_deref()
                    .unwrap_or("no_legacy_match")
                    .to_owned();
                let target_counts = target_breakdown.entry(target).or_insert_with(BTreeMap::new);
                *target_counts.entry("evaluations".to_owned()).or_default() += 1;
                *target_counts
                    .entry(detector.relation.as_str().to_owned())
                    .or_default() += 1;
                if detector.is_mismatch() {
                    *target_counts.entry("mismatches".to_owned()).or_default() += 1;
                    mismatches.push(MismatchReport {
                        case_id: case.id.to_owned(),
                        client: case.client.as_str().to_owned(),
                        source_id: case.source_id.to_owned(),
                        comparison: detector.clone(),
                    });
                }
                let rule_counts = rule_breakdown
                    .entry(detector.detector_id.clone())
                    .or_insert_with(BTreeMap::new);
                *rule_counts.entry("evaluations".to_owned()).or_default() += 1;
                *rule_counts
                    .entry(detector.relation.as_str().to_owned())
                    .or_default() += 1;
                if detector.is_mismatch() {
                    *rule_counts.entry("mismatches".to_owned()).or_default() += 1;
                }
            }
        }
        cases.push(CaseReport {
            case_id: case.id.to_owned(),
            client: case.client.as_str().to_owned(),
            source_id: case.source_id.to_owned(),
            session_count: comparison.sessions.len() as u64,
            canonical_observation_count: comparison
                .sessions
                .iter()
                .map(|session| session.canonical_observation_count)
                .sum(),
            atomic_equivalence: comparison.atomic_equivalence.clone(),
            mismatches: comparison
                .sessions
                .iter()
                .flat_map(|session| session.detectors.iter())
                .filter(|detector| detector.is_mismatch())
                .count() as u64,
        });
        evaluated.push((*case, comparison));
    }
    let expectations = load_expectations(root);
    let mut reference_source_ids = CASES
        .iter()
        .map(|case| case.source_id.to_owned())
        .collect::<Vec<_>>();
    reference_source_ids.sort();
    reference_source_ids.dedup();
    ShadowReport {
        schema_version: "detection-v2-shadow-report.v1".to_owned(),
        reference_source_ids,
        case_count: CASES.len() as u64,
        session_count: sessions,
        atomic_equivalence: atomic,
        modifier_equivalence: modifiers,
        risk_equivalence: risks,
        metadata_equivalence: metadata,
        non_evaluation_reason_counts: reasons,
        mismatch_class_counts: classes,
        source_breakdown,
        target_breakdown,
        rule_breakdown,
        reviewed_exceptions: expectations
            .expectations
            .iter()
            .map(|expectation| ReviewedExceptionReport {
                case_id: expectation.case_id.clone(),
                session_reference: expectation.session_reference.clone(),
                rule_id: expectation.rule_id.clone(),
                expected_relation: expectation.expected_relation.clone(),
                classification: expectation.classification.clone(),
                reason_code: expectation.reason_code.clone(),
            })
            .collect(),
        health,
        cases,
        mismatches,
    }
    .pipe(|report| (report, evaluated))
}

trait Pipe: Sized {
    fn pipe<T>(self, function: impl FnOnce(Self) -> T) -> T {
        function(self)
    }
}
impl<T> Pipe for T {}

fn expectation_key(case_id: &str, comparison: &AtomicComparison) -> ExpectationKey {
    (
        case_id.to_owned(),
        comparison
            .session_reference
            .clone()
            .unwrap_or_else(|| UNSCOPED_SESSION_REFERENCE.to_owned()),
        comparison.detector_id.clone(),
        comparison.relation.as_str().to_owned(),
        comparison
            .classification
            .map(MismatchClassification::as_str)
            .unwrap_or("missing_classification")
            .to_owned(),
        comparison.reason_code.clone().unwrap_or_default(),
    )
}

type ExpectationKey = (String, String, String, String, String, String);
type ExpectationCounts = BTreeMap<ExpectationKey, u64>;

fn valid_session_reference(value: &str) -> bool {
    value == UNSCOPED_SESSION_REFERENCE
        || value.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}

fn expectation_counts<I>(keys: I) -> ExpectationCounts
where
    I: IntoIterator<Item = ExpectationKey>,
{
    let mut counts = BTreeMap::new();
    for key in keys {
        *counts.entry(key).or_default() += 1;
    }
    counts
}

fn expectation_counts_match(actual: &ExpectationCounts, expected: &ExpectationCounts) -> bool {
    actual == expected
}

fn check_expectations(root: &Path, evaluated: &[(CaseDefinition, ShadowComparison)]) {
    let document = load_expectations(root);
    let mut actual_keys = Vec::new();
    for (case, comparison) in evaluated {
        for session in &comparison.sessions {
            for detector in &session.detectors {
                if !detector.is_mismatch() {
                    continue;
                }
                assert!(
                    detector.classification.is_some(),
                    "unclassified shadow mismatch: {}",
                    detector.detector_id
                );
                let session_reference = detector
                    .session_reference
                    .as_deref()
                    .unwrap_or(UNSCOPED_SESSION_REFERENCE);
                assert!(
                    valid_session_reference(session_reference),
                    "invalid shadow session reference"
                );
                actual_keys.push(expectation_key(case.id, detector));
            }
        }
    }
    let expected_keys = document
        .expectations
        .iter()
        .map(|item| {
            (
                item.case_id.clone(),
                item.session_reference.clone(),
                item.rule_id.clone(),
                item.expected_relation.clone(),
                item.classification.clone(),
                item.reason_code.clone(),
            )
        })
        .collect::<Vec<_>>();
    let actual_counts = expectation_counts(actual_keys);
    let expected_counts = expectation_counts(expected_keys);
    assert_eq!(actual_counts, expected_counts);
}

fn render(report: &ShadowReport) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(report).expect("shadow report JSON");
    bytes.push(b'\n');
    bytes
}

fn write_requested_report(bytes: &[u8]) {
    let Some(path) = std::env::var_os(REPORT_ENV) else {
        return;
    };
    let root = repo_root();
    let requested = Path::new(&path);
    assert_eq!(
        requested.components().count(),
        1,
        "report path must be a filename"
    );
    let output = root.join("target/detection-v2-shadow").join(requested);
    fs::create_dir_all(output.parent().unwrap()).expect("shadow report directory");
    fs::write(output, bytes).expect("shadow report");
}

#[test]
fn detection_v2_shadow_matches_reviewed_fixture_ledger() {
    let root = repo_root();
    let rules = load_default_rule_set().expect("bundled rule set");
    let (report, evaluated) = aggregate(&root, &rules);
    check_expectations(&root, &evaluated);
    let bytes = render(&report);
    write_requested_report(&bytes);
    assert_eq!(report.schema_version, "detection-v2-shadow-report.v1");
    assert_eq!(report.case_count, 8);
    assert_eq!(report.session_count, 9);
    assert_eq!(
        report.atomic_equivalence,
        AtomicEquivalenceCounts {
            both_match: 9,
            both_no_match: 139,
            legacy_only: 1,
            v2_only: 2,
            v2_indeterminate: 0,
            v2_error: 0,
            v2_not_applicable: 11,
        }
    );
    assert_eq!(
        report.risk_equivalence,
        EquivalenceCounts {
            equal: 6,
            legacy_only: 1,
            v2_only: 0,
            different: 2,
        }
    );
    assert_eq!(
        report.metadata_equivalence,
        EquivalenceCounts {
            equal: 6,
            legacy_only: 1,
            v2_only: 0,
            different: 2,
        }
    );
    assert_eq!(report.health.total_detector_session_evaluations, 162);
    assert_eq!(report.health.indeterminate, 0);
    assert_eq!(report.health.canonical_projection_errors, 0);
    assert!(!report.target_breakdown.is_empty());
    assert!(!report.rule_breakdown.is_empty());
    assert_eq!(report.reviewed_exceptions.len(), 3);
    assert_eq!(report.mismatches.len(), 3);
    assert!(report.source_breakdown.contains_key("claude.projects"));
    assert!(
        !report
            .source_breakdown
            .contains_key("claude.claude.projects")
    );
    let opencode_case = report
        .cases
        .iter()
        .find(|case| case.case_id == "p13-opencode-sqlite")
        .expect("OpenCode SQLite case");
    assert_eq!(opencode_case.session_count, 2);
    let serialized = String::from_utf8(bytes).expect("shadow report UTF-8");
    for forbidden in [
        "Synthetic",
        "encoded-http-exfil",
        "p13-shadow-archived",
        "p13-shadow-headless",
        "opencode-sqlite-benign",
        "tests/fixtures",
        "https://",
        "curl",
        "printf",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "shadow report contains forbidden value: {forbidden}"
        );
    }
}

#[test]
fn detection_v2_shadow_gate_rejects_unreviewed_mismatch() {
    let actual = expectation_counts([(
        "synthetic-case".to_owned(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "synthetic.rule".to_owned(),
        "v2_only".to_owned(),
        "visibility_gap".to_owned(),
        "canonical_capability_unknown".to_owned(),
    )]);
    let expected = ExpectationCounts::new();
    assert!(!expectation_counts_match(&actual, &expected));
}

#[test]
fn detection_v2_shadow_gate_rejects_disappeared_reviewed_mismatch() {
    let expected = expectation_counts([(
        "synthetic-case".to_owned(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "synthetic.rule".to_owned(),
        "v2_only".to_owned(),
        "visibility_gap".to_owned(),
        "canonical_capability_unknown".to_owned(),
    )]);
    let actual = ExpectationCounts::new();
    assert!(!expectation_counts_match(&actual, &expected));
}

#[test]
fn detection_v2_shadow_gate_compares_mismatch_multiplicity() {
    let key = (
        "synthetic-case".to_owned(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "synthetic.rule".to_owned(),
        "v2_only".to_owned(),
        "visibility_gap".to_owned(),
        "canonical_capability_unknown".to_owned(),
    );
    let actual_counts = expectation_counts([key.clone(), key.clone()]);
    let one_row = expectation_counts([key.clone()]);
    let two_rows = expectation_counts([key.clone(), key.clone()]);

    assert_eq!(actual_counts.get(&key), Some(&2));
    assert!(!expectation_counts_match(&actual_counts, &one_row));
    assert!(expectation_counts_match(&actual_counts, &two_rows));
}

#[test]
fn detection_v2_shadow_gate_does_not_move_reviewed_mismatch_between_sessions() {
    let expected = expectation_counts([(
        "synthetic-case".to_owned(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "synthetic.rule".to_owned(),
        "v2_only".to_owned(),
        "visibility_gap".to_owned(),
        "canonical_capability_unknown".to_owned(),
    )]);
    let actual = expectation_counts([(
        "synthetic-case".to_owned(),
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        "synthetic.rule".to_owned(),
        "v2_only".to_owned(),
        "visibility_gap".to_owned(),
        "canonical_capability_unknown".to_owned(),
    )]);

    assert!(!expectation_counts_match(&actual, &expected));
}

#[test]
fn detection_v2_shadow_report_is_byte_identical_twice() {
    let root = repo_root();
    let rules = load_default_rule_set().expect("bundled rule set");
    let (first, first_evaluated) = aggregate(&root, &rules);
    check_expectations(&root, &first_evaluated);
    let (second, second_evaluated) = aggregate(&root, &rules);
    check_expectations(&root, &second_evaluated);
    assert_eq!(render(&first), render(&second));
}
