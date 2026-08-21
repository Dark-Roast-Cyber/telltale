mod evaluate;
mod manifest;
mod process_chain;
mod report;

use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

use evaluate::evaluate_manifest;
use manifest::{load_manifest, validate_manifest_bytes};
use report::render_report;

const MANIFEST_PATH: &str = "tests/evaluation/manifest.yaml";
const GOLDEN_PATH: &str = "tests/evaluation/baseline-report.v1.json";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn current_report() -> Result<Vec<u8>, String> {
    let root = repo_root();
    let manifest = load_manifest(&root.join(MANIFEST_PATH), &root)?;
    let evaluation = evaluate_manifest(&manifest, &root)?;
    render_report(&manifest, &evaluation, &root)
}

fn write_eval_report_if_requested(bytes: &[u8]) -> Result<(), String> {
    let Some(path) = std::env::var_os("TELLTALE_EVAL_REPORT") else {
        return Ok(());
    };
    let root = repo_root();
    let path = evaluation_report_path(&root, &path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(path, bytes).map_err(|error| error.to_string())
}

fn evaluation_report_path(repo_root: &Path, requested: &OsStr) -> Result<PathBuf, String> {
    if requested
        .to_string_lossy()
        .chars()
        .any(|character| matches!(character, '/' | '\\'))
    {
        return Err("TELLTALE_EVAL_REPORT must be a single normal filename".to_string());
    }
    let requested = Path::new(requested);
    let mut components = requested.components();
    let Some(Component::Normal(filename)) = components.next() else {
        return Err("TELLTALE_EVAL_REPORT must be a single normal filename".to_string());
    };
    if components.next().is_some() {
        return Err("TELLTALE_EVAL_REPORT must be a single normal filename".to_string());
    }
    Ok(repo_root.join("target/evaluation").join(filename))
}

fn write_actual_report(bytes: &[u8]) -> Result<(), String> {
    let root = repo_root();
    let directory = root.join("target/evaluation");
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    fs::write(directory.join("actual-report.v1.json"), bytes).map_err(|error| error.to_string())?;
    write_eval_report_if_requested(bytes)
}

fn structured_diff(expected: &[u8], actual: &[u8]) -> String {
    let expected = String::from_utf8_lossy(expected);
    let actual = String::from_utf8_lossy(actual);
    let expected_lines = expected.lines().collect::<Vec<_>>();
    let actual_lines = actual.lines().collect::<Vec<_>>();
    let first_difference = expected_lines
        .iter()
        .zip(&actual_lines)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| expected_lines.len().min(actual_lines.len()));
    let start = first_difference.saturating_sub(2);
    let end = (first_difference + 3).min(expected_lines.len().max(actual_lines.len()));
    let mut diff = format!(
        "report differs at line {}; expected {} bytes, actual {} bytes\n",
        first_difference + 1,
        expected.len(),
        actual.len()
    );
    for index in start..end {
        let left = expected_lines.get(index).copied().unwrap_or("<end>");
        let right = actual_lines.get(index).copied().unwrap_or("<end>");
        if left != right {
            diff.push_str(&format!(
                "- {:04}: {left}\n+ {:04}: {right}\n",
                index + 1,
                index + 1
            ));
        }
    }
    diff
}

#[test]
fn manifest_schema_validation_failures() {
    let root = repo_root();
    let base = fs::read_to_string(root.join(MANIFEST_PATH)).expect("read manifest");

    let unsupported = base.replacen("version: 1", "version: 2", 1);
    assert!(validate_manifest_bytes(&unsupported, &root).is_err());

    let duplicate = format!(
        "{base}\n{}",
        base.split("  - id:").nth(1).expect("first case")
    );
    assert!(validate_manifest_bytes(&duplicate, &root).is_err());

    let duplicate_tags = base.replacen(
        "tags: [seed, opencode, source_conformance, characterization]",
        "tags: [seed, seed, opencode, source_conformance, characterization]",
        1,
    );
    assert!(validate_manifest_bytes(&duplicate_tags, &root).is_err());

    let unknown_enum = base.replacen(
        "expected_security_review: not_scored",
        "expected_security_review: unexpected",
        1,
    );
    assert!(validate_manifest_bytes(&unknown_enum, &root).is_err());

    let output_derived_rationale = base.replacen(
        "Uneventful assistant-only activity has no independent analyst security-review contract; it is a parser and visibility seed.",
        "Expected because the current score is 0.",
        1,
    );
    assert!(validate_manifest_bytes(&output_derived_rationale, &root).is_err());

    let score_contribution_mismatch = base.replacen("expected_score: 0", "expected_score: 1", 1);
    assert!(validate_manifest_bytes(&score_contribution_mismatch, &root).is_err());

    let exact_not_scored = base.replacen(
        "rule_expectations: []\n      exact_rule_set: true",
        "rule_expectations:\n        - rule_id: approval.bypass.context\n          expectation: not_scored\n      exact_rule_set: true",
        1,
    );
    assert!(validate_manifest_bytes(&exact_not_scored, &root).is_err());

    let benign_tag_contradiction = base.replacen(
        "    disposition: benign\n    expected_security_review: not_required\n    label_rationale: Authorized local formatting via a developer shell should not require security review.",
        "    disposition: benign\n    expected_security_review: required\n    label_rationale: Authorized local formatting via a developer shell should not require security review.",
        1,
    );
    assert!(validate_manifest_bytes(&benign_tag_contradiction, &root).is_err());

    let source_tag_on_normalized_input = base.replacen(
        "tags: [seed, opencode, routine, efficacy, characterization]",
        "tags: [seed, opencode, routine, efficacy, characterization, source_conformance]",
        1,
    );
    assert!(validate_manifest_bytes(&source_tag_on_normalized_input, &root).is_err());

    let candidate_tag_contradiction = base.replacen(
        "source_id: codex.project_sessions",
        "source_id: codex.sessions",
        1,
    );
    assert!(validate_manifest_bytes(&candidate_tag_contradiction, &root).is_err());
}

#[test]
fn evaluation_corpus_matches_golden_baseline() {
    let actual = current_report().expect("evaluate corpus");
    write_eval_report_if_requested(&actual).expect("write requested evaluation report");
    let expected = fs::read(repo_root().join(GOLDEN_PATH)).expect("read golden baseline");
    if actual != expected {
        write_actual_report(&actual).expect("write actual report");
        panic!("{}", structured_diff(&expected, &actual));
    }
}

#[test]
fn report_regenerates_byte_identically_twice_in_process() {
    let first = current_report().expect("first evaluation");
    let second = current_report().expect("second evaluation");
    assert_eq!(first, second, "evaluation report was not deterministic");
}

#[test]
fn evaluation_report_path_accepts_a_single_filename() {
    let root = Path::new("repo");
    assert_eq!(
        evaluation_report_path(root, OsStr::new("report.v1.json")),
        Ok(root.join("target/evaluation/report.v1.json"))
    );
}

#[test]
fn evaluation_report_path_rejects_parent_escape() {
    assert!(evaluation_report_path(Path::new("repo"), OsStr::new("../report.v1.json")).is_err());
}

#[test]
fn evaluation_report_path_rejects_nested_path() {
    assert!(
        evaluation_report_path(Path::new("repo"), OsStr::new("nested/report.v1.json")).is_err()
    );
    assert!(
        evaluation_report_path(Path::new("repo"), OsStr::new("nested\\report.v1.json")).is_err()
    );
}

#[test]
fn evaluation_report_path_rejects_absolute_path() {
    let absolute = std::env::current_dir()
        .expect("current directory")
        .join("report.v1.json");
    assert!(evaluation_report_path(Path::new("repo"), absolute.as_os_str()).is_err());
}

#[test]
fn evaluation_coverage_gate_is_complete() {
    let root = repo_root();
    let manifest = load_manifest(&root.join(MANIFEST_PATH), &root).expect("load manifest");
    let evaluation = evaluate_manifest(&manifest, &root).expect("evaluate corpus");
    assert!(
        evaluation.rule_coverage.uncovered.is_empty(),
        "uncovered regex rules: {:?}",
        evaluation.rule_coverage.uncovered
    );
    assert!(
        evaluation.modifier_coverage.uncovered.is_empty(),
        "uncovered modifiers: {:?}",
        evaluation.modifier_coverage.uncovered
    );
    assert!(
        evaluation.process_chain_coverage.uncovered_ids.is_empty(),
        "uncovered process-chain definitions: {:?}",
        evaluation.process_chain_coverage.uncovered_ids
    );
    assert_eq!(
        evaluation.source_coverage.supported_expected,
        evaluation.source_coverage.supported_represented,
        "not all supported sources were represented"
    );
}
