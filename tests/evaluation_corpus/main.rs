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
        "tags: [seed, opencode, routine, efficacy, characterization]",
        "tags: [seed, seed, opencode, routine, efficacy, characterization]",
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
        "Routine user-authorized repository inspection should not require security review.",
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
fn canonical_efficacy_native_invariants() {
    use manifest::Input;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::{JsonValue, ObservationBody, ObservedAt};
    use telltale_schema::source::Source;
    use telltale_sources::acquisition::{AcquisitionOptions, AcquisitionProgress, acquire_source};

    let root = repo_root();
    let manifest = load_manifest(&root.join(MANIFEST_PATH), &root).unwrap();
    for case in manifest
        .cases
        .iter()
        .filter(|case| case.tags.iter().any(|tag| tag == "canonical_efficacy"))
    {
        let Input::SourceFixture { fixture, .. } = &case.input else {
            panic!("native fixture")
        };
        let native = fs::read_to_string(root.join(fixture))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        for (source_id, kind) in [
            ("codex.sessions", SourceKind::Jsonl),
            ("codex.archived_sessions", SourceKind::ArchivedJsonl),
            ("codex.headless_sessions", SourceKind::HeadlessJsonl),
        ] {
            let source = Source {
                client: ClientId::Codex,
                source_id: source_id.into(),
                kind,
                path: root.join(fixture),
            };
            let options =
                || AcquisitionOptions::new(ObservedAt::new("2026-10-03T12:00:00Z").unwrap());
            let batch = acquire_source(&source, options()).unwrap();
            let replay = acquire_source(&source, options()).unwrap();
            assert_eq!(batch.observations.len(), 1, "{} {source_id}", case.id);
            assert_eq!(batch.progress, AcquisitionProgress::None);
            assert_eq!(
                batch.observations[0].observation_id(),
                replay.observations[0].observation_id()
            );
            assert_eq!(batch.observations[0].source().adapter_id(), source_id);
            assert_eq!(
                batch.observations[0].session_id().unwrap().value(),
                native[0]["payload"]["id"].as_str().unwrap()
            );
            assert_eq!(
                batch.accounting.sessions[0].counts.native_units,
                native.len() as u64
            );
            let item = &native.last().unwrap()["payload"]["item"];
            match batch.observations[0].body() {
                ObservationBody::Message(message) => {
                    let expected = item["content"].as_array().unwrap();
                    assert_eq!(message.content_parts().len(), expected.len());
                    for (part, expected) in message.content_parts().iter().zip(expected) {
                        assert_eq!(
                            part.value(),
                            &JsonValue::string(expected["text"].as_str().unwrap())
                        );
                    }
                    if case.tags.iter().any(|tag| tag == "long_text") {
                        assert!(expected[0]["text"].as_str().unwrap().len() > 4096);
                    }
                }
                ObservationBody::Tool(_) => {
                    assert_eq!(
                        batch.accounting.sessions[0].counts.record_counts.tool_call,
                        0
                    );
                    assert_eq!(
                        batch.accounting.sessions[0]
                            .counts
                            .record_counts
                            .tool_result,
                        1
                    );
                    assert_eq!(
                        batch.accounting.sessions[0].counts.contributions,
                        Default::default()
                    );
                }
                _ => panic!("unexpected family"),
            }
        }
    }
}

#[test]
fn canonical_efficacy_rejection_and_ambiguous_outcomes_are_not_confusion_cases() {
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::{
        JsonValue, ObservationBody, ObservationStage, ObservedAt, ToolStatus,
    };
    use telltale_schema::source::Source;
    use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};

    let fixture_root = repo_root().join("tests/evaluation/fixtures/canonical-efficacy");
    let read = |name: &str| {
        fs::read_to_string(fixture_root.join(name))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>()
    };
    let temp = tempfile::tempdir().unwrap();
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: temp.path().join("synthetic.jsonl"),
        };
        let acquire = |records: &[serde_json::Value]| {
            fs::write(
                &source.path,
                records
                    .iter()
                    .map(serde_json::Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .unwrap();
            acquire_source(
                &source,
                AcquisitionOptions::new(ObservedAt::new("2026-10-03T12:00:00Z").unwrap()),
            )
        };
        // Without the public turn authority, identical content is not a proven mirror.
        let mut mirrors = read("mirror-malicious.jsonl");
        mirrors[1]["payload"]
            .as_object_mut()
            .unwrap()
            .remove("internal_chat_message_metadata_passthrough");
        assert_eq!(acquire(&mirrors).unwrap().observations.len(), 2);
        let good = read("command-success.jsonl");
        for (field, value) in [
            ("status", serde_json::json!("in_progress")),
            (
                "status",
                serde_json::json!("SYNTHETIC-EFFICACY-PRIVATE-INVALID"),
            ),
            (
                "command",
                serde_json::json!("SYNTHETIC-EFFICACY-PRIVATE-INVALID"),
            ),
            (
                "exit_code",
                serde_json::json!("SYNTHETIC-EFFICACY-PRIVATE-INVALID"),
            ),
            (
                "aggregated_output",
                serde_json::json!({"secret":"SYNTHETIC-EFFICACY-PRIVATE-INVALID"}),
            ),
        ] {
            let mut bad = good[1].clone();
            bad["payload"]["item"][field] = value;
            let error = acquire(&[good[0].clone(), good[1].clone(), bad])
                .err()
                .expect("reject whole source after valid prefix");
            assert!(!format!("{error:?} {error}").contains("SYNTHETIC-EFFICACY-PRIVATE"));
        }
        for (status, expected) in [
            ("completed", ToolStatus::Succeeded),
            ("failed", ToolStatus::Failed),
            ("declined", ToolStatus::Denied),
        ] {
            for exit in [
                None,
                Some(serde_json::Value::Null),
                Some(serde_json::json!(0)),
                Some(serde_json::json!(7)),
            ] {
                let mut records = good.clone();
                let item = &mut records[1]["payload"]["item"];
                item["status"] = serde_json::json!(status);
                item.as_object_mut().unwrap().remove("aggregated_output");
                item.as_object_mut().unwrap().remove("exit_code");
                if let Some(exit) = &exit {
                    item["exit_code"] = exit.clone();
                }
                let batch = acquire(&records).unwrap();
                assert_eq!(batch.observations.len(), 1);
                let observation = &batch.observations[0];
                assert_eq!(observation.stage(), ObservationStage::ToolResultReturned);
                assert_eq!(
                    observation.facets()["tool.output_fidelity"].value(),
                    &JsonValue::string("not_captured")
                );
                let ObservationBody::Tool(tool) = observation.body() else {
                    panic!("tool")
                };
                assert_eq!(tool.reported_status(), Some(expected));
                assert_eq!(tool.name(), None);
                assert_eq!(tool.result().is_some(), exit.is_some());
            }
        }
    }
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
    let processes = &evaluation.process_chain_coverage;
    assert_eq!(
        processes.uncovered_ids,
        vec![
            "procchain.correlation.office_script_then_download",
            "procchain.correlation.rmm_then_credential_or_evasion",
            "procchain.correlation.webshell_then_discovery",
        ],
        "only the fixed structured-parent visibility gaps may remain"
    );
    assert_eq!(
        processes.rationales.keys().cloned().collect::<Vec<_>>(),
        processes.uncovered_ids
    );
    assert_eq!(processes.covered_correlation_ids.len(), 3);
    assert_eq!(processes.canonical_atomic_ids.len(), 6);
    assert_eq!(
        evaluation.source_coverage.supported_expected,
        evaluation.source_coverage.supported_represented,
        "not all supported sources were represented"
    );
}
