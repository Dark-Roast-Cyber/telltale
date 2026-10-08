//! Typed per-source outcome: hosts read coverage and failure without matching
//! Event 3 `event_type` strings or inferring failure from `completion: None`.

use telltale_core::*;

const RULE: &str = r#"
version: 1
description: Synthetic outcome coverage.
defaults: { case_insensitive: false, enabled: true }
modifiers: []
rules:
  - id: synthetic.outcome.command
    category: synthetic
    severity: high
    score: 70
    targets: [command]
    regex: needle
    tags: [synthetic]
    explanation: Synthetic test.
"#;

fn pipeline() -> Pipeline {
    Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .build()
        .unwrap()
}

fn claude_source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path,
    }
}

fn opencode_source(root: &std::path::Path) -> Source {
    let path = root.join("synthetic.db");
    let bytes = include_bytes!("../../fixtures/session_stores/opencode/opencode.db");
    std::fs::write(&path, bytes).unwrap();
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path,
    }
}

#[test]
fn successful_jsonl_scan_reports_whole_source_coverage_and_no_failure() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("session.jsonl");
    let row = serde_json::json!({"type":"assistant","uuid":"call","sessionId":"session","timestamp":"2026-09-17T00:00:00Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call","name":"Bash","input":{"command":"echo needle"}}]}});
    std::fs::write(&path, format!("{row}\n")).unwrap();
    let scan = pipeline()
        .scan_sources_detailed(
            &[claude_source(path)],
            &DetailedEvaluationOptions::default(),
        )
        .unwrap()
        .remove(0);
    assert!(scan.failure().is_none());
    assert_eq!(scan.coverage(), Some(SourceCoverage::WholeSource));
    assert!(scan.completion.is_some());
    assert!(!scan.action_findings.is_empty());
}

#[test]
fn source_failure_is_typed_and_content_free() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("private-missing-marker.jsonl");
    let scan = pipeline()
        .scan_sources_detailed(
            &[claude_source(missing.clone())],
            &DetailedEvaluationOptions::default(),
        )
        .unwrap()
        .remove(0);
    let failure = scan.failure().expect("typed failure");
    assert_eq!(failure.stage(), SourceFailureStage::SourceScope);
    assert_eq!(failure.acquisition_error(), None);
    assert_eq!(failure.code(), "canonical_source_scope_failed");
    assert!(!format!("{failure:?}").contains("private-missing-marker"));
    // The typed failure agrees with the unchanged Event 3 projection.
    assert_eq!(scan.coverage(), None);
    assert_eq!(scan.completion, None);
    assert!(scan.action_findings.is_empty());
    assert_eq!(scan.events.len(), 1);
    assert_eq!(scan.events[0].event_type, "scanner_error");
    assert!(!missing.exists());
}

#[cfg(feature = "opencode-sqlite")]
#[test]
fn opencode_selected_window_reports_partial_coverage() {
    let root = tempfile::tempdir().unwrap();
    let source = opencode_source(root.path());
    let scan = pipeline()
        .scan_sources_detailed(&[source], &DetailedEvaluationOptions::default())
        .unwrap()
        .remove(0);
    assert!(scan.failure().is_none());
    assert_eq!(scan.coverage(), Some(SourceCoverage::Partial));
}

#[cfg(not(feature = "opencode-sqlite"))]
#[test]
fn feature_off_opencode_reports_capability_not_compiled_without_reading() {
    let root = tempfile::tempdir().unwrap();
    let source = opencode_source(root.path());
    let before = std::fs::read(&source.path).unwrap();
    let scan = pipeline()
        .scan_sources_detailed(
            std::slice::from_ref(&source),
            &DetailedEvaluationOptions::default(),
        )
        .unwrap()
        .remove(0);
    let failure = scan.failure().expect("typed failure");
    assert_eq!(failure.stage(), SourceFailureStage::Acquisition);
    assert_eq!(
        failure.acquisition_error(),
        Some(AcquisitionError::CapabilityNotCompiled)
    );
    assert_eq!(
        failure.acquisition_error().map(AcquisitionError::code),
        Some("capability_not_compiled")
    );
    // Event 3 keeps its generic, content-free acquisition code.
    assert_eq!(failure.code(), "canonical_acquisition_failed");
    assert_eq!(scan.coverage(), None);
    assert_eq!(std::fs::read(&source.path).unwrap(), before);
}

#[test]
fn visibility_limited_completion_names_closed_reasons() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("session.jsonl");
    let row = serde_json::json!({"type":"assistant","uuid":"call","sessionId":"session","timestamp":"2026-09-17T00:00:00Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call","name":"Bash","input":{"command":"echo needle"}}]}});
    std::fs::write(&path, format!("{row}\n")).unwrap();
    let source = claude_source(path);
    let options = DetailedEvaluationOptions::default();
    // Bundled URL-target rules lack URL visibility: limited, with a named reason.
    let bundled = Pipeline::builder()
        .build()
        .unwrap()
        .scan_sources_detailed(std::slice::from_ref(&source), &options)
        .unwrap()
        .remove(0);
    assert_eq!(
        bundled.completion,
        Some(EvaluationCompletion::VisibilityLimited)
    );
    assert!(
        bundled
            .visibility_limits()
            .contains(&VisibilityLimit::RuleTargetUnavailable)
    );
    assert!(
        bundled
            .visibility_limits()
            .iter()
            .all(|limit| !limit.as_str().is_empty())
    );
    // A command-only rule set is complete and names no limits.
    let complete = pipeline()
        .scan_sources_detailed(&[source], &options)
        .unwrap()
        .remove(0);
    assert_eq!(complete.completion, Some(EvaluationCompletion::Complete));
    assert!(complete.visibility_limits().is_empty());
}
