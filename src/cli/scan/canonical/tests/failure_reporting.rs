use super::*;

#[test]
fn runtime_failures_become_private_scanner_errors_without_staging_eligibility() {
    use telltale_core::canonical_runtime::SourceFailure;
    let source = source("PRIVATE-path".into());
    let progress = AcquisitionProgress::OpenCodeSqlite {
        part_max_time_updated: Some(42),
    };
    for (stage, code) in [
        (FailureStage::SourceScope, "canonical_source_scope_failed"),
        (FailureStage::Acquisition, "canonical_acquisition_failed"),
        (FailureStage::Evaluation, "canonical_evaluation_failed"),
        (FailureStage::Projection, "canonical_projection_failed"),
        (FailureStage::Activity, "canonical_activity_failed"),
    ] {
        let result = adapt_result(
            &source,
            Err(SourceFailure {
                stage,
                progress,
                acquisition: None,
                processing: None,
            }),
        );
        assert_eq!(result.status, SourceProcessingStatus::Failed);
        assert_eq!(result.progress, progress);
        assert_eq!(result.sqlite_progress_candidate(false, false), None);
        assert_eq!(result.completion, None);
        assert!(result.accounting.is_empty());
        assert_eq!(
            result.baseline_replacement,
            BaselineReplacement::NoReplacement
        );
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].event_type, "scanner_error");
        assert_eq!(result.events[0].agent, None);
        let serialized = serde_json::to_string(&result.events).unwrap();
        assert!(serialized.contains(code));
        assert!(!serialized.contains("PRIVATE"));
        let summary = super::super::super::source_processing_accounting(&[result])
            .unwrap()
            .json();
        assert_eq!(summary["selected_source_coverage"], "partial");
        assert_eq!(summary["failures"][0]["stage"], format!("{stage:?}"));
        assert_eq!(summary["failures"][0]["source_count"], 1);
        assert_eq!(
            summary["failures"][0]["acquisition_code"],
            serde_json::Value::Null
        );
        assert_eq!(
            summary["failures"][0]["bound_category"],
            serde_json::Value::Null
        );
        assert_eq!(
            summary["failures"][0]["bound_dimension"],
            serde_json::Value::Null
        );
    }
}

#[test]
fn processing_failures_retain_distinct_content_free_diagnostic_codes() {
    use telltale_core::canonical_runtime::SourceFailure;
    use telltale_detect::v2::ProcessingError;
    let source = source("PRIVATE-path".into());
    for reason in [
        ProcessingError::InvalidSource,
        ProcessingError::DuplicateObservation,
        ProcessingError::Bounds,
        ProcessingError::Evaluation,
        ProcessingError::Projection,
    ] {
        let stage = if reason == ProcessingError::Projection {
            FailureStage::Projection
        } else {
            FailureStage::Evaluation
        };
        let result = adapt_result(
            &source,
            Err(SourceFailure {
                stage,
                progress: AcquisitionProgress::None,
                acquisition: None,
                processing: Some(reason),
            }),
        );
        let error = result.events[0]
            .evidence
            .iter()
            .find(|item| item.field == "error")
            .unwrap();
        assert_eq!(error.redacted_value, stage.code());
        let summary = super::super::super::source_processing_accounting(&[result])
            .unwrap()
            .json();
        assert_eq!(
            summary["failures"][0]["processing_code"],
            reason.to_string()
        );
        assert_eq!(
            summary["failures"][0]["acquisition_code"],
            serde_json::Value::Null
        );
        assert!(!summary.to_string().contains("PRIVATE"));
    }
}

#[test]
fn ownership_failure_returns_neither_accounting_nor_eligible_progress() {
    let directory = tempdir().unwrap();
    let source = database(&directory.path().join("synthetic.db"));
    let connection = rusqlite::Connection::open(&source.path).unwrap();
    connection
        .execute("UPDATE part SET session_id = 'PRIVATE-other'", [])
        .unwrap();
    let result = process_canonical_source(
        &source,
        &ScanState::default(),
        CanonicalProcessingOptions::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Failed);
    assert!(result.accounting.is_empty());
    assert_eq!(result.progress, AcquisitionProgress::None);
    assert_eq!(result.sqlite_progress_candidate(false, false), None);
    assert!(
        !serde_json::to_string(&result.events)
            .unwrap()
            .contains("PRIVATE")
    );
}

#[test]
fn contribution_budget_failure_returns_no_accounting_or_eligible_progress() {
    let directory = tempdir().unwrap();
    let source = source(directory.path().join("synthetic.jsonl"));
    let mut lines = Vec::new();
    for session in 0..2 {
        let hosts = (0..2100)
            .map(|i| format!("https://s{session}-h{i}.example/x"))
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(
            serde_json::json!({"type":"assistant","session_id":format!("s{session}"),
            "content":[{"type":"tool_use","id":"call-a","name":"shell","input":{}}],
            "sibling_context":hosts})
            .to_string(),
        );
    }
    std::fs::write(&source.path, lines.join("\n")).unwrap();
    let result = process_canonical_source(
        &source,
        &ScanState::default(),
        CanonicalProcessingOptions::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Failed);
    assert!(result.accounting.is_empty());
    assert_eq!(result.progress, AcquisitionProgress::None);
    assert_eq!(result.sqlite_progress_candidate(false, false), None);
    assert!(
        !serde_json::to_string(&result.events)
            .unwrap()
            .contains(".example")
    );
}

#[test]
fn acquisition_error_text_is_not_exposed() {
    let dir = tempdir().unwrap();
    let source = source(dir.path().join("PRIVATE-file"));
    std::fs::write(&source.path, "{PRIVATE-transcript-command-token").unwrap();
    let result = process_canonical_source(
        &source,
        &ScanState::default(),
        CanonicalProcessingOptions::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Failed);
    assert_eq!(result.progress, AcquisitionProgress::None);
    let json = serde_json::to_string(&result.events).unwrap();
    assert!(json.contains("canonical_acquisition_failed"));
    assert!(!json.contains("PRIVATE"));
}
