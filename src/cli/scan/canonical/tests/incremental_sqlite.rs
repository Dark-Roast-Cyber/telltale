use super::*;

#[test]
fn saturated_incremental_scan_never_stages_cursor_or_baseline() {
    let dir = tempdir().unwrap();
    let source = database(&dir.path().join("synthetic.db"));
    let mut conn = rusqlite::Connection::open(&source.path).unwrap();
    let transaction = conn.transaction().unwrap();
    for i in 0..25000 {
        transaction.execute(
            "INSERT INTO part VALUES (?1, 'm', 's', 1000, 1000, '{\"type\":\"text\",\"text\":\"synthetic\"}')",
            [format!("extra-{i}")],
        ).unwrap();
    }
    transaction.commit().unwrap();
    let plan = plan("url");
    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "part", 1000, 1);
    let prior = state.canonical_bytes().unwrap();
    for _ in 0..2 {
        let failed = process_canonical_source(
            &source,
            &state,
            CanonicalProcessingOptions::default(),
            clock(),
            &plan,
            None,
        );
        assert_eq!(failed.status, SourceProcessingStatus::Failed);
        assert_eq!(failed.events.len(), 1);
        assert_eq!(failed.events[0].event_type, "scanner_error");
        assert!(failed.accounting.is_empty());
        assert_eq!(failed.progress, AcquisitionProgress::None);
        assert_eq!(failed.sqlite_progress_candidate(false, false), None);
        assert_eq!(
            failed.baseline_replacement,
            BaselineReplacement::NoReplacement
        );
        assert_eq!(state.canonical_bytes().unwrap(), prior);
    }
    for (dry_run, backfill) in [(true, false), (false, true)] {
        let bootstrap = process_canonical_source(
            &source,
            &state,
            CanonicalProcessingOptions {
                dry_run,
                backfill,
                ..Default::default()
            },
            clock(),
            &plan,
            None,
        );
        assert_eq!(bootstrap.status, SourceProcessingStatus::Succeeded);
        assert_eq!(bootstrap.sqlite_progress_candidate(dry_run, backfill), None);
        assert_eq!(
            bootstrap.baseline_replacement,
            BaselineReplacement::NoReplacement
        );
    }
}

#[test]
fn incremental_backlog_over_one_page_recovers_ties_and_overlap_updates() {
    let dir = tempdir().unwrap();
    let source = database(&dir.path().join("recovery.db"));
    let mut conn = rusqlite::Connection::open(&source.path).unwrap();
    let tx = conn.transaction().unwrap();
    for i in 0..5000 {
        tx.execute("INSERT INTO part VALUES (?1,'m','s',1000,1000,'{\"type\":\"text\",\"text\":\"synthetic\"}')", [format!("extra-{i}")]).unwrap();
    }
    tx.commit().unwrap();
    conn.execute_batch("UPDATE part SET data='{\"type\":\"text\",\"text\":\"synthetic\"}' WHERE id='p';
        INSERT INTO message VALUES ('later','s',1000,1000,'{\"role\":\"user\",\"content\":\"needle envelope\"}');").unwrap();
    for (id, message_id, command, start) in [
        ("extra-4998", "m", "hostname", 1000),
        ("extra-4999", "later", "whoami", 2000),
    ] {
        conn.execute("UPDATE part SET message_id=?1, data=?2 WHERE id=?3", rusqlite::params![
            message_id,
            serde_json::json!({"type":"tool","tool":"bash","callID":id,"state":{"status":"running","input":{"command":command},"time":{"start":start}}}).to_string(),
            id,
        ]).unwrap();
    }
    let process_rules = telltale_rules::process_chain::load_process_chain_rules(r#"
version: 1
description: synthetic page boundary
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone:
  - { id: procchain.synthetic.hostname, title: command, category: discovery, severity: informational, score: 0, confidence: low, match: command_line, patterns: ["\\bhostname\\b"], mitre: [T1082], reason: command }
  - { id: procchain.synthetic.whoami, title: command, category: discovery, severity: informational, score: 0, confidence: low, match: command_line, patterns: ["\\bwhoami\\b"], mitre: [T1082], reason: command }
correlations:
  - id: procchain.correlation.synthetic_children
    title: child sequence
    category: discovery
    severity: medium
    score: 45
    confidence: medium
    mitre: [T1082]
    reason: child sequence
    window_seconds: 60
    entity: host
    sequence:
      - { any_rule_id: [procchain.synthetic.hostname], any_child: [hostname] }
      - { any_rule_id: [procchain.synthetic.whoami], any_child: [whoami] }
"#).unwrap();
    let process_config = ProcessChainConfig::default();
    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "part", 1000, 1);
    let plan = plan("user_context");
    let read = |state: &ScanState| {
        process_canonical_source(
            &source,
            state,
            CanonicalProcessingOptions::default(),
            clock(),
            &plan,
            Some((&process_rules, &process_config)),
        )
    };
    let first = read(&state);
    assert_eq!(first.status, SourceProcessingStatus::Succeeded);
    assert_eq!(
        first.accounting.first().unwrap().sessions[0]
            .counts
            .native_units,
        5003
    );
    assert_eq!(first.sqlite_progress_candidate(false, false), Some(1000));
    assert!(!first.events.iter().any(|e| e.event_type == "detection"));
    assert!(
        first.events.iter().any(|e| {
            e.rule_ids
                .iter()
                .any(|id| id == "procchain.correlation.synthetic_children")
        }),
        "event rules: {:?}",
        first
            .events
            .iter()
            .map(|e| (&e.event_type, &e.rule_ids))
            .collect::<Vec<_>>()
    );
    state.observe_sqlite_ingestion_cursor(&source, "part", 2000, 2);
    // An overlap update below the cursor is re-read; a newer part keeps the
    // store at the cursor, so this is not a regressed store.
    conn.execute_batch("UPDATE part SET data='{\"type\":\"text\",\"text\":\"needle changed\"}', time_updated=1500 WHERE id='extra-4999';
        UPDATE part SET time_updated=2000 WHERE id='extra-4998';").unwrap();
    let changed = read(&state);
    assert_eq!(changed.status, SourceProcessingStatus::Succeeded);
    assert!(changed.events.iter().any(|e| {
        e.event_type == "detection"
            && e.evidence
                .iter()
                .any(|v| v.redacted_value.contains("changed"))
    }));
    assert_eq!(changed.sqlite_progress_candidate(false, false), Some(2000));
    state.observe_sqlite_ingestion_cursor(&source, "part", 1500, 3);
    assert_eq!(
        state.sqlite_ingestion_cursor_time_updated(&source, "part"),
        Some(2000)
    );
}

#[test]
fn regressed_store_fails_closed_keeps_cursor_and_recovers_on_new_activity() {
    let dir = tempdir().unwrap();
    let source = database(&dir.path().join("synthetic.db"));
    let conn = rusqlite::Connection::open(&source.path).unwrap();
    conn.execute(
        "INSERT INTO part VALUES ('newest','m','s',2000,2000,'{\"type\":\"text\",\"text\":\"synthetic\"}')",
        [],
    )
    .unwrap();
    let plan = plan("url");
    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "part", 2000, 1);
    let read = |state: &ScanState| {
        process_canonical_source(
            &source,
            state,
            CanonicalProcessingOptions::default(),
            clock(),
            &plan,
            None,
        )
    };

    // An idle store still holding the cursor's part resumes normally.
    let idle = read(&state);
    assert_eq!(idle.status, SourceProcessingStatus::Succeeded);
    assert_eq!(idle.sqlite_progress_candidate(false, false), Some(2000));

    // Deleting the newest part (as session deletion can) regresses the store.
    conn.execute("DELETE FROM part WHERE id = 'newest'", [])
        .unwrap();
    let before = state.canonical_bytes().unwrap();
    for _ in 0..2 {
        let failed = read(&state);
        assert_eq!(failed.status, SourceProcessingStatus::Failed);
        assert_eq!(failed.events.len(), 1);
        assert_eq!(failed.events[0].event_type, "scanner_error");
        assert_eq!(failed.sqlite_progress_candidate(false, false), None);
        assert_eq!(
            failed.baseline_replacement,
            BaselineReplacement::NoReplacement
        );
        let summary =
            super::super::super::source_processing_accounting(std::slice::from_ref(&failed))
                .unwrap()
                .json();
        assert_eq!(
            summary["failures"][0]["acquisition_code"],
            "resume_regressed"
        );
        assert_eq!(state.canonical_bytes().unwrap(), before);
    }

    // New activity at or after the cursor resumes without resetting it.
    conn.execute(
        "INSERT INTO part VALUES ('later','m','s',2500,2500,'{\"type\":\"text\",\"text\":\"synthetic\"}')",
        [],
    )
    .unwrap();
    let resumed = read(&state);
    assert_eq!(resumed.status, SourceProcessingStatus::Succeeded);
    assert_eq!(resumed.sqlite_progress_candidate(false, false), Some(2500));

    // A store without its part table cannot hold the cursor either.
    conn.execute("DROP TABLE part", []).unwrap();
    let missing = read(&state);
    assert_eq!(missing.status, SourceProcessingStatus::Failed);
    let summary = super::super::super::source_processing_accounting(std::slice::from_ref(&missing))
        .unwrap()
        .json();
    assert_eq!(
        summary["failures"][0]["acquisition_code"],
        "resume_regressed"
    );
}

#[test]
fn malformed_message_after_valid_part_never_stages_scan_progress_or_baseline() {
    let dir = tempdir().unwrap();
    let source = database(&dir.path().join("synthetic.db"));
    let conn = rusqlite::Connection::open(&source.path).unwrap();
    conn.execute(
        "INSERT INTO message VALUES ('bad', 's', 1001, 1001, '[]')",
        [],
    )
    .unwrap();
    let mut state = ScanState::default();
    state.observe_sqlite_ingestion_cursor(&source, "part", 1000, 1);
    let before = state.canonical_bytes().unwrap();
    let failed = process_canonical_source(
        &source,
        &state,
        CanonicalProcessingOptions::default(),
        clock(),
        &plan("url"),
        None,
    );
    assert_eq!(failed.status, SourceProcessingStatus::Failed);
    assert_eq!(failed.events.len(), 1);
    assert_eq!(failed.events[0].event_type, "scanner_error");
    assert_eq!(failed.progress, AcquisitionProgress::None);
    assert!(failed.accounting.is_empty());
    assert_eq!(failed.sqlite_progress_candidate(false, false), None);
    assert_eq!(
        failed.baseline_replacement,
        BaselineReplacement::NoReplacement
    );
    assert_eq!(state.canonical_bytes().unwrap(), before);
}

#[test]
fn benign_opencode_sqlite_partial_source_has_no_canonical_detection() {
    use telltale_sources::acquisition::AccountingCoverage;

    let dir = tempdir().unwrap();
    let source = database(&dir.path().join("benign.db"));
    let connection = rusqlite::Connection::open(&source.path).unwrap();
    connection
        .execute(
            "UPDATE part SET data = ?1",
            [r#"{"type":"text","text":"This is a minimal Rust project."}"#],
        )
        .unwrap();
    let batch = acquire_source(&source, AcquisitionOptions::new(clock())).unwrap();
    assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
    assert!(!batch.observations.is_empty());

    let rules = load_default_rule_set().unwrap();
    let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
    let result = process_canonical_source(
        &source,
        &ScanState::default(),
        CanonicalProcessingOptions::default(),
        clock(),
        &plan,
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(
        result.accounting.first().unwrap().coverage,
        AccountingCoverage::PartialSource
    );
    assert_eq!(
        result.baseline_replacement,
        BaselineReplacement::NoReplacement
    );
    assert!(
        result
            .events
            .iter()
            .any(|event| event.event_type == "activity")
    );
    assert!(
        !result
            .events
            .iter()
            .any(|event| event.event_type == "detection")
    );
}

#[test]
fn sqlite_partial_success_retains_progress_without_installing_and_reuses_read_policy() {
    let dir = tempdir().unwrap();
    let source = database(&dir.path().join("synthetic.db"));
    let mut state = ScanState::default();
    // Partial (selected-window) accounting, not completion, prevents installing
    // a whole-source baseline; successful completion keeps progress eligible.
    let plan = plan("url");
    let result = process_canonical_source(
        &source,
        &state,
        CanonicalProcessingOptions::default(),
        clock(),
        &plan,
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(result.completion, Some(EvaluationCompletion::Complete));
    assert_eq!(
        result.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: Some(1000)
        }
    );
    assert_eq!(result.sqlite_progress_candidate(false, false), Some(1000));
    let accounting = result.accounting.first().unwrap();
    assert_eq!(
        accounting.coverage,
        telltale_sources::acquisition::AccountingCoverage::PartialSource
    );
    assert_eq!(accounting.sessions[0].counts.native_units, 2);
    assert_eq!(
        accounting.sessions[0].metadata,
        telltale_sources::acquisition::SessionMetadata::default()
    );
    assert_eq!(
        state.sqlite_ingestion_cursor_time_updated(&source, "part"),
        None
    );
    for (dry_run, backfill) in [(true, false), (false, true), (true, true)] {
        assert_eq!(result.sqlite_progress_candidate(dry_run, backfill), None);
    }
    // A cursor ahead of every part is a regressed store: the live read fails
    // closed and keeps the cursor, while dry-run and backfill still read.
    state.observe_sqlite_ingestion_cursor(&source, "part", 700_001, 1);
    let before = state.canonical_bytes().unwrap();
    let live = process_canonical_source(
        &source,
        &state,
        CanonicalProcessingOptions::default(),
        clock(),
        &plan,
        None,
    );
    assert_eq!(live.status, SourceProcessingStatus::Failed);
    assert!(live.accounting.is_empty());
    assert_eq!(live.sqlite_progress_candidate(false, false), None);
    assert_eq!(live.events.len(), 1);
    assert_eq!(live.events[0].event_type, "scanner_error");
    let summary = super::super::super::source_processing_accounting(std::slice::from_ref(&live))
        .unwrap()
        .json();
    assert_eq!(
        summary["failures"][0]["acquisition_code"],
        "resume_regressed"
    );
    assert_eq!(state.canonical_bytes().unwrap(), before);
    for (dry_run, backfill) in [(true, false), (false, true)] {
        let full = process_canonical_source(
            &source,
            &state,
            CanonicalProcessingOptions {
                backfill,
                dry_run,
                ..Default::default()
            },
            clock(),
            &plan,
            None,
        );
        assert_eq!(full.progress, result.progress);
        assert_eq!(
            full.accounting.first().unwrap().coverage,
            telltale_sources::acquisition::AccountingCoverage::PartialSource
        );
        assert_eq!(full.sqlite_progress_candidate(dry_run, backfill), None);
    }
    assert_eq!(
        state.sqlite_ingestion_cursor_time_updated(&source, "part"),
        Some(700_001)
    );
}
