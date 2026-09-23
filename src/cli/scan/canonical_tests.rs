use super::*;
use telltale_core::canonical_runtime::FailureStage;

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
            }),
        );
        assert_eq!(result.status, SourceProcessingStatus::Failed);
        assert_eq!(result.progress, progress);
        assert_eq!(result.sqlite_progress_candidate(false, false), None);
        assert_eq!(result.completion, None);
        assert!(result.accounting.is_none());
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
    assert!(result.accounting.is_none());
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
            "legacy_context":hosts})
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
    assert!(result.accounting.is_none());
    assert_eq!(result.progress, AcquisitionProgress::None);
    assert_eq!(result.sqlite_progress_candidate(false, false), None);
    assert!(
        !serde_json::to_string(&result.events)
            .unwrap()
            .contains(".example")
    );
}

#[test]
fn all_eight_native_contributions_match_fixed_accounting_expectations() {
    use std::collections::BTreeMap;
    use telltale_schema::activity_facts::PathClass;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_sources::acquisition::ActivityContributions;
    let directory = tempdir().unwrap();
    for (client, source_id, kind) in [
        (ClientId::Claude, "claude.projects", SourceKind::Jsonl),
        (ClientId::Codex, "codex.sessions", SourceKind::Jsonl),
        (
            ClientId::Codex,
            "codex.archived_sessions",
            SourceKind::ArchivedJsonl,
        ),
        (
            ClientId::Codex,
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
        ),
        (ClientId::OpenClaw, "openclaw.agents", SourceKind::Jsonl),
        (ClientId::Qwen, "qwen.projects", SourceKind::Jsonl),
        (
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
        ),
        (ClientId::OpenCode, "opencode.sqlite", SourceKind::Sqlite),
    ] {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind,
            path: directory.path().join(source_id),
        };
        if client == ClientId::OpenCode {
            let conn = rusqlite::Connection::open(&source.path).unwrap();
            conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
                CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
                INSERT INTO message VALUES ('m','s','{"role":"assistant"}');
                INSERT INTO part VALUES ('p','m','s',10,'{"type":"tool","tool":"shell","callID":"call-a","state":{"status":"running","input":{"command":"https://example.test/x /home/u/.env"}}}');
                INSERT INTO part VALUES ('done','m','s',11,'{"type":"tool","tool":"not-a-call","callID":"call-b","state":{"status":"completed","input":{"path":"/tmp/ignored"},"output":"done"}}');"#).unwrap();
        } else if client == ClientId::Copilot {
            std::fs::write(&source.path, concat!(
                "2026-04-27T16:16:57.841Z [INFO] Workspace initialized: s (checkpoints: 0)\n",
                "2026-04-27T16:17:17.990Z [INFO] Accumulated output items (1): ",
                r#"[{"type":"function_call","name":"shell","call_id":"call-a","arguments":"{\"command\":\"https://example.test/x /home/u/.env\"}","message":"https://ignored-result.test/"}]"#
            )).unwrap();
        } else {
            std::fs::write(&source.path, r#"{"type":"assistant","session_id":"s","content":[{"type":"tool_use","id":"call-a","name":"shell","input":{"command":"https://example.test/x /home/u/.env"}}],"legacy_context":"https://sibling.example.test/x /tmp/synthetic"}"#).unwrap();
        }
        let batch = acquire_source(&source, AcquisitionOptions::new(clock())).unwrap();
        let actual = &batch.accounting.sessions[0].counts.contributions;
        let (paths, hosts) = match source_id {
            "copilot.process_log" => (
                BTreeMap::from([(PathClass::SecretStore, 1)]),
                BTreeMap::from([("example.test".to_string(), 1)]),
            ),
            "opencode.sqlite" => (
                BTreeMap::from([(PathClass::SecretStore, 4), (PathClass::Other, 1)]),
                BTreeMap::from([("example.test".to_string(), 3)]),
            ),
            _ => (
                BTreeMap::from([(PathClass::SecretStore, 2), (PathClass::Temp, 1)]),
                BTreeMap::from([
                    ("example.test".to_string(), 2),
                    ("sibling.example.test".to_string(), 1),
                ]),
            ),
        };
        assert_eq!(
            actual.tool_calls,
            BTreeMap::from([("shell".into(), 1)]),
            "{source_id}"
        );
        assert_eq!(actual.path_classes, paths, "{source_id}");
        assert_eq!(actual.network_hosts, hosts, "{source_id}");
        assert_eq!(
            batch.accounting.unscoped.contributions,
            ActivityContributions::default()
        );
    }
}
use telltale_detect::v2::compile_rule_v1;
use telltale_rules::load_default_rule_set;
use telltale_schema::clients::{ClientId, SourceKind};
use tempfile::tempdir;

#[test]
fn complete_replacement_is_staged_and_empty_clears_only_its_source() {
    let directory = tempdir().unwrap();
    let mut source = source(directory.path().join("synthetic.jsonl"));
    source.client = ClientId::Codex;
    source.source_id = "codex.sessions".into();
    let other = Source {
        path: directory.path().join("other.jsonl"),
        ..source.clone()
    };
    std::fs::write(&source.path, r#"{"type":"user","session_id":"eligible","model":"model","provider":"provider","content":"hello"}"#).unwrap();
    let mut state = ScanState::default();
    let initial = process_canonical_source(
        &source,
        &state,
        Default::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    let BaselineReplacement::Replace(summaries) = initial.baseline_replacement else {
        panic!("complete file replacement")
    };
    assert_eq!(summaries.len(), 1);
    state
        .record_baseline_source_contribution(&source, "old".into(), summaries.clone())
        .unwrap();
    state
        .record_baseline_source_contribution(&other, "other".into(), summaries)
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    let before = serde_json::to_string(&state).unwrap();
    let ineligible = concat!(
        "{\"type\":\"session_meta\",\"payload\":{}}\n",
        "{\"type\":\"user\",\"session_id\":\"s\",\"model\":\"a\",\"content\":\"hello\"}\n",
        "{\"type\":\"user\",\"session_id\":\"s\",\"model\":\"b\",\"content\":\"hello\"}\n"
    );
    std::fs::write(&source.path, format!("{{\"type\":\"user\",\"session_id\":\"new\",\"model\":\"new-model\",\"content\":\"hello\"}}\n{ineligible}")).unwrap();
    let mixed = process_canonical_source(
        &source,
        &state,
        Default::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(mixed.status, SourceProcessingStatus::Succeeded);
    assert_eq!(serde_json::to_string(&state).unwrap(), before);
    let BaselineReplacement::Replace(eligible) = mixed.baseline_replacement else {
        panic!("mixed complete replacement")
    };
    assert_eq!(eligible.len(), 1);
    assert_eq!(eligible[0].key.model.as_deref(), Some("new-model"));
    state
        .record_baseline_source_contribution(&source, "mixed".into(), eligible)
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    assert_eq!(state.baseline_snapshots.snapshots.len(), 2);
    assert!(
        state
            .baseline_snapshots
            .snapshots
            .values()
            .all(|s| s.observations.records == 1)
    );
    let before = serde_json::to_string(&state).unwrap();
    // A complete reread now has only unscoped facts and an ambiguous session.
    std::fs::write(&source.path, ineligible).unwrap();
    let current = process_canonical_source(
        &source,
        &state,
        Default::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(current.status, SourceProcessingStatus::Succeeded);
    assert_eq!(serde_json::to_string(&state).unwrap(), before);
    let BaselineReplacement::Replace(empty) = current.baseline_replacement else {
        panic!("explicit empty replacement")
    };
    assert!(empty.is_empty());
    // Test-only simulation at the authoritative state boundary, not evaluation.
    state
        .record_baseline_source_contribution(&source, "new".into(), empty)
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    assert_eq!(
        state
            .baseline_snapshots
            .snapshots
            .values()
            .next()
            .unwrap()
            .observations
            .records,
        1
    );
    assert_eq!(state.baseline_source_contributions.len(), 2);
}

#[test]
fn partial_and_scanner_modes_cannot_stage_baseline_mutation() {
    let directory = tempdir().unwrap();
    let file = source(directory.path().join("synthetic.jsonl"));
    std::fs::write(
        &file.path,
        r#"{"type":"user","session_id":"s","content":"hello"}"#,
    )
    .unwrap();
    let sqlite = database(&directory.path().join("synthetic.db"));
    let mut state = ScanState::default();
    let initial = process_canonical_source(
        &file,
        &state,
        Default::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    let BaselineReplacement::Replace(summaries) = initial.baseline_replacement else {
        panic!("replacement")
    };
    state
        .record_baseline_source_contribution(&sqlite, "prior".into(), summaries)
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    let before = serde_json::to_string(&state).unwrap();
    for (backfill, dry_run) in [(false, false), (true, false), (false, true), (true, true)] {
        for source in [&file, &sqlite] {
            let result = process_canonical_source(
                source,
                &state,
                CanonicalProcessingOptions {
                    backfill,
                    dry_run,
                    ..Default::default()
                },
                clock(),
                &plan("url"),
                None,
            );
            assert_eq!(result.status, SourceProcessingStatus::Succeeded);
            assert!(
                result
                    .events
                    .iter()
                    .any(|event| event.event_type == "activity")
            );
            if backfill || dry_run || source.client == ClientId::OpenCode {
                assert_eq!(
                    result.baseline_replacement,
                    BaselineReplacement::NoReplacement
                );
            }
            if source.client == ClientId::OpenCode && !backfill && !dry_run {
                assert_eq!(result.sqlite_progress_candidate(false, false), Some(1000));
            }
            assert_eq!(serde_json::to_string(&state).unwrap(), before);
        }
    }
}

#[test]
fn canonical_candidate_round_trips_existing_state_without_plaintext_hosts() {
    let directory = tempdir().unwrap();
    let source = source(directory.path().join("synthetic.jsonl"));
    std::fs::write(&source.path, r#"{"type":"assistant","session_id":"s","model":"m","provider":"p","content":[{"type":"tool_use","id":"call","name":"shell","input":{"command":"curl https://recognizable-host.synthetic.example/path"}}]}"#).unwrap();
    let native = acquire_source(&source, AcquisitionOptions::new(clock())).unwrap();
    assert!(
        native.accounting.sessions[0]
            .counts
            .contributions
            .network_hosts
            .contains_key("recognizable-host.synthetic.example")
    );
    let mut state = ScanState::default();
    let result = process_canonical_source(
        &source,
        &state,
        Default::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    let BaselineReplacement::Replace(summaries) = result.baseline_replacement else {
        panic!("complete replacement")
    };
    assert_eq!(
        summaries[0].network_host_counts.keys().next().unwrap(),
        &telltale_detect::baseline::baseline_host_identity("recognizable-host.synthetic.example")
    );
    assert!(!format!("{summaries:?}").contains("recognizable-host"));
    state
        .record_baseline_source_contribution(&source, "synthetic-fingerprint".into(), summaries)
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    assert!(!format!("{state:?}").contains("recognizable-host"));
    assert!(
        !serde_json::to_string(&state)
            .unwrap()
            .contains("recognizable-host")
    );
    let path = directory.path().join("state.json");
    state.save(&path).unwrap();
    assert!(
        !std::fs::read_to_string(&path)
            .unwrap()
            .contains("recognizable-host")
    );
    let loaded = ScanState::load(&path).unwrap();
    assert_eq!(loaded.baseline_snapshots, state.baseline_snapshots);
    assert_eq!(
        loaded.baseline_source_contributions,
        state.baseline_source_contributions
    );
}

fn clock() -> ObservedAt {
    ObservedAt::new("2026-09-19T00:00:00Z").unwrap()
}

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path,
    }
}

#[test]
fn ordinary_zero_findings_and_missing_source_are_explicit() {
    let dir = tempdir().unwrap();
    let source = source(dir.path().join("PRIVATE-source.jsonl"));
    let rules = load_default_rule_set().unwrap();
    let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
    let state = ScanState::default();
    let failed = process_canonical_source(
        &source,
        &state,
        CanonicalProcessingOptions::default(),
        clock(),
        &plan,
        None,
    );
    assert_eq!(failed.status, SourceProcessingStatus::Failed);
    assert_eq!(failed.sqlite_progress_candidate(false, false), None);
    assert!(
        !serde_json::to_string(&failed.events)
            .unwrap()
            .contains("PRIVATE")
    );
    std::fs::write(&source.path, "{\"type\":\"user\",\"sessionId\":\"synthetic\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n").unwrap();
    let result = process_canonical_source(
        &source,
        &state,
        CanonicalProcessingOptions::default(),
        clock(),
        &plan,
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].event_type, "activity");
    assert!(result.completion.is_some());
    assert_eq!(result.progress, AcquisitionProgress::None);
    assert_eq!(result.sqlite_progress_candidate(false, false), None);
    let accounting = result.accounting.as_ref().unwrap();
    assert_eq!(
        accounting.coverage,
        telltale_sources::acquisition::AccountingCoverage::CompleteSource
    );
    assert_eq!(accounting.sessions[0].counts.native_units, 1);
    assert_eq!(
        accounting.sessions[0].metadata,
        telltale_sources::acquisition::SessionMetadata::default()
    );
}

#[test]
fn projection_borrows_only_known_metadata_and_retains_ambiguity_for_b3b() {
    use telltale_sources::acquisition::AttestedValue;
    let dir = tempdir().unwrap();
    let source = source(dir.path().join("synthetic.jsonl"));
    std::fs::write(&source.path, concat!(
        "{\"type\":\"user\",\"session_id\":\"s\",\"content\":\"needle\",\"agent\":\"native-agent\",\"model\":\"model-a\",\"provider\":\"native-provider\"}\n",
        "{\"type\":\"user\",\"session_id\":\"s\",\"content\":\"synthetic\",\"model\":\"model-b\"}\n"
    )).unwrap();
    let state = ScanState::default();
    let result = process_canonical_source(
        &source,
        &state,
        CanonicalProcessingOptions::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(result.completion, Some(EvaluationCompletion::Complete));
    assert_eq!(result.events.len(), 2);
    let event = &result.events[0];
    assert_eq!(event.agent.as_deref(), Some("native-agent"));
    assert_eq!(event.provider.as_deref(), Some("native-provider"));
    assert_eq!(event.model, None);
    let accounting = result.accounting.unwrap();
    assert_eq!(
        accounting.sessions[0].metadata.model,
        AttestedValue::Ambiguous
    );
    assert_eq!(accounting.sessions[0].counts.record_counts.user_message, 2);
    assert_eq!(result.progress, AcquisitionProgress::None);
}

#[test]
fn metadata_only_sessions_do_not_break_projection_and_ambiguous_sqlite_can_progress() {
    use telltale_sources::acquisition::AttestedValue;
    let dir = tempdir().unwrap();
    let mut source = source(dir.path().join("synthetic.jsonl"));
    source.client = ClientId::Codex;
    source.source_id = "codex.sessions".into();
    std::fs::write(&source.path, "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"metadata-only\",\"model\":\"source-model\"}}\n").unwrap();
    let result = process_canonical_source(
        &source,
        &ScanState::default(),
        CanonicalProcessingOptions::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].event_type, "activity");
    assert_eq!(
        result.accounting.unwrap().sessions[0]
            .metadata
            .model
            .known(),
        Some("source-model")
    );

    let source = database(&dir.path().join("synthetic.db"));
    let conn = rusqlite::Connection::open(&source.path).unwrap();
    conn.execute(
        "UPDATE message SET data = ?1",
        [r#"{"role":"user","model":"model-a","provider":"source-provider"}"#],
    )
    .unwrap();
    conn.execute(
        "UPDATE part SET data = ?1",
        [r#"{"type":"text","text":"needle","model":"model-b"}"#],
    )
    .unwrap();
    let state = ScanState::default();
    let result = process_canonical_source(
        &source,
        &state,
        CanonicalProcessingOptions::default(),
        clock(),
        &plan("url"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(
        result.completion,
        Some(EvaluationCompletion::VisibilityLimited)
    );
    assert_eq!(
        result.accounting.as_ref().unwrap().sessions[0]
            .metadata
            .model,
        AttestedValue::Ambiguous
    );
    assert_eq!(result.sqlite_progress_candidate(false, false), Some(1000));
    assert_eq!(result.sqlite_progress_candidate(true, false), None);
    assert_eq!(
        state.sqlite_ingestion_cursor_time_updated(&source, "part"),
        None
    );
}

fn plan(target: &str) -> RuleV1CompatibilityPlan {
    let yaml = format!(
        "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.target\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    targets: [{target}]\n    regex: needle\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers: []\n"
    );
    compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&yaml], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap()
}

#[test]
fn complete_projection_precedes_one_existing_allowlist_application() {
    use crate::allowlist::{Allowlist, suppress_detection};
    let directory = tempdir().unwrap();
    let source = source(directory.path().join("synthetic.jsonl"));
    std::fs::write(
        &source.path,
        r#"{"type":"user","session_id":"s","content":"needle"}"#,
    )
    .unwrap();
    let mut result = process_canonical_source(
        &source,
        &ScanState::default(),
        CanonicalProcessingOptions::default(),
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(result.completion, Some(EvaluationCompletion::Complete));
    assert_eq!(result.events.len(), 2);
    assert_eq!(result.events[1].event_type, "activity");
    let event = &mut result.events[0];
    assert_eq!(event.risk_score, 1);
    assert!(event.agent.is_none() && event.model.is_none() && event.provider.is_none());
    assert_eq!(
        event.source_path_hash.as_deref(),
        Some(path_hash(&source.path).as_str())
    );
    let allowlist = Allowlist::from_yaml(
        "version: 1\nsuppressions:\n  - name: synthetic\n    rule_ids: [synthetic.target]\n",
    )
    .unwrap();
    let suppression = allowlist.suppression_for(&source, event).unwrap();
    suppress_detection(event, &suppression);
    assert_eq!(event.risk_score, 0);
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
}

fn database(path: &std::path::Path) -> Source {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection.execute_batch("CREATE TABLE message (id TEXT, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('m','s',1000,1000,'{\"role\":\"user\"}');
        INSERT INTO part VALUES ('p','m','s',1000,1000,'{\"type\":\"text\",\"text\":\"needle\"}');").unwrap();
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: path.into(),
    }
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
        result.accounting.as_ref().unwrap().coverage,
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
fn sqlite_limited_success_retains_progress_without_installing_and_reuses_read_policy() {
    let dir = tempdir().unwrap();
    let source = database(&dir.path().join("synthetic.db"));
    let mut state = ScanState::default();
    let plan = plan("url"); // URL visibility is explicitly unavailable.
    let result = process_canonical_source(
        &source,
        &state,
        CanonicalProcessingOptions::default(),
        clock(),
        &plan,
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(
        result.completion,
        Some(EvaluationCompletion::VisibilityLimited)
    );
    assert_eq!(
        result.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: Some(1000)
        }
    );
    assert_eq!(result.sqlite_progress_candidate(false, false), Some(1000));
    let accounting = result.accounting.as_ref().unwrap();
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
    state.observe_sqlite_ingestion_cursor(&source, "part", 700_001, 1);
    let live = process_canonical_source(
        &source,
        &state,
        CanonicalProcessingOptions::default(),
        clock(),
        &plan,
        None,
    );
    assert_eq!(
        live.accounting.as_ref().unwrap().coverage,
        telltale_sources::acquisition::AccountingCoverage::PartialSource
    );
    assert_eq!(
        live.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: None
        }
    );
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
            full.accounting.as_ref().unwrap().coverage,
            telltale_sources::acquisition::AccountingCoverage::PartialSource
        );
        assert_eq!(full.sqlite_progress_candidate(dry_run, backfill), None);
    }
    assert_eq!(
        state.sqlite_ingestion_cursor_time_updated(&source, "part"),
        Some(700_001)
    );
}

#[test]
fn all_eight_identities_acquire_evaluate_project_without_legacy_records() {
    let dir = tempdir().unwrap();
    let db = database(&dir.path().join("synthetic.db"));
    let codex = dir.path().join("codex.jsonl");
    std::fs::write(&codex, "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"s\"}}\n{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"exec\",\"call_id\":\"c\",\"arguments\":{\"command\":\"printf synthetic\"}}}\n").unwrap();
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session_stores");
    let mut sources = vec![db];
    for (client, source_id, kind, path) in [
        (
            ClientId::Claude,
            "claude.projects",
            SourceKind::Jsonl,
            fixtures.join("claude/projects/project-b/session-tool-use.jsonl"),
        ),
        (
            ClientId::OpenClaw,
            "openclaw.agents",
            SourceKind::Jsonl,
            fixtures.join("openclaw/agents/project-b/uc001-openclaw-tool-result.jsonl"),
        ),
        (
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            fixtures.join("qwen/projects/project-b/chats/uc001-qwen-tool-result.jsonl"),
        ),
        (
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            fixtures.join("copilot/process-mixed-format.log"),
        ),
        (
            ClientId::Codex,
            "codex.sessions",
            SourceKind::Jsonl,
            codex.clone(),
        ),
        (
            ClientId::Codex,
            "codex.archived_sessions",
            SourceKind::ArchivedJsonl,
            codex.clone(),
        ),
        (
            ClientId::Codex,
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
            codex,
        ),
    ] {
        sources.push(Source {
            client,
            source_id: source_id.into(),
            kind,
            path,
        });
    }
    let rules = load_default_rule_set().unwrap();
    let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
    let state = ScanState::default();
    let process_rules = telltale_rules::process_chain::load_default_process_chain_rules().unwrap();
    let process_config = ProcessChainConfig::default();
    for source in &sources {
        let batch = acquire_source(source, AcquisitionOptions::new(clock())).unwrap();
        assert!(!batch.observations.is_empty(), "{}", source.source_id);
        assert!(batch.observations.iter().all(|o| o.source().adapter_id() == source.source_id && o.observed_at() == &clock()));
        let result = process_canonical_source(
            source,
            &state,
            CanonicalProcessingOptions::default(),
            clock(),
            &plan,
            Some((&process_rules, &process_config)),
        );
        assert_eq!(
            result.status,
            SourceProcessingStatus::Succeeded,
            "{}",
            source.source_id
        );
        assert_eq!(result.accounting.as_ref(), Some(&batch.accounting));
        assert!(
            result
                .events
                .iter()
                .all(|e| e.client == source.client.as_str())
        );
        if source.kind != SourceKind::Sqlite {
            assert_eq!(result.progress, AcquisitionProgress::None);
        }
    }
    assert_eq!(sources.len(), 8);
    for (client, id, kind) in [
        (ClientId::OpenCode, "opencode.json", SourceKind::Jsonl),
        (ClientId::Codex, "claude.projects", SourceKind::Jsonl),
        (ClientId::Claude, "claude.projects", SourceKind::Sqlite),
    ] {
        let invalid = Source {
            client,
            source_id: id.into(),
            kind,
            path: sources[1].path.clone(),
        };
        let result = process_canonical_source(
            &invalid,
            &state,
            CanonicalProcessingOptions::default(),
            clock(),
            &plan,
            None,
        );
        assert_eq!(result.status, SourceProcessingStatus::Failed);
        assert_eq!(result.progress, AcquisitionProgress::None);
    }
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
