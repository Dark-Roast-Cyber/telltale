use super::*;

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
            std::fs::write(&source.path, r#"{"type":"assistant","session_id":"s","content":[{"type":"tool_use","id":"call-a","name":"shell","input":{"command":"https://example.test/x /home/u/.env"}}],"sibling_context":"https://sibling.example.test/x /tmp/synthetic"}"#).unwrap();
        }
        let batch = acquire_source(&source, AcquisitionOptions::new(clock())).unwrap();
        let actual = &batch.accounting.sessions[0].counts.contributions;
        let (paths, hosts) = match source_id {
            "copilot.process_log" => (
                BTreeMap::from([(PathClass::SecretStore, 1)]),
                BTreeMap::from([("example.test".to_string(), 1)]),
            ),
            "opencode.sqlite" => (
                BTreeMap::from([(PathClass::SecretStore, 1)]),
                BTreeMap::from([("example.test".to_string(), 1)]),
            ),
            _ => (
                BTreeMap::from([(PathClass::SecretStore, 1), (PathClass::Temp, 1)]),
                BTreeMap::from([
                    ("example.test".to_string(), 1),
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
