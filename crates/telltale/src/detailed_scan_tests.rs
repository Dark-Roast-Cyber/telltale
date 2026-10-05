use super::*;
use crate::test_support::tree_snapshot;

#[test]
fn core_discovery_exports_preserve_existing_contracts() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join(".claude/projects/synthetic");
    std::fs::create_dir_all(&project).unwrap();
    let source = write_source(
        &project,
        "session.jsonl",
        "session",
        &[call("call", "2026-09-17T00:00:00Z", "echo ordinary")],
    );
    let checked = discover_sources(root.path()).unwrap();
    assert!(checked.iter().any(|found| found.path == source.path));
    assert_eq!(checked, discover_sources_best_effort(root.path()));
    let roots = discover_watch_roots_for_clients(root.path(), &[ClientId::Claude]);
    assert!(roots.iter().any(|watch| source.path.starts_with(watch)));
}

#[test]
fn review_custom_metadata_does_not_survive_detailed_serialization() {
    let root = tempfile::tempdir().unwrap();
    let source = write_source(
        root.path(),
        "metadata.jsonl",
        "session",
        &[call("call", "2026-09-17T00:00:00Z", "needle")],
    );
    let marker = "/home/synthetic/private-category";
    let document = format!(
        "version: 1\ndescription: synthetic\ndefaults: {{enabled: true, case_insensitive: false}}\nrules:\n  - id: synthetic.rule\n    category: {marker}\n    severity: high\n    score: 30\n    targets: [command]\n    regex: needle\n    tags: []\n    explanation: synthetic\nmodifiers: []\n"
    );
    let scans = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(document)
        .build()
        .unwrap()
        .scan_sources_detailed(&[source], &DetailedEvaluationOptions::default())
        .unwrap();
    let finding = &scans[0].action_findings[0];
    assert!(!serde_json::to_string(finding).unwrap().contains(marker));
    assert_eq!(finding.finding_kind(), ActionFindingKind::Atomic);
    assert_eq!(
        finding.supporting_observation_ids(),
        [finding.observation_id()]
    );
    assert!(!finding.coordinate().as_str().is_empty());
    assert!(!finding.severity().is_empty());
}

fn write_source(
    root: &std::path::Path,
    file: &str,
    session: &str,
    rows: &[serde_json::Value],
) -> Source {
    let path = root.join(file);
    let text = rows
        .iter()
        .cloned()
        .map(|mut row| {
            row["sessionId"] = session.into();
            serde_json::to_string(&row).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&path, text).unwrap();
    Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path,
    }
}
fn call(id: &str, time: &str, command: &str) -> serde_json::Value {
    serde_json::json!({"type":"assistant","uuid":id,"timestamp":time,"message":{"role":"assistant","content":[{"type":"tool_use","id":id,"name":"Bash","input":{"command":command}}]}})
}

#[test]
fn review_process_details_project_the_existing_owner() {
    let root = tempfile::tempdir().unwrap();
    let source = write_source(
        root.path(),
        "process.jsonl",
        "process-session",
        &[call(
            "process",
            "2026-09-17T00:00:00Z",
            "cmd.exe /c hostname && cmd.exe /c whoami",
        )],
    );
    let pipeline = Pipeline::builder().build().unwrap();
    let mut options = DetailedEvaluationOptions::default();
    options.process_chain = true;
    let scans = pipeline.scan_sources_detailed(&[source], &options).unwrap();
    let processes = scans[0]
        .action_findings
        .iter()
        .filter(|f| f.detector_kind() == "process_chain")
        .collect::<Vec<_>>();
    assert!(!processes.is_empty());
    assert!(
        processes
            .iter()
            .any(|finding| finding.finding_kind() == ActionFindingKind::Correlation)
    );
    for finding in processes {
        assert!(!finding.coordinate().as_str().is_empty());
        assert!(!finding.supporting_observation_ids().is_empty());
        assert_eq!(
            finding.score(),
            finding
                .contributions()
                .iter()
                .map(|c| c.points())
                .sum::<u64>()
        );
    }
}

#[test]
fn detailed_scan_is_additive_same_pass_and_replay_is_coordinate_independent() {
    let root = tempfile::tempdir().unwrap();
    let rows = [
        call("synthetic-call-1", "2026-09-17T00:00:00Z", "cat .env"),
        call("synthetic-call-2", "2026-09-17T00:01:00Z", "cat .env"),
    ];
    let first = write_source(root.path(), "first.jsonl", "session-one", &rows);
    let mut continued = vec![
        serde_json::json!({"type":"user","message":{"role":"user","content":"ordinary inserted bookkeeping"}}),
    ];
    continued.extend(rows.clone());
    let second = write_source(root.path(), "second.jsonl", "session-two", &continued);
    let pipeline = Pipeline::builder().build().unwrap();
    let before = tree_snapshot(root.path());
    let scans = pipeline
        .scan_sources_detailed(
            &[first.clone(), second],
            &DetailedEvaluationOptions::default(),
        )
        .unwrap();
    assert_eq!(scans[0].action_findings.len(), 2);
    assert_eq!(scans[1].action_findings.len(), 2);
    for (a, b) in scans[0]
        .action_findings
        .iter()
        .zip(&scans[1].action_findings)
    {
        assert_eq!(a.replay_identity(), b.replay_identity());
        assert!(a.replay_identity().is_some());
        assert_ne!(a.observation_id(), b.observation_id());
        assert_eq!(a.score(), 35);
    }
    let compatibility = pipeline.scan_sources_with_occurrences(&[first]).unwrap();
    assert!(compatibility[0].action_findings.is_empty());
    assert_eq!(
        scans[0].occurrences.len(),
        compatibility[0].occurrences.len()
    );
    assert_eq!(
        scans[0].events[0].rule_ids,
        compatibility[0].events[0].rule_ids
    );
    assert_eq!(
        scans[0].events[0].risk_score,
        compatibility[0].events[0].risk_score
    );
    assert_eq!(tree_snapshot(root.path()), before);
}

#[test]
fn detailed_context_is_opt_in_same_session_anchor_excluded_and_redacted() {
    let root = tempfile::tempdir().unwrap();
    let marker = "SyntheticControlledSecretValue93847";
    let source = write_source(
        root.path(),
        "context.jsonl",
        "context-session",
        &[
            serde_json::json!({"type":"user","timestamp":"2026-09-17T00:00:00Z","message":{"role":"user","content":format!("password={marker} please inspect /home/synthetic/private/.env")}}),
            serde_json::json!({"type":"assistant","timestamp":"2026-09-17T00:00:01Z","message":{"role":"assistant","content":"I will inspect the requested file"}}),
            call("context-call", "2026-09-17T00:00:02Z", "cat .env"),
            serde_json::json!({"type":"user","timestamp":"2026-09-17T00:00:03Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"context-call","content":format!("never context {marker}")}]}}),
            serde_json::json!({"type":"assistant","timestamp":"2026-09-17T00:00:04Z","message":{"role":"assistant","content":"Inspection complete"}}),
        ],
    );
    let pipeline = Pipeline::builder().build().unwrap();
    let mut options = DetailedEvaluationOptions::default();
    options.context.before = 5;
    options.context.after = 3;
    options.context.assistant_text = true;
    options.context.tool_arguments = true;
    let default_user = pipeline
        .scan_sources_detailed(std::slice::from_ref(&source), &options)
        .unwrap();
    let finding = &default_user[0].action_findings[0];
    assert!(
        finding
            .context()
            .iter()
            .all(|c| c.kind() != "user_message" && c.kind() != "tool_result" && c.offset() != 0)
    );
    let replay = finding.replay_identity().cloned();
    options.context.user_text = true;
    let opted = pipeline.scan_sources_detailed(&[source], &options).unwrap();
    let finding = &opted[0].action_findings[0];
    assert_eq!(finding.replay_identity(), replay.as_ref());
    assert!(finding.context().iter().any(|c| c.kind() == "user_message"));
    let serialized = serde_json::to_string(finding).unwrap();
    assert!(!serialized.contains(marker));
    assert!(!serialized.contains("/home/synthetic/private"));
    assert!(
        finding
            .context()
            .iter()
            .all(|c| c.offset() != 0 && c.kind() != "tool_result")
    );
}

#[test]
fn pipeline_errors_have_typed_sources_and_safe_rendering() {
    let error = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document("synthetic invalid /home/synthetic/private token=controlledsecret")
        .build()
        .err()
        .unwrap();
    assert!(matches!(error, PipelineError::Compilation(_)));
    assert!(std::error::Error::source(&error).is_some());
    assert_eq!(format!("{error:?}"), "pipeline_compilation_failed");
    let error = Pipeline::builder()
        .build()
        .unwrap()
        .scan_root(std::path::Path::new("/synthetic/nonexistent/root"))
        .err()
        .unwrap();
    assert!(matches!(error, PipelineError::Discovery(_)));
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<DiscoveryError>()
            .is_some()
    );
    assert_eq!(error.to_string(), "pipeline_discovery_failed");
}

#[test]
fn codex_external_import_turn_is_inert_for_detailed_semantics() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("import.jsonl");
    let rows = [
        serde_json::json!({"type":"session_meta","payload":{"session_id":"import-session"}}),
        serde_json::json!({"type":"event_msg","payload":{"type":"task_started","turn_id":"external-import-turn-1"}}),
        serde_json::json!({"type":"response_item","timestamp":"2026-09-17T00:00:00Z","payload":{"type":"function_call","name":"exec_command","call_id":"imported-call","arguments":"{\"cmd\":\"cmd.exe /c hostname && cmd.exe /c whoami\"}"}}),
        serde_json::json!({"type":"response_item","timestamp":"2026-09-17T00:00:00Z","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"<tool_call>{\"name\":\"exec\",\"arguments\":{}}</tool_call>"}]}}),
        serde_json::json!({"type":"event_msg","payload":{"type":"task_started","turn_id":"ordinary-turn"}}),
        serde_json::json!({"type":"response_item","timestamp":"2026-09-17T00:01:00Z","payload":{"type":"function_call","name":"exec_command","call_id":"real-call","arguments":"{\"cmd\":\"cat .env\"}"}}),
    ];
    std::fs::write(
        &path,
        rows.iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .unwrap();
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".into(),
        path,
    };
    let mut options = DetailedEvaluationOptions::default();
    options.process_chain = true;
    let scans = Pipeline::builder()
        .build()
        .unwrap()
        .scan_sources_detailed(&[source], &options)
        .unwrap();
    assert!(
        scans[0]
            .events
            .iter()
            .all(|e| e.event_type != "scanner_error")
    );
    assert_eq!(scans[0].action_findings.len(), 1);
    assert_eq!(scans[0].action_findings[0].rule_ids(), ["secret.env.read"]);
    assert!(
        scans[0]
            .events
            .iter()
            .any(|event| event.rule_ids.iter().any(|id| id.starts_with("procchain.")))
    );
}

#[test]
fn policy_and_semantic_provenance_track_effective_rules_not_context_choices() {
    let root = tempfile::tempdir().unwrap();
    let source = write_source(
        root.path(),
        "policy.jsonl",
        "policy-session",
        &[call("policy-call", "2026-09-17T00:00:00Z", "cat .env")],
    );
    let enabled = Pipeline::builder().build().unwrap();
    let disabled = Pipeline::builder()
        .policy_document("version: 1\ndisabled_rules: [secret.env.read]\n")
        .build()
        .unwrap();
    let first = enabled
        .scan_sources_detailed(
            std::slice::from_ref(&source),
            &DetailedEvaluationOptions::default(),
        )
        .unwrap();
    let second = disabled
        .scan_sources_detailed(
            std::slice::from_ref(&source),
            &DetailedEvaluationOptions::default(),
        )
        .unwrap();
    assert_eq!(first[0].action_findings.len(), 1);
    assert!(second[0].action_findings.is_empty());
    assert_ne!(first[0].semantic_provenance, second[0].semantic_provenance);
    let mut options = DetailedEvaluationOptions::default();
    options.context.user_text = true;
    options.context.before = 2;
    let with_context = enabled.scan_sources_detailed(&[source], &options).unwrap();
    assert_eq!(
        first[0].semantic_provenance,
        with_context[0].semantic_provenance
    );
    options.context.before = 33;
    assert!(matches!(
        enabled.scan_sources_detailed(&[], &options),
        Err(PipelineError::InvalidOptions)
    ));
}

#[test]
fn replay_same_time_calls_use_reported_identity_and_duplicates_remain_visible() {
    let root = tempfile::tempdir().unwrap();
    let same_time = "2026-09-17T00:00:00Z";
    let source = write_source(
        root.path(),
        "same-time.jsonl",
        "same-time-session",
        &[
            call("one", same_time, "cat .env"),
            call("two", same_time, "cat .env"),
        ],
    );
    let scans = Pipeline::builder()
        .build()
        .unwrap()
        .scan_sources_detailed(&[source], &DetailedEvaluationOptions::default())
        .unwrap();
    let findings = &scans[0].action_findings;
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.replay_identity().is_some()));
    assert_ne!(findings[0].replay_identity(), findings[1].replay_identity());
    let path = root.path().join("ambiguous.jsonl");
    let mut first = call("same-call", same_time, "cat .env");
    first["sessionId"] = "one".into();
    let mut second = first.clone();
    second["sessionId"] = "two".into();
    std::fs::write(&path, format!("{}\n{}\n", first, second)).unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path,
    };
    let scans = Pipeline::builder()
        .build()
        .unwrap()
        .scan_sources_detailed(&[source], &DetailedEvaluationOptions::default())
        .unwrap();
    assert_eq!(scans[0].action_findings.len(), 2);
    assert!(
        scans[0]
            .action_findings
            .iter()
            .all(|f| f.replay_identity().is_none())
    );
}

#[cfg(feature = "opencode-sqlite")]
#[test]
fn sqlite_detailed_context_comes_from_the_acquired_batch_and_is_session_scoped() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("synthetic.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('u','s','{"role":"user","time":{"created":1789603199000}}');
        INSERT INTO message VALUES ('a','s','{"role":"assistant","time":{"created":1789603200000}}');
        INSERT INTO message VALUES ('other','another','{"role":"user","time":{"created":1789603199000}}');
        INSERT INTO part VALUES ('up','u','s',1,'{"type":"text","time":{"start":1789603199000},"text":"please inspect the requested file"}');
        INSERT INTO part VALUES ('op','other','another',2,'{"type":"text","time":{"start":1789603199000},"text":"another session must not appear"}');
        INSERT INTO part VALUES ('tp','a','s',3,'{"type":"tool","tool":"shell","callID":"synthetic-call","state":{"status":"running","input":{"command":"cat .env"},"time":{"start":1789603200000}}}');"#).unwrap();
    drop(conn);
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path,
    };
    let mut options = DetailedEvaluationOptions::default();
    options.context.before = 5;
    options.context.user_text = true;
    let scans = Pipeline::builder()
        .build()
        .unwrap()
        .scan_sources_detailed(&[source], &options)
        .unwrap();
    assert!(
        scans[0]
            .events
            .iter()
            .all(|e| e.event_type != "scanner_error")
    );
    assert_eq!(scans[0].action_findings.len(), 1);
    let context = scans[0].action_findings[0].context();
    assert!(
        context
            .iter()
            .any(|c| c.redacted_text().contains("requested file"))
    );
    assert!(
        context
            .iter()
            .all(|c| !c.redacted_text().contains("another session"))
    );
}
