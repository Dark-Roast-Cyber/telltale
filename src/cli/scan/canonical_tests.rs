use super::*;

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
        false,
        false,
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
        false,
        false,
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
fn all_eight_native_contributions_match_legacy_semantic_counts() {
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
        let legacy = telltale_sources::parser::parse_source_records(&source).unwrap();
        let summaries = telltale_detect::baseline::build_baseline_summaries(&legacy);
        assert_eq!(summaries.len(), 1);
        let expected = &summaries[0];
        let actual = &batch.accounting.sessions[0].counts.contributions;
        assert_eq!(actual.tool_calls, expected.tool_call_counts, "{source_id}");
        assert_eq!(
            actual.path_classes, expected.path_class_counts,
            "{source_id}"
        );
        assert_eq!(
            actual.network_hosts, expected.network_host_counts,
            "{source_id}"
        );
        assert_eq!(
            batch.accounting.unscoped.contributions,
            ActivityContributions::default()
        );
        assert!(!actual.tool_calls.is_empty(), "{source_id}");
    }
}
use telltale_detect::v2::compile_rule_v1;
use telltale_rules::load_default_rule_set;
use telltale_schema::clients::{ClientId, SourceKind};
use tempfile::tempdir;

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
    let failed = process_canonical_source(&source, &state, false, false, clock(), &plan, None);
    assert_eq!(failed.status, SourceProcessingStatus::Failed);
    assert_eq!(failed.sqlite_progress_candidate(false, false), None);
    assert!(
        !serde_json::to_string(&failed.events)
            .unwrap()
            .contains("PRIVATE")
    );
    std::fs::write(&source.path, "{\"type\":\"user\",\"sessionId\":\"synthetic\",\"message\":{\"role\":\"user\",\"content\":\"hello\"}}\n").unwrap();
    let result = process_canonical_source(&source, &state, false, false, clock(), &plan, None);
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert!(result.events.is_empty());
    assert!(result.completion.is_some());
    assert_eq!(result.progress, AcquisitionProgress::None);
    assert_eq!(result.sqlite_progress_candidate(false, false), None);
    let accounting = result.accounting.as_ref().unwrap();
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
        false,
        false,
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(result.completion, Some(EvaluationCompletion::Complete));
    assert_eq!(result.events.len(), 1);
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
        false,
        false,
        clock(),
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert!(result.events.is_empty());
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
    let result =
        process_canonical_source(&source, &state, false, false, clock(), &plan("url"), None);
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

#[test]
fn instance_scope_is_file_bound_not_content_or_session_bound() {
    let dir = tempdir().unwrap();
    let a = source(dir.path().join("a"));
    let b = source(dir.path().join("b"));
    std::fs::write(&a.path, "same").unwrap();
    std::fs::write(&b.path, "same").unwrap();
    let (_, first) = verified_source(&a).unwrap();
    assert_ne!(first, verified_source(&b).unwrap().1);
    std::fs::write(&a.path, "changed").unwrap();
    assert_eq!(first, verified_source(&a).unwrap().1);
    let alias = source(dir.path().join(".").join("a"));
    assert_eq!(first, verified_source(&alias).unwrap().1);
    let mut other_identity = a.clone();
    other_identity.client = ClientId::Qwen;
    other_identity.source_id = "qwen.projects".into();
    assert_ne!(first, verified_source(&other_identity).unwrap().1);
    assert!(verified_source(&source(dir.path().to_owned())).is_err());
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

fn message(
    id: &str,
    session: Option<&str>,
) -> telltale_schema::observation::CanonicalObservationV2 {
    use telltale_schema::observation::*;
    let provenance = SourceProvenance::new(
        IngestionMode::SessionStore,
        "claude_code",
        "claude.projects",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id(id)
    .unwrap();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string("needle")),
        ),
        ObservationStage::MessageObserved,
        clock(),
        provenance,
    )
    .fact_metadata("message.role", FactMetadata::reported().unwrap())
    .fact_metadata("message.content", FactMetadata::reported().unwrap())
    .capability_context(
        CapabilityContext::new()
            .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported),
    );
    if let Some(session) = session {
        builder = builder.session_id(CorrelationId::source_reported(session).unwrap());
    }
    builder.build().unwrap()
}

#[test]
fn evaluation_and_projection_failures_discard_all_findings_but_retain_ineligible_candidate() {
    let source = source("PRIVATE-path".into());
    let instance = CorrelationId::source_reported("test-instance").unwrap();
    let progress = AcquisitionProgress::OpenCodeSqlite {
        part_max_time_updated: Some(42),
    };
    let plan = plan("user_context");
    for (observations, expected) in [
        (
            vec![
                message("duplicate", Some("s")),
                message("duplicate", Some("s")),
            ],
            "canonical_evaluation_failed",
        ),
        (
            vec![message("scoped", Some("s")), message("unscoped", None)],
            "canonical_projection_failed",
        ),
    ] {
        let result = finish_batch(
            &source,
            &instance,
            AcquisitionBatch {
                accounting: SourceAccounting::default(),
                observations,
                progress,
            },
            &plan,
            None,
        );
        assert_eq!(result.status, SourceProcessingStatus::Failed);
        assert_eq!(result.progress, progress);
        assert_eq!(result.sqlite_progress_candidate(false, false), None);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].event_type, "scanner_error");
        let serialized = serde_json::to_string(&result.events).unwrap();
        assert!(serialized.contains(expected));
        assert!(!serialized.contains("PRIVATE"));
        assert!(!serialized.contains("needle"));
    }
    let mut wrong_source = source;
    wrong_source.source_id = "codex.sessions".into();
    let result = finish_batch(
        &wrong_source,
        &instance,
        AcquisitionBatch {
            accounting: SourceAccounting::default(),
            observations: vec![message("one", Some("same-session"))],
            progress,
        },
        &plan,
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Failed);
}

#[test]
fn complete_projection_precedes_one_existing_allowlist_application() {
    use crate::allowlist::{Allowlist, suppress_detection};
    let source = source("synthetic".into());
    let instance = CorrelationId::source_reported("test-instance").unwrap();
    let mut result = finish_batch(
        &source,
        &instance,
        AcquisitionBatch {
            accounting: SourceAccounting::default(),
            observations: vec![message("one", Some("s"))],
            progress: AcquisitionProgress::None,
        },
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(result.completion, Some(EvaluationCompletion::Complete));
    assert_eq!(result.events.len(), 1);
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

#[test]
fn metadata_origin_must_match_not_just_visible_session_id() {
    use telltale_sources::acquisition::{AttestedValue, SessionAccounting, SessionMetadata};
    let source = source("synthetic".into());
    let instance = CorrelationId::source_reported("test-instance").unwrap();
    let result = finish_batch(
        &source,
        &instance,
        AcquisitionBatch {
            observations: vec![message("one", Some("s"))],
            progress: AcquisitionProgress::None,
            accounting: SourceAccounting {
                sessions: vec![SessionAccounting {
                    session_id: CorrelationId::new("s", CorrelationOrigin::TelltaleOriginated)
                        .unwrap(),
                    metadata: SessionMetadata {
                        agent: AttestedValue::Known("wrong-origin-agent".into()),
                        ..Default::default()
                    },
                    counts: Default::default(),
                }],
                unscoped: Default::default(),
            },
        },
        &plan("user_context"),
        None,
    );
    assert_eq!(result.status, SourceProcessingStatus::Succeeded);
    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].agent, None);
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
fn sqlite_limited_success_retains_progress_without_installing_and_reuses_read_policy() {
    let dir = tempdir().unwrap();
    let source = database(&dir.path().join("synthetic.db"));
    let mut state = ScanState::default();
    let plan = plan("url"); // URL visibility is explicitly unavailable.
    let result = process_canonical_source(&source, &state, false, false, clock(), &plan, None);
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
    let live = process_canonical_source(&source, &state, false, false, clock(), &plan, None);
    assert_eq!(
        live.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: None
        }
    );
    for (dry_run, backfill) in [(true, false), (false, true)] {
        let full =
            process_canonical_source(&source, &state, backfill, dry_run, clock(), &plan, None);
        assert_eq!(full.progress, result.progress);
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
            false,
            false,
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
        let result = process_canonical_source(&invalid, &state, false, false, clock(), &plan, None);
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
        false,
        false,
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
