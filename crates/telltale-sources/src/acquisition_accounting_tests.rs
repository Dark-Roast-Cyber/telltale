use super::*;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;
use tempfile::tempdir;

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new("2026-09-18T12:00:00Z").unwrap())
}

#[test]
fn jsonl_attestation_is_native_bounded_and_order_independent() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic.jsonl");
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
    ] {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind,
            path: path.clone(),
        };
        let first = r#"{"type":"user","session_id":"session-a","agent":"native-agent","model":"model-a","provider":"native-provider","content":"synthetic"}"#;
        let second =
            r#"{"type":"user","session_id":"session-a","model":"model-b","content":"synthetic"}"#;
        std::fs::write(&path, first).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert_eq!(
            batch.accounting.coverage,
            AccountingCoverage::CompleteSource
        );
        let session = &batch.accounting.sessions[0];
        assert_eq!(session.metadata.agent.known(), Some("native-agent"));
        assert_eq!(session.metadata.model.known(), Some("model-a"));
        assert_eq!(session.metadata.provider.known(), Some("native-provider"));
        assert_eq!(session.counts.native_units, 1);
        assert_eq!(session.counts.record_counts.user_message, 1);
        std::fs::write(&path, format!("{first}\n{second}\n")).unwrap();
        let forward = acquire_source(&source, options()).unwrap().accounting;
        std::fs::write(&path, format!("{second}\n{first}\n")).unwrap();
        let reverse = acquire_source(&source, options()).unwrap().accounting;
        assert_eq!(forward, reverse, "{source_id}");
        assert_eq!(forward.sessions[0].metadata.model, AttestedValue::Ambiguous);
        assert_eq!(
            forward.sessions[0].metadata.agent.known(),
            Some("native-agent")
        );
        std::fs::write(
            &path,
            r#"{"type":"user","session_id":"session-missing","content":"synthetic"}"#,
        )
        .unwrap();
        let missing = acquire_source(&source, options()).unwrap();
        assert_eq!(
            missing.accounting.sessions[0].metadata,
            SessionMetadata::default()
        );
        assert_eq!(missing.accounting.unscoped.native_units, 0);
    }
}

#[test]
fn native_count_is_not_observation_count() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic.jsonl");
    std::fs::write(&path, r#"{"type":"assistant","session_id":"session-a","content":[{"type":"text","text":"synthetic"},{"type":"tool_use","id":"call-a","name":"shell","input":{"command":"printf synthetic"}}]}"#).unwrap();
    let batch = acquire_source(
        &Source {
            client: ClientId::Claude,
            source_id: "claude.projects".into(),
            kind: SourceKind::Jsonl,
            path,
        },
        options(),
    )
    .unwrap();
    assert_eq!(batch.observations.len(), 2);
    assert_eq!(batch.accounting.sessions[0].counts.native_units, 1);
    assert_eq!(
        batch.accounting.sessions[0].counts.record_counts.tool_call,
        1
    );
    assert_eq!(
        batch.accounting.sessions[0].metadata,
        SessionMetadata::default()
    );
}

#[test]
fn sqlite_accounts_suppressed_parents_selected_parts_and_unscoped_rows() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(r#"
        CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('m','s','{"role":"assistant","agent":"native-agent","modelID":"model-a","providerID":"provider-a"}');
        INSERT INTO message VALUES ('unscoped',NULL,'{"role":"user","content":"synthetic"}');
        INSERT INTO part VALUES ('p','m','s',10,'{"type":"tool","tool":"shell","callID":"call-a","model":"model-b","state":{"status":"completed","input":{"command":"printf synthetic"},"output":"synthetic"}}');
        INSERT INTO part VALUES ('ignored','m','s',99,'{"type":"reasoning","model":"not-attested"}');
    "#).unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path,
    };
    let batch = acquire_source(&source, options()).unwrap();
    let session = &batch.accounting.sessions[0];
    assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
    assert_eq!(session.session_id.value(), "s");
    assert_eq!(
        session.session_id.origin(),
        telltale_schema::observation::CorrelationOrigin::SourceReported
    );
    assert_eq!(session.metadata.agent.known(), Some("native-agent"));
    assert_eq!(session.metadata.model, AttestedValue::Ambiguous);
    assert_eq!(session.metadata.provider.known(), Some("provider-a"));
    assert_eq!(session.counts.native_units, 2); // suppressed message + selected part
    assert_eq!(session.counts.record_counts.assistant_message, 1);
    assert_eq!(session.counts.record_counts.tool_result, 1);
    assert_eq!(batch.accounting.unscoped.native_units, 1);
    assert_eq!(batch.accounting.unscoped.record_counts.user_message, 1);
    assert_eq!(batch.observations.len(), 3); // unscoped message + completed + result
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: Some(10)
        }
    );
    let bounded = acquire_opencode_sqlite(
        &source,
        options(),
        OpenCodeSqliteReadOptions {
            part_min_time_updated: Some(11),
            part_limit: 1,
        },
    )
    .unwrap();
    assert_eq!(bounded.accounting.sessions[0].counts.native_units, 1);
    assert_eq!(
        bounded.accounting.sessions[0].metadata.model.known(),
        Some("model-a")
    );
    assert_eq!(
        bounded.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: None
        }
    );
}

#[test]
fn copilot_counts_items_not_lines_or_observations_and_never_defaults_metadata() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic.log");
    let source = Source {
        client: ClientId::Copilot,
        source_id: "copilot.process_log".into(),
        kind: SourceKind::CopilotProcessLog,
        path,
    };
    std::fs::write(&source.path, concat!(
        "2026-04-27T16:16:57.841Z [INFO] Workspace initialized: synthetic-session (checkpoints: 0)\n",
        "2026-04-27T16:17:17.990Z [INFO] Accumulated output items (3): ",
        r#"[{"type":"reasoning"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"synthetic"}]},{"type":"function_call","name":"view","call_id":"call-a","arguments":"{}","message":"","agent":"native-agent","model":"native-model","provider":"native-provider"}]"#,
        "\n2026-04-27T16:17:45.200Z [INFO] Session completed.\n"
    )).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    let session = &batch.accounting.sessions[0];
    assert_eq!(
        batch.accounting.coverage,
        AccountingCoverage::CompleteSource
    );
    assert_eq!(session.counts.native_units, 4); // workspace + three items, not completion control
    assert_eq!(
        session.counts.record_counts,
        RecordCounts {
            session_meta: 1,
            tool_call: 1,
            tool_result: 1,
            ..Default::default()
        }
    );
    assert_eq!(session.metadata.agent.known(), Some("native-agent"));
    assert_eq!(session.metadata.model.known(), Some("native-model"));
    assert_eq!(session.metadata.provider.known(), Some("native-provider"));
    std::fs::write(&source.path, "2026-04-27T16:16:57.841Z [INFO] Workspace initialized: synthetic-session (checkpoints: 0)\n").unwrap();
    let missing = acquire_source(&source, options()).unwrap();
    assert!(missing.observations.is_empty());
    assert_eq!(
        missing.accounting.coverage,
        AccountingCoverage::CompleteSource
    );
    assert_eq!(missing.accounting.sessions[0].counts.native_units, 1);
    assert_eq!(
        missing.accounting.sessions[0].metadata,
        SessionMetadata::default()
    );
}

#[test]
fn exhaustive_file_coverage_is_not_returned_after_a_malformed_tail() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    let valid = r#"{"type":"user","session_id":"s","content":"synthetic"}"#;
    std::fs::write(&source.path, format!("{valid}\n\n{valid}\n")).unwrap();
    let complete = acquire_source(&source, options()).unwrap();
    assert_eq!(
        complete.accounting.coverage,
        AccountingCoverage::CompleteSource
    );
    assert_eq!(complete.accounting.sessions[0].counts.native_units, 2);
    std::fs::write(&source.path, format!("{valid}\n{{malformed-tail")).unwrap();
    assert!(matches!(
        acquire_source(&source, options()),
        Err(AcquisitionError::SourceRead)
    ));
}

#[test]
fn sqlite_overlap_and_mutable_rereads_never_attest_source_replacement() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: directory.path().join("synthetic.db"),
    };
    let conn = rusqlite::Connection::open(&source.path).unwrap();
    conn.execute_batch(r#"
        CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('m','s','{"role":"assistant"}');
        INSERT INTO part VALUES ('a','m','s',100,'{"type":"text","text":"synthetic A"}');
        INSERT INTO part VALUES ('b','m','s',200,'{"type":"text","text":"synthetic B"}');
    "#).unwrap();
    let read = |min, limit| {
        acquire_opencode_sqlite(
            &source,
            options(),
            OpenCodeSqliteReadOptions {
                part_min_time_updated: min,
                part_limit: limit,
            },
        )
        .unwrap()
    };
    let ab = read(Some(0), 2);
    conn.execute(
        "INSERT INTO part VALUES ('c','m','s',300,'{\"type\":\"text\",\"text\":\"synthetic C\"}')",
        [],
    )
    .unwrap();
    let bc = read(Some(200), 2);
    for (batch, ids, high_water) in [(&ab, ["a", "b"], 200), (&bc, ["b", "c"], 300)] {
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 3); // parent + two parts
        assert_eq!(
            batch
                .observations
                .iter()
                .map(|o| o.source().native_id().unwrap())
                .collect::<Vec<_>>(),
            ids
        );
        assert_eq!(
            batch.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: Some(high_water)
            }
        );
    }
    assert_eq!(
        ab.observations[1].observation_id(),
        bc.observations[0].observation_id()
    );
    // Uncursored reads select the latest limit, not the complete source.
    let latest = read(None, 2);
    assert_eq!(latest.accounting, bc.accounting);
    assert_eq!(read(Some(200), 2).accounting, bc.accounting);
    conn.execute("UPDATE part SET data = '{\"type\":\"text\",\"text\":\"synthetic revised B\"}', time_updated = 400 WHERE id = 'b'", []).unwrap();
    let revised = read(Some(200), 2);
    assert_eq!(
        revised.accounting.coverage,
        AccountingCoverage::PartialSource
    );
    assert_eq!(
        bc.observations[0].observation_id(),
        revised.observations[1].observation_id()
    );
    assert_ne!(bc.observations[0].body(), revised.observations[1].body());
    // No lower bound, oversized limits, default reads, and absent high-water
    // do not establish a shared snapshot or a complete-replacement contract.
    for batch in [
        read(None, i64::MAX),
        read(Some(500), 2),
        acquire_source(&source, options()).unwrap(),
    ] {
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
    }
    conn.execute_batch("DELETE FROM part; DELETE FROM message;")
        .unwrap();
    let empty = read(None, 2);
    assert_eq!(empty.accounting.coverage, AccountingCoverage::PartialSource);
    assert_eq!(
        empty.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: None
        }
    );
}

#[test]
fn coverage_defaults_fail_closed_and_has_no_source_controlled_metadata() {
    assert_eq!(
        SourceAccounting::default().coverage,
        AccountingCoverage::PartialSource
    );
    assert_eq!(
        format!("{:?}", AccountingCoverage::CompleteSource),
        "CompleteSource"
    );
    assert_eq!(
        format!("{:?}", AccountingCoverage::PartialSource),
        "PartialSource"
    );
}

#[test]
fn rejected_metadata_is_private_and_conflicts_do_not_retain_candidates() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("PRIVATE-PATH"),
    };
    for invalid in [
        serde_json::json!("PRIVATE-MARKER".repeat(400)),
        serde_json::json!(" ".repeat(telltale_schema::observation::LOCAL_MAX_STRING_BYTES + 1)),
        serde_json::json!("PRIVATE-MARKER\nsecond-line"),
        serde_json::json!({"PRIVATE-MARKER": true}),
    ] {
        let value = serde_json::json!({"type":"user","session_id":"s","content":"synthetic","model":invalid});
        std::fs::write(&source.path, value.to_string()).unwrap();
        let error = acquire_source(&source, options()).err().unwrap();
        assert_eq!(error, AcquisitionError::InvalidAttestation);
        assert!(!format!("{error} {error:?}").contains("PRIVATE"));
    }
    std::fs::write(&source.path, r#"{"type":"user","session_id":"s","content":"synthetic","model":"PRIVATE-A","message":{"model":"PRIVATE-B"},"agent":"native-agent","input":{"provider":"not-source-metadata"}}"#).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch.accounting.sessions[0].metadata.model,
        AttestedValue::Ambiguous
    );
    assert_eq!(
        batch.accounting.sessions[0].metadata.provider,
        AttestedValue::Missing
    );
    assert!(!format!("{:?}", batch.accounting).contains("PRIVATE"));
}

#[test]
fn codex_metadata_only_sessions_and_inheritance_are_not_file_wide() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    std::fs::write(&source.path, concat!(
        "{\"type\":\"session_meta\",\"agent\":\"unscoped-agent\"}\n",
        "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"a\",\"model\":\"model-a\"}}\n",
        "{\"type\":\"user\",\"content\":\"synthetic\"}\n",
        "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"b\"}}\n"
    )).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(batch.accounting.sessions.len(), 2);
    assert_eq!(batch.accounting.unscoped.native_units, 1);
    assert_eq!(batch.accounting.unscoped.record_counts.session_meta, 1);
    assert_eq!(
        batch.accounting.sessions[0].metadata.agent,
        AttestedValue::Missing
    );
    assert_eq!(batch.accounting.sessions[0].counts.native_units, 2);
    assert_eq!(
        batch.accounting.sessions[0].metadata.model.known(),
        Some("model-a")
    );
    assert_eq!(
        batch.accounting.sessions[1]
            .counts
            .record_counts
            .session_meta,
        1
    );
    assert_eq!(
        batch.accounting.sessions[1].metadata.model,
        AttestedValue::Missing
    );
}

#[test]
fn codex_generic_tool_accounting_distinguishes_requests_from_results() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    for (label, value, expected, tool_name, request_host) in [
        (
            "arguments only",
            serde_json::json!({"type":"tool","session_id":"s","arguments":{"url":"https://request.example.test/"}}),
            RecordCounts {
                tool_call: 1,
                ..Default::default()
            },
            "unknown",
            true,
        ),
        (
            "named request",
            serde_json::json!({"type":"tool","session_id":"s","name":"shell","arguments":{"command":"true"}}),
            RecordCounts {
                tool_call: 1,
                ..Default::default()
            },
            "shell",
            false,
        ),
        (
            "reported error",
            serde_json::json!({"type":"tool","session_id":"s","name":"shell","state":{"status":"error","error":"https://error.example.test/"}}),
            RecordCounts {
                tool_result: 1,
                ..Default::default()
            },
            "shell",
            false,
        ),
        (
            "completed output",
            serde_json::json!({"type":"tool","session_id":"s","name":"shell","state":{"status":"completed","output":"https://output.example.test/"}}),
            RecordCounts {
                tool_result: 1,
                ..Default::default()
            },
            "shell",
            false,
        ),
    ] {
        std::fs::write(&source.path, value.to_string()).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        let counts = &batch.accounting.sessions[0].counts;
        assert_eq!(counts.record_counts, expected, "{label}");
        assert_eq!(counts.native_units, 1, "{label}");
        let is_call = expected.tool_call == 1;
        assert_eq!(
            counts.contributions.tool_calls.get(tool_name),
            is_call.then_some(&1),
            "{label}"
        );
        assert_eq!(
            counts.tool_usage.get("shell").map(|usage| usage.count),
            (is_call && tool_name == "shell").then_some(1),
            "{label}"
        );
        assert_eq!(
            counts
                .contributions
                .network_hosts
                .get("request.example.test"),
            request_host.then_some(&1),
            "{label}"
        );
        if !is_call {
            assert!(counts.contributions.network_hosts.is_empty(), "{label}");
            assert!(counts.contributions.tool_calls.is_empty(), "{label}");
            assert!(counts.tool_usage.is_empty(), "{label}");
        }
    }
}

#[test]
fn gemini_native_units_count_as_assistant_messages() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic.jsonl");
    for (client, source_id) in [
        (ClientId::Codex, "codex.sessions"),
        (ClientId::OpenClaw, "openclaw.agents"),
        (ClientId::Qwen, "qwen.projects"),
    ] {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind: SourceKind::Jsonl,
            path: path.clone(),
        };
        std::fs::write(
            &path,
            r#"{"type":"gemini","session_id":"s","content":"synthetic assistant message"}"#,
        )
        .unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert_eq!(
            batch.accounting.sessions[0].counts.record_counts,
            RecordCounts {
                assistant_message: 1,
                ..Default::default()
            },
            "{source_id}"
        );
    }
}

#[test]
fn selected_message_metadata_is_not_lost_or_resolved_by_precedence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic.jsonl");
    for (client, source_id) in [
        (ClientId::OpenClaw, "openclaw.agents"),
        (ClientId::Qwen, "qwen.projects"),
    ] {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind: SourceKind::Jsonl,
            path: path.clone(),
        };
        std::fs::write(&path, r#"{"payload":{"type":"user","session_id":"s","message":{"content":"synthetic","agent":"native-agent","model":"model-a","provider":"native-provider"}}}"#).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        let metadata = &batch.accounting.sessions[0].metadata;
        assert_eq!(metadata.agent.known(), Some("native-agent"));
        assert_eq!(metadata.model.known(), Some("model-a"));
        assert_eq!(metadata.provider.known(), Some("native-provider"));
        std::fs::write(&path, r#"{"model":"outside-selected-envelope","payload":{"type":"user","session_id":"s","model":"model-b","message":{"content":"synthetic","agent":"native-agent","model":"model-a"}}}"#).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert_eq!(
            batch.accounting.sessions[0].metadata.model,
            AttestedValue::Ambiguous
        );
        assert_eq!(
            batch.accounting.sessions[0].metadata.agent.known(),
            Some("native-agent")
        );
    }
}

#[test]
fn sqlite_row_and_data_metadata_conflict_is_not_selected_by_precedence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, model TEXT, data TEXT);
        INSERT INTO message VALUES ('m','s','model-a','{"role":"user","content":"synthetic","model":"model-b"}');"#).unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path,
    };
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch.accounting.sessions[0].metadata.model,
        AttestedValue::Ambiguous
    );
}

#[test]
fn recognized_message_labels_are_not_lost() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic.jsonl");
    for (client, source_id) in [
        (ClientId::Claude, "claude.projects"),
        (ClientId::Codex, "codex.sessions"),
    ] {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind: SourceKind::Jsonl,
            path: path.clone(),
        };
        std::fs::write(&path, r#"{"type":"user","content":"synthetic","session_id":"s","model":"model-a","message":{"agent":"native-agent","model":"model-b","provider":"native-provider"}}"#).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        let metadata = &batch.accounting.sessions[0].metadata;
        assert_eq!(metadata.agent.known(), Some("native-agent"));
        assert_eq!(metadata.model, AttestedValue::Ambiguous);
        assert_eq!(metadata.provider.known(), Some("native-provider"));
    }
}

#[test]
fn conflicting_jsonl_ownership_is_atomic_and_private() {
    let directory = tempdir().unwrap();
    for (client, source_id) in [
        (ClientId::Claude, "claude.projects"),
        (ClientId::Codex, "codex.sessions"),
        (ClientId::OpenClaw, "openclaw.agents"),
        (ClientId::Qwen, "qwen.projects"),
    ] {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind: SourceKind::Jsonl,
            path: directory.path().join("synthetic.jsonl"),
        };
        for conflict in [
            r#"{"type":"user","session_id":"PRIVATE-A","sessionID":"PRIVATE-B","content":"synthetic"}"#,
            r#"{"type":"user","session_id":"PRIVATE-A","message":{"sessionId":"PRIVATE-B","content":"synthetic"}}"#,
        ] {
            std::fs::write(&source.path, format!("{{\"type\":\"user\",\"session_id\":\"valid\",\"content\":\"synthetic\"}}\n{conflict}\n")).unwrap();
            let error = acquire_source(&source, options()).err().expect(source_id);
            assert_eq!(error.code(), "conflicting_session_ownership");
            assert!(!format!("{error} {error:?}").contains("PRIVATE"));
        }
        std::fs::write(&source.path, r#"{"type":"user","session_id":"same","sessionID":"same","message":{"sessionId":"same","content":"synthetic"}}"#).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert_eq!(batch.accounting.sessions[0].session_id.value(), "same");
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 1);
    }
}

#[test]
fn sqlite_ownership_checks_row_data_and_join_without_changing_legacy() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: directory.path().join("synthetic.db"),
    };
    let conn = rusqlite::Connection::open(&source.path).unwrap();
    conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('m','same','{"role":"user","modelID":"native-model"}');
        INSERT INTO part VALUES ('p','m','same',10,'{"type":"text","sessionID":"same","text":"synthetic"}');"#).unwrap();
    assert_eq!(
        acquire_source(&source, options())
            .unwrap()
            .accounting
            .sessions[0]
            .counts
            .native_units,
        2
    );
    for statement in [
        "UPDATE part SET session_id = 'PRIVATE-other'",
        "UPDATE part SET session_id = 'same', data = '{\"type\":\"text\",\"session_id\":\"PRIVATE-other\",\"text\":\"synthetic\"}'",
        "UPDATE part SET data = '{\"type\":\"text\",\"text\":\"synthetic\"}'; UPDATE message SET data = '{\"role\":\"user\",\"session_id\":\"PRIVATE-other\"}'",
    ] {
        conn.execute_batch(statement).unwrap();
        let error = acquire_source(&source, options())
            .err()
            .expect("conflict must reject whole batch");
        assert_eq!(error.code(), "conflicting_session_ownership");
        assert!(!format!("{error} {error:?}").contains("PRIVATE"));
    }
}

#[test]
fn unrelated_payload_labels_are_not_metadata() {
    let directory = tempdir().unwrap();
    for (client, source_id) in [
        (ClientId::Claude, "claude.projects"),
        (ClientId::Codex, "codex.sessions"),
    ] {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind: SourceKind::Jsonl,
            path: directory.path().join("synthetic.jsonl"),
        };
        std::fs::write(&source.path, r#"{"type":"user","session_id":"s","content":"synthetic","payload":{"agent":"unrelated","model":"unrelated","provider":"unrelated","payload":{"model":"unrelated"}},"session_meta":{"payload":{"model":"unrelated"}},"unrelated":{"agent":"unrelated","model":"unrelated","provider":"unrelated"}}"#).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert_eq!(
            batch.accounting.sessions[0].metadata,
            SessionMetadata::default(),
            "{source_id}"
        );
    }
}

#[test]
fn discarded_native_sibling_retains_semantic_contributions() {
    use telltale_schema::activity_facts::PathClass;
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    let mut value = serde_json::json!({"type":"assistant","session_id":"s","content":[{"type":"tool_use","id":"call-a","name":"shell","input":{"command":"true"}}]});
    std::fs::write(&source.path, value.to_string()).unwrap();
    let before = acquire_source(&source, options()).unwrap();
    value["sibling_context"] = serde_json::json!("https://internal.example.test/x /home/u/.env");
    std::fs::write(&source.path, value.to_string()).unwrap();
    let after = acquire_source(&source, options()).unwrap();
    assert_eq!(before.observations.len(), after.observations.len());
    for (left, right) in before.observations.iter().zip(&after.observations) {
        assert_eq!(left.body(), right.body());
        assert_eq!(left.facets(), right.facets());
        assert_eq!(left.fact_metadata(), right.fact_metadata());
        assert_eq!(left.stage(), right.stage());
        assert_eq!(left.session_id(), right.session_id());
    }
    let before = &before.accounting.sessions[0];
    let after = &after.accounting.sessions[0];
    assert_eq!(before.metadata, after.metadata);
    assert_eq!(before.counts.native_units, after.counts.native_units);
    assert_eq!(before.counts.record_counts, after.counts.record_counts);
    assert_eq!(after.counts.contributions.tool_calls.get("shell"), Some(&1));
    assert_eq!(
        after
            .counts
            .contributions
            .path_classes
            .get(&PathClass::SecretStore),
        Some(&1)
    );
    assert_eq!(
        after
            .counts
            .contributions
            .network_hosts
            .get("internal.example.test"),
        Some(&1)
    );
    assert_ne!(before.counts.contributions, after.counts.contributions);
    assert!(!format!("{:?}", after.counts.contributions).contains("internal.example"));
}

#[test]
fn unscoped_native_contributions_and_private_failures() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: directory.path().join("synthetic.db"),
    };
    let conn = rusqlite::Connection::open(&source.path).unwrap();
    conn.execute_batch(r#"CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO part VALUES ('p',NULL,NULL,10,'{"type":"tool","tool":"shell","callID":"call-a","state":{"status":"running","input":{"command":"https://unscoped.example.test/"}}}');"#).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert!(batch.accounting.sessions.is_empty());
    assert_eq!(
        batch
            .accounting
            .unscoped
            .contributions
            .tool_calls
            .get("shell"),
        Some(&1)
    );
    assert!(
        batch
            .accounting
            .unscoped
            .contributions
            .network_hosts
            .contains_key("unscoped.example.test")
    );

    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("PRIVATE-path"),
    };
    let text = format!("https://PRIVATE{}", "x".repeat(4096));
    let value = serde_json::json!({"type":"assistant","session_id":"s","content":[{"type":"tool_use","id":"call-a","name":"shell","input":{}}],"sibling_context":text});
    std::fs::write(&source.path, value.to_string()).unwrap();
    let error = acquire_source(&source, options())
        .err()
        .expect("oversized discarded contribution must fail");
    assert_eq!(error, AcquisitionError::InvalidContribution);
    assert!(!format!("{error} {error:?}").contains("PRIVATE"));
}

#[test]
fn codex_recognized_metadata_payloads_and_ignored_siblings() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    std::fs::write(&source.path, concat!(
        "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"s\",\"agent_nickname\":\"native-agent\",\"model\":\"a\",\"model_provider\":\"native-provider\"}}\n",
        "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"model\":\"b\",\"content\":[{\"type\":\"output_text\",\"text\":\"synthetic\"}]}}\n"
    )).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    let session = &batch.accounting.sessions[0];
    assert_eq!(session.metadata.agent.known(), Some("native-agent"));
    assert_eq!(session.metadata.provider.known(), Some("native-provider"));
    assert_eq!(session.metadata.model, AttestedValue::Ambiguous);
    assert_eq!(session.counts.native_units, 2);
}

#[test]
fn claude_explicit_metadata_record_payload_is_recognized() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    std::fs::write(&source.path, r#"{"type":"session_meta","role":"user","payload":{"session_id":"s","agent_nickname":"native-agent","model":"native-model","model_provider":"native-provider"}}"#).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    let session = &batch.accounting.sessions[0];
    assert_eq!(session.metadata.agent.known(), Some("native-agent"));
    assert_eq!(session.metadata.model.known(), Some("native-model"));
    assert_eq!(session.metadata.provider.known(), Some("native-provider"));
}

#[test]
fn multi_record_contribution_budget_is_acquisition_wide() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    let unit = |session: &str, start: usize, end: usize| {
        let hosts = (start..end)
            .map(|i| format!("https://synthetic-{i}.example/x"))
            .collect::<Vec<_>>()
            .join(" ");
        serde_json::json!({"type":"assistant","session_id":session,
            "content":[{"type":"tool_use","id":"call-a","name":"shell","input":{}}],
            "sibling_context":hosts})
        .to_string()
    };
    // Two tool keys plus 4,092 host keys across two sessions. Repeated facts
    // increment counts without reserving more keys.
    let first = unit("a", 0, 2046);
    let second = unit("b", 2046, 4092);
    let below = format!("{first}\n{second}\n{first}\n");
    std::fs::write(&source.path, &below).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(batch.accounting.sessions.len(), 2);
    assert_eq!(
        batch.accounting.sessions[0].counts.contributions.tool_calls["shell"],
        2
    );
    assert_eq!(
        batch.accounting.sessions[0]
            .counts
            .contributions
            .network_hosts["synthetic-0.example"],
        2
    );
    assert_eq!(
        batch.accounting.sessions[1]
            .counts
            .contributions
            .network_hosts
            .len(),
        2046
    );

    // Every individual unit is below the bound; only the shared budget fails.
    let over = format!("{below}{}\n", unit("c", 4092, 4095));
    std::fs::write(&source.path, &over).unwrap();
    assert_eq!(
        acquire_source(&source, options()).err().unwrap(),
        AcquisitionError::ContributionCapacity
    );
}

#[test]
fn sqlite_private_transport_alias_is_not_json_ownership() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: directory.path().join("synthetic.db"),
    };
    let conn = rusqlite::Connection::open(&source.path).unwrap();
    conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('m','same','{"role":"assistant","__telltale_message_session_id":"attacker-value"}');
        INSERT INTO part VALUES ('p','m','same',10,'{"type":"tool","tool":"shell","callID":"call-a","state":{"status":"running","input":{}},"__telltale_message_session_id":"attacker-value"}');"#).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(batch.accounting.sessions.len(), 1);
    assert_eq!(batch.accounting.sessions[0].session_id.value(), "same");
    conn.execute_batch("UPDATE part SET session_id = NULL; UPDATE message SET session_id = NULL;")
        .unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert!(batch.accounting.sessions.is_empty());
    assert_eq!(batch.accounting.unscoped.native_units, 2);
    assert!(batch.observations.iter().all(|o| o.session_id().is_none()));
    conn.execute_batch("UPDATE part SET session_id = 'a'; UPDATE message SET session_id = 'b';")
        .unwrap();
    assert_eq!(
        acquire_source(&source, options()).err().unwrap(),
        AcquisitionError::ConflictingSessionOwnership
    );

    conn.execute_batch(
        r#"UPDATE message SET session_id = 'transport.example', data = '{"role":"assistant"}';
        UPDATE part SET session_id = NULL, data = '{"type":"tool","tool":"shell","callID":"call-a","state":{"status":"running","input":{}}}';"#,
    )
    .unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch.accounting.sessions[0].session_id.value(),
        "transport.example"
    );
    assert!(
        batch.accounting.sessions[0]
            .counts
            .contributions
            .network_hosts
            .is_empty()
    );
    assert!(
        batch.accounting.sessions[0]
            .counts
            .contributions
            .path_classes
            .is_empty()
    );
}

#[test]
fn copilot_ignored_items_cannot_attest_or_conflict_with_recognized_metadata() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Copilot,
        source_id: "copilot.process_log".into(),
        kind: SourceKind::CopilotProcessLog,
        path: directory.path().join("synthetic.log"),
    };
    for ignored_type in [Some("reasoning"), Some("future-item"), None] {
        for recognized in [
            serde_json::json!({"type":"function_call","name":"view","call_id":"a","arguments":"{}"}),
            serde_json::json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"synthetic"}]}),
        ] {
            let mut ignored =
                serde_json::json!({"agent":"ignored","model":"ignored","provider":"ignored"});
            if let Some(kind) = ignored_type {
                ignored["type"] = kind.into();
            }
            for labeled in [false, true] {
                let mut recognized = recognized.clone();
                if labeled {
                    for key in ["agent", "model", "provider"] {
                        recognized[key] = "native".into();
                    }
                }
                let items = serde_json::json!([ignored, recognized]);
                std::fs::write(&source.path, format!("Workspace initialized: s (checkpoints: 0)\nAccumulated output items (2): {items}\n")).unwrap();
                let native =
                    crate::sources::copilot::native::extract_copilot_native_events(&source)
                        .unwrap();
                let items = native.iter().filter_map(|event| match event {
                    crate::sources::copilot::native::CopilotNativeEvent::AccumulatedOutputItem { item, .. } => Some(item),
                    _ => None,
                }).collect::<Vec<_>>();
                assert_eq!(
                    items[0].attestation.as_ref().unwrap(),
                    &SessionMetadata::default()
                );
                let recognized_metadata = items[1].attestation.as_ref().unwrap();
                for field in [
                    &recognized_metadata.agent,
                    &recognized_metadata.model,
                    &recognized_metadata.provider,
                ] {
                    assert_eq!(field.known(), labeled.then_some("native"));
                }
                // Unsupported discriminators still fail canonical mapping; do not
                // weaken that contract just to inspect their discarded metadata.
                if ignored_type == Some("future-item") {
                    assert_eq!(
                        acquire_source(&source, options()).err().unwrap().code(),
                        "unknown_output_item_type"
                    );
                    continue;
                }
                let batch = acquire_source(&source, options()).unwrap();
                let metadata = &batch.accounting.sessions[0].metadata;
                for field in [&metadata.agent, &metadata.model, &metadata.provider] {
                    assert_eq!(field.known(), labeled.then_some("native"));
                    if !labeled {
                        assert_eq!(*field, AttestedValue::Missing);
                    }
                }
            }
        }
    }
}
