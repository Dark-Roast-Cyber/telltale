use super::*;

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
#[cfg(feature = "opencode-sqlite")]
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
            resume_high_water: None,
            ..Default::default()
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
#[cfg(feature = "opencode-sqlite")]
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
                resume_high_water: None,
                ..Default::default()
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
fn coverage_defaults_to_partial_source() {
    assert_eq!(
        SourceAccounting::default().coverage,
        AccountingCoverage::PartialSource
    );
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
