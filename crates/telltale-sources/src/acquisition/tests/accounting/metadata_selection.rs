use super::*;

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
#[cfg(feature = "opencode-sqlite")]
fn sqlite_desktop_structured_model_attests_joined_parts_and_rejects_invalid_fields() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO part VALUES ('p','m','s',10,'{"type":"text","text":"synthetic user message"}');"#).unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path,
    };
    let replace_message = |model: serde_json::Value, model_id: Option<&str>| {
        conn.execute("DELETE FROM message", []).unwrap();
        let mut data = serde_json::json!({"role":"user", "model":model});
        if let Some(id) = model_id {
            data["modelID"] = id.into();
        }
        conn.execute(
            "INSERT INTO message VALUES ('m','s',?1)",
            [data.to_string()],
        )
        .unwrap();
    };
    replace_message(
        serde_json::json!({"modelID":"model-a","providerID":"provider-a"}),
        None,
    );
    let batch = acquire_source(&source, options()).unwrap();
    let metadata = &batch.accounting.sessions[0].metadata;
    assert_eq!(metadata.model.known(), Some("model-a"));
    assert_eq!(metadata.provider.known(), Some("provider-a"));
    assert_eq!(
        batch.accounting.sessions[0]
            .counts
            .record_counts
            .user_message,
        2 // Native message metadata and its text part both contribute accounting.
    );
    assert_eq!(batch.observations.len(), 1);
    let native = crate::sources::opencode::native::extract_sqlite_native_source(
        &source,
        OpenCodeSqliteReadOptions::default(),
    )
    .unwrap();
    let context = native
        .records
        .iter()
        .find_map(|record| {
            if let crate::sources::opencode::native::OpenCodeSqliteNativeRecord::Text(record) =
                record
            {
                Some(&record.context)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(context.model.as_deref(), Some("model-a"));
    assert_eq!(context.provider.as_deref(), Some("provider-a"));
    replace_message(
        serde_json::json!({"modelID":"model-a","providerID":"provider-a"}),
        Some("model-b"),
    );
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch.accounting.sessions[0].metadata.model,
        AttestedValue::Ambiguous
    );
    for model in [
        serde_json::json!({}),
        serde_json::json!({"modelID":1,"providerID":"provider-a"}),
        serde_json::json!({"modelID":"model-a","providerID":[]}),
    ] {
        replace_message(model, None);
        assert_eq!(
            acquire_source(&source, options()).err().unwrap().code(),
            "invalid_session_attestation"
        );
    }
}

#[test]
#[cfg(feature = "opencode-sqlite")]
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
