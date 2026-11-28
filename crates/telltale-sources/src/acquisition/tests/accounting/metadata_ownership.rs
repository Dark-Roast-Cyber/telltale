use super::*;

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
#[cfg(feature = "opencode-sqlite")]
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
#[cfg(feature = "opencode-sqlite")]
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
fn copilot_metadata_aliases_preserve_attestation_ambiguity_and_failure() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Copilot,
        source_id: "copilot.process_log".into(),
        kind: SourceKind::CopilotProcessLog,
        path: directory.path().join("synthetic.log"),
    };
    for (field, alias) in [("model", "modelID"), ("provider", "providerID")] {
        for kind in ["function_call", "message"] {
            for (labels, expected) in [
                (
                    serde_json::json!({alias: "native"}),
                    AttestedValue::Known("native".into()),
                ),
                (
                    serde_json::json!({field: "native", alias: "native"}),
                    AttestedValue::Known("native".into()),
                ),
                (
                    serde_json::json!({field: "native", alias: "different"}),
                    AttestedValue::Ambiguous,
                ),
            ] {
                let mut item = serde_json::json!({"type":kind,"name":"view","role":"assistant","content":[{"type":"output_text","text":"synthetic"}]});
                item.as_object_mut()
                    .unwrap()
                    .extend(labels.as_object().unwrap().clone());
                std::fs::write(&source.path, format!("Workspace initialized: s (checkpoints: 0)\nAccumulated output items (1): {}\n", serde_json::json!([item]))).unwrap();
                let batch = acquire_source(&source, options()).unwrap();
                let metadata = &batch.accounting.sessions[0].metadata;
                let actual = if field == "model" {
                    &metadata.model
                } else {
                    &metadata.provider
                };
                assert_eq!(actual, &expected);
            }
            let mut item = serde_json::json!({"type":kind,"name":"view","role":"assistant","content":[{"type":"output_text","text":"synthetic"}]});
            item[alias] = serde_json::json!({"private-marker":42});
            std::fs::write(
                &source.path,
                format!(
                    "Workspace initialized: s (checkpoints: 0)\nAccumulated output items (1): {}\n",
                    serde_json::json!([item])
                ),
            )
            .unwrap();
            let error = acquire_source(&source, options()).err().unwrap();
            assert_eq!(error, AcquisitionError::InvalidAttestation);
            assert!(!format!("{error} {error:?}").contains("private-marker"));
        }
    }
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
