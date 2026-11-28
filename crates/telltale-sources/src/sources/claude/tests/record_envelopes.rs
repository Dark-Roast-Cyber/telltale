use super::*;

#[test]
fn transcript_session_id_owns_records_that_also_name_another_session() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-continued.jsonl"),
    };
    let first = json!({"type":"user","sessionId":"synthetic-transcript",
        "session_id":"synthetic-transcript","uuid":"synthetic-1",
        "message":{"role":"user","content":"first turn"}});
    let continued = json!({"type":"assistant","sessionId":"synthetic-transcript",
        "session_id":"synthetic-continuation","uuid":"synthetic-2",
        "message":{"role":"assistant","content":[{"type":"text","text":"second turn"}]}});
    std::fs::write(&source.path, format!("{first}\n{continued}\n")).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(batch.observations.len(), 2);
    assert!(batch.observations.iter().all(|observation| {
        observation.session_id().unwrap().value() == "synthetic-transcript"
    }));
    assert_eq!(batch.accounting.sessions.len(), 1);
    assert_eq!(
        batch.accounting.sessions[0].session_id.value(),
        "synthetic-transcript"
    );

    let fallback = json!({"type":"user","session_id":"synthetic-fallback",
        "message":{"role":"user","content":"turn"}});
    std::fs::write(&source.path, format!("{fallback}\n")).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch.accounting.sessions[0].session_id.value(),
        "synthetic-fallback"
    );

    let conflict = json!({"type":"user","session_id":"synthetic-fallback",
        "sessionID":"synthetic-other","message":{"role":"user","content":"turn"}});
    std::fs::write(&source.path, format!("{conflict}\n")).unwrap();
    assert!(matches!(
        acquire_source(&source, options()),
        Err(AcquisitionError::ConflictingSessionOwnership)
    ));
}

#[test]
fn explicit_outer_record_types_cannot_be_shadowed_by_payload_types() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory
            .path()
            .join("synthetic-discriminator-shadow.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid turn"});
    for kind in [
        "api-request",
        "api-request-blob",
        "api-request-shape",
        "attachment",
        "pr-link",
        "artifact-autoreact-ledger",
        "artifact-comment-monitor",
        "continued-in",
        "Future",
    ] {
        for payload in [
            json!({"type":"assistant"}),
            json!({"payload":{"type":"assistant"}}),
        ] {
            let record = json!({"type":kind,"sessionId":"synthetic","payload":payload,
                "message":{"role":"assistant","content":[{"type":"tool_use","id":"synthetic-call",
                    "name":"Bash","input":{"command":"printf synthetic"}}]}});
            std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
            let batch = acquire_source(&source, options()).unwrap();
            assert_eq!(batch.observations.len(), 1, "{kind}");
            assert_eq!(
                batch.quarantined.len(),
                usize::from(kind == "Future"),
                "{kind}"
            );
            assert_eq!(
                batch.accounting.sessions[0].counts.record_counts.tool_call, 0,
                "{kind}"
            );
        }
    }
}

#[test]
fn malformed_jsonl_is_a_json_read_error() {
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path: crate::test_fixture_path("rule_samples/malformed-source.jsonl"),
    };
    let error =
        super::super::native::extract_claude_native_records(&source).expect_err("malformed");
    let message = error.to_string();
    assert!(matches!(error, SourceReadError::Json(_)));
    assert!(message.contains("json parse error"));
    assert!(!message.contains("malformed-source"));
}

#[test]
fn missing_jsonl_is_an_io_read_error() {
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path: "missing-session.jsonl".into(),
    };
    let error = super::super::native::extract_claude_native_records(&source).expect_err("missing");
    assert!(matches!(error, SourceReadError::Io(_)));
    assert!(error.to_string().contains("io error"));
}

#[test]
fn non_object_envelope_is_schema_drift() {
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path: crate::test_fixture_path("parser_maturity/non_discovered/schema-drift.jsonl"),
    };
    let error = super::super::native::extract_claude_native_records(&source).expect_err("drift");
    let message = error.to_string();
    assert!(matches!(error, SourceReadError::SchemaDrift { .. }));
    assert!(message.contains("schema drift"));
    assert!(!message.contains("Synthetic schema envelope drift"));
}
