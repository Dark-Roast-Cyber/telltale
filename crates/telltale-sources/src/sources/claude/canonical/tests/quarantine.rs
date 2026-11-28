use super::*;

#[test]
fn unknown_discriminators_are_quarantined_without_content() {
    let source = fixture_source("parser_maturity/non_discovered/unknown-variant.jsonl");
    let projection = project_claude_native_records(
        &super::super::super::native::extract_claude_native_records(&source).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap();
    assert!(projection.observations.is_empty());
    assert_eq!(projection.quarantined.len(), 1);
    assert_eq!(projection.quarantined[0].code, "unknown_discriminator");
    assert!(!format!("{:?}", projection.quarantined).contains("Synthetic unknown record variant"));
}

#[test]
fn source_schema_errors_remain_distinct_and_missing_call_ids_fail_closed() {
    let drift = fixture_source("parser_maturity/non_discovered/schema-drift.jsonl");
    let error = crate::acquisition::acquire_source(
        &drift,
        crate::acquisition::AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .err()
    .expect("schema drift must remain a source error");
    assert_eq!(error.code(), "source_read");
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains("schema-drift.jsonl"));
        assert!(!rendered.contains("Synthetic"));
    }

    let directory = tempdir().unwrap();
    let path = directory.path().join("missing-id.jsonl");
    fs::write(
            &path,
            br#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Read","input":{"file_path":"README.md"}}]}}"#,
        )
        .unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path,
    };
    let error = project_claude_native_records(
        &super::super::super::native::extract_claude_native_records(&source).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect_err("tool_use without id must fail");
    assert_eq!(error.code(), "missing_tool_id");
}

#[test]
fn unknown_content_blocks_quarantine_only_their_record() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("unknown-block.jsonl");
    fs::write(
            &path,
            concat!(
                r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"future_block","value":"synthetic payload"}]}}"#,
                "\n",
                r#"{"type":"user","sessionId":"s","message":{"role":"user","content":"Synthetic next turn."}}"#,
            ),
        )
        .unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path,
    };
    let projection = project_claude_native_records(
        &super::super::super::native::extract_claude_native_records(&source).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap();
    assert_eq!(projection.observations.len(), 1);
    assert_eq!(
        projection.observations[0].source().source_sequence(),
        Some(1)
    );
    assert_eq!(projection.quarantined.len(), 1);
    assert_eq!(projection.quarantined[0].source_sequence, 0);
    assert_eq!(projection.quarantined[0].code, "unknown_content_block");
    assert!(!format!("{:?}", projection.quarantined).contains("synthetic payload"));
}

#[test]
fn claude_code_metadata_records_are_skipped() {
    let mut lines = [
        "attachment",
        "queue-operation",
        "last-prompt",
        "custom-title",
        "ai-title",
        "agent-name",
        "atis-latch",
        "file-history-snapshot",
        "file-history-delta",
        "summary",
        "system",
        "progress",
        "api-request",
        "api-request-blob",
        "api-request-shape",
        "mode",
        "permission-mode",
        "relocated",
        "worktree-state",
        "cost-state",
        "pr-link",
        "artifact-autoreact-ledger",
        "artifact-comment-monitor",
        "continued-in",
    ]
    .map(|kind| format!(r#"{{"type":"{kind}","sessionId":"s","content":"synthetic"}}"#))
    .to_vec();
    let metadata_count = lines.len();
    lines.push(
        r#"{"type":"user","sessionId":"s","message":{"role":"user","content":"Synthetic turn."}}"#
            .to_owned(),
    );
    let projection = project_lines(&lines.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(projection.quarantined.is_empty());
    assert_eq!(projection.observations.len(), 1);
    assert_eq!(
        projection.observations[0].source().source_sequence(),
        Some(metadata_count as u64)
    );
}

#[test]
fn reasoning_and_media_blocks_are_dropped_from_messages() {
    let projection = project_lines(&[
        r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"thinking","thinking":"synthetic reasoning","signature":"x"}]}}"#,
        r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"redacted_thinking","data":"x"},{"type":"text","text":"Synthetic answer."}]}}"#,
        r#"{"type":"user","sessionId":"s","message":{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}},{"type":"text","text":"Synthetic caption."}]}}"#,
    ]);
    assert!(projection.quarantined.is_empty());
    assert_eq!(projection.observations.len(), 2);
    for observation in &projection.observations {
        let ObservationBody::Message(message) = observation.body() else {
            panic!("expected message")
        };
        assert_eq!(message.content_parts().len(), 1);
        assert_eq!(message.content_parts()[0].kind(), ContentPartKind::Text);
    }
}
