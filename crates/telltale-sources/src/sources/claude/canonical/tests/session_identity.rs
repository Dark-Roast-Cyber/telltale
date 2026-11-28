use super::*;

#[test]
fn basic_conversation_without_source_session_is_replay_unverifiable() {
    let mut source = fixture_source("session_stores/claude/projects/project-a/session-a.jsonl");
    let temp = tempfile::tempdir().unwrap();
    let input = std::fs::read_to_string(&source.path).unwrap();
    source.path = temp.path().join("session-a.jsonl");
    std::fs::write(
        &source.path,
        input.replace("\"sessionId\":\"session-a\",", ""),
    )
    .unwrap();
    let error = project_claude_native_records(
        &super::super::super::native::extract_claude_native_records(&source).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");
}

#[test]
fn scoped_identity_is_stable_across_artifact_moves_and_detects_content_change() {
    let contents =
        r#"{"type":"user","sessionId":"synthetic-session","content":"Synthetic message."}"#;
    let first_directory = tempdir().unwrap();
    let second_directory = tempdir().unwrap();
    let first_path = first_directory.path().join("first-name.jsonl");
    let second_path = second_directory.path().join("moved-name.jsonl");
    fs::write(&first_path, contents).unwrap();
    fs::write(&second_path, contents).unwrap();
    let source = |path| Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path,
    };
    let first = project_claude_native_records(
        &super::super::super::native::extract_claude_native_records(&source(first_path)).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    let moved = project_claude_native_records(
        &super::super::super::native::extract_claude_native_records(&source(second_path)).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    assert_eq!(first[0].observation_id(), moved[0].observation_id());
    assert_eq!(first[0].session_id().unwrap().value(), "synthetic-session");

    let changed_directory = tempdir().unwrap();
    let changed_path = changed_directory.path().join("changed.jsonl");
    fs::write(
        &changed_path,
        r#"{"type":"user","sessionId":"synthetic-session","content":"Synthetic changed message."}"#,
    )
    .unwrap();
    let changed = project_claude_native_records(
        &super::super::super::native::extract_claude_native_records(&source(changed_path)).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    assert_eq!(first[0].observation_id(), changed[0].observation_id());
    assert_eq!(
        first[0]
            .semantic_comparison()
            .compare(changed[0].semantic_comparison()),
        telltale_schema::observation::SemanticReplayVerdict::Mutated
    );
}

#[test]
fn different_source_sessions_scope_local_ordinals() {
    let first_directory = tempdir().unwrap();
    let second_directory = tempdir().unwrap();
    let first_path = first_directory.path().join("session-a.jsonl");
    let second_path = second_directory.path().join("session-b.jsonl");
    fs::write(
        &first_path,
        r#"{"type":"user","sessionId":"synthetic-session-a","content":"Synthetic message."}"#,
    )
    .unwrap();
    fs::write(
        &second_path,
        r#"{"type":"user","sessionId":"synthetic-session-b","content":"Synthetic message."}"#,
    )
    .unwrap();
    let source = |path| Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path,
    };
    let first = project_claude_native_records(
        &super::super::super::native::extract_claude_native_records(&source(first_path)).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    let second = project_claude_native_records(
        &super::super::super::native::extract_claude_native_records(&source(second_path)).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    assert_ne!(first[0].observation_id(), second[0].observation_id());
}

#[test]
fn capability_fidelity_and_source_provenance_are_explicit() {
    let observations = project("session_stores/claude/projects/project-b/session-tool-use.jsonl");
    for observation in observations {
        assert_eq!(
            observation.source().ingestion_mode(),
            IngestionMode::SessionStore
        );
        assert_eq!(observation.source().adapter_type(), "claude_code");
        assert_eq!(observation.source().adapter_id(), "claude.projects");
        assert_eq!(observation.source().adapter_version(), None);
        assert_eq!(observation.source().fidelity(), Fidelity::PartialStructured);
        assert_eq!(observation.source().native_id(), None);
        assert_eq!(observation.source().source_path_hash(), None);
        let capabilities = observation.capability_context().unwrap();
        assert_eq!(capabilities.overrides().len(), 3);
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolCall),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unsupported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::UserContext),
            CapabilityAvailability::Supported
        );
    }
}
