use std::fs;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

use telltale_schema::observation::{
    CapabilityAvailability, CapabilityId, ContentPartKind, Fidelity, IngestionMode, JsonValue,
    MessageRole, ObservationBody, ObservationFamily, ObservationStage, ObservedAt,
};
use tempfile::tempdir;

use super::{ClaudeCanonicalOptions, project_claude_native_records};

const OBSERVED_AT: &str = "2026-09-02T12:00:00Z";

fn fixture_source(relative: &str) -> Source {
    Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path: crate::test_fixture_path(relative),
    }
}

fn project(relative: &str) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
    project_claude_native_records(
        &super::super::native::extract_claude_native_records(&fixture_source(relative)).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect("canonical observations")
    .observations
}

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
        &super::super::native::extract_claude_native_records(&source).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");
}

#[test]
fn tool_flow_retains_parts_call_ids_and_structured_values() {
    let observations = project("session_stores/claude/projects/project-b/session-tool-use.jsonl");
    assert_eq!(observations.len(), 4);

    let ObservationBody::Message(user) = observations[0].body() else {
        panic!("expected user message")
    };
    assert_eq!(user.role(), Some(MessageRole::User));
    assert_eq!(user.content_parts().len(), 1);
    assert_eq!(user.content_parts()[0].kind(), ContentPartKind::Text);
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "claude-tool-use"
    );

    let ObservationBody::Message(assistant) = observations[1].body() else {
        panic!("expected assistant message")
    };
    assert_eq!(assistant.role(), Some(MessageRole::Assistant));
    assert_eq!(assistant.content_parts().len(), 2);
    assert_eq!(assistant.content_parts()[0].kind(), ContentPartKind::Text);
    assert_eq!(
        assistant.content_parts()[1].kind(),
        ContentPartKind::ToolUse
    );

    assert_eq!(observations[1].stage(), ObservationStage::MessageObserved);
    let ObservationBody::Tool(tool) = observations[2].body() else {
        panic!("expected tool request")
    };
    assert_eq!(tool.name(), Some("Read"));
    assert_eq!(observations[2].stage(), ObservationStage::ToolRequested);
    assert_eq!(
        observations[3].stage(),
        ObservationStage::ToolResultReturned
    );
    assert!(observations.iter().all(|observation| !matches!(
        observation.stage(),
        ObservationStage::ToolExecutionStarted
            | ObservationStage::ToolExecutionCompleted
            | ObservationStage::ToolProposed
    )));

    let ObservationBody::Tool(result) = observations[3].body() else {
        panic!("expected tool result")
    };
    assert_eq!(result.is_error(), Some(false));
    assert_eq!(
        result.result(),
        Some(&JsonValue::string(
            "# Telltale\nSynthetic README excerpt for parser coverage."
        ))
    );
    assert_eq!(
        observations[3].correlation().call_id().unwrap().value(),
        "toolu_fixture_read"
    );
    assert_eq!(
        observations[3].correlation().call_id().unwrap().origin(),
        telltale_schema::observation::CorrelationOrigin::SourceReported
    );
    assert_eq!(observations[2].source().source_sequence(), Some(1));
    assert_eq!(observations[3].source().source_sequence(), Some(2));
    assert_eq!(observations[1].identity_basis().child_ordinal(), 0);
    assert_eq!(observations[2].identity_basis().child_ordinal(), 1);
    assert_eq!(observations[3].identity_basis().child_ordinal(), 0);
    assert_eq!(
        observations[1].identity_basis().domain(),
        "claude_code:claude.projects"
    );
    assert!(matches!(
        observations[1].identity_basis().coordinate().unwrap().1,
        telltale_schema::observation::IdentityCoordinateValue::SourceSequence {
            namespace,
            ordinal: 1
        } if namespace == "claude-tool-use"
    ));

    let ObservationBody::Tool(request) = observations[2].body() else {
        panic!("expected tool request")
    };
    assert_eq!(request.name(), Some("Read"));
    assert_eq!(
        request.arguments(),
        Some(
            &JsonValue::object([("file_path".to_owned(), JsonValue::string("README.md"),)])
                .unwrap()
        )
    );
    assert_eq!(
        observations[2].correlation().call_id().unwrap().value(),
        "toolu_fixture_read"
    );
    assert_eq!(
        observations[2]
            .facets()
            .get("resource.path")
            .unwrap()
            .value(),
        &JsonValue::string("README.md")
    );
    assert_eq!(
        observations[2]
            .fact_metadata()
            .get("resource.path")
            .unwrap()
            .provenance(),
        telltale_schema::observation::FactProvenance::Parsed
    );
    assert_eq!(observations[2].fact_metadata().len(), 3);
    assert_eq!(observations[3].fact_metadata().len(), 2);
    assert!(
        observations
            .iter()
            .all(|observation| observation.kind() != ObservationFamily::File
                && observation.kind() != ObservationFamily::Process
                && observation.kind() != ObservationFamily::Network)
    );
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
        &super::super::native::extract_claude_native_records(&source(first_path)).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    let moved = project_claude_native_records(
        &super::super::native::extract_claude_native_records(&source(second_path)).unwrap(),
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
        &super::super::native::extract_claude_native_records(&source(changed_path)).unwrap(),
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
        &super::super::native::extract_claude_native_records(&source(first_path)).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    let second = project_claude_native_records(
        &super::super::native::extract_claude_native_records(&source(second_path)).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    assert_ne!(first[0].observation_id(), second[0].observation_id());
}

#[test]
fn object_command_facets_preserve_paths_without_result_or_execution_inference() {
    use serde_json::json;
    use telltale_schema::observation::{FactProvenance, Sensitivity};

    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path: directory.path().join("synthetic-command-facets.jsonl"),
    };
    for (case, mut input, expected) in [
        (
            "command",
            json!({"command":"printf synthetic"}),
            Some("printf synthetic"),
        ),
        (
            "cmd",
            json!({"cmd":"synthetic fallback"}),
            Some("synthetic fallback"),
        ),
        (
            "precedence",
            json!({"command":"printf synthetic","cmd":"synthetic fallback"}),
            Some("printf synthetic"),
        ),
        ("non-string", json!({"command":7}), None),
        (
            "non-string-fallback",
            json!({"command":7,"cmd":"synthetic fallback"}),
            Some("synthetic fallback"),
        ),
        ("no-command", json!({"cmd":false}), None),
    ] {
        input["file_path"] = json!("synthetic-file.txt");
        let request = json!({"type":"assistant","sessionId":"synthetic-command-session","message":{"role":"assistant","content":[{"type":"tool_use","id":"synthetic-call","name":"shell","input":input}]}});
        let result = json!({"type":"user","sessionId":"synthetic-command-session","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"synthetic-call","content":"printf synthetic"}]}});
        fs::write(&source.path, format!("{request}\n{result}\n")).unwrap();
        let observations = project_claude_native_records(
            &super::super::native::extract_claude_native_records(&source).unwrap(),
            &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap()
        .observations;
        let request = observations
            .iter()
            .find(|o| o.stage() == ObservationStage::ToolRequested)
            .unwrap();
        assert!(
            request
                .facets()
                .get("command.text")
                .map(|facet| facet.value())
                == expected.map(JsonValue::string).as_ref(),
            "{case}: command.text"
        );
        if expected.is_some() {
            let metadata = &request.fact_metadata()["command.text"];
            assert!(
                metadata.provenance() == FactProvenance::Parsed,
                "{case}: command.provenance"
            );
            assert!(
                metadata.sensitivity() == Sensitivity::Normal,
                "{case}: command.sensitivity"
            );
        } else {
            assert!(
                !request.fact_metadata().contains_key("command.text"),
                "{case}: command.metadata_absent"
            );
        }
        assert!(
            request.facets()["resource.path"].value() == &JsonValue::string("synthetic-file.txt"),
            "{case}: resource.path"
        );
        assert!(
            request.fact_metadata()["resource.path"].provenance() == FactProvenance::Parsed,
            "{case}: resource.provenance"
        );
        let result = observations
            .iter()
            .find(|o| o.stage() == ObservationStage::ToolResultReturned)
            .unwrap();
        assert!(result.facets().is_empty(), "{case}: result.facets_absent");
        assert!(
            !result.fact_metadata().contains_key("command.text"),
            "{case}: result.command_metadata_absent"
        );
        assert!(
            observations
                .iter()
                .all(|o| o.kind() != ObservationFamily::Process
                    && !matches!(
                        o.stage(),
                        ObservationStage::ToolExecutionStarted
                            | ObservationStage::ToolExecutionCompleted
                    )),
            "{case}: execution.absent"
        );
    }
}

#[test]
fn additional_tool_result_fixture_links_call_ids() {
    let observations =
        project("session_stores/claude/projects/project-c/uc001-claude-tool-result.jsonl");
    // The status call and its result, then the message and the transfer
    // call that follow it.
    assert_eq!(observations.len(), 6);
    assert_eq!(observations[2].stage(), ObservationStage::ToolRequested);
    assert_eq!(
        observations[3].stage(),
        ObservationStage::ToolResultReturned
    );
    assert_eq!(observations[4].kind(), ObservationFamily::Message);
    assert_eq!(observations[5].stage(), ObservationStage::ToolRequested);
    assert_eq!(
        observations[5].correlation().call_id().unwrap().value(),
        "toolu_fixture_upload"
    );
    assert_eq!(
        observations[2].correlation().call_id().unwrap().value(),
        "toolu_fixture_repo_status"
    );
    assert_eq!(
        observations[3].correlation().call_id().unwrap().value(),
        "toolu_fixture_repo_status"
    );
}

#[test]
fn assistant_tool_result_is_emitted_after_message() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("assistant-tool-result.jsonl");
    fs::write(
            &path,
            br#"{"type":"assistant","sessionId":"synthetic-assistant","message":{"role":"assistant","content":[{"type":"text","text":"Synthetic assistant response."},{"type":"tool_result","tool_use_id":"toolu_assistant_result","content":"Synthetic tool result."}]}}"#,
        )
        .unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path,
    };

    let observations = project_claude_native_records(
        &super::super::native::extract_claude_native_records(&source).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect("assistant tool result should project")
    .observations;

    assert_eq!(
        observations
            .iter()
            .map(|observation| observation.kind())
            .collect::<Vec<_>>(),
        vec![ObservationFamily::Message, ObservationFamily::Tool]
    );
    assert_eq!(observations[0].stage(), ObservationStage::MessageObserved);
    assert_eq!(
        observations[1].stage(),
        ObservationStage::ToolResultReturned
    );
    assert_eq!(
        observations[1].correlation().call_id().unwrap().value(),
        "toolu_assistant_result"
    );
    assert_eq!(
        observations[1].correlation().call_id().unwrap().origin(),
        telltale_schema::observation::CorrelationOrigin::SourceReported
    );
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

#[test]
fn unknown_discriminators_are_quarantined_without_content() {
    let source = fixture_source("parser_maturity/non_discovered/unknown-variant.jsonl");
    let projection = project_claude_native_records(
        &super::super::native::extract_claude_native_records(&source).unwrap(),
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
        &super::super::native::extract_claude_native_records(&source).unwrap(),
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
        &super::super::native::extract_claude_native_records(&source).unwrap(),
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

fn project_lines(lines: &[&str]) -> super::ClaudeProjection {
    let directory = tempdir().unwrap();
    let path = directory.path().join("session.jsonl");
    fs::write(&path, lines.join("\n")).unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path,
    };
    project_claude_native_records(
        &super::super::native::extract_claude_native_records(&source).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
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

#[test]
fn nested_and_authored_tool_arguments_project_on_the_tool_observation() {
    let long = "x".repeat(20_000);
    let write = format!(
        r#"{{"type":"assistant","sessionId":"s","message":{{"role":"assistant","content":[{{"type":"tool_use","id":"toolu_write","name":"Write","input":{{"file_path":"C:\\repo\\big.txt","content":"{long}"}}}}]}}}}"#
    );
    let projection = project_lines(&[
        r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"text","text":"Planning."},{"type":"tool_use","id":"toolu_todo","name":"TodoWrite","input":{"todos":[{"content":"Synthetic step","status":"pending","activeForm":"Doing it"}]}}]}}"#,
        r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_multi","name":"MultiEdit","input":{"file_path":"C:\\repo\\a.rs","edits":[{"old_string":"a","new_string":"b"}]}}]}}"#,
        &write,
        r#"{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_ps","name":"PowerShell","input":{"command":"Get-ChildItem $env:USERPROFILE\\.ssh"}}]}}"#,
    ]);
    assert!(
        projection.quarantined.is_empty(),
        "{:?}",
        projection.quarantined
    );
    let tools = projection
        .observations
        .iter()
        .filter_map(|observation| match observation.body() {
            ObservationBody::Tool(tool) => Some((observation, tool)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tools
            .iter()
            .map(|(_, tool)| tool.name())
            .collect::<Vec<_>>(),
        vec![
            Some("TodoWrite"),
            Some("MultiEdit"),
            Some("Write"),
            Some("PowerShell")
        ]
    );
    assert!(tools.iter().all(|(_, tool)| tool.arguments().is_some()));
    let (write, _) = tools[2];
    assert_eq!(
        write.facets().get("resource.path").unwrap().value(),
        &JsonValue::string("C:\\repo\\big.txt")
    );
    let (shell, _) = tools[3];
    assert!(shell.facets().get("command.text").is_some());
    // The message part references the call without repeating its input.
    let ObservationBody::Message(message) = projection.observations[0].body() else {
        panic!("expected message")
    };
    assert_eq!(
        message.content_parts()[1].value(),
        &JsonValue::object([
            ("id".to_owned(), JsonValue::string("toolu_todo")),
            ("name".to_owned(), JsonValue::string("TodoWrite")),
        ])
        .unwrap()
    );
}

#[test]
fn text_array_tool_results_join_into_direct_text() {
    let long = "y".repeat(10_000);
    let line = format!(
        r#"{{"type":"user","sessionId":"s","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"toolu_a","content":[{{"type":"text","text":"first"}},{{"type":"text","text":"{long}"}}]}}]}}}}"#
    );
    let projection = project_lines(&[&line]);
    assert!(projection.quarantined.is_empty());
    let ObservationBody::Tool(tool) = projection.observations[0].body() else {
        panic!("expected tool result")
    };
    assert_eq!(
        tool.result(),
        Some(&JsonValue::string(format!("first\n{long}")))
    );
}

fn project_lines_with(lines: &[&str], options: &ClaudeCanonicalOptions) -> super::ClaudeProjection {
    let directory = tempdir().unwrap();
    let path = directory.path().join("session.jsonl");
    fs::write(&path, lines.join("\n")).unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path,
    };
    project_claude_native_records(
        &super::super::native::extract_claude_native_records(&source).unwrap(),
        options,
    )
    .unwrap()
}

/// An MCP-shaped call with one over-bound argument: the call, its name
/// and its admitted path are projected, the over-bound value is not, and
/// the record is reported as bounded rather than quarantined.
#[test]
fn oversized_tool_arguments_are_replaced_not_quarantined() {
    use telltale_schema::observation::{BoundDimension, BoundedTarget};
    let long = "z".repeat(5_000);
    let line = format!(
        r#"{{"type":"assistant","sessionId":"s","message":{{"role":"assistant","content":[{{"type":"tool_use","id":"toolu_x","name":"mcp__synthetic__run","input":{{"command":"{long}","file_path":"/synthetic/project/notes.txt"}}}}]}}}}"#
    );
    let turn =
        r#"{"type":"user","sessionId":"s","message":{"role":"user","content":"Synthetic turn."}}"#;
    let projection = project_lines(&[&line, turn]);
    assert!(projection.quarantined.is_empty());
    // The assistant record (its message and the call) and the turn
    // after it are all projected.
    assert_eq!(projection.observations.len(), 3);
    assert!(matches!(
        projection.observations[2].body(),
        ObservationBody::Message(_)
    ));
    assert_eq!(
        projection.observations[2].source().source_sequence(),
        Some(1)
    );
    assert_eq!(
        projection.bounded,
        [crate::tool_operation::BoundedRecord {
            source_sequence: 0,
            target: BoundedTarget::Arguments,
            dimension: BoundDimension::StringBytes,
        }]
    );
    let call = projection
        .observations
        .iter()
        .find(|observation| matches!(observation.body(), ObservationBody::Tool(_)))
        .expect("the call is projected");
    let ObservationBody::Tool(tool) = call.body() else {
        unreachable!()
    };
    assert_eq!(tool.name(), Some("mcp__synthetic__run"));
    let JsonValue::Object(arguments) = tool.arguments().unwrap() else {
        panic!("arguments stay an object")
    };
    assert_eq!(arguments["command"], JsonValue::Null);
    assert_eq!(
        arguments["file_path"],
        JsonValue::string("/synthetic/project/notes.txt")
    );
    assert_eq!(
        call.facets()["resource.path"].value(),
        &JsonValue::string("/synthetic/project/notes.txt")
    );
    assert!(!call.facets().contains_key("command.text"));
    assert!(call.fact_metadata().contains_key("tool.bounded_values"));

    // Strict values keep today's whole-record quarantine (hook journals).
    let strict =
        ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()).with_strict_values();
    let projection = project_lines_with(&[&line, turn], &strict);
    assert!(projection.bounded.is_empty());
    // Only the turn after the quarantined record survives.
    assert_eq!(projection.observations.len(), 1);
    assert!(matches!(
        projection.observations[0].body(),
        ObservationBody::Message(_)
    ));
    assert_eq!(
        projection.observations[0].source().source_sequence(),
        Some(1)
    );
    assert_eq!(projection.quarantined.len(), 1);
    assert_eq!(projection.quarantined[0].code, "unbounded_value");
    assert_eq!(
        projection.quarantined[0].bound.map(|bound| bound.category),
        Some(telltale_schema::observation::CanonicalFieldCategory::ToolArguments)
    );
    assert!(
        projection
            .observations
            .iter()
            .all(|observation| !matches!(observation.body(), ObservationBody::Tool(_)))
    );
}
