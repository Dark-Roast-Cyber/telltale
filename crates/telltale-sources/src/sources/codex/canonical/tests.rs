use std::fs;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

use telltale_schema::observation::{
    CapabilityAvailability, CapabilityId, ContentPartKind, Fidelity, IngestionMode, JsonValue,
    MessageRole, ObservationBody, ObservationFamily, ObservationStage, ObservedAt, ToolStatus,
};
use tempfile::tempdir;

use super::{CodexCanonicalOptions, project_codex_native_records};

const OBSERVED_AT: &str = "2026-09-02T12:00:00Z";

fn source(source_id: &str, kind: SourceKind, relative: &str) -> Source {
    Source {
        client: ClientId::Codex,
        kind,
        source_id: source_id.to_owned(),
        path: crate::test_fixture_path(relative),
    }
}

fn temp_source(source_id: &str, kind: SourceKind, contents: &str) -> (tempfile::TempDir, Source) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("synthetic-codex.jsonl");
    fs::write(&path, contents).expect("Codex fixture");
    (
        directory,
        Source {
            client: ClientId::Codex,
            kind,
            source_id: source_id.to_owned(),
            path,
        },
    )
}

fn project(source: &Source) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
    project_codex_native_records(
        &super::super::native::extract_codex_native_records(source).unwrap(),
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect("canonical observations")
    .observations
}

/// One record's own mapping error, before projection quarantines it.
fn project_one(
    record: &super::super::native::CodexNativeRecord,
) -> Result<(), super::CodexCanonicalError> {
    super::project_record(
        record,
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        &mut crate::acquisition::CanonicalCollector::default(),
    )
}

#[test]
fn bound_error_debug_and_display_are_content_free() {
    use telltale_schema::observation::{
        BoundDimension, CanonicalBoundContext, CanonicalFieldCategory,
    };
    let marker = "SYNTHETIC-PRIVATE-CANONICAL-";
    let options = CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap());
    // A tool call's over-bound argument is replaced: the record is
    // projected and reported by coordinates, with no content.
    let value = format!("{marker}{}", "x".repeat(4097));
    let input = serde_json::json!({"type":"tool_call", "session_id":marker, "name":marker, "arguments":{marker:value}});
    let (_directory, source) = temp_source("codex.sessions", SourceKind::Jsonl, &input.to_string());
    let records = super::super::native::extract_codex_native_records(&source).unwrap();
    let projection = project_codex_native_records(&records, &options).unwrap();
    assert!(projection.quarantined.is_empty());
    assert_eq!(projection.observations.len(), 1);
    assert_eq!(
        projection.bounded,
        [crate::tool_operation::BoundedRecord {
            source_sequence: 0,
            target: telltale_schema::observation::BoundedTarget::Arguments,
            dimension: BoundDimension::StringBytes,
        }]
    );
    let ObservationBody::Tool(tool) = projection.observations[0].body() else {
        panic!("expected tool")
    };
    for rendered in [
        format!("{:?}", projection.bounded),
        format!("{:?}", tool.bounded_values()),
    ] {
        assert!(!rendered.contains(marker), "controlled content leaked");
    }
    // Message text over its budget still fails its record.
    let value = format!("{marker}{}", "x".repeat(65_537));
    let input = serde_json::json!({"type":"user", "session_id":marker, "content":value});
    let (_directory, source) = temp_source("codex.sessions", SourceKind::Jsonl, &input.to_string());
    let records = super::super::native::extract_codex_native_records(&source).unwrap();
    let error = project_one(&records[0]).unwrap_err();
    let super::CodexCanonicalError::Observation(observation) = &error else {
        panic!("expected canonical validation")
    };
    let bound = Some(CanonicalBoundContext {
        category: CanonicalFieldCategory::MessageContent,
        dimension: BoundDimension::StringBytes,
    });
    assert_eq!(observation.bound_context(), bound);
    // The projection quarantines that record alone, by coordinates.
    let projection = project_codex_native_records(&records, &options).unwrap();
    assert!(projection.observations.is_empty());
    assert_eq!(
        projection.quarantined,
        vec![super::CodexQuarantinedRecord {
            source_sequence: 0,
            code: "unbounded_value",
            bound,
        }]
    );
    assert_eq!(
        observation.to_string(),
        "canonical observation rejected (unbounded_value)"
    );
    for rendered in [
        format!("{error:?}"),
        error.to_string(),
        format!("{observation:?}"),
    ] {
        assert!(!rendered.contains(marker), "controlled content leaked");
    }
}

#[test]
fn simple_messages_use_source_time_but_not_filename_session() {
    let mut source = source(
        "codex.sessions",
        SourceKind::Jsonl,
        "session_stores/codex/sessions/2026/04/session-a.jsonl",
    );
    let temp = tempfile::tempdir().unwrap();
    let input = std::fs::read_to_string(&source.path).unwrap();
    source.path = temp.path().join("session-a.jsonl");
    std::fs::write(
        &source.path,
        input.replace("\"session_id\":\"session-a\",", ""),
    )
    .unwrap();
    let error = project_codex_native_records(
        &super::super::native::extract_codex_native_records(&source).unwrap(),
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");
}

#[test]
fn event_messages_map_to_truthful_roles() {
    let (_directory, source) = temp_source(
        "codex.sessions",
        SourceKind::Jsonl,
        r#"{"type":"session_meta","payload":{"session_id":"synthetic-event-session"}}
{"type":"event_msg","payload":{"type":"user_message","message":"Synthetic user."}}
{"type":"event_msg","payload":{"type":"assistant_message","message":"Synthetic assistant."}}"#,
    );
    let observations = project(&source);
    assert_eq!(observations.len(), 2);
    for (observation, role) in observations
        .iter()
        .zip([MessageRole::User, MessageRole::Assistant])
    {
        let ObservationBody::Message(message) = observation.body() else {
            panic!("expected message")
        };
        assert_eq!(message.role(), Some(role));
        assert_eq!(observation.stage(), ObservationStage::MessageObserved);
    }
}

#[test]
fn direct_source_session_id_is_used_without_filename_identity() {
    let (_directory, source) = temp_source(
        "codex.sessions",
        SourceKind::Jsonl,
        r#"{"type":"user","sessionId":"source-session","content":"Synthetic user message."}"#,
    );
    let observations = project(&source);
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "source-session"
    );
    assert_eq!(observations[0].source().source_sequence(), Some(0));
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
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_owned(),
        path,
    };
    let first = project_codex_native_records(
        &super::super::native::extract_codex_native_records(&source(first_path)).unwrap(),
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    let moved = project_codex_native_records(
        &super::super::native::extract_codex_native_records(&source(second_path)).unwrap(),
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
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
    let changed = project_codex_native_records(
        &super::super::native::extract_codex_native_records(&source(changed_path)).unwrap(),
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
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
fn different_effective_sessions_scope_local_ordinals() {
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
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_owned(),
        path,
    };
    let first = project_codex_native_records(
        &super::super::native::extract_codex_native_records(&source(first_path)).unwrap(),
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    let second = project_codex_native_records(
        &super::super::native::extract_codex_native_records(&source(second_path)).unwrap(),
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
    .observations;
    assert_ne!(first[0].observation_id(), second[0].observation_id());
}

#[test]
fn unknown_message_role_fails_closed() {
    let (_directory, source) = temp_source(
        "codex.sessions",
        SourceKind::Jsonl,
        r#"{"type":"message","role":"future_role","content":"Synthetic role marker."}"#,
    );
    let error = project_codex_native_records(
        &super::super::native::extract_codex_native_records(&source).unwrap(),
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect_err("unknown role");
    assert_eq!(error.code(), "unsupported_role");
    assert!(!error.to_string().contains("Synthetic role marker"));
}

#[test]
fn response_items_preserve_ordered_parts_and_custom_native_string_input() {
    let (_directory, source) = temp_source(
        "codex.sessions",
        SourceKind::Jsonl,
        r#"{"type":"session_meta","payload":{"session_id":"codex-app-session"}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Inspect."}]}}
{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"I will inspect."},{"type":"tool_use","name":"exec","input":{"cmd":"git status"}}]}}
{"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"call-1","input":"{\"cmd\":\"git status\"}"}}
{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"call-1","output":{"status":"clean"}}}
"#,
    );
    let observations = project(&source);
    assert_eq!(observations.len(), 5);
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "codex-app-session"
    );
    assert_eq!(observations[1].kind(), ObservationFamily::Message);
    assert_eq!(observations[2].kind(), ObservationFamily::Tool);
    assert_eq!(observations[2].stage(), ObservationStage::ToolRequested);
    let ObservationBody::Tool(content_tool) = observations[2].body() else {
        panic!("expected content tool")
    };
    assert_eq!(
        content_tool.arguments(),
        Some(&JsonValue::object([("cmd".to_owned(), JsonValue::string("git status")),]).unwrap())
    );
    assert_eq!(observations[3].stage(), ObservationStage::ToolRequested);
    let ObservationBody::Tool(custom_tool) = observations[3].body() else {
        panic!("expected custom tool")
    };
    assert_eq!(
        custom_tool.arguments(),
        Some(&JsonValue::string(r#"{"cmd":"git status"}"#))
    );
    assert_eq!(
        observations[3].facets()["command.text"].value(),
        &JsonValue::string("git status")
    );
    assert_eq!(
        observations[3].correlation().call_id().unwrap().value(),
        "call-1"
    );
    assert_eq!(
        observations[4].stage(),
        ObservationStage::ToolResultReturned
    );
    assert_eq!(
        observations[4].correlation().call_id().unwrap().value(),
        "call-1"
    );
    assert_eq!(observations[1].identity_basis().child_ordinal(), 0);
    assert_eq!(observations[2].identity_basis().child_ordinal(), 1);
}

#[test]
fn function_call_records_are_canonical_tools() {
    let (_directory, source) = temp_source(
        "codex.headless_sessions",
        SourceKind::HeadlessJsonl,
        r#"{"type":"event_msg","session_id":"function-session","payload":{"type":"function_call","name":"shell","call_id":"call-function-1","arguments":{"command":"printf synthetic"}}}
{"type":"event_msg","session_id":"function-session","payload":{"type":"function_call_output","call_id":"call-function-1","output":{"exit_code":0}}}"#,
    );
    let observations = project(&source);
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
    assert_eq!(
        observations[1].stage(),
        ObservationStage::ToolResultReturned
    );
    assert_eq!(
        observations[0].correlation().call_id().unwrap().value(),
        "call-function-1"
    );
    let ObservationBody::Tool(tool) = observations[0].body() else {
        panic!("expected function call tool")
    };
    assert_eq!(tool.name(), Some("shell"));
    assert_eq!(
        tool.arguments(),
        Some(
            &JsonValue::object([("command".to_owned(), JsonValue::string("printf synthetic"),)])
                .unwrap()
        )
    );
    let ObservationBody::Tool(result) = observations[1].body() else {
        panic!("expected function call result")
    };
    assert_eq!(
        result.result(),
        Some(&JsonValue::object([("exit_code".to_owned(), JsonValue::Integer(0))]).unwrap())
    );
}

#[test]
fn content_block_tool_ids_are_optional_and_values_stay_structured() {
    let (_directory, source) = temp_source(
        "codex.sessions",
        SourceKind::Jsonl,
        r#"{"type":"assistant","session_id":"content-blocks","content":[{"type":"text","text":"Run it."},{"type":"tool_use","name":"exec","input":{"command":"printf synthetic"}}]}
{"type":"assistant","session_id":"content-blocks","content":[{"type":"tool_result","content":{"exit_code":0}}]}"#,
    );
    let observations = project(&source);
    assert_eq!(observations.len(), 4);
    assert_eq!(observations[0].kind(), ObservationFamily::Message);
    let ObservationBody::Message(message) = observations[0].body() else {
        panic!("expected message")
    };
    assert_eq!(message.content_parts()[0].kind(), ContentPartKind::Text);
    assert_eq!(observations[1].stage(), ObservationStage::ToolRequested);
    assert_eq!(observations[2].stage(), ObservationStage::MessageObserved);
    assert_eq!(
        observations[3].stage(),
        ObservationStage::ToolResultReturned
    );
    assert_eq!(observations[1].correlation().call_id(), None);
    let ObservationBody::Tool(tool) = observations[1].body() else {
        panic!("expected tool")
    };
    assert!(matches!(tool.arguments(), Some(JsonValue::Object(_))));
    assert_eq!(observations[3].correlation().call_id(), None);
    let ObservationBody::Tool(result) = observations[3].body() else {
        panic!("expected result tool")
    };
    assert_eq!(
        result.result(),
        Some(&JsonValue::object([("exit_code".to_owned(), JsonValue::Integer(0),)]).unwrap())
    );
}

#[test]
fn generic_tool_states_never_become_execution_stages() {
    let (_directory, source) = temp_source(
        "codex.sessions",
        SourceKind::Jsonl,
        r#"{"type":"tool","session_id":"generic-session","state":{"status":"running"}}
{"type":"tool","session_id":"generic-session","name":"exec","state":{"status":"completed"}}
{"type":"tool","session_id":"generic-session","state":{"status":"error","error":{"message":"synthetic failure"}}}"#,
    );
    let observations = project(&source);
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
    assert_eq!(
        observations[1].stage(),
        ObservationStage::ToolResultReturned
    );
    assert_eq!(
        observations[2].stage(),
        ObservationStage::ToolResultReturned
    );
    let ObservationBody::Tool(running) = observations[0].body() else {
        panic!("expected running tool")
    };
    assert_eq!(running.reported_status(), Some(ToolStatus::Unknown));
    let ObservationBody::Tool(completed) = observations[1].body() else {
        panic!("expected completed tool")
    };
    assert_eq!(completed.reported_status(), Some(ToolStatus::Unknown));
    let ObservationBody::Tool(error) = observations[2].body() else {
        panic!("expected error tool")
    };
    assert_eq!(error.reported_status(), Some(ToolStatus::Failed));
    assert!(observations.iter().all(|observation| !matches!(
        observation.stage(),
        ObservationStage::ToolProposed
            | ObservationStage::ToolExecutionStarted
            | ObservationStage::ToolExecutionCompleted
    )));
}

#[test]
fn session_meta_is_skipped_and_its_id_is_inherited() {
    let source = source(
        "codex.sessions",
        SourceKind::Jsonl,
        "session_stores/codex/sessions/2026/04/encoded-http-exfil.jsonl",
    );
    let observations = project(&source);
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "encoded-http-exfil"
    );
    assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
}

#[test]
fn headless_turn_context_is_skipped_without_process_observations() {
    let headless_source = source(
        "codex.headless_sessions",
        SourceKind::HeadlessJsonl,
        "session_stores/codex/headless/headless-a.jsonl",
    );
    assert!(project(&headless_source).is_empty());
    let (_directory, headless_source) = temp_source(
        "codex.headless_sessions",
        SourceKind::HeadlessJsonl,
        r#"{"type":"session_meta","payload":{"session_id":"synthetic-headless-session"}}
{"type":"event_msg","payload":{"type":"user_message","message":"Synthetic user."}}
{"type":"event_msg","payload":{"type":"assistant_message","message":"Synthetic assistant."}}"#,
    );
    let observations = project(&headless_source);
    assert_eq!(observations.len(), 2);
    assert!(
        observations
            .iter()
            .all(|observation| observation.kind() != ObservationFamily::Process)
    );
    assert!(
        observations
            .iter()
            .all(|observation| observation.source().adapter_id() == "codex.headless_sessions")
    );
}

#[test]
fn provenance_capabilities_and_three_source_identities_are_explicit() {
    let contents = r#"{"type":"user","session_id":"same-shape","content":"Synthetic message."}"#;
    let identities = [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ];
    let mut ids = Vec::new();
    for (source_id, kind) in identities {
        let (_directory, source) = temp_source(source_id, kind, contents);
        let observations = project(&source);
        let observation = &observations[0];
        assert_eq!(observation.source().adapter_type(), "codex");
        assert_eq!(observation.source().adapter_id(), source_id);
        assert_eq!(
            observation.source().ingestion_mode(),
            IngestionMode::SessionStore
        );
        assert_eq!(observation.source().fidelity(), Fidelity::PartialStructured);
        assert_eq!(observation.source().adapter_version(), None);
        assert_eq!(observation.source().native_id(), None);
        assert_eq!(observation.source().source_path_hash(), None);
        let capabilities = observation.capability_context().unwrap();
        assert_eq!(capabilities.overrides().len(), 3);
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolCall),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::UserContext),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unsupported
        );
        ids.push(observation.observation_id().to_owned());
    }
    assert_eq!(ids.windows(2).filter(|pair| pair[0] == pair[1]).count(), 0);
}

#[test]
fn command_and_resource_facets_do_not_create_activity_families() {
    let (_directory, source) = temp_source(
        "codex.sessions",
        SourceKind::Jsonl,
        r#"{"type":"tool_call","session_id":"facet-session","arguments":{"command":"git status","file_path":"README.md"},"message":"synthetic command"}"#,
    );
    let observations = project(&source);
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].facets()["command.text"].value(),
        &JsonValue::string("git status")
    );
    assert_eq!(
        observations[0].facets()["resource.path"].value(),
        &JsonValue::string("README.md")
    );
    assert!(matches!(
        observations[0].fact_metadata()["command.text"].provenance(),
        telltale_schema::observation::FactProvenance::Parsed
    ));
    assert!(observations.iter().all(|observation| !matches!(
        observation.kind(),
        ObservationFamily::File | ObservationFamily::Process | ObservationFamily::Network
    )));
}

#[test]
fn unknown_and_schema_errors_are_privacy_safe() {
    let unknown_source = source(
        "codex.sessions",
        SourceKind::Jsonl,
        "parser_maturity/non_discovered/unknown-variant.jsonl",
    );
    let records = super::super::native::extract_codex_native_records(&unknown_source).unwrap();
    let error = records
        .iter()
        .find_map(|record| project_one(record).err())
        .expect("unknown discriminator");
    assert_eq!(error.code(), "unknown_discriminator");
    let projection = project_codex_native_records(
        &records,
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap();
    assert_eq!(projection.quarantined.len(), 1);
    assert_eq!(projection.quarantined[0].code, "unknown_discriminator");
    assert!(
        !error
            .to_string()
            .contains("Synthetic unknown record variant")
    );
    assert!(!format!("{error:?}").contains("Synthetic unknown record variant"));

    let drift = source(
        "codex.archived_sessions",
        SourceKind::ArchivedJsonl,
        "parser_maturity/non_discovered/schema-drift.jsonl",
    );
    let error = crate::acquisition::acquire_source(
        &drift,
        crate::acquisition::AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .err()
    .expect("schema drift");
    assert_eq!(error.code(), "source_read");
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains("schema-drift.jsonl"));
        assert!(!rendered.contains("Synthetic"));
    }
}

#[test]
fn unknown_content_block_quarantines_its_record() {
    let (_directory, source) = temp_source(
        "codex.sessions",
        SourceKind::Jsonl,
        r#"{"type":"assistant","content":[{"type":"future_block","value":"Synthetic payload marker."}]}"#,
    );
    let records = super::super::native::extract_codex_native_records(&source).unwrap();
    let error = project_one(&records[0]).expect_err("unknown block");
    assert_eq!(error.code(), "unknown_content_block");
    assert!(!error.to_string().contains("Synthetic payload marker"));
    let projection = project_codex_native_records(
        &records,
        &CodexCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap();
    assert!(projection.observations.is_empty());
    assert_eq!(projection.quarantined[0].code, "unknown_content_block");
}

#[test]
fn all_projected_families_are_bounded_to_messages_and_tools() {
    let (_directory, source) = temp_source(
        "codex.sessions",
        SourceKind::Jsonl,
        r#"{"type":"session_meta","payload":{"session_id":"synthetic-project-session"}}
{"type":"event_msg","payload":{"type":"assistant_message","message":"Synthetic response."}}"#,
    );
    let observations = project(&source);
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].source().adapter_id(), "codex.sessions");
    assert!(observations.iter().all(|observation| matches!(
        observation.kind(),
        ObservationFamily::Message | ObservationFamily::Tool
    )));
    assert!(observations.iter().all(|observation| !matches!(
        observation.kind(),
        ObservationFamily::File
            | ObservationFamily::Process
            | ObservationFamily::Network
            | ObservationFamily::Session
            | ObservationFamily::Inference
    )));
}
