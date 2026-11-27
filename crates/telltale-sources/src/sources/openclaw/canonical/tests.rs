use std::fs;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

use telltale_schema::observation::{
    CapabilityAvailability, CapabilityId, ContentPartKind, Fidelity, IdentityCoordinateKind,
    IdentityCoordinateValue, IngestionMode, JsonValue, MessageRole, ObservationBody,
    ObservationFamily, ObservationStage, ObservedAt, SemanticReplayVerdict,
};
use tempfile::tempdir;

use super::{OpenClawCanonicalOptions, project_openclaw_native_records};

const OBSERVED_AT: &str = "2026-09-04T12:00:00Z";

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::OpenClaw,
        kind: SourceKind::Jsonl,
        source_id: "openclaw.agents".to_owned(),
        path,
    }
}

fn project(path: std::path::PathBuf) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
    project_openclaw_native_records(
        &super::super::native::extract_openclaw_native_records(&source(path)).unwrap(),
        &OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect("OpenClaw canonical observations")
}

#[test]
fn benign_baseline_preserves_direct_tool_calls() {
    let path = crate::test_fixture_path(
        "benign_baselines/openclaw/agents/baseline-project/benign-baseline.jsonl",
    );
    let observations = project(path.clone());
    assert_eq!(observations.len(), 5);

    assert_eq!(observations[0].kind(), ObservationFamily::Message);
    assert_eq!(observations[0].stage(), ObservationStage::MessageObserved);
    assert_eq!(observations[0].observed_at().as_str(), OBSERVED_AT);
    assert_eq!(
        observations[0].occurred_at().unwrap().as_str(),
        "2026-05-10T17:00:00Z"
    );
    let ObservationBody::Message(user) = observations[0].body() else {
        panic!("expected user message")
    };
    assert_eq!(user.role(), Some(MessageRole::User));
    assert_eq!(
        user.content(),
        Some(&JsonValue::string("Show me the contents of the Makefile."))
    );

    let ObservationBody::Message(assistant) = observations[1].body() else {
        panic!("expected assistant message")
    };
    assert_eq!(assistant.role(), Some(MessageRole::Assistant));
    assert_eq!(observations[1].source().source_sequence(), Some(1));
    assert_eq!(observations[1].identity_basis().child_ordinal(), 0);

    let ObservationBody::Tool(request) = observations[2].body() else {
        panic!("expected direct tool request")
    };
    assert_eq!(request.name(), Some("read_file"));
    assert_eq!(
        request.arguments(),
        Some(&JsonValue::object([("path".to_owned(), JsonValue::string("Makefile"))]).unwrap())
    );
    assert_eq!(observations[2].stage(), ObservationStage::ToolRequested);
    assert_eq!(observations[2].identity_basis().child_ordinal(), 1);
    assert_eq!(
        observations[2].correlation().call_id().unwrap().value(),
        "tc-openclaw-baseline-001"
    );
    assert_eq!(
        observations[2].facets()["resource.path"].value(),
        &JsonValue::string("Makefile")
    );
    assert_eq!(
        observations[2].fact_metadata()["resource.path"].provenance(),
        telltale_schema::observation::FactProvenance::Parsed
    );

    let ObservationBody::Tool(result) = observations[3].body() else {
        panic!("expected tool result")
    };
    assert_eq!(
        observations[3].stage(),
        ObservationStage::ToolResultReturned
    );
    assert_eq!(
        result.result().map(|value| value
            == &JsonValue::string(
                "build:\n\tcargo build --release\n\ntest:\n\tcargo test\n\nclean:\tcargo clean"
            )),
        Some(true)
    );
    assert_eq!(
        observations[3].correlation().call_id().unwrap().value(),
        "tc-openclaw-baseline-001"
    );

    assert!(observations.iter().all(|observation| {
        observation.source().ingestion_mode() == IngestionMode::SessionStore
            && observation.source().adapter_type() == "openclaw"
            && observation.source().adapter_id() == "openclaw.agents"
            && observation.source().fidelity() == Fidelity::PartialStructured
            && observation
                .capability_context()
                .unwrap()
                .resolve(CapabilityId::ToolCall)
                == CapabilityAvailability::Supported
            && observation
                .capability_context()
                .unwrap()
                .resolve(CapabilityId::ToolExecution)
                == CapabilityAvailability::Unknown
            && observation
                .capability_context()
                .unwrap()
                .resolve(CapabilityId::UserContext)
                == CapabilityAvailability::Supported
    }));
}

#[test]
fn structured_tool_fixture_keeps_values_and_allows_missing_call_ids() {
    let path = crate::test_fixture_path(
        "session_stores/openclaw/agents/project-b/uc001-openclaw-tool-result.jsonl",
    );
    let observations = project(path);
    // The status call and its result, then the transfer call.
    assert_eq!(observations.len(), 4);
    assert_eq!(observations[0].kind(), ObservationFamily::Message);
    assert_eq!(observations[1].stage(), ObservationStage::ToolRequested);
    assert_eq!(
        observations[2].stage(),
        ObservationStage::ToolResultReturned
    );
    assert_eq!(observations[3].stage(), ObservationStage::ToolRequested);
    assert_eq!(observations[1].correlation().call_id(), None);
    assert_eq!(observations[2].correlation().call_id(), None);

    let ObservationBody::Tool(request) = observations[1].body() else {
        panic!("expected tool request")
    };
    assert_eq!(
        request.arguments(),
        Some(&JsonValue::object([("format".to_owned(), JsonValue::string("json"))]).unwrap())
    );
    let ObservationBody::Tool(result) = observations[2].body() else {
        panic!("expected tool result")
    };
    assert!(matches!(result.result(), Some(JsonValue::String(_))));
    assert!(observations.iter().all(|observation| {
        !matches!(
            observation.stage(),
            ObservationStage::ToolProposed
                | ObservationStage::ToolExecutionStarted
                | ObservationStage::ToolExecutionCompleted
        )
    }));
}

#[test]
fn generic_tool_snapshots_emit_only_direct_request_and_result_facts() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("generic-tools.jsonl");
    fs::write(
            &path,
            r#"{"type":"tool","sessionId":"generic-session","tool":"shell","callID":"call-running","state":{"status":"running","input":{"command":"printf synthetic"}}}
{"type":"tool","sessionId":"generic-session","tool":"shell","callID":"call-completed","state":{"status":"completed","output":{"status":"ok"}}}"#,
        )
        .unwrap();
    let observations = project(path);
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
    assert_eq!(
        observations[2].stage(),
        ObservationStage::ToolResultReturned
    );
    let ObservationBody::Tool(result) = observations[2].body() else {
        panic!("expected returned result")
    };
    assert_eq!(
        result.result(),
        Some(&JsonValue::object([("status".to_owned(), JsonValue::string("ok"))]).unwrap())
    );
    assert!(observations.iter().all(|observation| {
        !matches!(
            observation.stage(),
            ObservationStage::ToolExecutionStarted | ObservationStage::ToolExecutionCompleted
        )
    }));
}

#[test]
fn explicit_call_id_forms_are_correlation_not_native_identity() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("call-id-forms.jsonl");
    let keys = [
        "tool_call_id",
        "call_id",
        "callID",
        "callId",
        "toolCallId",
        "tool_use_id",
    ];
    let contents = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                format!(
                    "{{\"type\":\"tool_result\",\"sessionId\":\"call-id-session\",\"{key}\":\"call-{index}\",\"content\":{{\"ok\":true}}}}"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
    fs::write(&path, contents).unwrap();
    let observations = project(path);
    assert_eq!(observations.len(), keys.len());
    for (index, observation) in observations.iter().enumerate() {
        assert_eq!(observation.source().native_id(), None);
        assert_eq!(
            observation.correlation().call_id().unwrap().value(),
            format!("call-{index}")
        );
    }
}

#[test]
fn mixed_content_keeps_ordered_parts_without_empty_result_message() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("mixed.jsonl");
    fs::write(
            &path,
            r#"{"type":"assistant","sessionId":"mixed-session","content":[{"type":"text","text":"Synthetic request."},{"type":"tool_use","id":"call-mixed","name":"read_file","input":{"file_path":"synthetic.txt"}}]}
{"type":"user","sessionId":"mixed-session","content":[{"type":"tool_result","tool_use_id":"call-mixed","content":{"status":"ok"}}]}"#,
        )
        .unwrap();

    let observations = project(path);
    assert_eq!(observations.len(), 3);
    let ObservationBody::Message(message) = observations[0].body() else {
        panic!("expected assistant message")
    };
    assert_eq!(message.content_parts().len(), 2);
    assert_eq!(message.content_parts()[0].kind(), ContentPartKind::Text);
    assert_eq!(message.content_parts()[1].kind(), ContentPartKind::ToolUse);
    assert_eq!(observations[0].identity_basis().child_ordinal(), 0);
    assert_eq!(observations[1].stage(), ObservationStage::ToolRequested);
    assert_eq!(observations[1].identity_basis().child_ordinal(), 1);
    assert_ne!(
        observations[0].observation_id(),
        observations[1].observation_id()
    );
    assert_eq!(
        observations[2].stage(),
        ObservationStage::ToolResultReturned
    );
    assert_eq!(observations[2].identity_basis().child_ordinal(), 0);
    assert!(observations.iter().all(|observation| {
        !(observation.kind() == ObservationFamily::Message
            && observation.source().source_sequence() == Some(1))
    }));
}

#[test]
fn payload_envelopes_preserve_messages_tools_and_structured_arguments() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("payloads.jsonl");
    fs::write(
            &path,
            r#"{"payload":{"type":"user","sessionId":"payload-session","content":"Synthetic payload user."}}
{"content":"Synthetic outer nested assistant.","sessionId":"outer-nested-session","id":"outer-nested-id","timestamp":"2026-09-04T10:00:00Z","payload":{"payload":{"type":"assistant","sessionId":"nested-payload-session","id":"nested-payload-id","timestamp":"2026-09-04T10:00:01Z","content":"Synthetic nested assistant."}}}
{"payload":{"type":"tool_call","sessionId":"payload-tool-session","tool_name":"read_file","arguments":{"path":"synthetic.txt","options":{"depth":1}}}}
{"payload":{"type":"user_message","sessionId":"payload-message-session","message":"Synthetic payload message."}}"#,
        )
        .unwrap();

    let observations = project(path);
    assert_eq!(observations.len(), 4);

    let ObservationBody::Message(user) = observations[0].body() else {
        panic!("expected payload user message")
    };
    assert_eq!(
        user.content(),
        Some(&JsonValue::string("Synthetic payload user."))
    );
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "payload-session"
    );

    let ObservationBody::Message(assistant) = observations[1].body() else {
        panic!("expected nested payload assistant message")
    };
    assert_eq!(
        assistant.content(),
        Some(&JsonValue::string("Synthetic nested assistant."))
    );
    assert_eq!(
        observations[1].session_id().unwrap().value(),
        "nested-payload-session"
    );
    assert_eq!(
        observations[1].source().native_id(),
        Some("nested-payload-id")
    );
    assert_eq!(
        observations[1].occurred_at().unwrap().as_str(),
        "2026-09-04T10:00:01Z"
    );

    let ObservationBody::Tool(tool) = observations[2].body() else {
        panic!("expected payload tool request")
    };
    assert_eq!(
        tool.arguments(),
        Some(
            &JsonValue::object([
                ("path".to_owned(), JsonValue::string("synthetic.txt")),
                (
                    "options".to_owned(),
                    JsonValue::object([("depth".to_owned(), JsonValue::Integer(1))]).unwrap(),
                ),
            ])
            .unwrap(),
        )
    );
    assert_eq!(observations[2].stage(), ObservationStage::ToolRequested);

    let ObservationBody::Message(message) = observations[3].body() else {
        panic!("expected payload message-field message")
    };
    assert_eq!(
        message.content(),
        Some(&JsonValue::string("Synthetic payload message."))
    );
}

#[test]
fn payload_message_identity_is_stable_when_content_changes() {
    let first_directory = tempdir().unwrap();
    let second_directory = tempdir().unwrap();
    let first_path = first_directory.path().join("first.jsonl");
    let second_path = second_directory.path().join("moved.jsonl");
    fs::write(
            &first_path,
            r#"{"payload":{"type":"user","id":"payload-message-identity","sessionId":"stable-payload-session","content":"Synthetic first payload."}}"#,
        )
        .unwrap();
    fs::write(
            &second_path,
            r#"{"payload":{"type":"user","id":"payload-message-identity","sessionId":"stable-payload-session","content":"Synthetic changed payload."}}"#,
        )
        .unwrap();

    let first = project(first_path);
    let changed = project(second_path);
    assert_eq!(
        first[0].source().native_id(),
        Some("payload-message-identity")
    );
    assert_eq!(
        changed[0].source().native_id(),
        Some("payload-message-identity")
    );
    assert!(matches!(
        first[0].identity_basis().coordinate(),
        Some((
            IdentityCoordinateKind::NativeId,
            IdentityCoordinateValue::NativeId(value)
        )) if value == "payload-message-identity"
    ));
    assert_eq!(first[0].observation_id(), changed[0].observation_id());
    let ObservationBody::Message(message) = changed[0].body() else {
        panic!("expected payload message")
    };
    assert_eq!(
        message.content(),
        Some(&JsonValue::string("Synthetic changed payload."))
    );
}

#[test]
fn selected_payload_owns_message_and_tool_evidence_over_outer_fields() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("conflicting-payload.jsonl");
    fs::write(
            &path,
            r#"{"type":"assistant","role":"assistant","sessionId":"outer-session","id":"outer-message-id","timestamp":"2026-09-04T11:00:00Z","content":"Synthetic outer content.","tool_calls":[{"id":"outer-call","name":"outer_tool","arguments":{"command":"outer"}}],"payload":{"type":"user","sessionId":"inner-session","id":"inner-message-id","timestamp":"2026-09-04T11:00:01Z","content":"Synthetic inner content.","tool_calls":[{"id":"inner-call","name":"inner_tool","arguments":{"command":"inner"}}]}}"#,
        )
        .unwrap();

    let observations = project(path);
    assert_eq!(observations.len(), 2);
    let ObservationBody::Message(message) = observations[0].body() else {
        panic!("expected selected payload message")
    };
    assert_eq!(message.role(), Some(MessageRole::User));
    assert_eq!(
        message.content(),
        Some(&JsonValue::string("Synthetic inner content."))
    );
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "inner-session"
    );
    assert_eq!(
        observations[0].source().native_id(),
        Some("inner-message-id")
    );
    assert_eq!(
        observations[0].occurred_at().unwrap().as_str(),
        "2026-09-04T11:00:01Z"
    );

    let ObservationBody::Tool(tool) = observations[1].body() else {
        panic!("expected selected payload tool call")
    };
    assert_eq!(tool.name(), Some("inner_tool"));
    assert_eq!(
        tool.arguments(),
        Some(&JsonValue::object([("command".to_owned(), JsonValue::string("inner"),)]).unwrap())
    );
    assert_eq!(
        observations[1].correlation().call_id().unwrap().value(),
        "inner-call"
    );
}

#[test]
fn selected_payload_call_ids_ignore_outer_tool_results_but_keep_selected_nested_results() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("conflicting-payload-call-ids.jsonl");
    fs::write(
            &path,
            r#"{"call_id":"outer-direct-call","tool_result":{"call_id":"outer-payload-call"},"payload":{"type":"tool_call","sessionId":"payload-call-session","tool_name":"payload_tool","arguments":{"command":"inner"}}}
{"call_id":"outer-direct-result","tool_result":{"tool_use_id":"outer-payload-result"},"payload":{"type":"tool_result","sessionId":"payload-result-session","content":"Synthetic payload result."}}
{"tool_result":{"call_id":"outer-nested-call"},"payload":{"payload":{"type":"tool_call","sessionId":"nested-call-session","tool_name":"nested_tool","arguments":{"command":"nested"},"tool_result":{"call_id":"inner-nested-call"}}}}
{"tool_result":{"tool_use_id":"outer-nested-result"},"payload":{"payload":{"type":"tool_result","sessionId":"nested-result-session","content":"Synthetic nested result.","tool_result":{"tool_use_id":"inner-nested-result"}}}}"#,
        )
        .unwrap();

    let observations = project(path);
    assert_eq!(observations.len(), 4);
    assert_eq!(observations[0].correlation().call_id(), None);
    assert_eq!(observations[1].correlation().call_id(), None);
    assert_eq!(
        observations[2].correlation().call_id().unwrap().value(),
        "inner-nested-call"
    );
    assert_eq!(
        observations[3].correlation().call_id().unwrap().value(),
        "inner-nested-result"
    );
}

#[test]
fn payload_tool_calls_array_is_preserved() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("payload-tool-calls.jsonl");
    fs::write(
            &path,
            r#"{"payload":{"type":"assistant","sessionId":"payload-tool-calls-session","content":"Synthetic response.","tool_calls":[{"id":"payload-call","name":"read_file","arguments":{"path":"synthetic.txt"}}]}}"#,
        )
        .unwrap();

    let observations = project(path);
    assert_eq!(observations.len(), 2);
    let ObservationBody::Tool(tool) = observations[1].body() else {
        panic!("expected payload tool call")
    };
    assert_eq!(tool.name(), Some("read_file"));
    assert_eq!(
        tool.arguments(),
        Some(
            &JsonValue::object([("path".to_owned(), JsonValue::string("synthetic.txt"),)]).unwrap()
        )
    );
    assert_eq!(
        observations[1].correlation().call_id().unwrap().value(),
        "payload-call"
    );
}

#[test]
fn payload_assistant_tool_calls_without_content_skip_empty_message() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("payload-tool-calls-only.jsonl");
    fs::write(
            &path,
            r#"{"payload":{"type":"assistant","sessionId":"payload-tool-calls-only-session","tool_calls":[{"id":"payload-call-only","name":"shell","arguments":{"command":"printf synthetic"}}]}}"#,
        )
        .unwrap();

    let observations = project(path);
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].kind(), ObservationFamily::Tool);
    assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
    let ObservationBody::Tool(tool) = observations[0].body() else {
        panic!("expected payload tool call")
    };
    assert_eq!(tool.name(), Some("shell"));
    assert_eq!(
        tool.arguments(),
        Some(
            &JsonValue::object([("command".to_owned(), JsonValue::string("printf synthetic")),])
                .unwrap()
        )
    );
}

#[test]
fn payload_message_without_evidence_fails_but_top_level_empty_message_remains_valid() {
    let directory = tempdir().unwrap();
    let payload_path = directory.path().join("payload-empty.jsonl");
    fs::write(
            &payload_path,
            r#"{"content":"Synthetic outer content.","sessionId":"outer-session","payload":{"type":"user","sessionId":"payload-empty-session","name":"x"}}"#,
        )
        .unwrap();
    let error = project_openclaw_native_records(
        &super::super::native::extract_openclaw_native_records(&source(payload_path.clone()))
            .unwrap(),
        &OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect_err("payload message without evidence must fail closed");
    assert_eq!(error.code(), "missing_payload_evidence");

    let top_level_path = directory.path().join("top-level-empty.jsonl");
    fs::write(
        &top_level_path,
        r#"{"type":"user","sessionId":"top-level-empty-session"}"#,
    )
    .unwrap();
    let observations = project(top_level_path);
    assert_eq!(observations.len(), 1);
    let ObservationBody::Message(message) = observations[0].body() else {
        panic!("expected top-level empty message")
    };
    assert_eq!(message.content(), None);
}

#[test]
fn payload_generic_tool_snapshot_maps_state_facts_without_execution_lifecycle() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("payload-generic-tool.jsonl");
    fs::write(
            &path,
            r#"{"payload":{"type":"tool","sessionId":"s","tool":"shell","state":{"status":"completed","input":{"command":"printf synthetic"},"output":"ok"}}}"#,
        )
        .unwrap();
    let _source_path = path.clone();
    let observations = project(path);

    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].kind(), ObservationFamily::Tool);
    assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
    let ObservationBody::Tool(request) = observations[0].body() else {
        panic!("expected payload tool request")
    };
    assert_eq!(request.name(), Some("shell"));
    assert_eq!(
        request.arguments(),
        Some(
            &JsonValue::object([("command".to_owned(), JsonValue::string("printf synthetic")),])
                .unwrap()
        )
    );

    assert_eq!(
        observations[1].stage(),
        ObservationStage::ToolResultReturned
    );
    let ObservationBody::Tool(result) = observations[1].body() else {
        panic!("expected payload tool result")
    };
    assert_eq!(result.result(), Some(&JsonValue::string("ok")));
    assert!(observations.iter().all(|observation| {
        observation
            .capability_context()
            .expect("capabilities")
            .resolve(CapabilityId::ToolExecution)
            == CapabilityAvailability::Unknown
            && !matches!(
                observation.stage(),
                ObservationStage::ToolExecutionStarted | ObservationStage::ToolExecutionCompleted
            )
    }));
}

#[test]
fn selected_payload_owns_generic_tool_state_over_outer_state() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("conflicting-tool-state.jsonl");
    fs::write(
            &path,
            r#"{"state":{"status":"completed","input":{"command":"outer"},"output":"Synthetic outer result."},"payload":{"type":"tool","sessionId":"inner-tool-session","call_id":"inner-tool-call","tool":"inner_shell","state":{"status":"completed","input":{"command":"inner"},"output":"Synthetic inner result."}}}"#,
        )
        .unwrap();

    let observations = project(path);
    assert_eq!(observations.len(), 2);
    for observation in &observations {
        assert_eq!(
            observation.session_id().unwrap().value(),
            "inner-tool-session"
        );
        assert_eq!(
            observation.correlation().call_id().unwrap().value(),
            "inner-tool-call"
        );
    }
    let ObservationBody::Tool(request) = observations[0].body() else {
        panic!("expected selected payload tool request")
    };
    assert_eq!(request.name(), Some("inner_shell"));
    assert_eq!(
        request.arguments(),
        Some(&JsonValue::object([("command".to_owned(), JsonValue::string("inner"),)]).unwrap())
    );
    let ObservationBody::Tool(result) = observations[1].body() else {
        panic!("expected selected payload tool result")
    };
    assert_eq!(
        result.result(),
        Some(&JsonValue::string("Synthetic inner result."))
    );
}

#[test]
fn session_metadata_does_not_copy_onto_later_records() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("metadata.jsonl");
    fs::write(
            &path,
            b"{\"type\":\"session_meta\",\"sessionId\":\"metadata-session\",\"agent\":\"fixture-agent\",\"provider\":\"fixture-provider\",\"model\":\"fixture-model\"}\n{\"type\":\"assistant\",\"sessionId\":\"metadata-session\",\"content\":\"Synthetic response.\"}\n",
        )
        .unwrap();

    let native = super::super::native::extract_openclaw_native_records(&source(path.clone()))
        .expect("native records");
    assert_eq!(
        native[0].attestation.as_ref().unwrap().provider.known(),
        Some("fixture-provider")
    );
    assert_eq!(
        native[1].attestation.as_ref().unwrap().provider.known(),
        None
    );
    assert_eq!(native[1].attestation.as_ref().unwrap().agent.known(), None);
}

#[test]
fn canonical_session_does_not_inherit_from_session_meta() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("session-meta-only.jsonl");
    fs::write(
            &path,
            b"{\"type\":\"session_meta\",\"sessionId\":\"meta-session\"}\n{\"type\":\"assistant\",\"content\":\"Synthetic response.\"}\n",
        )
        .unwrap();
    let error = project_openclaw_native_records(
        &super::super::native::extract_openclaw_native_records(&source(path.clone())).unwrap(),
        &OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect_err("session meta must not scope the following record");
    assert_eq!(error.code(), "replay_unverifiable");
    let native = super::super::native::extract_openclaw_native_records(&source(path.clone()))
        .expect("native records");
    assert_eq!(native[1].session_id, None);
}

#[test]
fn native_record_id_is_used_only_for_message_envelopes() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("native-id.jsonl");
    fs::write(
            &path,
            b"{\"type\":\"user\",\"id\":\"message-native-id\",\"content\":\"Synthetic message.\"}\n{\"type\":\"tool_call\",\"sessionId\":\"tool-session\",\"id\":\"call-native-id\",\"name\":\"read_file\",\"input\":{\"path\":\"synthetic.txt\"}}\n",
        )
        .unwrap();
    let observations = project(path);
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].source().native_id(),
        Some("message-native-id")
    );
    assert_eq!(observations[0].session_id(), None);
    assert_eq!(observations[1].source().native_id(), None);
    assert_eq!(
        observations[1].correlation().call_id().unwrap().value(),
        "call-native-id"
    );
}

#[test]
fn source_session_scopes_ids_across_moves_and_content_changes() {
    let first_directory = tempdir().unwrap();
    let second_directory = tempdir().unwrap();
    let first_path = first_directory.path().join("first.jsonl");
    let second_path = second_directory.path().join("moved.jsonl");
    fs::write(
        &first_path,
        r#"{"type":"user","sessionId":"stable-session","content":"Synthetic first message."}"#,
    )
    .unwrap();
    fs::write(
        &second_path,
        r#"{"type":"user","sessionId":"stable-session","content":"Synthetic changed message."}"#,
    )
    .unwrap();
    let first = project(first_path);
    let changed = project(second_path);
    assert_eq!(first[0].observation_id(), changed[0].observation_id());
    assert_eq!(
        first[0]
            .semantic_comparison()
            .compare(changed[0].semantic_comparison()),
        SemanticReplayVerdict::Mutated
    );
    assert!(matches!(
        first[0].identity_basis().coordinate().unwrap().1,
        telltale_schema::observation::IdentityCoordinateValue::SourceSequence {
            namespace,
            ordinal: 0
        } if namespace == "stable-session"
    ));
}

#[test]
fn unknown_canonical_inputs_fail_closed() {
    let unknown = crate::test_fixture_path("parser_maturity/non_discovered/unknown-variant.jsonl");
    let error = project_openclaw_native_records(
        &super::super::native::extract_openclaw_native_records(&source(unknown.clone())).unwrap(),
        &OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect_err("unknown discriminator must fail canonical mapping");
    assert_eq!(error.code(), "unknown_discriminator");
    assert!(!error.to_string().contains("Synthetic unknown"));
    assert!(!format!("{error:?}").contains("Synthetic unknown"));

    let directory = tempdir().unwrap();
    let path = directory.path().join("payload-unknown.jsonl");
    fs::write(
        &path,
        r#"{"payload":{"type":"future_payload_kind","content":"Synthetic payload secret."}}"#,
    )
    .unwrap();
    let error = project_openclaw_native_records(
        &super::super::native::extract_openclaw_native_records(&source(path.clone())).unwrap(),
        &OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect_err("unknown payload discriminator must fail canonical mapping");
    assert_eq!(error.code(), "unknown_discriminator");
    assert!(!error.to_string().contains("Synthetic payload secret"));
    assert!(!format!("{error:?}").contains("payload-unknown.jsonl"));

    let directory = tempdir().unwrap();
    let path = directory.path().join("unknown-block.jsonl");
    fs::write(
            &path,
            br#"{"type":"assistant","sessionId":"unknown-block","content":[{"type":"future_block","value":"synthetic payload"}]}"#,
        )
        .unwrap();
    let error = project_openclaw_native_records(
        &super::super::native::extract_openclaw_native_records(&source(path.clone())).unwrap(),
        &OpenClawCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect_err("unknown content block must fail canonical mapping");
    assert_eq!(error.code(), "unknown_content_block");
    assert!(!error.to_string().contains("synthetic payload"));
}

#[test]
fn source_read_failure_is_distinct() {
    let source = source(crate::test_fixture_path(
        "parser_maturity/non_discovered/schema-drift.jsonl",
    ));
    let error = crate::acquisition::acquire_source(
        &source,
        crate::acquisition::AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .err()
    .expect("schema drift must remain a source error");
    assert_eq!(error.code(), "source_read");
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains("schema-drift.jsonl"));
        assert!(!rendered.contains("Synthetic"));
    }
}
