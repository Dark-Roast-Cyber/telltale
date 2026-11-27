use std::fs;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

use telltale_schema::observation::{
    CapabilityAvailability, CapabilityId, ContentPartKind, Fidelity, IngestionMode, JsonValue,
    ObservationBody, ObservationFamily, ObservationStage, ObservedAt,
};
use tempfile::tempdir;

use super::{CopilotCanonicalOptions, project_copilot_native_events};
use crate::sources::copilot::native::{CopilotNativeEvent, extract_copilot_native_events};

const OBSERVED_AT: &str = "2026-09-04T12:00:00Z";

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::Copilot,
        kind: SourceKind::CopilotProcessLog,
        source_id: "copilot.process_log".to_owned(),
        path,
    }
}

fn project(path: std::path::PathBuf) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
    project_copilot_native_events(
        &extract_copilot_native_events(&source(path)).unwrap(),
        &CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect("Copilot canonical observations")
}

#[test]
fn optional_tool_strings_preserve_absent_null_empty_and_valid_compatibility() {
    use crate::acquisition::{AcquisitionOptions, AcquisitionProgress, acquire_source};
    use serde_json::json;

    let directory = tempdir().unwrap();
    let path = directory.path().join("optional-strings.log");
    for optional in [None, Some(json!(null)), Some(json!(""))] {
        let mut item = json!({"type": "function_call", "name": "bash"});
        if let Some(value) = optional {
            for field in ["id", "call_id", "arguments", "message", "role"] {
                item[field] = value.clone();
            }
        }
        fs::write(&path, format!("Workspace initialized: optional-session (checkpoints: 0)\nAccumulated output items (1): {}\n", json!([item]))).unwrap();
        let acquired = acquire_source(
            &source(path.clone()),
            AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap();
        assert_eq!(acquired.progress, AcquisitionProgress::None);
        assert_eq!(acquired.observations.len(), 1);
        let observation = &acquired.observations[0];
        assert_eq!(observation.sequence(), Some(0));
        assert!(observation.correlation().call_id().is_none());
        let ObservationBody::Tool(tool) = observation.body() else {
            panic!("expected tool")
        };
        assert_eq!(tool.name(), Some("bash"));
        assert!(tool.arguments().is_none());
        assert!(tool.searchable_arguments().is_none());
        let repeated = project(path.clone());
        assert_eq!(observation.observation_id(), repeated[0].observation_id());
    }
    for optional in [None, Some(json!(null)), Some(json!(""))] {
        let mut item = json!({"type": "function_call", "arguments": "not-json-synthetic"});
        if let Some(value) = optional {
            item["name"] = value;
        }
        fs::write(&path, format!("Workspace initialized: optional-session (checkpoints: 0)\nAccumulated output items (1): {}\n", json!([item]))).unwrap();
        let observations = project(path.clone());
        let ObservationBody::Tool(tool) = observations[0].body() else {
            panic!("expected tool")
        };
        assert!(tool.name().is_none());
        assert_eq!(
            tool.arguments(),
            Some(&JsonValue::string("not-json-synthetic"))
        );
    }
    for optional in [None, Some(json!(null)), Some(json!(""))] {
        let mut item = json!({"arguments": {"ignored": true}});
        if let Some(value) = optional {
            item["type"] = value;
        }
        fs::write(&path, format!("Workspace initialized: optional-session (checkpoints: 0)\nAccumulated output items (1): {}\n", json!([item]))).unwrap();
        assert!(project(path.clone()).is_empty());
    }
    fs::write(&path, "Workspace initialized: valid-session (checkpoints: 0)\nAccumulated output items (2): [{\"type\":\"function_call\",\"name\":\"bash\",\"call_id\":\"call-a\",\"arguments\":\"{\\\"command\\\":\\\"synthetic-command\\\"}\",\"message\":\"synthetic-result\"},{\"type\":\"function_call\",\"arguments\":\"not-json-synthetic\"}]\n").unwrap();
    let observations = project(path);
    assert_eq!(observations.len(), 3);
    assert_eq!(
        observations[0].correlation().call_id().unwrap().value(),
        "call-a"
    );
    assert_eq!(
        observations[1].correlation().call_id(),
        observations[0].correlation().call_id()
    );
    assert_eq!(
        observations[1].stage(),
        ObservationStage::ToolResultReturned
    );
    assert_eq!(
        observations[0].facets()["command.text"].value(),
        &JsonValue::string("synthetic-command")
    );
    let ObservationBody::Tool(tool) = observations[2].body() else {
        panic!("expected tool")
    };
    assert_eq!(
        tool.arguments(),
        Some(&JsonValue::string("not-json-synthetic"))
    );
    assert_eq!(tool.searchable_arguments(), Some("not-json-synthetic"));
}

#[test]
fn mixed_fixture_preserves_assistant_parts() {
    let path = crate::test_fixture_path("session_stores/copilot/process-mixed-format.log");
    let observations = project(path.clone());
    assert_eq!(observations.len(), 4);
    assert!(observations.iter().all(|observation| {
        observation.source().ingestion_mode() == IngestionMode::SessionStore
            && observation.source().adapter_type() == "copilot"
            && observation.source().adapter_id() == "copilot.process_log"
            && observation.source().fidelity() == Fidelity::PartialStructured
            && observation
                .capability_context()
                .unwrap()
                .resolve(CapabilityId::ToolCall)
                == CapabilityAvailability::Supported
            && observation
                .capability_context()
                .unwrap()
                .resolve(CapabilityId::UserContext)
                == CapabilityAvailability::Unsupported
            && observation
                .capability_context()
                .unwrap()
                .resolve(CapabilityId::ToolExecution)
                == CapabilityAvailability::Unknown
    }));
    let ObservationBody::Message(message) = observations[0].body() else {
        panic!("expected assistant message")
    };
    assert_eq!(message.content_parts().len(), 1);
    assert_eq!(message.content_parts()[0].kind(), ContentPartKind::Text);
    assert_eq!(
        message.content_parts()[0].value(),
        &JsonValue::string("I will inspect synthetic files.")
    );
    assert_eq!(observations[0].stage(), ObservationStage::MessageObserved);
    assert_eq!(
        observations[0].occurred_at().unwrap().as_str(),
        "2026-04-27T16:17:17.990Z"
    );
    assert_eq!(observations[1].source().source_sequence(), Some(2));
    assert_eq!(observations[1].identity_basis().child_ordinal(), 0);
    assert_eq!(observations[2].identity_basis().child_ordinal(), 0);
    assert_eq!(observations[3].identity_basis().child_ordinal(), 1);
    assert_ne!(
        observations[2].observation_id(),
        observations[3].observation_id()
    );
}

#[test]
fn multi_session_boundaries_and_reactivation_use_truthful_ordinals() {
    let path = crate::test_fixture_path("session_stores/copilot/process-multi-session.log");
    let observations = project(path);
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "copilot-multi-session-a"
    );
    assert_eq!(
        observations[1].session_id().unwrap().value(),
        "copilot-multi-session-b"
    );
    assert_eq!(observations[0].sequence(), Some(0));
    assert_eq!(observations[1].sequence(), Some(0));
    assert_ne!(
        observations[0].observation_id(),
        observations[1].observation_id()
    );

    let directory = tempdir().unwrap();
    let repeated = directory.path().join("repeated.log");
    fs::write(
            &repeated,
            "Workspace initialized: repeated-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"reasoning\"}]\nSession completed.\nWorkspace initialized: repeated-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();
    let observations = project(repeated);
    assert_eq!(observations[0].sequence(), Some(1));
}

#[test]
fn tool_identity_is_coordinate_only_and_call_ids_are_optional_correlations() {
    let directory = tempdir().unwrap();
    let first = directory.path().join("first.log");
    let second = directory.path().join("renamed.log");
    let line = "2026-04-27T16:17:17Z [INFO] Workspace initialized: identity-session (checkpoints: 0)\n2026-04-27T16:17:18Z [INFO] Accumulated output items (1): [{\"arguments\":\"{\\\"path\\\":\\\"synthetic-a.txt\\\"}\",\"call_id\":\"call-a\",\"id\":\"c1\",\"name\":\"view\",\"type\":\"function_call\"}]\n";
    fs::write(&first, line).unwrap();
    fs::write(
        &second,
        line.replace("synthetic-a.txt", "synthetic-b.txt")
            .replace("call-a", "call-b"),
    )
    .unwrap();
    let left = project(first);
    let right = project(second);
    assert_eq!(left[0].observation_id(), right[0].observation_id());
    assert_eq!(left[0].identity_basis().child_ordinal(), 0);
    assert_eq!(left[0].source().native_id(), None);
    assert_eq!(left[0].correlation().call_id().unwrap().value(), "call-a");
    let ObservationBody::Tool(tool) = left[0].body() else {
        panic!("expected tool")
    };
    assert_eq!(
        tool.arguments(),
        Some(
            &JsonValue::object([("path".to_owned(), JsonValue::string("synthetic-a.txt"))])
                .unwrap()
        )
    );
    assert_eq!(
        tool.searchable_arguments(),
        Some("{\"path\":\"synthetic-a.txt\"}")
    );
    assert_eq!(
        left[0].facets()["resource.path"].value(),
        &JsonValue::string("synthetic-a.txt")
    );

    let missing = directory.path().join("missing-call.log");
    fs::write(
            &missing,
            "Workspace initialized: missing-call-session (checkpoints: 0)\nAccumulated output items (1): [{\"arguments\":\"not-json-synthetic\",\"id\":\"c1\",\"name\":\"view\",\"type\":\"function_call\"}]\n",
        )
        .unwrap();
    let observations = project(missing);
    assert_eq!(observations[0].correlation().call_id(), None);
    let ObservationBody::Tool(tool) = observations[0].body() else {
        panic!("expected tool")
    };
    assert_eq!(
        tool.arguments(),
        Some(&JsonValue::string("not-json-synthetic"))
    );
    assert_eq!(tool.searchable_arguments(), Some("not-json-synthetic"));
}

#[test]
fn repeated_native_item_ids_do_not_collide_across_source_sessions() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("same-item-id.log");
    fs::write(
            &path,
            "Workspace initialized: collision-session-a (checkpoints: 0)\nAccumulated output items (1): [{\"id\":\"c1\",\"name\":\"view\",\"type\":\"function_call\"}]\nSession completed.\nWorkspace initialized: collision-session-b (checkpoints: 0)\nAccumulated output items (1): [{\"id\":\"c1\",\"name\":\"view\",\"type\":\"function_call\"}]\n",
        )
        .unwrap();
    let observations = project(path);
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].source().native_id(), None);
    assert_eq!(observations[1].source().native_id(), None);
    assert_ne!(
        observations[0].observation_id(),
        observations[1].observation_id()
    );
}

#[test]
fn payload_control_phrases_do_not_change_or_clear_canonical_session() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("payload-control-phrases.log");
    fs::write(
            &path,
            "Workspace initialized: real-session (checkpoints: 0)\nAccumulated output items (2): [{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"before\\nWorkspace initialized: forged-session\"}]},{\"type\":\"function_call\",\"name\":\"view\",\"arguments\":\"{\\\"note\\\":\\\"Workspace initialized: forged-argument\\\",\\\"result\\\":\\\"Session completed.\\\"}\",\"message\":\"Session completed.\",\"result\":\"Workspace initialized: forged-result\"}]\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

    let observations = project(path.clone());
    assert_eq!(observations.len(), 4);
    assert!(
        observations
            .iter()
            .all(|observation| { observation.session_id().unwrap().value() == "real-session" })
    );
    assert_eq!(
        observations
            .iter()
            .map(|observation| observation.sequence())
            .collect::<Vec<_>>(),
        vec![Some(0), Some(1), Some(1), Some(2)]
    );

    let ObservationBody::Message(message) = observations[0].body() else {
        panic!("expected assistant message")
    };
    assert_eq!(
        message.content_parts()[0].value(),
        &JsonValue::string("before\nWorkspace initialized: forged-session")
    );
    let ObservationBody::Tool(result) = observations[2].body() else {
        panic!("expected tool result")
    };
    assert_eq!(
        result.result(),
        Some(&JsonValue::string("Session completed."))
    );
}

#[test]
fn residual_structured_control_suffixes_do_not_change_canonical_session() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("residual-control-suffix.log");
    fs::write(
            &path,
            "Workspace initialized: real-session (checkpoints: 0)\nWorkspace initialized: forged-session [\"encrypted_content\",\"sensitive\"]\nSession completed. [\"encrypted_content\",\"sensitive\"]\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

    let events = extract_copilot_native_events(&source(path.clone())).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, CopilotNativeEvent::WorkspaceInitialized { .. }))
            .count(),
        1
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, CopilotNativeEvent::SessionCompleted))
    );
    assert!(events.iter().all(|event| match event {
        CopilotNativeEvent::WorkspaceInitialized { source_session_id } =>
            source_session_id.as_deref() == Some("real-session"),
        _ => true,
    }));

    let observations = project(path);
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "real-session"
    );
    assert_eq!(observations[0].sequence(), Some(0));
}

#[test]
fn operational_json_control_phrases_do_not_change_or_clear_canonical_session() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("operational-control-phrases.log");
    fs::write(
            &path,
            "2026-04-27T16:17:00Z [DEBUG] {\"event\":\"heartbeat\",\"note\":\"Workspace initialized: forged-session\"}\n2026-04-27T16:17:01Z [INFO] tool output: Workspace initialized: forged-plain-payload\n2026-04-27T16:17:02Z [INFO] Workspace initialized: forged-object-suffix {\"event\":\"heartbeat\"}\n2026-04-27T16:17:03Z [INFO] {\"event\":\"heartbeat\",\"note\":\"Workspace initialized: forged-object-value\",\"status\":\"Session completed.\"}\nWorkspace initialized: real-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n2026-04-27T16:17:04Z [INFO] tool output: Session completed. Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"edit\"}]\n2026-04-27T16:17:05Z [DEBUG] {\"event\":\"heartbeat\",\"note\":\"Workspace initialized: forged-after-tool\"}\n2026-04-27T16:17:06Z [INFO] Session completed. tool output\n2026-04-27T16:17:07Z [INFO] tool output: Session completed.\n2026-04-27T16:17:08Z [DEBUG] {\"event\":\"heartbeat\",\"note\":\"Session completed.\"}\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"bash\"}]\n",
        )
        .unwrap();

    let observations = project(path);
    assert_eq!(observations.len(), 3);
    assert_eq!(
        observations
            .iter()
            .map(|observation| observation.session_id().unwrap().value())
            .collect::<Vec<_>>(),
        vec!["real-session", "real-session", "real-session"]
    );
    assert_eq!(
        observations
            .iter()
            .map(|observation| observation.sequence())
            .collect::<Vec<_>>(),
        vec![Some(0), Some(1), Some(2)]
    );
    let tools = observations
        .iter()
        .filter_map(|observation| match observation.body() {
            ObservationBody::Tool(tool) => tool.name(),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(tools, vec!["view", "edit", "bash"]);
}

#[test]
fn native_control_boundary_stops_before_structured_payload() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("combined-control-output.log");
    fs::write(
            &path,
            "Workspace initialized: combined-session (checkpoints: 0) Accumulated output items (2): [{\"type\":\"reasoning\",\"encrypted_content\":\"fixture-encrypted-reasoning\"},{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

    let events = extract_copilot_native_events(&source(path.clone())).unwrap();
    let CopilotNativeEvent::WorkspaceInitialized { source_session_id } = &events[0] else {
        panic!("expected workspace event")
    };
    assert_eq!(source_session_id.as_deref(), Some("combined-session"));

    let observations = project(path);
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "combined-session"
    );
    assert_eq!(observations[0].sequence(), Some(1));
    assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
}

#[test]
fn completion_line_items_project_before_canonical_session_clear() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("completion-with-output.log");
    fs::write(
            &path,
            "Workspace initialized: completion-line-session (checkpoints: 0)\nSession completed. Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

    let observations = project(path);
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].session_id().unwrap().value(),
        "completion-line-session"
    );
    assert_eq!(observations[0].sequence(), Some(0));
    assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
}

#[test]
fn unsupported_message_shapes_and_completed_status_fail_or_remain_non_results() {
    let directory = tempdir().unwrap();
    let message = directory.path().join("message-shapes.log");
    fs::write(
            &message,
            "Workspace initialized: message-shapes-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"unknown_block\",\"text\":\"secret-marker\"}]}]\n",
        )
        .unwrap();
    let error = project_copilot_native_events(
        &extract_copilot_native_events(&source(message)).unwrap(),
        &CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code(), "unknown_content_block");
    assert!(!format!("{error} {error:?}").contains("secret-marker"));

    let role = directory.path().join("message-role.log");
    fs::write(
            &role,
            "Workspace initialized: message-role-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"message\",\"role\":\"user\",\"content\":[]}]\n",
        )
        .unwrap();
    let error = project_copilot_native_events(
        &extract_copilot_native_events(&source(role)).unwrap(),
        &CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code(), "unsupported_role");

    let completed = directory.path().join("completed.log");
    fs::write(
            &completed,
            "Workspace initialized: completed-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\",\"status\":\"completed\"}]\n",
        )
        .unwrap();
    let observations = project(completed);
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].stage(), ObservationStage::ToolRequested);
}

#[test]
fn malformed_unknown_and_unscoped_output_fail_without_payloads() {
    let directory = tempdir().unwrap();
    let malformed = directory.path().join("malformed.log");
    fs::write(
            &malformed,
            "Workspace initialized: malformed-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\"}\n",
        )
        .unwrap();
    let error = project_copilot_native_events(
        &extract_copilot_native_events(&source(malformed)).unwrap(),
        &CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code(), "malformed_structured_output");
    assert!(!format!("{error:?}").contains("malformed-session"));

    let non_array = directory.path().join("non-array.log");
    fs::write(
            &non_array,
            "Workspace initialized: non-array-session (checkpoints: 0)\nAccumulated output items (1): {\"type\":\"function_call\"}\n",
        )
        .unwrap();
    let error = project_copilot_native_events(
        &extract_copilot_native_events(&source(non_array)).unwrap(),
        &CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code(), "malformed_structured_output");

    let unknown = directory.path().join("unknown.log");
    fs::write(
            &unknown,
            "Workspace initialized: unknown-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"future_variant_secret_marker\",\"encrypted_content\":\"fixture-encrypted-reasoning\"}]\n",
        )
        .unwrap();
    let error = project_copilot_native_events(
        &extract_copilot_native_events(&source(unknown.clone())).unwrap(),
        &CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code(), "unknown_output_item_type");
    let rendered = format!("{error} {error:?}");
    for forbidden in [
        "future_variant_secret_marker",
        "fixture-encrypted-reasoning",
        "unknown-session",
    ] {
        assert!(!rendered.contains(forbidden));
    }

    let unscoped = directory.path().join("unscoped.log");
    fs::write(
        &unscoped,
        "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
    )
    .unwrap();
    let error = project_copilot_native_events(
        &extract_copilot_native_events(&source(unscoped)).unwrap(),
        &CopilotCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");
}

#[test]
fn canonical_rejects_wrong_kind_before_reading_and_preserves_observed_at() {
    let source_path = std::path::PathBuf::from("does-not-exist-process.log");
    let mut wrong = source(source_path);
    wrong.kind = SourceKind::Jsonl;
    let error = crate::acquisition::acquire_source(
        &wrong,
        crate::acquisition::AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .err()
    .expect("wrong kind must fail before reading");
    assert_eq!(error.code(), "source_kind_mismatch");
    assert!(!error.to_string().contains("does-not-exist"));
    assert!(!format!("{error:?}").contains("does-not-exist"));

    let observations = project(crate::test_fixture_path(
        "session_stores/copilot/process-uc001.log",
    ));
    assert!(
        observations
            .iter()
            .all(|observation| observation.observed_at().as_str() == OBSERVED_AT)
    );
}

#[test]
fn no_activity_families_or_execution_lifecycle_are_fabricated() {
    let observations = project(crate::test_fixture_path(
        "session_stores/copilot/process-uc001.log",
    ));
    assert!(observations.iter().all(|observation| {
        observation.kind() != ObservationFamily::Process
            && observation.kind() != ObservationFamily::File
            && observation.kind() != ObservationFamily::Network
            && observation.kind() != ObservationFamily::Inference
            && !matches!(
                observation.stage(),
                ObservationStage::ToolProposed
                    | ObservationStage::ToolExecutionStarted
                    | ObservationStage::ToolExecutionCompleted
            )
    }));
}
