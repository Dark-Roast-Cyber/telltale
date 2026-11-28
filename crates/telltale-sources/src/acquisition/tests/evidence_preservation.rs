use super::*;

#[test]
fn openclaw_qwen_acquisition_preserves_coordinates_and_evidence_strength() {
    use telltale_schema::observation::{
        CapabilityAvailability, CapabilityId, JsonValue, ObservationStage,
    };
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic-evidence.jsonl");
    let moved_path = directory.path().join("renamed-evidence.jsonl");
    let input = concat!(
        "{\"type\":\"user\",\"id\":\"native-message\",\"sessionId\":\"source-session\",\"content\":\"synthetic native message\"}\n",
        "{\"type\":\"user\",\"sessionId\":\"source-session\",\"content\":\"synthetic scoped message\"}\n",
        "{\"type\":\"tool_call\",\"sessionId\":\"source-session\",\"callID\":\"source-call\",\"name\":\"shell\",\"input\":{\"command\":\"printf synthetic\",\"path\":\"README.md\"}}\n",
        "{\"type\":\"tool_result\",\"sessionId\":\"source-session\",\"callID\":\"source-call\",\"tool\":\"shell\",\"output\":{\"text\":\"synthetic result\"},\"timestamp\":\"invalid-source-time\"}\n"
    );
    std::fs::write(&path, input).unwrap();
    std::fs::write(&moved_path, input).unwrap();
    for (client, source_id) in [
        (ClientId::OpenClaw, "openclaw.agents"),
        (ClientId::Qwen, "qwen.projects"),
    ] {
        let source = Source {
            client,
            source_id: source_id.to_owned(),
            kind: SourceKind::Jsonl,
            path: path.clone(),
        };
        let batch = super::super::acquire_source(&source, options()).unwrap();
        let relocated = super::super::acquire_source(
            &Source {
                path: moved_path.clone(),
                ..source.clone()
            },
            options(),
        )
        .unwrap();
        let reference = if client == ClientId::OpenClaw {
            super::super::project_openclaw_native_records(
                &super::super::extract_openclaw_native_records(&source).unwrap(),
                &super::super::OpenClawCanonicalOptions::new(options().observed_at),
            )
            .unwrap()
        } else {
            super::super::project_qwen_native_records(
                &super::super::extract_qwen_native_records(&source).unwrap(),
                &super::super::QwenCanonicalOptions::new(options().observed_at),
            )
            .unwrap()
        };
        assert_eq!(batch.progress, AcquisitionProgress::None);
        assert_eq!(batch.observations.len(), 4);
        assert_eq!(
            batch.observations[0].source().native_id(),
            Some("native-message")
        );
        assert!(batch.observations[1].source().native_id().is_none());
        for ((actual, moved), expected) in batch
            .observations
            .iter()
            .zip(&relocated.observations)
            .zip(&reference)
        {
            assert_eq!(actual.observation_id(), moved.observation_id());
            assert_eq!(actual.session_id(), moved.session_id());
            assert_eq!(actual.session_id().unwrap().value(), "source-session");
            assert_eq!(actual.observed_at().as_str(), OBSERVED_AT);
            assert!(actual.occurred_at().is_none());
            assert_eq!(actual.body(), expected.body());
            assert_eq!(actual.correlation(), expected.correlation());
            assert_eq!(actual.capability_context(), expected.capability_context());
            for (capability, availability) in [
                (CapabilityId::ToolCall, CapabilityAvailability::Supported),
                (CapabilityId::UserContext, CapabilityAvailability::Supported),
                (CapabilityId::ToolExecution, CapabilityAvailability::Unknown),
            ] {
                assert_eq!(
                    actual.capability_context().unwrap().resolve(capability),
                    availability
                );
            }
            assert!(matches!(
                actual.body(),
                ObservationBody::Message(_) | ObservationBody::Tool(_)
            ));
            assert!(matches!(
                actual.stage(),
                ObservationStage::MessageObserved
                    | ObservationStage::ToolRequested
                    | ObservationStage::ToolResultReturned
            ));
        }
        for observation in &batch.observations[2..] {
            assert_eq!(
                observation.correlation().call_id().unwrap().value(),
                "source-call"
            );
        }
        let ObservationBody::Tool(request) = batch.observations[2].body() else {
            panic!("expected tool request")
        };
        assert_eq!(
            request.arguments(),
            Some(
                &JsonValue::try_from_source_value(
                    &serde_json::json!({"command":"printf synthetic", "path":"README.md"})
                )
                .unwrap()
            )
        );
        let ObservationBody::Tool(result) = batch.observations[3].body() else {
            panic!("expected tool result")
        };
        assert_eq!(
            result.result(),
            Some(
                &JsonValue::try_from_source_value(&serde_json::json!({"text":"synthetic result"}))
                    .unwrap()
            )
        );

        std::fs::write(
            &moved_path,
            format!("{{\"type\":\"session_meta\"}}\n{input}"),
        )
        .unwrap();
        let shifted = super::super::acquire_source(
            &Source {
                path: moved_path.clone(),
                ..source
            },
            options(),
        )
        .unwrap();
        assert_eq!(
            batch.observations[0].observation_id(),
            shifted.observations[0].observation_id()
        );
        assert_ne!(
            batch.observations[1].observation_id(),
            shifted.observations[1].observation_id()
        );
        std::fs::write(&moved_path, input).unwrap();
    }
}

#[test]
fn copilot_acquisition_preserves_reference_lifecycle_and_evidence() {
    use telltale_schema::observation::{CapabilityAvailability, CapabilityId, ObservationStage};
    let directory = tempdir().unwrap();
    let reactivated = directory.path().join("reactivated.log");
    std::fs::write(&reactivated, concat!(
            "Workspace initialized: session-a (checkpoints: 0)\n",
            "Accumulated output items (2): [{\"type\":\"reasoning\"},{\"type\":\"function_call\",\"name\":\"view\",\"call_id\":\"call-a\"}]\n",
            "Session completed.\nWorkspace initialized: session-b (checkpoints: 0)\n",
            "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
            "Session completed.\nWorkspace initialized: session-a (checkpoints: 0)\n",
            "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\nSession completed.\n"
        )).unwrap();
    for (path, sequences) in [
        (
            crate::test_fixture_path("session_stores/copilot/process-mixed-format.log"),
            vec![1, 2, 3, 3],
        ),
        (
            crate::test_fixture_path("session_stores/copilot/process-multi-session.log"),
            vec![0, 0],
        ),
        (reactivated, vec![1, 0, 2]),
    ] {
        let source = Source {
            client: ClientId::Copilot,
            source_id: "copilot.process_log".to_owned(),
            kind: SourceKind::CopilotProcessLog,
            path,
        };
        let acquired = super::super::acquire_source(&source, options()).unwrap();
        let replay = super::super::acquire_source(&source, options()).unwrap();
        let reference = super::super::project_copilot_native_events(
            &crate::sources::copilot::native::extract_copilot_native_events(&source).unwrap(),
            &super::super::CopilotCanonicalOptions::new(options().observed_at),
        )
        .unwrap();
        assert_eq!(acquired.progress, AcquisitionProgress::None);
        assert_eq!(acquired.observations.len(), reference.len());
        assert_eq!(acquired.observations.len(), replay.observations.len());
        assert_eq!(
            acquired
                .observations
                .iter()
                .map(|o| o.sequence().unwrap())
                .collect::<Vec<_>>(),
            sequences
        );
        for ((actual, expected), repeated) in acquired
            .observations
            .iter()
            .zip(&reference)
            .zip(&replay.observations)
        {
            assert_eq!(actual.observation_id(), expected.observation_id());
            assert_eq!(actual.observation_id(), repeated.observation_id());
            assert_eq!(actual.session_id(), expected.session_id());
            assert_eq!(actual.source(), expected.source());
            assert!(actual.source().native_id().is_none());
            assert_eq!(actual.observed_at().as_str(), OBSERVED_AT);
            assert_eq!(actual.occurred_at(), expected.occurred_at());
            assert_eq!(actual.body(), expected.body());
            assert_eq!(actual.correlation(), expected.correlation());
            assert_eq!(actual.facets(), expected.facets());
            assert_eq!(actual.fact_metadata(), expected.fact_metadata());
            assert_eq!(actual.capability_context(), expected.capability_context());
            for (id, availability) in [
                (CapabilityId::ToolCall, CapabilityAvailability::Supported),
                (CapabilityId::ToolExecution, CapabilityAvailability::Unknown),
                (
                    CapabilityId::UserContext,
                    CapabilityAvailability::Unsupported,
                ),
            ] {
                assert_eq!(
                    actual.capability_context().unwrap().resolve(id),
                    availability
                );
            }
            assert!(matches!(
                actual.body(),
                ObservationBody::Message(_) | ObservationBody::Tool(_)
            ));
            assert!(matches!(
                actual.stage(),
                ObservationStage::MessageObserved
                    | ObservationStage::ToolRequested
                    | ObservationStage::ToolResultReturned
            ));
        }
        if sequences == [1, 2, 3, 3] {
            assert!(matches!(
                acquired.observations[0].body(),
                ObservationBody::Message(_)
            ));
            assert_eq!(
                acquired.observations[0].occurred_at().unwrap().as_str(),
                "2026-04-27T16:17:17.990Z"
            );
            assert_eq!(
                acquired.observations[1]
                    .correlation()
                    .call_id()
                    .unwrap()
                    .value(),
                "call_mixed_001"
            );
        }
    }
}

#[test]
fn copilot_acquisition_failures_preserve_strict_reference_behavior() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("private-path-marker.log");
    let source = Source {
        client: ClientId::Copilot,
        source_id: "copilot.process_log".to_owned(),
        kind: SourceKind::CopilotProcessLog,
        path: path.clone(),
    };
    let init = "Workspace initialized: private-session-marker (checkpoints: 0)\n";
    let item = "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"private-tool-marker\",\"call_id\":\"private-call-marker\",\"arguments\":\"private-argument-marker\",\"message\":\"private-result-marker\"}]\n";
    for (input, expected) in [
        (
            item.to_owned(),
            AcquisitionError::CanonicalMapping {
                code: "replay_unverifiable",
            },
        ),
        (
            format!("{init}{item}Session completed.\n{item}"),
            AcquisitionError::CanonicalMapping {
                code: "replay_unverifiable",
            },
        ),
        (
            format!("{init}{item}Accumulated output items (1): [{{private-malformed-marker"),
            AcquisitionError::CanonicalMapping {
                code: "malformed_structured_output",
            },
        ),
        (
            "Accumulated output items (1): [private-malformed-marker".to_owned(),
            AcquisitionError::CanonicalMapping {
                code: "replay_unverifiable",
            },
        ),
        (
            format!("{init}Accumulated output items (1): [42]"),
            AcquisitionError::SourceRead,
        ),
    ] {
        std::fs::write(&path, input).unwrap();
        let error = acquisition_error(super::super::acquire_source(&source, options()));
        assert_eq!(error, expected);
        assert!(!format!("{error} {error:?}").contains("private-"));
    }
    // Each invocation starts fresh, even after a previous initialized stream.
    std::fs::write(&path, format!("{init}{item}")).unwrap();
    assert!(super::super::acquire_source(&source, options()).is_ok());
    std::fs::write(&path, item).unwrap();
    assert_eq!(
        acquisition_error(super::super::acquire_source(&source, options())).code(),
        "replay_unverifiable"
    );
}
