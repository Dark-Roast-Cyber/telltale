use super::*;

#[test]
fn every_family_has_a_valid_constructed_observation() {
    assert_eq!(ObservationFamily::ALL.len(), 12);
    let cases = [
        (
            ObservationBody::Message(MessageObservation::new(MessageRole::User)),
            ObservationStage::MessageObserved,
            vec!["message.role"],
        ),
        (
            ObservationBody::Inference(
                InferenceObservation::new()
                    .with_provider("synthetic")
                    .unwrap(),
            ),
            ObservationStage::InferenceRequested,
            vec!["inference.provider"],
        ),
        (
            ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
            ObservationStage::ToolProposed,
            vec!["tool.name"],
        ),
        (
            ObservationBody::ToolDefinition(
                ToolDefinitionObservation::new("added")
                    .unwrap()
                    .with_name("shell")
                    .unwrap(),
            ),
            ObservationStage::DefinitionChanged,
            vec!["tool_definition.name", "tool_definition.change"],
        ),
        (
            ObservationBody::Mcp(McpObservation::new("added").unwrap()),
            ObservationStage::McpInventoryChanged,
            vec!["mcp.change"],
        ),
        (
            ObservationBody::Process(ProcessObservation::new().with_operation("exec").unwrap()),
            ObservationStage::ProcessObserved,
            vec!["process.operation"],
        ),
        (
            ObservationBody::File(FileObservation::new().with_operation("read").unwrap()),
            ObservationStage::FileObserved,
            vec!["file.operation"],
        ),
        (
            ObservationBody::Network(NetworkObservation::new().with_state("connected").unwrap()),
            ObservationStage::NetworkObserved,
            vec!["network.state"],
        ),
        (
            ObservationBody::Browser(
                BrowserObservation::new()
                    .with_state_marker("visible")
                    .unwrap(),
            ),
            ObservationStage::BrowserObserved,
            vec!["browser.state_marker"],
        ),
        (
            ObservationBody::Runtime(
                RuntimeObservation::new()
                    .with_state_marker("isolated")
                    .unwrap(),
            ),
            ObservationStage::RuntimeObserved,
            vec!["runtime.state_marker"],
        ),
        (
            ObservationBody::Session(SessionObservation::new(SessionLifecycle::Opened)),
            ObservationStage::SessionOpened,
            vec!["session.lifecycle"],
        ),
        (
            ObservationBody::Other(
                OtherObservation::new("adapter_notice", "capability_gap")
                    .unwrap()
                    .with_summary("fixture")
                    .unwrap(),
            ),
            ObservationStage::OtherObserved,
            vec![
                "other.registered_kind",
                "other.registry_version",
                "other.classification",
                "other.summary",
            ],
        ),
    ];

    for (body, stage, paths) in cases {
        let observation = if matches!(&body, ObservationBody::Session(_)) {
            let session_id =
                CorrelationId::new("session-fixture", CorrelationOrigin::SourceReported).unwrap();
            let mut builder = CanonicalObservationV2::builder(
                body,
                stage,
                ObservedAt::new(OBSERVED_AT).unwrap(),
                source(),
            )
            .session_id(session_id);
            for path in paths {
                builder = builder.fact_metadata(path, metadata(FactProvenance::Reported));
            }
            builder.build().unwrap()
        } else if matches!(
            &body,
            ObservationBody::Process(_) | ObservationBody::File(_) | ObservationBody::Network(_)
        ) {
            let mut builder = CanonicalObservationV2::builder(
                body,
                stage,
                ObservedAt::new(OBSERVED_AT).unwrap(),
                source(),
            );
            for path in paths {
                builder = builder.fact_metadata(path, metadata(FactProvenance::Observed));
            }
            builder.build().unwrap()
        } else {
            build(body, stage, &paths)
        };
        assert_eq!(
            observation.kind().as_str(),
            observation.body().kind().as_str()
        );
    }
}

#[test]
fn tool_lifecycle_stages_are_distinct_and_do_not_infer_failure() {
    let stages = [
        ObservationStage::ToolProposed,
        ObservationStage::ToolRequested,
        ObservationStage::ToolExecutionStarted,
        ObservationStage::ToolExecutionCompleted,
        ObservationStage::ToolResultReturned,
    ];
    let observations = stages.map(|stage| {
        let body = match stage {
            ObservationStage::ToolExecutionCompleted => {
                ToolObservation::new().with_result(JsonValue::string("done"))
            }
            ObservationStage::ToolResultReturned => ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_is_error(true),
            _ => ToolObservation::new().with_name("shell").unwrap(),
        };
        build(
            ObservationBody::Tool(body),
            stage,
            if matches!(stage, ObservationStage::ToolExecutionCompleted) {
                &["tool.result"]
            } else if matches!(stage, ObservationStage::ToolResultReturned) {
                &["tool.name", "tool.is_error"]
            } else {
                &["tool.name"]
            },
        )
    });
    assert_eq!(observations.map(|item| item.stage()), stages);
    assert!(
        build(
            ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
            ObservationStage::ToolRequested,
            &["tool.name"]
        )
        .body()
        .kind()
            == ObservationFamily::Tool
    );
}

#[test]
fn invalid_stage_and_other_registry_are_rejected() {
    let error = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .build()
    .unwrap_err();
    assert_eq!(error.code(), "invalid_stage");
    assert!(OtherObservation::new("unknown", "anything").is_err());
    assert!(OtherObservation::new("adapter_notice", "redaction").is_err());
    assert_eq!(OTHER_REGISTRY_VERSION, "other-v1");

    let session = SessionObservation::new(SessionLifecycle::Opened);
    let mismatch = CanonicalObservationV2::builder(
        ObservationBody::Session(session),
        ObservationStage::SessionClosed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .session_id(CorrelationId::new("session-fixture", CorrelationOrigin::SourceReported).unwrap())
    .fact_metadata("session.lifecycle", metadata(FactProvenance::Reported))
    .build();
    assert_eq!(mismatch.unwrap_err().code(), "family_minimum");
}
