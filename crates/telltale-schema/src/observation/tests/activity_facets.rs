use super::*;

#[test]
fn time_correlation_capability_and_provenance_boundaries_are_explicit() {
    assert!(ObservedAt::new("").is_err());
    assert!(ObservedAt::new("2026-09-02T12:00:00").is_err());
    assert!(CorrelationId::new("../session", CorrelationOrigin::SourceReported).is_err());
    assert!(CorrelationId::new("session", CorrelationOrigin::SourceReported).is_ok());

    let context = CapabilityContext::new()
        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Unsupported)
        .with_override(CapabilityId::ToolExecution, CapabilityAvailability::Unknown);
    assert_eq!(
        context.resolve(CapabilityId::ToolCall),
        CapabilityAvailability::Unsupported
    );
    assert_eq!(
        context.resolve(CapabilityId::ToolExecution),
        CapabilityAvailability::Unknown
    );
    assert_eq!(
        context.resolve(CapabilityId::UserContext),
        CapabilityAvailability::Unknown
    );
    assert_eq!(Fidelity::DerivedOnly.as_str(), "derived_only");
    assert_eq!(FactProvenance::Observed.as_str(), "observed");
    assert_eq!(IngestionMode::Gateway.as_str(), "gateway");

    let parsed_tool = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .facet(
        "network.domain",
        SemanticFacet::new(JsonValue::string("example.invalid")),
    )
    .unwrap()
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("network.domain", metadata(FactProvenance::Parsed))
    .build()
    .unwrap();
    assert_eq!(parsed_tool.kind(), ObservationFamily::Tool);
    let direct_network = CanonicalObservationV2::builder(
        ObservationBody::Network(
            NetworkObservation::new()
                .with_operation("connect")
                .unwrap()
                .with_destination_class("public")
                .unwrap()
                .with_domain("example.invalid")
                .unwrap(),
        ),
        ObservationStage::NetworkObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("network.operation", metadata(FactProvenance::Observed))
    .fact_metadata(
        "network.destination_class",
        metadata(FactProvenance::Observed),
    )
    .fact_metadata("network.domain", metadata(FactProvenance::Observed))
    .build()
    .unwrap();
    assert_eq!(direct_network.kind(), ObservationFamily::Network);

    let no_occurrence = build(
        ObservationBody::Message(MessageObservation::new(MessageRole::Assistant)),
        ObservationStage::MessageObserved,
        &["message.role"],
    );
    assert!(no_occurrence.occurred_at().is_none());
    assert_eq!(no_occurrence.observed_at().as_str(), OBSERVED_AT);
}

#[test]
fn metadata_is_sole_facet_authority_and_observed_activity_is_required() {
    let missing = CanonicalObservationV2::builder(
        ObservationBody::Network(
            NetworkObservation::new()
                .with_destination_class("public")
                .unwrap()
                .with_domain("example.invalid")
                .unwrap(),
        ),
        ObservationStage::NetworkObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata(
        "network.destination_class",
        metadata(FactProvenance::Parsed),
    )
    .fact_metadata("network.domain", metadata(FactProvenance::Parsed))
    .build();
    assert_eq!(missing.unwrap_err().code(), "family_minimum");

    let destination_only = build_with_provenance(
        ObservationBody::Network(
            NetworkObservation::new()
                .with_destination_class("public")
                .unwrap()
                .with_domain("example.invalid")
                .unwrap(),
        ),
        ObservationStage::NetworkObserved,
        &[
            ("network.destination_class", FactProvenance::Observed),
            ("network.domain", FactProvenance::Observed),
        ],
    );
    assert_eq!(destination_only.unwrap_err().code(), "family_minimum");

    let extra = CanonicalObservationV2::builder(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .fact_metadata("native.key", metadata(FactProvenance::Reported))
    .build();
    assert_eq!(extra.unwrap_err().code(), "metadata_coverage");
    let arbitrary = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .facet("native.command", SemanticFacet::new(JsonValue::string("x")));
    assert!(arbitrary.is_err());
}

#[test]
fn parsed_activity_cannot_construct_direct_process_file_or_network() {
    let parsed_process_name = build_with_provenance(
        ObservationBody::Process(ProcessObservation::new().with_name("shell").unwrap()),
        ObservationStage::ProcessObserved,
        &[("process.name", FactProvenance::Parsed)],
    );
    assert_eq!(parsed_process_name.unwrap_err().code(), "family_minimum");

    let parsed_process_activity = build_with_provenance(
        ObservationBody::Process(
            ProcessObservation::new()
                .with_operation("exec")
                .unwrap()
                .with_name("shell")
                .unwrap(),
        ),
        ObservationStage::ProcessObserved,
        &[
            ("process.operation", FactProvenance::Parsed),
            ("process.name", FactProvenance::Parsed),
        ],
    );
    assert_eq!(
        parsed_process_activity.unwrap_err().code(),
        "family_minimum"
    );

    let parsed_file_activity = build_with_provenance(
        ObservationBody::File(
            FileObservation::new()
                .with_operation("read")
                .unwrap()
                .with_path_class("workspace")
                .unwrap(),
        ),
        ObservationStage::FileObserved,
        &[
            ("file.operation", FactProvenance::Parsed),
            ("file.path_class", FactProvenance::Parsed),
        ],
    );
    assert_eq!(parsed_file_activity.unwrap_err().code(), "family_minimum");

    let parsed_network_activity = build_with_provenance(
        ObservationBody::Network(
            NetworkObservation::new()
                .with_operation("connect")
                .unwrap()
                .with_domain("example.invalid")
                .unwrap(),
        ),
        ObservationStage::NetworkObserved,
        &[
            ("network.operation", FactProvenance::Parsed),
            ("network.domain", FactProvenance::Observed),
        ],
    );
    assert_eq!(
        parsed_network_activity.unwrap_err().code(),
        "family_minimum"
    );

    let direct_process = build_with_provenance(
        ObservationBody::Process(ProcessObservation::new().with_state("running").unwrap()),
        ObservationStage::ProcessObserved,
        &[("process.state", FactProvenance::Observed)],
    )
    .unwrap();
    assert_eq!(direct_process.kind(), ObservationFamily::Process);

    let direct_file = build_with_provenance(
        ObservationBody::File(FileObservation::new().with_operation("read").unwrap()),
        ObservationStage::FileObserved,
        &[("file.operation", FactProvenance::Observed)],
    )
    .unwrap();
    assert_eq!(direct_file.kind(), ObservationFamily::File);

    let direct_network = build_with_provenance(
        ObservationBody::Network(NetworkObservation::new().with_state("connected").unwrap()),
        ObservationStage::NetworkObserved,
        &[("network.state", FactProvenance::Observed)],
    )
    .unwrap();
    assert_eq!(direct_network.kind(), ObservationFamily::Network);
}

#[test]
fn parsed_command_facets_remain_tool_observation_facets() {
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .facet(
        "process.name",
        SemanticFacet::new(JsonValue::string("shell")),
    )
    .unwrap()
    .facet(
        "network.domain",
        SemanticFacet::new(JsonValue::string("example.invalid")),
    )
    .unwrap()
    .facet(
        "resource.path",
        SemanticFacet::new(JsonValue::string("workspace/config")),
    )
    .unwrap()
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("process.name", metadata(FactProvenance::Parsed))
    .fact_metadata("network.domain", metadata(FactProvenance::Parsed))
    .fact_metadata("resource.path", metadata(FactProvenance::Parsed))
    .build()
    .unwrap();

    assert_eq!(observation.kind(), ObservationFamily::Tool);
}
