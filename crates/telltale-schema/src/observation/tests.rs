use super::*;

const OBSERVED_AT: &str = "2026-09-02T12:00:00Z";
const PRODUCER_KEY: &[u8] = b"synthetic-only-producer-key-epoch-1";
const ASSIGNMENT_KEY: &[u8] = b"synthetic-only-assignment-comparison-key-1";

fn source() -> SourceProvenance {
    SourceProvenance::new(
        IngestionMode::Harness,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id("native-record-1")
    .unwrap()
}

fn metadata(provenance: FactProvenance) -> FactMetadata {
    FactMetadata::new(provenance, Sensitivity::Normal).unwrap()
}

fn build(body: ObservationBody, stage: ObservationStage, paths: &[&str]) -> CanonicalObservationV2 {
    let mut builder = CanonicalObservationV2::builder(
        body,
        stage,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    );
    for path in paths {
        builder = builder.fact_metadata(*path, metadata(FactProvenance::Reported));
    }
    builder.build().unwrap()
}

fn build_with_provenance(
    body: ObservationBody,
    stage: ObservationStage,
    paths: &[(&str, FactProvenance)],
) -> Result<CanonicalObservationV2, ObservationError> {
    let mut builder = CanonicalObservationV2::builder(
        body,
        stage,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    );
    for (path, provenance) in paths {
        builder = builder.fact_metadata(*path, metadata(*provenance));
    }
    builder.build()
}

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

#[test]
fn identity_is_deterministic_ordered_and_child_specific() {
    let first = build(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        &["message.role"],
    );
    let second = build(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        &["message.role"],
    );
    assert_eq!(first.observation_id(), second.observation_id());
    assert!(valid_observation_id(first.observation_id()));
    assert!(first.observation_id().chars().skip(13).all(
        |character| character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == ':'
    ));

    let changed = CanonicalObservationV2::builder(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source().with_native_id("native-record-2").unwrap(),
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert_ne!(first.observation_id(), changed.observation_id());

    let child = CanonicalObservationV2::builder(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .child_ordinal(1)
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert_ne!(first.observation_id(), child.observation_id());
    assert_eq!(child.identity_basis().child_ordinal(), 1);

    let semantic_changed = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string("changed")),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .fact_metadata("message.content", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert_ne!(first.observation_id(), semantic_changed.observation_id());

    let ordered = SourceProvenance::new(
        IngestionMode::Harness,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id("native-coordinate")
    .unwrap()
    .with_source_sequence(7);
    let ordered_again = ordered.clone().with_source_sequence(8);
    let one = CanonicalObservationV2::builder(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        ordered,
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    let two = CanonicalObservationV2::builder(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        ordered_again,
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert_eq!(one.observation_id(), two.observation_id());
}

#[test]
fn canonical_identity_encoding_normalizes_unicode_and_sorts_objects() {
    let first = JsonValue::object([
        ("z".to_owned(), JsonValue::string("é")),
        ("a".to_owned(), JsonValue::Integer(1)),
    ])
    .unwrap();
    let second = JsonValue::object([
        ("a".to_owned(), JsonValue::Integer(1)),
        ("z".to_owned(), JsonValue::string("e\u{301}")),
    ])
    .unwrap();
    assert_eq!(
        canonical_identity_json(&first).unwrap(),
        canonical_identity_json(&second).unwrap()
    );
    assert_eq!(
        canonical_identity_json(&first).unwrap(),
        "{\"a\":1,\"z\":\"é\"}".as_bytes()
    );
    assert!(canonical_identity_json(&JsonValue::Number(f64::NAN)).is_err());

    let fixture_source = SourceProvenance::new(
        IngestionMode::Harness,
        "fixture.adapter",
        "fixture.harness",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_adapter_version("fixture-1")
    .unwrap()
    .with_native_id("native-basic")
    .unwrap()
    .with_source_sequence(4)
    .with_offset("row:4")
    .unwrap();
    let fixture = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("read")
                .unwrap()
                .with_arguments(
                    JsonValue::object([(
                        "path".to_owned(),
                        JsonValue::string("workspace/SYNTHETIC.txt"),
                    )])
                    .unwrap(),
                ),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        fixture_source,
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("tool.arguments", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert_eq!(
        fixture.observation_id(),
        "obs:v2:sha256:0725791c7bb678b938772a1ac10bcf828289ac30bb243f71eed6a10df90d07cf"
    );
}

#[test]
fn sensitive_semantics_use_keyed_digest_not_raw_value() {
    let secret = JsonValue::string("synthetic-secret-marker");
    let key_ref = LocalReference::new("producerkey:v2:synthetic-1", "identity_key").unwrap();
    let source = source().with_producer_identity_key_ref(key_ref).unwrap();
    let fingerprint = KeyedFingerprint::compute(
        "tool.arguments",
        Sensitivity::Secret,
        &secret,
        "keyepoch:v2:synthetic-1",
        PRODUCER_KEY,
    )
    .unwrap();
    let facts = FactMetadata::new(FactProvenance::Reported, Sensitivity::Secret)
        .unwrap()
        .with_keyed_fingerprint(fingerprint)
        .unwrap();
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_arguments(secret)
                .with_name("shell")
                .unwrap(),
        ),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source,
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("tool.arguments", facts)
    .build()
    .unwrap();
    assert!(
        !observation
            .observation_id()
            .contains("synthetic-secret-marker")
    );
    assert_eq!(
        observation.identity_basis().fingerprint_key_epoch_ref(),
        "keyepoch:v2:synthetic-1"
    );
}

#[test]
fn empty_hmac_keys_fail_closed_without_disclosing_payloads() {
    let error = KeyedFingerprint::compute(
        "tool.arguments",
        Sensitivity::Secret,
        &JsonValue::string("synthetic-secret-marker"),
        "keyepoch:v2:synthetic-1",
        &[],
    )
    .unwrap_err();
    assert_eq!(error.code(), "invalid_fingerprint");
    assert!(!error.to_string().contains("synthetic-secret-marker"));

    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let error = builder.assignment_commitment(&[]).unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");

    let mut store = InMemoryAssignmentStore::new();
    let error = store
        .insert_key("assignmentkey:v2:synthetic-empty", &[])
        .unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");
}

#[test]
fn local_values_store_canonical_unicode() {
    let value = LocalValue::new(
        JsonValue::String("e\u{301}".into()),
        None::<&str>,
        FactProvenance::Reported,
        Sensitivity::Normal,
    )
    .unwrap();
    assert_eq!(value.value(), &JsonValue::string("é"));
}

#[test]
fn semantic_body_and_facet_values_are_bounded_without_payload_errors() {
    let body_error = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_arguments(JsonValue::String("S".repeat(LOCAL_MAX_STRING_BYTES + 1))),
        ),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("tool.arguments", metadata(FactProvenance::Reported))
    .build()
    .unwrap_err();
    assert_eq!(body_error.code(), "unbounded_value");
    assert!(!body_error.to_string().contains('S'));

    let facet_error = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .facet(
        "tool.payload",
        SemanticFacet::new(JsonValue::String("S".repeat(LOCAL_MAX_STRING_BYTES + 1))),
    )
    .unwrap()
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("tool.payload", metadata(FactProvenance::Reported))
    .build()
    .unwrap_err();
    assert_eq!(facet_error.code(), "unbounded_value");
    assert!(!facet_error.to_string().contains('S'));
}

#[test]
fn observation_debug_redacts_body_values() {
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_arguments(JsonValue::string("synthetic-secret-marker")),
        ),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("tool.arguments", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert!(!format!("{observation:?}").contains("synthetic-secret-marker"));
}

#[test]
fn no_coordinate_has_no_random_fallback_and_assignment_replay_is_protected() {
    let source = SourceProvenance::new(
        IngestionMode::Import,
        "synthetic",
        "assignment",
        Fidelity::FullNative,
    )
    .unwrap();
    let assignment = LocalReference::new("assignment-ref-1", "assignment").unwrap();
    let basis = IdentityBasis::persisted(
        "synthetic:assignment:unversioned",
        "replay-key-1",
        assignment.clone(),
        0,
        "none",
    )
    .unwrap();
    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source.clone(),
    )
    .identity_basis(basis.clone())
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let error = builder.build().unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");

    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source.clone(),
    )
    .identity_basis(basis.clone())
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let commitment = builder.assignment_commitment(ASSIGNMENT_KEY).unwrap();
    let mut store = InMemoryAssignmentStore::new();
    store
        .insert_key("assignmentkey:v2:synthetic-1", ASSIGNMENT_KEY)
        .unwrap();
    store
        .insert_assignment(
            assignment.handle(),
            "obs:v2:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "assignmentkey:v2:synthetic-1",
            commitment,
        )
        .unwrap();
    let observation = builder.build_with_assignments(&store).unwrap();
    assert_eq!(
        observation.observation_id(),
        "obs:v2:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    let changed = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("different").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source,
    )
    .identity_basis(basis)
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    assert_eq!(
        changed.build_with_assignments(&store).unwrap_err().code(),
        "replay_collision"
    );

    let missing_key_builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        SourceProvenance::new(
            IngestionMode::Import,
            "synthetic",
            "assignment",
            Fidelity::FullNative,
        )
        .unwrap(),
    )
    .identity_basis(
        IdentityBasis::persisted(
            "synthetic:assignment:unversioned",
            "replay-key-1",
            LocalReference::new("assignment-ref-1", "assignment").unwrap(),
            0,
            "none",
        )
        .unwrap(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let commitment = missing_key_builder
        .assignment_commitment(ASSIGNMENT_KEY)
        .unwrap();
    let mut missing_key_store = InMemoryAssignmentStore::new();
    missing_key_store
        .insert_assignment(
            "assignment-ref-1",
            "obs:v2:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "missing-key",
            commitment,
        )
        .unwrap();
    assert_eq!(
        missing_key_builder
            .build_with_assignments(&missing_key_store)
            .unwrap_err()
            .code(),
        "replay_unverifiable"
    );
}

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
fn local_values_are_structured_bounded_and_not_export_references() {
    let arguments = LocalValue::new(
        JsonValue::object([("command".to_owned(), JsonValue::string("echo synthetic"))]).unwrap(),
        Some("echo synthetic"),
        FactProvenance::Reported,
        Sensitivity::Normal,
    )
    .unwrap();
    let local = LocalEvidence::new()
        .insert("tool.arguments", arguments)
        .unwrap();
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .local(local)
    .build()
    .unwrap();
    assert_eq!(observation.local().unwrap().structured_values().len(), 1);
    assert!(
        LocalEvidence::new()
            .insert(
                "other.payload",
                LocalValue::new(
                    JsonValue::Null,
                    None::<&str>,
                    FactProvenance::Reported,
                    Sensitivity::Normal
                )
                .unwrap()
            )
            .is_err()
    );
    assert!(LocalReference::new("raw-handle", "exportable").is_err());
    let raw_local =
        LocalEvidence::new().with_raw_ref(LocalReference::new("raw-handle", "local_only").unwrap());
    let raw_observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .local(raw_local)
    .build()
    .unwrap();
    assert!(raw_observation.local().unwrap().raw_ref().is_some());
    assert!(
        LocalValue::new(
            JsonValue::Number(f64::INFINITY),
            None::<&str>,
            FactProvenance::Reported,
            Sensitivity::Normal
        )
        .is_err()
    );
    let oversized = LocalValue::new(
        JsonValue::string("S".repeat(LOCAL_MAX_STRING_BYTES + 1)),
        None::<&str>,
        FactProvenance::Reported,
        Sensitivity::Normal,
    )
    .unwrap_err();
    assert!(!oversized.to_string().contains('S'));
    let prohibited = LocalValue::new(
        JsonValue::Null,
        None::<&str>,
        FactProvenance::Reported,
        Sensitivity::Prohibited,
    );
    assert!(prohibited.is_err());
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
