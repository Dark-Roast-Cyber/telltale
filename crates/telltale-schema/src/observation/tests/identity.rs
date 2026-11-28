use super::*;

#[test]
fn observation_id_shape_is_the_lowercase_prefixed_sha256_digest() {
    assert!(ObservationId::new(format!("obs:v2:sha256:{}", "0a".repeat(32))).is_ok());
    for value in [
        "0a".repeat(32),
        format!("obs:v1:sha256:{}", "0a".repeat(32)),
        format!("obs:v2:sha256:{}", "0A".repeat(32)),
        format!("obs:v2:sha256:{}", "0g".repeat(32)),
        format!("obs:v2:sha256:{}", "a".repeat(63)),
        format!("obs:v2:sha256:{}", "a".repeat(65)),
    ] {
        assert!(ObservationId::new(&value).is_err(), "{value}");
    }
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
    assert_eq!(first.observation_id(), semantic_changed.observation_id());
    assert_eq!(
        first
            .semantic_comparison()
            .compare(semantic_changed.semantic_comparison()),
        SemanticReplayVerdict::Mutated
    );

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
fn stable_identity_is_coordinate_only_and_comparison_detects_mutation() {
    let first = scoped_message(scoped_source("session-a"), "synthetic-first").unwrap();
    let changed = scoped_message(scoped_source("session-a"), "synthetic-second").unwrap();
    assert_eq!(
        first
            .semantic_comparison()
            .compare(first.semantic_comparison()),
        SemanticReplayVerdict::Equivalent
    );
    assert_eq!(first.observation_id(), changed.observation_id());
    assert_eq!(
        first
            .semantic_comparison()
            .compare(changed.semantic_comparison()),
        SemanticReplayVerdict::Mutated
    );

    let versioned_source = scoped_source("session-a")
        .with_adapter_version("fixture-v2")
        .unwrap();
    let versioned = scoped_message(versioned_source, "synthetic-first").unwrap();
    assert_eq!(first.observation_id(), versioned.observation_id());
}

#[test]
fn fingerprint_epoch_changes_are_incomparable_but_not_identity_changes() {
    let secret = JsonValue::string("synthetic-secret-marker");
    let source = scoped_source("session-a")
        .with_producer_identity_key_ref(
            LocalReference::new("producerkey:v2:synthetic-1", "identity_key").unwrap(),
        )
        .unwrap();
    let build_secret = |epoch: &str| {
        let fingerprint = KeyedFingerprint::compute(
            "tool.arguments",
            Sensitivity::Secret,
            &secret,
            epoch,
            PRODUCER_KEY,
        )
        .unwrap();
        CanonicalObservationV2::builder(
            ObservationBody::Tool(
                ToolObservation::new()
                    .with_name("shell")
                    .unwrap()
                    .with_arguments(secret.clone()),
            ),
            ObservationStage::ToolRequested,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            source.clone(),
        )
        .fact_metadata("tool.name", FactMetadata::reported().unwrap())
        .fact_metadata(
            "tool.arguments",
            FactMetadata::new(FactProvenance::Reported, Sensitivity::Secret)
                .unwrap()
                .with_keyed_fingerprint(fingerprint)
                .unwrap(),
        )
        .build()
        .unwrap()
    };
    let first = build_secret("keyepoch:v2:synthetic-1");
    let rotated = build_secret("keyepoch:v2:synthetic-2");
    assert_eq!(first.observation_id(), rotated.observation_id());
    assert_eq!(
        first
            .semantic_comparison()
            .compare(rotated.semantic_comparison()),
        SemanticReplayVerdict::Incomparable
    );
}

#[test]
fn scoped_coordinates_are_required_and_namespaced() {
    let first = scoped_message(scoped_source("session-a"), "synthetic").unwrap();
    let second = scoped_message(scoped_source("session-b"), "synthetic").unwrap();
    assert_ne!(first.observation_id(), second.observation_id());
    let coordinate = first.identity_basis().coordinate().unwrap().1;
    assert!(matches!(
        coordinate,
        IdentityCoordinateValue::SourceSequence {
            namespace,
            ordinal: 0
        } if namespace == "session-a"
    ));
    assert_eq!(
        canonical_identity_json(
            &IdentityCoordinateValue::SourceSequence {
                namespace: "session-a".to_owned(),
                ordinal: 0,
            }
            .as_json()
        )
        .unwrap(),
        br#"["session","session-a",0]"#
    );

    let bare_source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_source_sequence(0);
    assert_eq!(
        scoped_message(bare_source, "synthetic").unwrap_err().code(),
        "replay_unverifiable"
    );
    assert_eq!(
        SourceProvenance::new(
            IngestionMode::SessionStore,
            "synthetic",
            "fixture",
            Fidelity::FullNative,
        )
        .unwrap()
        .with_identity_source_sequence("../session", 0)
        .unwrap_err()
        .code(),
        "path_derived_id"
    );
    let bare_offset = SourceProvenance::new(
        IngestionMode::SessionStore,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_offset("row:0")
    .unwrap();
    assert_eq!(
        scoped_message(bare_offset, "synthetic").unwrap_err().code(),
        "replay_unverifiable"
    );
    let scoped_offset = SourceProvenance::new(
        IngestionMode::SessionStore,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_identity_offset("artifact", "row:0")
    .unwrap();
    assert_eq!(
        scoped_message(scoped_offset, "synthetic")
            .unwrap()
            .identity_basis()
            .coordinate()
            .unwrap()
            .0,
        IdentityCoordinateKind::Offset
    );
}

#[test]
fn stable_sensitive_identity_can_be_unavailable_without_a_key() {
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_arguments(JsonValue::string("synthetic-secret-marker")),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        scoped_source("session-a"),
    )
    .fact_metadata("tool.name", FactMetadata::reported().unwrap())
    .fact_metadata(
        "tool.arguments",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Secret).unwrap(),
    )
    .build()
    .unwrap();
    assert!(matches!(
        observation.semantic_comparison(),
        SemanticComparison::Unavailable
    ));
    assert!(
        !observation
            .observation_id()
            .contains("synthetic-secret-marker")
    );
    assert_eq!(
        observation
            .semantic_comparison()
            .compare(observation.semantic_comparison()),
        SemanticReplayVerdict::Incomparable
    );
}

#[test]
fn comparison_debug_is_redacted() {
    let observation =
        scoped_message(scoped_source("session-a"), "synthetic-secret-marker").unwrap();
    let debug = format!("{:?}", observation.semantic_comparison());
    let display = observation.semantic_comparison().to_string();
    assert!(!debug.contains("sha256:"));
    assert!(!debug.contains("synthetic-secret-marker"));
    assert!(!display.contains("sha256:"));
    assert!(!display.contains("synthetic-secret-marker"));
    assert!(!format!("{observation:?}").contains("synthetic-secret-marker"));
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
        "obs:v2:sha256:81ad3e8e171654579fde3de76a7a9f56bddefa04322928035445932410c4a21c"
    );
}
