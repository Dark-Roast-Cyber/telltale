use super::*;

#[test]
fn source_value_and_provenance_helpers_preserve_schema_ownership() {
    let value = JsonValue::try_from_source_value(&serde_json::json!({
        "number": 7,
        "nested": [true, null, "é"],
    }))
    .unwrap();
    assert_eq!(
        value,
        JsonValue::object([
            ("number".to_owned(), JsonValue::Integer(7)),
            (
                "nested".to_owned(),
                JsonValue::array(vec![
                    JsonValue::Bool(true),
                    JsonValue::Null,
                    JsonValue::string("é"),
                ]),
            ),
        ])
        .unwrap()
    );
    assert_eq!(
        FactMetadata::reported().unwrap().provenance(),
        FactProvenance::Reported
    );
    assert_eq!(
        FactMetadata::parsed().unwrap().provenance(),
        FactProvenance::Parsed
    );
    assert_eq!(
        CorrelationId::source_reported("synthetic-session")
            .unwrap()
            .origin(),
        CorrelationOrigin::SourceReported
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
    // Independently calculated HMAC-SHA256 over the canonical JSON tuple.
    assert_eq!(
        fingerprint.digest(),
        "hmac-sha256:v1:aa046bae2d93160005553c2dcbc5e5307169b61df38fae2db735709f4a0cc285"
    );
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
    assert!(matches!(
        observation.semantic_comparison(),
        SemanticComparison::Comparable { .. }
    ));
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
                .with_name("read")
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
