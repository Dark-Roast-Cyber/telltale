use super::*;

#[test]
fn no_coordinate_has_no_random_fallback_and_assignment_replay_is_protected() {
    let coordinate_less_source = SourceProvenance::new(
        IngestionMode::Import,
        "synthetic",
        "assignment",
        Fidelity::FullNative,
    )
    .unwrap();
    let assignment = LocalReference::new("assignment-ref-1", "assignment").unwrap();
    let basis = IdentityBasis::persisted(
        "synthetic:assignment",
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
        coordinate_less_source.clone(),
    )
    .identity_basis(basis.clone())
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let error = builder.build().unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");

    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        coordinate_less_source.clone(),
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
            AssignmentRecord::new(
                "synthetic:assignment",
                "replay-key-1",
                0,
                "obs:v2:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "assignmentkey:v2:synthetic-1",
                commitment,
            )
            .unwrap(),
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
        coordinate_less_source,
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
            "synthetic:assignment",
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
            AssignmentRecord::new(
                "synthetic:assignment",
                "replay-key-1",
                0,
                "obs:v2:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "missing-key",
                commitment,
            )
            .unwrap(),
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
fn assignment_record_is_bound_to_domain_replay_key_and_child_ordinal() {
    let source = SourceProvenance::new(
        IngestionMode::Import,
        "synthetic",
        "assignment",
        Fidelity::FullNative,
    )
    .unwrap();
    let assignment = LocalReference::new("assignment-ref-bound", "assignment").unwrap();
    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source,
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let commitment = builder.assignment_commitment(ASSIGNMENT_KEY).unwrap();

    for (record_domain, record_replay_key, record_child_ordinal) in [
        ("other:assignment", "replay-key-bound", 0),
        ("synthetic:assignment", "replay-key-other", 0),
        ("synthetic:assignment", "replay-key-bound", 1),
    ] {
        let mut store = InMemoryAssignmentStore::new();
        store
            .insert_key("assignmentkey:v2:synthetic-bound", ASSIGNMENT_KEY)
            .unwrap();
        store
            .insert_assignment(
                assignment.handle(),
                AssignmentRecord::new(
                    record_domain,
                    record_replay_key,
                    record_child_ordinal,
                    "obs:v2:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "assignmentkey:v2:synthetic-bound",
                    &commitment,
                )
                .unwrap(),
            )
            .unwrap();
        let basis = IdentityBasis::persisted(
            "synthetic:assignment",
            "replay-key-bound",
            assignment.clone(),
            0,
            "none",
        )
        .unwrap();
        assert_eq!(
            builder
                .clone()
                .identity_basis(basis)
                .build_with_assignments(&store)
                .unwrap_err()
                .code(),
            "replay_unverifiable"
        );
    }

    let mut store = InMemoryAssignmentStore::new();
    store
        .insert_key("assignmentkey:v2:synthetic-bound", ASSIGNMENT_KEY)
        .unwrap();
    store
        .insert_assignment(
            assignment.handle(),
            AssignmentRecord::new(
                "synthetic:assignment",
                "replay-key-bound",
                0,
                "obs:v2:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "assignmentkey:v2:synthetic-bound",
                commitment,
            )
            .unwrap(),
        )
        .unwrap();
    let wrong_child_basis = IdentityBasis::persisted(
        "synthetic:assignment",
        "replay-key-bound",
        assignment,
        0,
        "none",
    )
    .unwrap();
    assert_eq!(
        builder
            .child_ordinal(1)
            .identity_basis(wrong_child_basis)
            .build_with_assignments(&store)
            .unwrap_err()
            .code(),
        "invalid_identity_basis"
    );
}

#[test]
fn assignment_claim_material_is_io_free_bounded_and_coordinate_less() {
    let coordinate_less_source = SourceProvenance::new(
        IngestionMode::Import,
        "synthetic",
        "assignment",
        Fidelity::FullNative,
    )
    .unwrap();
    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        coordinate_less_source,
    )
    .child_ordinal(7)
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));

    let material = builder.prepare_assignment_claim(ASSIGNMENT_KEY).unwrap();
    assert_eq!(material.adapter_type(), "synthetic");
    assert_eq!(material.adapter_id(), "assignment");
    assert_eq!(material.domain(), "synthetic:assignment");
    assert_eq!(material.child_ordinal(), 7);
    assert_eq!(material.fingerprint_key_epoch_ref(), "none");
    assert!(
        material
            .commitment()
            .starts_with(ASSIGNMENT_COMMITMENT_PREFIX)
    );
    let debug = format!("{material:?}");
    assert!(!debug.contains(material.commitment()));
    assert!(!debug.contains("synthetic:assignment"));

    let stable = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    assert_eq!(
        stable
            .prepare_assignment_claim(ASSIGNMENT_KEY)
            .unwrap_err()
            .code(),
        "invalid_identity_basis"
    );
    assert_eq!(
        builder
            .clone()
            .identity_basis(
                IdentityBasis::persisted(
                    "synthetic:assignment",
                    "replay-key-bound",
                    LocalReference::new("assignment-ref-bound", "assignment").unwrap(),
                    7,
                    "none",
                )
                .unwrap(),
            )
            .prepare_assignment_claim(ASSIGNMENT_KEY)
            .unwrap_err()
            .code(),
        "invalid_identity_basis"
    );
}

#[test]
fn persisted_identity_debug_redacts_protected_local_material() {
    let secret = "synthetic-protected-replay-secret";
    let basis = IdentityBasis::persisted(
        "synthetic:assignment",
        secret,
        LocalReference::new("synthetic-assignment-secret", "assignment").unwrap(),
        0,
        "synthetic-key-secret",
    )
    .unwrap();
    let debug = format!("{basis:?}");
    assert!(!debug.contains(secret));
    assert!(!debug.contains("synthetic-assignment-secret"));
    assert!(!debug.contains("synthetic-key-secret"));

    let record = AssignmentRecord::new(
        "synthetic:assignment",
        secret,
        0,
        "obs:v2:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "synthetic-key-secret",
        format!("{ASSIGNMENT_COMMITMENT_PREFIX}{}", "e".repeat(64)),
    )
    .unwrap();
    let debug = format!("{record:?}");
    assert!(!debug.contains(secret));
    assert!(!debug.contains("synthetic-key-secret"));
    assert!(!debug.contains(&"e".repeat(64)));

    let mut store = InMemoryAssignmentStore::new();
    store
        .insert_key("synthetic-comparison-key", b"synthetic-key-marker")
        .unwrap();
    let debug = format!("{store:?}");
    assert!(!debug.contains("synthetic-comparison-key"));
    assert!(!debug.contains("synthetic-key-marker"));
}
