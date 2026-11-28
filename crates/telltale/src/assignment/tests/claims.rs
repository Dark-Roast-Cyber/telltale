use super::*;

#[cfg(target_os = "linux")]
#[test]
fn claim_replay_reopen_and_mutation_are_deterministic() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let first_id = {
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        let first = store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        let replay = store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        assert_eq!(first.observation_id(), replay.observation_id());
        assert!(valid_prefixed_hex(
            first.observation_id(),
            OBSERVATION_ID_PREFIX
        ));
        let collision = store
            .claim_or_replay(tool_builder("different"), &association(b"record-a"))
            .unwrap_err();
        assert_eq!(collision.code(), "replay_collision");
        first.observation_id().to_owned()
    };
    let mut reopened = ProtectedAssignmentStore::open(&root).unwrap();
    let replay = reopened
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap();
    assert_eq!(replay.observation_id(), first_id);
}

#[cfg(target_os = "linux")]
#[test]
fn long_message_assignment_reopen_hashes_the_full_suffix_without_raw_persistence() {
    use telltale_schema::observation::{JsonValue, MessageObservation, MessageRole};
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let builder = |suffix| {
        // Use the same reviewed coordinate-less test adapter without a tool
        // body or any invented source coordinate.
        CanonicalObservationV2::builder(
            ObservationBody::Message(MessageObservation::new(MessageRole::User).with_content(
                JsonValue::string(format!(
                    "SYNTHETIC-PRIVATE-LONG-{}-{suffix}",
                    "ordinary ".repeat(1_000)
                )),
            )),
            ObservationStage::MessageObserved,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            SourceProvenance::new(
                IngestionMode::SessionStore,
                "synthetic",
                "coordinate-less",
                Fidelity::FullNative,
            )
            .unwrap(),
        )
        .fact_metadata("message.role", FactMetadata::reported().unwrap())
        .fact_metadata("message.content", FactMetadata::reported().unwrap())
    };
    let id = {
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        store
            .claim_or_replay(builder("A"), &association(b"long-record"))
            .unwrap()
            .observation_id()
            .to_owned()
    };
    let mut store = ProtectedAssignmentStore::open(&root).unwrap();
    assert_eq!(
        store
            .claim_or_replay(builder("A"), &association(b"long-record"))
            .unwrap()
            .observation_id(),
        id
    );
    assert_eq!(
        store
            .claim_or_replay(builder("B"), &association(b"long-record"))
            .unwrap_err()
            .code(),
        "replay_collision"
    );
    let database = std::fs::read(root.join(DATABASE_NAME)).unwrap();
    assert!(
        !database
            .windows(b"SYNTHETIC-PRIVATE-LONG".len())
            .any(|bytes| bytes == b"SYNTHETIC-PRIVATE-LONG")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn distinct_stable_associations_can_represent_semantic_duplicates() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = ProtectedAssignmentStore::initialize(private_root(&temp)).unwrap();
    let first = store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap();
    let second = store
        .claim_or_replay(tool_builder("shell"), &association(b"record-b"))
        .unwrap();
    assert_ne!(first.observation_id(), second.observation_id());
}

#[cfg(target_os = "linux")]
#[test]
fn child_ordinal_is_part_of_transactional_uniqueness() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = ProtectedAssignmentStore::initialize(private_root(&temp)).unwrap();
    let first = store
        .claim_or_replay(
            tool_builder("shell").child_ordinal(0),
            &association(b"record-a"),
        )
        .unwrap();
    let second = store
        .claim_or_replay(
            tool_builder("shell").child_ordinal(1),
            &association(b"record-a"),
        )
        .unwrap();
    assert_ne!(first.observation_id(), second.observation_id());
}

#[cfg(target_os = "linux")]
#[test]
fn claim_rejects_coordinate() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = ProtectedAssignmentStore::initialize(private_root(&temp)).unwrap();
    let stable_source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "synthetic",
        "stable",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id("record-a")
    .unwrap();
    let stable = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        stable_source,
    )
    .fact_metadata("tool.name", FactMetadata::reported().unwrap());
    assert_eq!(
        store
            .claim_or_replay(stable, &association(b"record-a"))
            .unwrap_err()
            .code(),
        "invalid_claim"
    );
}

#[test]
fn association_namespace_and_locator_are_bounded() {
    let domain = || AssignmentAdapterDomain::registered("synthetic", "coordinate-less").unwrap();
    assert!(ReplayAssociation::new(domain(), "synthetic-record:v1", b"record").is_ok());
    assert_eq!(
        ReplayAssociation::new(domain(), "unversioned", b"record")
            .unwrap_err()
            .code(),
        "invalid_association"
    );
    assert_eq!(
        ReplayAssociation::new(domain(), "synthetic-record:v1", [])
            .unwrap_err()
            .code(),
        "invalid_association"
    );
    assert_eq!(
        ReplayAssociation::new(
            domain(),
            "synthetic-record:v1",
            vec![b'x'; MAX_ASSOCIATION_LOCATOR_BYTES + 1]
        )
        .unwrap_err()
        .code(),
        "invalid_association"
    );
}
