use super::*;

#[cfg(target_os = "linux")]
#[test]
fn privacy_markers_do_not_reach_errors_debug_or_database() {
    let marker = "synthetic-secret-marker://credential@example.invalid";
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    let replay = ReplayAssociation::new(
        AssignmentAdapterDomain::registered("synthetic", "coordinate-less").unwrap(),
        "synthetic-record:v1",
        marker.as_bytes(),
    )
    .unwrap();
    let builder = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string(marker)),
        ),
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
    .fact_metadata(
        "message.content",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Secret).unwrap(),
    );
    let observation = store.claim_or_replay(builder, &replay).unwrap();
    assert!(!format!("{store:?}{replay:?}{observation:?}").contains(marker));
    let error_value = store
        .claim_or_replay(tool_builder("different"), &replay)
        .unwrap_err();
    assert!(!format!("{error_value:?} {error_value}").contains(marker));
    drop(store);
    let database = fs::read(root.join(DATABASE_NAME)).unwrap();
    assert!(
        !database
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    );
    for directory in [
        root.join(KEY_DIRECTORY_NAME),
        root.join(RECEIPT_DIRECTORY_NAME),
    ] {
        for entry in fs::read_dir(directory).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(
                !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
            );
        }
    }
    let authority = fs::read(root.join(AUTHORITY_FILE_NAME)).unwrap();
    assert!(
        !authority
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn unsafe_modes_newer_schema_and_windows_fail_before_use() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    assert_eq!(
        ProtectedAssignmentStore::open_for_platform(&root, true)
            .unwrap_err()
            .code(),
        "unsupported_platform"
    );
    assert!(!root.exists());

    drop(ProtectedAssignmentStore::initialize(&root).unwrap());
    let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
    connection
        .pragma_update(None, "user_version", STORE_SCHEMA_VERSION + 1)
        .unwrap();
    drop(connection);
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "unsupported_version"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(root).unwrap_err().code(),
            "unsafe_storage"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn closed_store_root_can_move_without_changing_assignment() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    let original = store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap()
        .observation_id()
        .to_owned();
    drop(store);
    let moved = temp.path().join("moved-assignment-store");
    fs::rename(root, &moved).unwrap();
    let mut reopened = ProtectedAssignmentStore::open(moved).unwrap();
    assert_eq!(
        reopened
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap()
            .observation_id(),
        original
    );
}
