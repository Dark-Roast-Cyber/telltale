use super::*;

#[cfg(target_os = "linux")]
#[test]
fn row_tamper_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap();
    drop(store);

    let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
    connection
        .execute(
            "UPDATE assignments SET replay_key = ?1",
            params![format!("{REPLAY_KEY_PREFIX}{}", "a".repeat(64))],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        ProtectedAssignmentStore::open(root).unwrap_err().code(),
        "corrupt_state"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn deleted_or_lost_assignment_state_never_allocates_a_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap();
    drop(store);

    let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
    connection.execute("DELETE FROM assignments", []).unwrap();
    drop(connection);
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "corrupt_state"
    );

    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap();
    drop(store);
    fs::remove_file(root.join(DATABASE_NAME)).unwrap();
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "corrupt_state"
    );
    assert!(!root.join(DATABASE_NAME).exists());
    assert_eq!(
        ProtectedAssignmentStore::initialize(&root)
            .unwrap_err()
            .code(),
        "unsafe_storage"
    );

    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    let snapshot = temp.path().join("pre-claim.sqlite3");
    fs::copy(root.join(DATABASE_NAME), &snapshot).unwrap();
    store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap();
    drop(store);
    fs::copy(snapshot, root.join(DATABASE_NAME)).unwrap();
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "corrupt_state"
    );

    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap();
    drop(store);
    let receipt = fs::read_dir(root.join(RECEIPT_DIRECTORY_NAME))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::remove_file(receipt).unwrap();
    assert_eq!(
        ProtectedAssignmentStore::open(root).unwrap_err().code(),
        "corrupt_state"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn same_version_wrong_schema_and_ambiguous_adapter_components_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    drop(ProtectedAssignmentStore::initialize(&root).unwrap());
    let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
    connection.execute("DROP TABLE assignments", []).unwrap();
    connection
        .execute(
            "CREATE TABLE assignments (assignment_ref TEXT PRIMARY KEY)",
            [],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "corrupt_state"
    );

    let temp = tempfile::tempdir().unwrap();
    let mut store = ProtectedAssignmentStore::initialize(private_root(&temp)).unwrap();
    for (adapter_type, adapter_id) in [("a:b", "c"), ("a", "b:c"), ("path", "a/b")] {
        let builder = CanonicalObservationV2::builder(
            ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
            ObservationStage::ToolProposed,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            SourceProvenance::new(
                IngestionMode::SessionStore,
                adapter_type,
                adapter_id,
                Fidelity::FullNative,
            )
            .unwrap(),
        )
        .fact_metadata("tool.name", FactMetadata::reported().unwrap());
        assert_eq!(
            store
                .claim_or_replay(builder, &association(b"record"))
                .unwrap_err()
                .code(),
            "invalid_claim"
        );
    }
    let leaked_type: &'static str = Box::leak("runtime-tenant".to_owned().into_boxed_str());
    let leaked_id: &'static str = Box::leak("runtime-secret".to_owned().into_boxed_str());
    assert_eq!(
        AssignmentAdapterDomain::registered(leaked_type, leaked_id)
            .unwrap_err()
            .code(),
        "invalid_claim"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn live_database_path_replacement_fails_before_another_claim() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap();
    let database_path = root.join(DATABASE_NAME);
    let replacement = temp.path().join("replacement.sqlite3");
    fs::copy(&database_path, &replacement).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(FILE_MODE)).unwrap();
    }
    fs::rename(&database_path, temp.path().join("displaced.sqlite3")).unwrap();
    fs::rename(replacement, &database_path).unwrap();
    assert_eq!(
        store
            .claim_or_replay(tool_builder("shell"), &association(b"record-b"))
            .unwrap_err()
            .code(),
        "unsafe_storage"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn authority_and_receipt_tamper_each_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap();
    drop(store);
    let authority_path = root.join(AUTHORITY_FILE_NAME);
    let mut authority = fs::read(&authority_path).unwrap();
    let last = authority.last_mut().unwrap();
    *last ^= 1;
    fs::write(&authority_path, authority).unwrap();
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "corrupt_state"
    );

    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap();
    drop(store);
    let receipt_path = fs::read_dir(root.join(RECEIPT_DIRECTORY_NAME))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut receipt = fs::read(&receipt_path).unwrap();
    let last = receipt.last_mut().unwrap();
    *last ^= 1;
    fs::write(receipt_path, receipt).unwrap();
    assert_eq!(
        ProtectedAssignmentStore::open(root).unwrap_err().code(),
        "corrupt_state"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn foreign_corrupt_and_linked_storage_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
    }
    let database_path = root.join(DATABASE_NAME);
    let connection = Connection::open(&database_path).unwrap();
    connection
        .execute("CREATE TABLE foreign_state (id INTEGER)", [])
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&database_path, fs::Permissions::from_mode(FILE_MODE)).unwrap();
    }
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "unsafe_storage"
    );

    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    drop(ProtectedAssignmentStore::initialize(&root).unwrap());
    fs::write(root.join(DATABASE_NAME), b"synthetic-corrupt-database").unwrap();
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "corrupt_state"
    );

    #[cfg(unix)]
    {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let store = ProtectedAssignmentStore::initialize(&root).unwrap();
        let key_ref: String = store
            .connection
            .query_row("SELECT key_ref FROM key_epochs LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        drop(store);
        let key = key_path(&root.join(KEY_DIRECTORY_NAME), &key_ref).unwrap();
        fs::hard_link(&key, temp.path().join("linked-key")).unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "unsafe_storage"
        );

        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::set_permissions(&target, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let alias = temp.path().join("alias");
        symlink(&target, &alias).unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(alias).unwrap_err().code(),
            "unsafe_storage"
        );
    }
}
