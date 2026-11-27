#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Barrier};
#[cfg(target_os = "linux")]
use std::thread;

#[cfg(target_os = "linux")]
use rusqlite::Connection;
#[cfg(target_os = "linux")]
use telltale_schema::observation::{
    FactMetadata, FactProvenance, Fidelity, IngestionMode, JsonValue, MessageObservation,
    MessageRole, ObservationBody, ObservationStage, ObservedAt, Sensitivity, SourceProvenance,
    ToolObservation,
};

use super::*;

#[cfg(target_os = "linux")]
const OBSERVED_AT: &str = "2026-09-06T12:00:00Z";

#[cfg(target_os = "linux")]
fn private_root(temp: &tempfile::TempDir) -> PathBuf {
    temp.path().join("protected-assignment")
}

#[cfg(target_os = "linux")]
fn tool_builder(name: &str) -> ObservationBuilder {
    CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name(name).unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        SourceProvenance::new(
            IngestionMode::SessionStore,
            "synthetic",
            "coordinate-less",
            Fidelity::FullNative,
        )
        .unwrap(),
    )
    .fact_metadata("tool.name", FactMetadata::reported().unwrap())
}

#[cfg(target_os = "linux")]
fn association(locator: &[u8]) -> ReplayAssociation {
    ReplayAssociation::new(
        AssignmentAdapterDomain::registered("synthetic", "coordinate-less").unwrap(),
        "synthetic-record:v1",
        locator,
    )
    .unwrap()
}

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

#[cfg(target_os = "linux")]
#[test]
fn concurrent_first_claims_converge() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    drop(ProtectedAssignmentStore::initialize(&root).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut store = ProtectedAssignmentStore::open(root).unwrap();
                barrier.wait();
                store
                    .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
                    .unwrap()
                    .observation_id()
                    .to_owned()
            })
        })
        .collect::<Vec<_>>();
    let ids = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids[0], ids[1]);
    let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn process_level_claims_converge() {
    use std::env;
    use std::process::{Command, Stdio};

    if let (Ok(root), Ok(output)) = (
        env::var("TELLTALE_ASSIGNMENT_CHILD_ROOT"),
        env::var("TELLTALE_ASSIGNMENT_CHILD_OUTPUT"),
    ) {
        let mut store = ProtectedAssignmentStore::open(PathBuf::from(root)).unwrap();
        let claimed = store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        fs::write(output, claimed.observation_id()).unwrap();
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    drop(ProtectedAssignmentStore::initialize(&root).unwrap());
    let outputs = [temp.path().join("first.id"), temp.path().join("second.id")];
    let children = outputs
        .iter()
        .map(|output| {
            Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "assignment::tests::process_level_claims_converge",
                ])
                .env("TELLTALE_ASSIGNMENT_CHILD_ROOT", &root)
                .env("TELLTALE_ASSIGNMENT_CHILD_OUTPUT", output)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let statuses = children
        .into_iter()
        .map(|mut child| child.wait().unwrap())
        .collect::<Vec<_>>();
    assert!(statuses.iter().all(|status| status.success()));
    let ids = outputs
        .iter()
        .map(|output| fs::read_to_string(output).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids[0], ids[1]);
    let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn concurrent_commitment_disagreement_has_one_winner() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    drop(ProtectedAssignmentStore::initialize(&root).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let handles = ["shell", "different"]
        .into_iter()
        .map(|name| {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut store = ProtectedAssignmentStore::open(root).unwrap();
                barrier.wait();
                store
                    .claim_or_replay(tool_builder(name), &association(b"record-a"))
                    .map(|observation| observation.observation_id().to_owned())
                    .map_err(|error| error.code())
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .is_err_and(|code| *code == "replay_collision"))
            .count(),
        1
    );
    let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn transaction_fault_boundaries_preserve_claim_semantics() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    store.fail_next_before_commit();
    assert_eq!(
        store
            .claim_or_replay(tool_builder("shell"), &association(b"before"))
            .unwrap_err()
            .code(),
        "storage_unavailable"
    );
    let count: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);

    store.fail_next_after_commit();
    assert_eq!(
        store
            .claim_or_replay(tool_builder("shell"), &association(b"after"))
            .unwrap_err()
            .code(),
        "storage_unavailable"
    );
    drop(store);
    let mut reopened = ProtectedAssignmentStore::open(&root).unwrap();
    let first = reopened
        .claim_or_replay(tool_builder("shell"), &association(b"after"))
        .unwrap();
    let second = reopened
        .claim_or_replay(tool_builder("shell"), &association(b"after"))
        .unwrap();
    assert_eq!(first.observation_id(), second.observation_id());
}

#[cfg(target_os = "linux")]
#[test]
fn rotation_keeps_old_assignments_replayable() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    let old = store
        .claim_or_replay(tool_builder("shell"), &association(b"old"))
        .unwrap()
        .observation_id()
        .to_owned();
    store.rotate_key().unwrap();
    let replay = store
        .claim_or_replay(tool_builder("shell"), &association(b"old"))
        .unwrap();
    assert_eq!(replay.observation_id(), old);
    let new = store
        .claim_or_replay(tool_builder("shell"), &association(b"new"))
        .unwrap();
    assert_ne!(new.observation_id(), old);
    drop(store);
    let mut reopened = ProtectedAssignmentStore::open(root).unwrap();
    assert_eq!(
        reopened
            .claim_or_replay(tool_builder("shell"), &association(b"old"))
            .unwrap()
            .observation_id(),
        old
    );
}

#[cfg(target_os = "linux")]
#[test]
fn association_ambiguity_across_epochs_fails_without_selection() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
    let replay = association(b"ambiguous");
    store
        .claim_or_replay(tool_builder("shell"), &replay)
        .unwrap();
    store.rotate_key().unwrap();

    let key_directory = store.key_directory.clone();
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let epochs = load_key_epochs(&transaction, &key_directory).unwrap();
    let active = exactly_one_active(&epochs).unwrap();
    let comparison_key = derive_subkey(&active.root_key, COMPARISON_SUBKEY_PURPOSE).unwrap();
    let material = tool_builder("shell")
        .prepare_assignment_claim(&comparison_key)
        .unwrap();
    let replay_key = protected_replay_key(
        active,
        material.adapter_type(),
        material.adapter_id(),
        &replay,
    )
    .unwrap();
    let authority = load_authority(&store.authority_path, &epochs).unwrap();
    let stored = allocate_assignment_candidate(
        &transaction,
        active,
        authority.count + 1,
        material.domain(),
        &replay_key,
        material.child_ordinal(),
        material.commitment(),
    )
    .unwrap();
    let receipt = AssignmentReceipt {
        sequence: stored.ledger_sequence,
        previous_head: authority.head,
        assignment: stored.clone(),
    };
    let pending =
        write_pending_receipt(&store.receipt_directory, &receipt, &active.root_key).unwrap();
    insert_assignment(&transaction, &stored).unwrap();
    transaction.commit().unwrap();
    finalize_receipt(
        &store.authority_path,
        &store.receipt_directory,
        &receipt,
        &pending,
        &authority,
        &epochs,
    )
    .unwrap();

    assert_eq!(
        store
            .claim_or_replay(tool_builder("shell"), &replay)
            .unwrap_err()
            .code(),
        "replay_unverifiable"
    );
    let count: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[cfg(target_os = "linux")]
#[test]
fn key_epoch_limit_blocks_rotation_not_replay() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = ProtectedAssignmentStore::initialize(private_root(&temp)).unwrap();
    let original = store
        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
        .unwrap()
        .observation_id()
        .to_owned();
    for _ in 1..MAX_KEY_EPOCHS {
        store.rotate_key().unwrap();
    }
    assert_eq!(
        store.rotate_key().unwrap_err().code(),
        "storage_unavailable"
    );
    assert_eq!(
        store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap()
            .observation_id(),
        original
    );
}

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
fn key_metadata_tamper_and_missing_key_each_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    let store = ProtectedAssignmentStore::initialize(&root).unwrap();
    drop(store);
    let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
    connection
        .execute(
            "UPDATE key_epochs SET metadata_mac = ?1",
            params![vec![0_u8; 32]],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "corrupt_state"
    );

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
    fs::remove_file(key_path(&root.join(KEY_DIRECTORY_NAME), &key_ref).unwrap()).unwrap();
    assert_eq!(
        ProtectedAssignmentStore::open(root).unwrap_err().code(),
        "corrupt_state"
    );

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
    fs::write(
        key_path(&root.join(KEY_DIRECTORY_NAME), &key_ref).unwrap(),
        b"synthetic-malformed-key",
    )
    .unwrap();
    assert_eq!(
        ProtectedAssignmentStore::open(root).unwrap_err().code(),
        "corrupt_state"
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

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platforms_fail_before_state_creation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("protected-assignment");
    assert_eq!(
        ProtectedAssignmentStore::initialize(&root)
            .unwrap_err()
            .code(),
        "unsupported_platform"
    );
    assert!(!root.exists());
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "unsupported_platform"
    );
    assert!(!root.exists());
}
