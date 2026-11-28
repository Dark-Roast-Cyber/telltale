use super::*;

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
