use super::*;

#[test]
fn prune_pending_generation_is_recovered_after_restart() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let generation = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation");
    assert!(
        mark_generation_prune_pending(&mut outbox.connection, &generation.identity)
            .expect("mark prune pending")
    );
    drop(outbox);

    let mut restarted = Outbox::open(&outbox_path).expect("restart outbox");
    let report = restarted.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 1);
    assert_eq!(report.finalized_pending, 1);
    assert!(
        !rotated.exists(),
        "pending deletion should complete after restart"
    );
}

#[test]
fn missing_prune_pending_file_is_finalized_and_cleanup_is_idempotent() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let generation = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation");
    assert!(
        mark_generation_prune_pending(&mut outbox.connection, &generation.identity)
            .expect("mark prune pending")
    );
    std::fs::remove_file(&rotated).expect("simulate missing rotated file");

    let first = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(first.finalized_pending, 1);
    assert!(first.warnings.is_empty());
    let second = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(second, super::super::PruneReport::default());
}

#[test]
fn invalid_generation_lifecycle_fails_safe_without_pruning_source_bytes() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let rotated_identity = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation")
        .identity;
    drop(outbox);

    let connection = Connection::open(&outbox_path).expect("raw lifecycle fixture");
    if connection
        .pragma_update(None, "ignore_check_constraints", "ON")
        .is_err()
    {
        drop(connection);
        fs::write(&outbox_path, b"synthetic-corrupt-lifecycle-database")
            .expect("corrupt database fallback");
        let error = Outbox::open(&outbox_path).expect_err("corrupt fallback must fail closed");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured corrupt lifecycle fallback error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(outbox_path.exists());
        assert!(rotated.exists(), "corrupt storage must retain JSONL bytes");
        return;
    }
    connection
        .execute(
            "UPDATE journal_generations
                 SET lifecycle = 'synthetic-invalid-lifecycle'
                 WHERE generation_id = ?1",
            [&rotated_identity],
        )
        .expect("insert invalid lifecycle fixture");
    drop(connection);

    let mut reopened = Outbox::open(&outbox_path).expect("reopen normal outbox");
    let report = reopened.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(!report.warnings.is_empty());
    assert!(
        rotated.exists(),
        "invalid lifecycle must retain JSONL bytes"
    );
}

#[test]
fn unknown_or_mismatched_cursor_state_never_authorizes_pruning() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    outbox
        .connection
        .execute(
            "UPDATE ingest_cursor SET generation_id = 'unknown-generation' WHERE id = 1",
            [],
        )
        .expect("corrupt cursor identity");
    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert!(rotated.exists(), "unknown cursor must retain bytes");
    assert_eq!(report.pruned, 0);
    assert!(!report.warnings.is_empty());

    outbox
            .connection
            .execute(
                "UPDATE ingest_cursor SET generation_id = (SELECT generation_id FROM journal_generations WHERE lifecycle = 'present' ORDER BY observed_at LIMIT 1), journal_path_hash = ?1 WHERE id = 1",
                ["f".repeat(64)],
            )
            .expect("corrupt cursor journal binding");
    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert!(rotated.exists(), "mismatched cursor must retain bytes");
    assert_eq!(report.pruned, 0);
}

#[test]
fn rename_restart_keeps_unregistered_generation_until_reconciliation() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut restarted = Outbox::open(&outbox_path).expect("restart outbox");
    let cursor_before = restarted
        .ingest_cursor()
        .expect("cursor before restart")
        .expect("cursor row");
    let rotated_identity = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation")
        .identity;
    assert_eq!(cursor_before.generation_id, rotated_identity);

    // The rename and new active-file write happened before the process
    // stopped. The old cursor and generation metadata are still the only
    // committed state, so cleanup must wait for restart reconciliation.
    let before_reconcile = restarted.prune_eligible_rotations(&log_path, 0);
    assert_eq!(before_reconcile.pruned, 0);
    assert!(!before_reconcile.warnings.is_empty());
    assert!(rotated.exists());

    restarted
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("reconcile renamed generation after restart");
    let after_reconcile = restarted.prune_eligible_rotations(&log_path, 0);
    assert_eq!(after_reconcile.pruned, 1);
    assert!(!rotated.exists());
}

#[test]
fn rotation_pruning_is_serialized_by_the_jsonl_sidecar_lock() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");

    let lock =
        crate::file_lock::SidecarLock::acquire_lock_only(&log_path).expect("hold rotation lock");
    let blocked = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(blocked.pruned, 0);
    assert!(!blocked.warnings.is_empty());
    assert!(rotated.exists(), "a locked lifecycle cannot prune bytes");
    drop(lock);

    let after_release = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(after_release.pruned, 1);
    assert!(!rotated.exists());
}

#[test]
fn corrupt_generation_metadata_disables_pruning() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let rotated_identity = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation")
        .identity;
    outbox
        .connection
        .execute(
            "UPDATE journal_generations SET journal_path_hash = 'corrupt' WHERE generation_id = ?1",
            [&rotated_identity],
        )
        .expect("corrupt generation metadata fixture");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(!report.warnings.is_empty());
    assert!(rotated.exists(), "corrupt metadata must retain JSONL");
}

#[test]
fn deletion_failure_leaves_prune_pending_until_restart_recovery() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let rotated_identity = discover_jsonl_generations(&log_path)
        .expect("discover generations")
        .into_iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation")
        .identity;
    outbox.fail_next_prune_deletion();

    let failed = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(failed.pruned, 0);
    assert!(!failed.warnings.is_empty());
    assert!(rotated.exists(), "failed deletion must retain JSONL");
    let lifecycle: String = outbox
        .connection
        .query_row(
            "SELECT lifecycle FROM journal_generations WHERE generation_id = ?1",
            [&rotated_identity],
            |row| row.get(0),
        )
        .expect("pending lifecycle");
    assert_eq!(lifecycle, "prune_pending");
    drop(outbox);

    let mut restarted = Outbox::open(&outbox_path).expect("restart after deletion failure");
    let recovered = restarted.prune_eligible_rotations(&log_path, 0);
    assert_eq!(recovered.pruned, 1);
    assert_eq!(recovered.finalized_pending, 1);
    assert!(!rotated.exists());
}

#[test]
fn missing_active_generation_disables_pruning() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    fs::remove_file(&log_path).expect("remove active generation");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(!report.warnings.is_empty());
    assert!(rotated.exists(), "missing active state must retain bytes");
}
