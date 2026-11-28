use super::*;

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
