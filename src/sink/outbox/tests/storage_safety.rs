use super::*;

#[cfg(unix)]
#[test]
fn journal_path_hash_is_stable_across_missing_to_created_symlinked_ancestor() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let real_parent = temp.path().join("real");
    let alias_parent = temp.path().join("alias");
    fs::create_dir(&real_parent).expect("real parent");
    symlink(&real_parent, &alias_parent).expect("symlink parent");

    let journal_path = alias_parent.join("events.jsonl");
    let before = journal_path_hash(&journal_path);
    fs::write(&journal_path, b"synthetic journal\n").expect("journal leaf");
    let after = journal_path_hash(&journal_path);

    assert_eq!(before, after);
}

#[cfg(unix)]
#[test]
fn journal_path_hash_distinguishes_symlink_then_parent_alias() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("root");
    let target_nested = temp.path().join("target").join("nested");
    fs::create_dir_all(&root).expect("root");
    fs::create_dir_all(&target_nested).expect("target nested");
    symlink(&target_nested, root.join("alias")).expect("alias symlink");

    let root_journal = root.join("events.jsonl");
    let aliased_parent_journal = root.join("alias").join("..").join("events.jsonl");
    fs::write(&root_journal, b"synthetic-root-journal\n").expect("root journal");
    fs::write(&aliased_parent_journal, b"synthetic-target-journal\n")
        .expect("aliased parent journal");

    assert_eq!(
        fs::read(&root_journal).expect("read root journal"),
        b"synthetic-root-journal\n"
    );
    assert_eq!(
        fs::read(&aliased_parent_journal).expect("read aliased parent journal"),
        b"synthetic-target-journal\n"
    );
    assert_ne!(
        journal_path_hash(&root_journal),
        journal_path_hash(&aliased_parent_journal)
    );
}

#[cfg(unix)]
#[test]
fn outbox_parent_and_database_are_private() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let _outbox = Outbox::open(&path).expect("open outbox");
    let parent_mode = fs::metadata(path.parent().expect("outbox parent"))
        .expect("parent metadata")
        .permissions()
        .mode()
        & 0o777;
    let database = fs::metadata(&path).expect("database metadata");
    assert_eq!(parent_mode, 0o700);
    assert_eq!(database.permissions().mode() & 0o777, 0o600);
    assert_eq!(database.nlink(), 1);
}

#[cfg(unix)]
#[test]
fn unsafe_outbox_database_is_rejected_without_changing_target() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    for case in ["symlink", "hardlink", "broad-mode"] {
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let target = path.with_file_name("synthetic-target");
        fs::write(&target, b"synthetic database bytes").expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("private target");
        let expected = match case {
            "symlink" => {
                symlink(&target, &path).expect("symlink");
                "outbox database is not a regular file"
            }
            "hardlink" => {
                fs::hard_link(&target, &path).expect("hardlink");
                "outbox database hard links are not allowed"
            }
            _ => {
                fs::rename(&target, &path).expect("database");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("broad mode");
                "outbox database permissions are too broad"
            }
        };

        let error = Outbox::open(&path).expect_err("unsafe database");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("storage error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage, "{case}");
        assert!(delivery.message.contains(expected), "{case}: {delivery:?}");
        assert_eq!(
            fs::read(&path).unwrap(),
            b"synthetic database bytes",
            "{case}"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            if case == "broad-mode" { 0o640 } else { 0o600 },
            "{case}"
        );
    }
}

#[cfg(unix)]
#[test]
fn broad_outbox_parent_permissions_are_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().expect("temporary directory");
    let parent = temp.path().join("broad-outbox");
    fs::create_dir(&parent).expect("parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).expect("permissions");
    let error =
        Outbox::open(parent.join("outbox.sqlite")).expect_err("broad parent must be rejected");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured permissions error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(!delivery.message.contains("TT_PRIVACY"));
}

#[test]
fn corrupt_outbox_is_a_bounded_durable_storage_error() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    fs::write(&path, b"synthetic-not-a-sqlite-database").expect("corrupt database");
    make_database_private(&path);

    let error = Outbox::open(&path).expect_err("corrupt database must fail closed");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured corrupt database error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_PRIVACY"));
}

#[test]
fn locked_outbox_fails_closed_without_losing_an_accepted_event() {
    use std::time::{Duration, Instant};

    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let accepted = marked_event("TT_OUTBOX_LOCK_ACCEPTED_26");
    let blocked = marked_event("TT_OUTBOX_LOCK_BLOCKED_26");
    let mut holder = Outbox::open(&path).expect("open holding outbox");
    holder
        .insert_event(&accepted, &["sink-a"])
        .expect("accepted event");
    let mut contender = Outbox::open(&path).expect("open second outbox");
    contender
        .connection
        .busy_timeout(Duration::from_millis(25))
        .expect("bounded contender busy timeout");

    holder
        .connection
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("hold an exclusive lock");
    let started = Instant::now();
    let error = contender
        .insert_event(&blocked, &["sink-a"])
        .expect_err("locked outbox must reject the new event");
    let elapsed = started.elapsed();
    holder
        .connection
        .execute_batch("ROLLBACK")
        .expect("release exclusive lock");

    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured lock error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(
        elapsed < Duration::from_secs(1),
        "lock failure was not bounded"
    );
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_OUTBOX_LOCK"));
    assert!(
        holder
            .get_event(&accepted.event_id)
            .expect("accepted event lookup")
            .is_some()
    );
    assert!(
        contender
            .get_event(&blocked.event_id)
            .expect("blocked event lookup")
            .is_none()
    );
}
