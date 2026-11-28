use super::*;

#[cfg(unix)]
#[test]
fn pure_durable_validation_rejects_nontraversable_parent_path_without_artifacts() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("journal").join("events.jsonl");
    let outbox_path = temp
        .path()
        .join("missing")
        .join("..")
        .join("journal")
        .join("events.jsonl");

    let error = match pure_durable_sink_set(&log_path, &outbox_path) {
        Err(error) => error,
        Ok(_) => panic!("nontraversable durable path must be rejected"),
    };
    assert!(
        error
            .to_string()
            .contains("could not resolve persistence path ancestor"),
        "error: {error}"
    );
    assert!(!log_path.exists());
    assert!(!outbox_path.parent().expect("outbox parent").exists());
    assert!(!temp.path().join("missing").exists());
    assert!(!temp.path().join("journal").exists());
}

#[cfg(unix)]
#[test]
fn pure_durable_validation_rejects_traversable_parent_alias_without_artifacts() {
    let temp = tempdir().expect("tempdir");
    let intermediate = temp.path().join("existing");
    std::fs::create_dir(&intermediate).expect("traversable intermediate");
    let log_path = temp.path().join("journal/events.jsonl");
    let outbox_path = intermediate.join("../journal/events.jsonl");

    let error = match pure_durable_sink_set(&log_path, &outbox_path) {
        Err(error) => error,
        Ok(_) => panic!("traversable durable path alias must be rejected"),
    };
    assert!(error.to_string().contains("collides"), "error: {error}");
    assert!(!log_path.exists());
    assert!(!outbox_path.parent().expect("outbox parent").exists());
    assert!(!temp.path().join("journal").exists());
}

#[cfg(unix)]
#[test]
fn pure_durable_validation_rejects_relative_absolute_alias_without_artifacts() {
    let working_dir = std::env::current_dir().expect("working directory");
    let temp = tempdir_in(&working_dir).expect("temporary directory");
    let absolute_path = temp.path().join("events.jsonl");
    let relative_root = temp
        .path()
        .strip_prefix(&working_dir)
        .expect("temporary directory under working directory");
    let relative_path = relative_root.join("events.jsonl");

    let error = match pure_durable_sink_set(&absolute_path, &relative_path) {
        Err(error) => error,
        Ok(_) => panic!("relative/absolute durable path alias must be rejected"),
    };
    assert!(error.to_string().contains("collides"), "error: {error}");
    assert!(!absolute_path.exists());
}

#[cfg(unix)]
#[test]
fn pure_durable_validation_rejects_symlink_parent_alias_without_artifacts() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let real_parent = temp.path().join("real");
    let alias_parent = temp.path().join("alias");
    std::fs::create_dir(&real_parent).expect("real parent");
    symlink(&real_parent, &alias_parent).expect("symlink parent");
    let log_path = real_parent.join("events.jsonl");
    let outbox_path = alias_parent.join("events.jsonl");

    let error = match pure_durable_sink_set(&log_path, &outbox_path) {
        Err(error) => error,
        Ok(_) => panic!("symlink-parent durable path alias must be rejected"),
    };
    assert!(error.to_string().contains("collides"), "error: {error}");
    assert!(!log_path.exists());
    assert!(!outbox_path.exists());
}

#[cfg(unix)]
#[test]
fn pure_durable_validation_rejects_existing_symlink_leaf_alias_without_opening_outbox() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = temp.path().join("outbox.sqlite");
    std::fs::write(&log_path, b"synthetic JSONL fixture\n").expect("log fixture");
    symlink(&log_path, &outbox_path).expect("symlink leaf fixture");

    let error = match pure_durable_sink_set(&log_path, &outbox_path) {
        Err(error) => error,
        Ok(_) => panic!("symlink-leaf durable path alias must be rejected"),
    };
    assert!(error.to_string().contains("collides"), "error: {error}");
    assert_eq!(
        std::fs::read(&log_path).expect("read log fixture"),
        b"synthetic JSONL fixture\n"
    );
}

#[cfg(unix)]
#[test]
fn pure_durable_validation_rejects_existing_hard_link_alias_without_opening_outbox() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = temp.path().join("outbox.sqlite");
    std::fs::write(&log_path, b"synthetic durable path fixture\n").expect("log fixture");
    std::fs::hard_link(&log_path, &outbox_path).expect("hard-link fixture");

    let before = std::fs::read(&log_path).expect("read log fixture");
    let error = match pure_durable_sink_set(&log_path, &outbox_path) {
        Err(error) => error,
        Ok(_) => panic!("hard-linked durable paths must be rejected"),
    };
    assert!(error.to_string().contains("collides"), "error: {error}");
    assert_eq!(
        std::fs::read(&outbox_path).expect("read outbox fixture"),
        before
    );
}

#[cfg(unix)]
#[test]
fn pure_durable_validation_accepts_distinct_paths_without_activation() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");

    let sinks = pure_durable_sink_set(&log_path, &outbox_path).expect("distinct paths");
    assert!(sinks.has_persistent_replay());
    assert!(!outbox_path.exists());
    assert!(!log_path.exists());
    assert!(!outbox_path.parent().expect("outbox parent").exists());
}

#[cfg(unix)]
#[test]
fn pure_durable_validation_rejects_delete_journal_sidecar_alias() {
    let temp = tempdir().expect("tempdir");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");
    let log_path = temp.path().join("private").join("outbox.sqlite-journal");

    let error = match pure_durable_sink_set(&log_path, &outbox_path) {
        Err(error) => error,
        Ok(_) => panic!("SQLite rollback journal alias must be rejected"),
    };
    assert!(error.to_string().contains("journal"), "error: {error}");
    assert!(!outbox_path.parent().expect("outbox parent").exists());
}

#[cfg(unix)]
#[test]
fn pure_durable_validation_rejects_jsonl_coordination_sidecar_alias() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = temp.path().join("events.jsonl.lock");

    let error = match pure_durable_sink_set(&log_path, &outbox_path) {
        Err(error) => error,
        Ok(_) => panic!("JSONL coordination sidecar alias must be rejected"),
    };
    assert!(error.to_string().contains("sidecar"), "error: {error}");
    assert!(!outbox_path.exists());
}
