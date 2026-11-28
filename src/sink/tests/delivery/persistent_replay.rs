use super::*;

#[test]
fn persistent_replay_prunes_ingested_rotation_before_unavailable_delivery() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = marked_event("TT_SINK_ROTATION_FIRST_26");
    let second = marked_event("TT_SINK_ROTATION_SECOND_26");
    let sink = LocalJsonlSink::with_rotation(
        &log_path,
        RotationConfig {
            max_size_bytes: 1,
            keep: 0,
        },
    )
    .with_durable_rotation();
    let namespace = sink.rotation_namespace().expect("rotation namespace");
    let (remote, _) = ScriptedDurableSink::new(
        "remote",
        [ScriptedOutcome::Failure(
            DeliveryErrorClass::TransportNoResponse,
        )],
    );
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation_and_keep(
        "jsonl",
        Box::new(sink),
        log_path.clone(),
        namespace,
        Some(0),
    );
    sinks.add_best_effort("http", Box::new(remote));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path,
        vec!["remote".to_string()],
        CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("persist first event");
    let pre_admission_failures = sinks
        .persist_for_durable_replay_with_failures(std::slice::from_ref(&second))
        .expect("persist and prune rotated event");
    assert_eq!(pre_admission_failures.len(), 1);
    let generations = crate::sink::jsonl::discover_jsonl_generations(&log_path)
        .expect("discover post-prune generations");
    assert!(generations.iter().any(|generation| generation.is_active));
    assert!(generations.iter().all(|generation| generation.is_active));

    let failures = sinks.deliver_durable().expect("post-admission dispatch");
    assert!(failures.is_empty());
}

#[test]
fn persistent_replay_persists_canonical_jsonl_and_outbox_before_delivery() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    let sink = LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled());
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(sink),
        log_path.clone(),
        None,
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path,
        vec!["remote".to_string()],
        super::super::super::outbox::CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("persistent handoff");

    let output = std::fs::read_to_string(log_path).expect("canonical JSONL");
    assert_eq!(output.lines().count(), 1);
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let outbox = Outbox::open(outbox_path).expect("open outbox");
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("outbox event")
            .is_some()
    );
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "remote")
            .expect("outbox delivery")
            .expect("pending delivery")
            .state,
        DeliveryState::Pending
    );
}

#[cfg(unix)]
#[test]
fn persistent_replay_classifies_unresolvable_rollback_journal_without_mutation() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("TT_OUTBOX_PATH_PRIVATE_175.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = make_health_event();
    let second = make_health_event();
    let (remote, calls) = ScriptedDurableSink::new("remote", [ScriptedOutcome::Success]);
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort_with_retry("synthetic", Box::new(remote), retry_config(3, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        CapacityLimits::default(),
    );
    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("admit first event");
    let outbox = Outbox::open_read_only(&outbox_path).expect("read admitted outbox");
    let cursor_before = outbox.ingest_cursor().expect("admitted cursor");
    assert!(cursor_before.is_some());
    let delivery_before = outbox
        .get_delivery(&first.event_id, "remote")
        .expect("admitted delivery")
        .expect("pending delivery");
    assert_eq!(delivery_before.state, DeliveryState::Pending);
    drop(outbox);
    let snapshots = [
        log_path.clone(),
        outbox_path.clone(),
        log_path.with_file_name("TT_OUTBOX_PATH_PRIVATE_175.jsonl.lock"),
        outbox_path.with_file_name("outbox.sqlite.lock"),
    ]
    .map(|path| {
        let bytes = fs::read(&path).expect("persistence snapshot");
        (path, bytes)
    });

    // A dangling journal reaches canonicalization's ENOENT deterministically
    // after symlink_metadata finds it, without racing a SQLite transaction.
    let journal_path = outbox_path.with_file_name("outbox.sqlite-journal");
    let missing_target = directory.path().join("TT_OUTBOX_PATH_PRIVATE_175-missing");
    symlink(&missing_target, &journal_path).expect("dangling rollback journal");
    assert!(
        fs::symlink_metadata(&journal_path)
            .expect("journal symlink exists")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::canonicalize(&journal_path)
            .expect_err("journal target is missing")
            .kind(),
        std::io::ErrorKind::NotFound
    );

    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect_err("unresolvable rollback journal must fail closed");
    assert!(calls.lock().expect("calls lock").is_empty());
    for (path, before) in snapshots {
        assert_eq!(fs::read(path).expect("unchanged persistence bytes"), before);
    }
    assert_eq!(
        fs::read_link(&journal_path).expect("unchanged rollback journal symlink"),
        missing_target
    );
    assert!(!missing_target.exists());
    fs::remove_file(&journal_path).expect("remove synthetic dangling journal");
    let outbox = Outbox::open_read_only(&outbox_path).expect("read unchanged outbox");
    assert_eq!(
        outbox.ingest_cursor().expect("unchanged cursor"),
        cursor_before
    );
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "remote")
            .expect("unchanged delivery"),
        Some(delivery_before)
    );
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("rejected event lookup")
            .is_none()
    );

    let delivery = error
        .downcast_ref::<DeliveryError>()
        .unwrap_or_else(|| panic!("expected structured path-validation error, got {error:?}"));
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert_eq!(delivery.attempts, 0);
    assert!(
        delivery
            .message
            .starts_with("outbox validate JSONL/outbox paths:")
    );
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_OUTBOX_PATH_PRIVATE_175"));
    assert!(
        !delivery
            .message
            .contains(directory.path().to_str().expect("temp path"))
    );
    assert!(!delivery.message.chars().any(char::is_control));
}

#[test]
fn persistent_replay_delivers_canonical_jsonl_only_once() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    let sink = LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled());
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(sink),
        log_path.clone(),
        None,
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path,
        vec!["remote".to_string()],
        super::super::super::outbox::CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("persistent handoff");
    sinks
        .deliver_best_effort(std::slice::from_ref(&event))
        .expect("best-effort delivery");

    let output = std::fs::read_to_string(log_path).expect("canonical JSONL");
    assert_eq!(output.lines().count(), 1);
}

#[test]
fn persistent_replay_survives_best_effort_failure_after_state_handoff() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let state_path = directory.path().join("state.json");
    let event = make_health_event();
    let canonical = LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled());
    let (remote, _) = FailingSink::new("best-effort-remote");
    let (durable, _) = RecordingSink::new("durable-remote");
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(canonical),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort("synthetic", Box::new(remote));
    sinks.add_best_effort("synthetic", Box::new(durable));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["durable-remote".to_string()],
        super::super::super::outbox::CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("durable persistence");
    crate::state::ScanState::default()
        .prepare_atomic_save(&state_path)
        .expect("prepare scanner state")
        .install_replace(&state_path)
        .expect("install scanner state");
    let failures = sinks
        .deliver_best_effort(std::slice::from_ref(&event))
        .expect("best-effort failure is reported");
    assert_eq!(failures.len(), 1);

    assert_eq!(
        std::fs::read_to_string(log_path)
            .expect("JSONL")
            .lines()
            .count(),
        1
    );
    let outbox = Outbox::open(outbox_path).expect("reopen outbox");
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("outbox event")
            .is_some()
    );
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "durable-remote")
            .expect("outbox delivery")
            .expect("pending delivery")
            .state,
        DeliveryState::Pending
    );
}
