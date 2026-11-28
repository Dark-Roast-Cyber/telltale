use super::*;

#[test]
fn persistent_replay_rejects_before_append_when_pending_capacity_is_full() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = marked_event("TT_CAPACITY_SINK_FIRST_26");
    let second = marked_event("TT_CAPACITY_SINK_SECOND_26");
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
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("first event persists");
    let before = fs::read(&log_path).expect("canonical JSONL");
    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect_err("second event exceeds pending capacity");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured capacity error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(delivery.message.contains("limit_kind=pending_events"));
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_CAPACITY_SINK"));
    assert_eq!(
        fs::read(&log_path).expect("canonical JSONL unchanged"),
        before
    );
    sinks.durable_capacity_limits = capacity_limits(0, 0);
    sinks
        .persist_for_durable_replay(&[])
        .expect("recovery-only admission must not reject already accepted work");
    assert_eq!(fs::read(&log_path).expect("no empty append"), before);
    assert_eq!(
        fs::read_to_string(&log_path)
            .expect("canonical JSONL")
            .lines()
            .count(),
        1
    );

    let outbox = Outbox::open(outbox_path).expect("reopen outbox");
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("second event lookup")
            .is_none()
    );
    assert!(
        outbox
            .get_event(&first.event_id)
            .expect("first event lookup")
            .is_some()
    );
}

#[test]
fn persistent_replay_rejects_committed_unread_jsonl_before_append() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = marked_event("TT_CAPACITY_SINK_UNREAD_FIRST_26");
    let second = marked_event("TT_CAPACITY_SINK_UNREAD_SECOND_26");
    LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled())
        .emit(std::slice::from_ref(&first))
        .expect("committed canonical JSONL");
    let outbox = Outbox::open(&outbox_path).expect("create empty outbox");
    drop(outbox);
    let before = fs::read(&log_path).expect("canonical JSONL");

    let attempt = || {
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
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["remote".to_string()],
            capacity_limits(1, u64::MAX),
        );
        sinks.persist_for_durable_replay(std::slice::from_ref(&second))
    };

    for error in [
        attempt().expect_err("unread event consumes the one-event capacity"),
        attempt().expect_err("the same result survives outbox reopen"),
    ] {
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured capacity error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(delivery.message.contains("limit_kind=pending_events"));
        assert!(delivery.message.len() <= 200);
        assert!(!delivery.message.contains("TT_CAPACITY_SINK"));
    }
    assert_eq!(
        fs::read(&log_path).expect("canonical JSONL unchanged"),
        before
    );
    let outbox = Outbox::open(outbox_path).expect("reopen empty outbox");
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("second event lookup")
            .is_none()
    );
    assert!(
        outbox
            .get_event(&first.event_id)
            .expect("first recovered event lookup")
            .is_some(),
        "the already committed event must be reconciled before the new-event gate"
    );
    let cursor = outbox
        .ingest_cursor()
        .expect("recovered cursor lookup")
        .expect("recovered cursor");
    assert_eq!(cursor.byte_offset, before.len() as u64);
}

#[test]
fn persistent_replay_recovers_before_capacity_scan_when_unread_bytes_exceed_limit() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = marked_event("TT_CAPACITY_SINK_BOUNDED_RECOVERY_FIRST_26");
    let second = marked_event("TT_CAPACITY_SINK_BOUNDED_RECOVERY_SECOND_26");
    LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled())
        .emit(std::slice::from_ref(&first))
        .expect("committed canonical JSONL");
    let before = fs::read(&log_path).expect("canonical JSONL");
    assert!(before.len() > 1, "synthetic record must exceed scan limit");

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
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );
    // The production bound remains 64 MiB. This injected test limit makes
    // the already-committed record exceed the unread scan bound without
    // allocating a 64 MiB fixture. Recovery must advance the cursor first.
    sinks.set_durable_capacity_scan_limit((before.len() as u64) - 1);

    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect_err("new event must be rejected after recovery fills capacity");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured capacity error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(delivery.message.contains("limit_kind=pending_events"));
    assert!(
        !delivery
            .message
            .contains("capacity scan exceeds the bounded inspection range")
    );
    assert_eq!(
        fs::read(&log_path).expect("canonical JSONL unchanged"),
        before
    );

    let outbox = Outbox::open(outbox_path).expect("reopen recovered outbox");
    assert!(
        outbox
            .get_event(&first.event_id)
            .expect("first recovered event lookup")
            .is_some()
    );
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("prospective event lookup")
            .is_none()
    );
    assert_eq!(
        outbox
            .ingest_cursor()
            .expect("cursor lookup")
            .expect("recovered cursor")
            .byte_offset,
        before.len() as u64
    );
}

#[test]
fn persistent_replay_rejects_uncertain_capacity_before_append() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = marked_event("TT_CAPACITY_SINK_UNCERTAIN_FIRST_26");
    let second = marked_event("TT_CAPACITY_SINK_UNCERTAIN_SECOND_26");
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
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(10, u64::MAX),
    );
    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("initialize durable journal metadata");

    fs::OpenOptions::new()
        .write(true)
        .open(&log_path)
        .expect("open journal for deterministic truncation")
        .set_len(0)
        .expect("truncate journal");
    let after_truncation = fs::read(&log_path).expect("truncated JSONL");
    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect_err("uncertain journal capacity must fail closed");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured durable storage error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_CAPACITY_SINK"));
    assert_eq!(
        fs::read(&log_path).expect("journal unchanged"),
        after_truncation
    );

    let outbox = Outbox::open(outbox_path).expect("reopen outbox");
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("second event lookup")
            .is_none()
    );
}
