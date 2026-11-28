use super::*;

#[test]
fn dispatch_owner_serializes_standalone_ack_and_late_failure() {
    assert_dispatch_ownership(false, false);
}

#[test]
fn dispatch_owner_serializes_admission_before_standalone() {
    assert_dispatch_ownership(true, false);
}

#[test]
fn dispatch_owner_serializes_standalone_before_admission() {
    assert_dispatch_ownership(false, true);
}

#[test]
fn dispatch_owner_failure_preserves_rows_cursor_and_eligible_rotation() {
    let directory = tempdir().unwrap();
    let log = directory.path().join("events.jsonl");
    let path = directory.path().join("private/outbox.sqlite");
    let local = LocalJsonlSink::with_rotation(
        &log,
        RotationConfig {
            max_size_bytes: 1,
            keep: 0,
        },
    )
    .with_durable_rotation();
    let namespace = local.rotation_namespace().unwrap();
    let first = make_health_event();
    local.emit(std::slice::from_ref(&first)).unwrap();
    local.emit(&[make_health_event()]).unwrap();
    let mut outbox = Outbox::open(&path).unwrap();
    outbox.reconcile_jsonl(&log, &["remote"]).unwrap();
    let cursor = outbox.ingest_cursor().unwrap();
    let row = outbox.get_delivery(&first.event_id, "remote").unwrap();
    drop(outbox);
    let generations = super::super::super::jsonl::discover_jsonl_generations(&log).unwrap();
    assert_eq!(generations.len(), 2);
    let journal = fs::read(&log).unwrap();
    let (remote, calls) = ScriptedDurableSink::new("remote", []);
    let mut sinks = durable_sink_set(&path, remote, retry_config(3, 1));
    sinks.add_canonical_first_write_path_with_rotation_and_keep(
        "jsonl",
        Box::new(local),
        log.clone(),
        namespace,
        Some(0),
    );
    let lock = super::super::super::outbox::acquire_admission_lock(&path).unwrap();
    let result = sinks.deliver_durable_with_clock(&FakeClock::new(1_000));
    drop(lock);
    let error = result.expect_err("busy owner must reject before send or pruning");
    let error = error.downcast_ref::<DeliveryError>().unwrap();
    assert_eq!(
        (error.class, error.attempts),
        (DeliveryErrorClass::DurableStorage, 0)
    );
    assert!(calls.lock().unwrap().is_empty());
    let outbox = Outbox::open(&path).unwrap();
    assert_eq!(outbox.get_delivery(&first.event_id, "remote").unwrap(), row);
    assert_eq!(outbox.ingest_cursor().unwrap(), cursor);
    drop(outbox);
    assert_eq!(fs::read(&log).unwrap(), journal);
    assert_eq!(
        super::super::super::jsonl::discover_jsonl_generations(&log)
            .unwrap()
            .len(),
        2
    );
    assert!(
        sinks
            .deliver_durable_with_clock(&FakeClock::new(1_000))
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls.lock().unwrap().len(), 2);
    assert_eq!(
        super::super::super::jsonl::discover_jsonl_generations(&log)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn dispatch_owner_unsafe_sidecar_rejects_before_send_or_update() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("private/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&path, &[&event], &["remote"]).unwrap();
    let before = Outbox::open(&path)
        .unwrap()
        .get_delivery(&event.event_id, "remote")
        .unwrap();
    fs::create_dir(path.with_extension("sqlite.lock")).unwrap();
    let (remote, calls) = ScriptedDurableSink::new("remote", []);
    let sinks = durable_sink_set(&path, remote, retry_config(3, 1));
    let error = sinks
        .deliver_durable_with_clock(&FakeClock::new(1_000))
        .unwrap_err();
    let error = error.downcast_ref::<DeliveryError>().unwrap();
    assert_eq!(
        (error.class, error.attempts),
        (DeliveryErrorClass::DurableStorage, 0)
    );
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(
        Outbox::open(&path)
            .unwrap()
            .get_delivery(&event.event_id, "remote")
            .unwrap(),
        before
    );
}

#[test]
fn durable_dispatch_bounds_each_sink_and_leaves_replayable_work() {
    let directory = tempdir().unwrap();
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
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
    let (first, first_calls) =
        ScriptedDurableSink::new("first", (0..40).map(|_| ScriptedOutcome::Success));
    let (second, second_calls) =
        ScriptedDurableSink::new("second", (0..40).map(|_| ScriptedOutcome::Success));
    sinks.add_best_effort_with_retry("synthetic", Box::new(first), retry_config(3, 1));
    sinks.add_best_effort_with_retry("synthetic", Box::new(second), retry_config(3, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["first".into(), "second".into()],
        capacity_limits(100, u64::MAX),
    );
    let events = (0..40).map(|_| make_health_event()).collect::<Vec<_>>();
    sinks.persist_for_durable_replay(&events).unwrap();
    let clock = FakeClock::new(1_000);
    sinks.deliver_durable_with_clock(&clock).unwrap();
    for calls in [&first_calls, &second_calls] {
        assert_eq!(calls.lock().unwrap().len(), 16);
    }
    let outbox = Outbox::open(&outbox_path).unwrap();
    assert!(events.iter().any(|event| {
        outbox
            .get_delivery(&event.event_id, "first")
            .unwrap()
            .unwrap()
            .state
            == DeliveryState::Pending
    }));
    drop(outbox);
    for _ in 0..2 {
        sinks.deliver_durable_with_clock(&clock).unwrap();
    }
    assert_eq!(first_calls.lock().unwrap().len(), 40);
    assert_eq!(second_calls.lock().unwrap().len(), 40);
}
