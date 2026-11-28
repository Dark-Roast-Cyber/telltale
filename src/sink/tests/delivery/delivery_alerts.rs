use super::*;

#[test]
fn persistent_delivery_alert_is_admitted_once_to_jsonl_and_outbox() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    let alert = operational_alert_event(OperationalAlertInput {
        alert_type: "sink_delivery_failure".to_string(),
        threshold: "attempts_made=1".to_string(),
        actual_value: "sink=synthetic-remote type=synthetic class=transport_no_response"
            .to_string(),
        scan_duration_ms: None,
        scanner_error_count: None,
    });
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
        vec!["synthetic-remote".to_string()],
        CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("persist original event");
    sinks
        .persist_for_durable_replay(std::slice::from_ref(&alert))
        .expect("persist delivery alert");

    let lines = fs::read_to_string(&log_path)
        .expect("canonical JSONL")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSONL event"))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line["event_id"] == event.event_id)
            .count(),
        1
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line["event_id"] == alert.event_id)
            .count(),
        1
    );

    let outbox = Outbox::open(outbox_path).expect("reopen outbox");
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("original event")
            .is_some()
    );
    assert!(
        outbox
            .get_event(&alert.event_id)
            .expect("alert event")
            .is_some()
    );
    assert!(
        outbox
            .get_delivery(&alert.event_id, "synthetic-remote")
            .expect("alert delivery lookup")
            .is_none(),
        "sink-delivery alerts must not become durable replay work"
    );
}

#[test]
fn full_capacity_rejects_delivery_alert_before_append_without_recursion() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    let alert = operational_alert_event(OperationalAlertInput {
        alert_type: "sink_delivery_failure".to_string(),
        threshold: "attempts_made=1".to_string(),
        actual_value: "sink=failed-remote type=synthetic class=transport_no_response".to_string(),
        scan_duration_ms: None,
        scanner_error_count: None,
    });
    let (failed, failed_calls) = ScriptedDurableSink::new(
        "failed-remote",
        [ScriptedOutcome::Failure(
            DeliveryErrorClass::AuthenticationBlocked { status: 403 },
        )],
    );
    let (healthy, healthy_calls, healthy_alert_calls) =
        ScriptedDurableSink::new_with_alerts("healthy-remote", [ScriptedOutcome::Success]);
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
    sinks.add_best_effort_with_retry("synthetic", Box::new(healthy), retry_config(1, 1));
    sinks.add_best_effort_with_retry("synthetic", Box::new(failed), retry_config(1, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["failed-remote".to_string(), "healthy-remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("persist original event");
    let failures = sinks
        .dispatch_durable_with_clock(&FakeClock::new(7_000))
        .expect("record failed delivery");
    assert_eq!(failures.len(), 1);
    let before = fs::read(&log_path).expect("canonical JSONL before alert");

    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&alert))
        .expect_err("full capacity must reject alert before append");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured capacity error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert_eq!(
        fs::read(&log_path).expect("unchanged canonical JSONL"),
        before
    );

    let failed_names = failures
        .iter()
        .map(|failure| failure.name.as_str())
        .collect::<Vec<_>>();
    assert!(
        !sinks
            .deliver_alerts(std::slice::from_ref(&alert), &failed_names)
            .unwrap()
    );
    assert_eq!(failed_calls.lock().expect("failed calls").len(), 1);
    assert_eq!(healthy_calls.lock().expect("healthy calls").len(), 1);
    assert_eq!(*healthy_alert_calls.lock().expect("healthy alert calls"), 0);

    let outbox = Outbox::open(outbox_path).expect("reopen outbox");
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("original event")
            .is_some()
    );
    assert!(
        outbox
            .get_event(&alert.event_id)
            .expect("alert event")
            .is_none()
    );
}

#[test]
fn durable_delivery_failure_alert_is_one_time_and_reaches_healthy_sinks() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    let (failed, failed_calls) = ScriptedDurableSink::new(
        "failed-remote",
        [ScriptedOutcome::Failure(
            DeliveryErrorClass::TransportNoResponse,
        )],
    );
    let (healthy, healthy_calls, healthy_alert_calls) =
        ScriptedDurableSink::new_with_alerts("healthy-remote", [ScriptedOutcome::Success]);
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
    sinks.add_best_effort_with_retry("synthetic", Box::new(failed), retry_config(1, 1));
    sinks.add_best_effort_with_retry("synthetic", Box::new(healthy), retry_config(1, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["failed-remote".to_string(), "healthy-remote".to_string()],
        CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("admit source event");
    let failures = sinks
        .dispatch_durable_with_clock(&FakeClock::new(8_000))
        .expect("record one failed sink and one healthy sink");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].name, "failed-remote");
    assert_eq!(failed_calls.lock().expect("failed calls").len(), 1);
    assert_eq!(healthy_calls.lock().expect("healthy calls").len(), 1);

    let alert = operational_alert_event(OperationalAlertInput {
        alert_type: "sink_delivery_failure".to_string(),
        threshold: format!("attempts_made={}", failures[0].attempts),
        actual_value: format!(
            "sink={} type={} class={}",
            failures[0].name,
            failures[0].kind,
            failures[0].class.as_str()
        ),
        scan_duration_ms: None,
        scanner_error_count: None,
    });
    assert_eq!(alert.check_name.as_deref(), Some("sink_delivery"));
    sinks
        .persist_for_durable_replay(std::slice::from_ref(&alert))
        .expect("admit operational alert once");
    assert!(
        sinks
            .deliver_alerts(std::slice::from_ref(&alert), &[failures[0].name.as_str()])
            .unwrap()
    );
    assert_eq!(
        *healthy_alert_calls.lock().expect("healthy alert calls"),
        1,
        "healthy durable sink receives the one-time operational signal"
    );
    assert_eq!(failed_calls.lock().expect("failed calls").len(), 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen alert outbox");
    assert!(
        outbox
            .get_delivery(&alert.event_id, "failed-remote")
            .expect("failed alert delivery lookup")
            .is_none()
    );
    assert!(
        outbox
            .get_delivery(&alert.event_id, "healthy-remote")
            .expect("healthy alert delivery lookup")
            .is_none()
    );
    drop(outbox);

    for _ in 0..3 {
        assert!(
            sinks
                .dispatch_durable_with_clock(&FakeClock::new(8_000))
                .expect("later durable cycle")
                .is_empty(),
            "delivery-failure alerts must not recurse into later cycles"
        );
    }
    assert_eq!(*healthy_alert_calls.lock().expect("healthy alert calls"), 1);
}
