use super::*;

#[test]
fn durable_retryable_failure_waits_for_the_fake_clock_before_ack() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::TransportNoResponse),
            ScriptedOutcome::Success,
        ],
    );
    let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 100));
    let clock = FakeClock::new(1_000);

    let failures = sinks
        .dispatch_durable_with_clock(&clock)
        .expect("schedule retry");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].class, DeliveryErrorClass::TransportNoResponse);
    assert_eq!(calls.lock().expect("calls lock").len(), 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("pending row");
    assert_eq!(row.state, DeliveryState::Pending);
    assert_eq!(row.next_attempt_at, Some(1_100));
    assert_eq!(
        row.last_error_class,
        Some(DeliveryErrorClass::TransportNoResponse)
    );
    assert!(
        outbox
            .next_ready_delivery("remote", clock.now_millis())
            .expect("ready lookup")
            .is_none()
    );
    drop(outbox);

    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("not due dispatch");
    assert_eq!(calls.lock().expect("calls lock").len(), 1);

    clock.advance(100);
    let failures = sinks
        .dispatch_durable_with_clock(&clock)
        .expect("retry succeeds");
    assert!(failures.is_empty());
    assert_eq!(calls.lock().expect("calls lock").len(), 2);
    let outbox = Outbox::open(&outbox_path).expect("reopen acked outbox");
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("acked row");
    assert_eq!(row.state, DeliveryState::Acked);
    assert_eq!(row.next_attempt_at, None);
}

#[test]
fn pending_retry_time_survives_outbox_and_sink_set_restart() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");
    let clock = FakeClock::new(2_000);

    let (first_sink, first_calls) = ScriptedDurableSink::new(
        "remote",
        [ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus {
            status: 503,
        })],
    );
    {
        let sinks = durable_sink_set(&outbox_path, first_sink, retry_config(3, 250));
        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("schedule retry before restart");
    }
    assert_eq!(first_calls.lock().expect("calls lock").len(), 1);

    let reopened = Outbox::open(&outbox_path).expect("reopen outbox");
    let row = reopened
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("pending row");
    assert_eq!(row.state, DeliveryState::Pending);
    assert_eq!(row.next_attempt_at, Some(2_250));
    drop(reopened);

    let (second_sink, second_calls) =
        ScriptedDurableSink::new("remote", [ScriptedOutcome::Success]);
    let restarted_sinks = durable_sink_set(&outbox_path, second_sink, retry_config(3, 250));
    restarted_sinks
        .dispatch_durable_with_clock(&clock)
        .expect("restart does not send early");
    assert!(second_calls.lock().expect("calls lock").is_empty());

    clock.advance(250);
    restarted_sinks
        .dispatch_durable_with_clock(&clock)
        .expect("restart replays when due");
    assert_eq!(second_calls.lock().expect("calls lock").len(), 1);
    let reopened = Outbox::open(&outbox_path).expect("reopen acked outbox");
    assert_eq!(
        reopened
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("acked row")
            .state,
        DeliveryState::Acked
    );
}

#[test]
fn http_429_and_5xx_are_pending_until_a_later_success() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 429 }),
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 503 }),
            ScriptedOutcome::Success,
        ],
    );
    let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
    let clock = FakeClock::new(3_000);

    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("schedule 429 retry");
    let outbox = Outbox::open(&outbox_path).expect("reopen after 429");
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("pending row");
    assert_eq!(row.state, DeliveryState::Pending);
    assert_eq!(row.next_attempt_at, Some(3_010));
    assert_eq!(
        row.last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 429 })
    );
    drop(outbox);

    clock.advance(10);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("schedule 5xx retry");
    let outbox = Outbox::open(&outbox_path).expect("reopen after 5xx");
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("pending row");
    assert_eq!(row.state, DeliveryState::Pending);
    assert_eq!(row.next_attempt_at, Some(3_030));
    assert_eq!(
        row.last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 503 })
    );
    drop(outbox);

    clock.advance(20);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("5xx retry succeeds");
    assert_eq!(calls.lock().expect("calls lock").len(), 3);
    let outbox = Outbox::open(&outbox_path).expect("reopen successful outbox");
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("acked row")
            .state,
        DeliveryState::Acked
    );
}

#[test]
fn authentication_failures_block_until_each_row_is_explicitly_released() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = make_health_event();
    let second = make_health_event();
    seed_pending(&outbox_path, &[&first, &second], &["remote"]).expect("seed pending events");
    {
        let mut outbox = Outbox::open(&outbox_path).expect("open seeded outbox");
        outbox
            .record_delivery_at(
                &first.event_id,
                "remote",
                DeliveryUpdate {
                    state: DeliveryState::Pending,
                    attempts: 0,
                    next_attempt_at: None,
                    last_error_class: None,
                    updated_at: 1,
                },
            )
            .expect("order first authentication failure");
        outbox
            .record_delivery_at(
                &second.event_id,
                "remote",
                DeliveryUpdate {
                    state: DeliveryState::Pending,
                    attempts: 0,
                    next_attempt_at: None,
                    last_error_class: None,
                    updated_at: 2,
                },
            )
            .expect("order second authentication failure");
    }

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 401 }),
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 403 }),
            ScriptedOutcome::Success,
            ScriptedOutcome::Success,
        ],
    );
    let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
    let clock = FakeClock::new(4_000);

    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("block authentication failures");
    let outbox = Outbox::open(&outbox_path).expect("reopen blocked outbox");
    for (event, status) in [(&first, 401), (&second, 403)] {
        let row = outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("blocked row");
        assert_eq!(row.state, DeliveryState::Blocked);
        assert_eq!(row.next_attempt_at, None);
        assert_eq!(
            row.last_error_class,
            Some(DeliveryErrorClass::AuthenticationBlocked { status })
        );
    }
    assert!(
        outbox
            .next_ready_delivery("remote", clock.now_millis())
            .expect("blocked ready lookup")
            .is_none()
    );
    drop(outbox);
    assert_eq!(calls.lock().expect("calls lock").len(), 2);

    let mut outbox = Outbox::open(&outbox_path).expect("open for first release");
    outbox
        .release_blocked_delivery(&first.event_id, "remote", clock.now_millis())
        .expect("release first blocked row");
    drop(outbox);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("deliver released first row");
    assert_eq!(calls.lock().expect("calls lock").len(), 3);

    let mut outbox = Outbox::open(&outbox_path).expect("open for second release");
    outbox
        .release_blocked_delivery(&second.event_id, "remote", clock.now_millis())
        .expect("release second blocked row");
    drop(outbox);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("deliver released second row");
    assert_eq!(calls.lock().expect("calls lock").len(), 4);

    let outbox = Outbox::open(&outbox_path).expect("reopen released outbox");
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "remote")
            .expect("first delivery")
            .expect("first row")
            .state,
        DeliveryState::Acked
    );
    assert_eq!(
        outbox
            .get_delivery(&second.event_id, "remote")
            .expect("second delivery")
            .expect("second row")
            .state,
        DeliveryState::Acked
    );
}

#[test]
fn poison_delivery_is_dead_but_does_not_wedge_a_later_valid_event() {
    assert_poison_delivery_progress(0, false);
}

#[test]
fn poison_delivery_preserves_valid_work_at_the_dispatch_time_boundary() {
    for (step_millis, deferred) in [(99, false), (100, true), (101, true)] {
        assert_poison_delivery_progress(step_millis, deferred);
    }
}

#[test]
fn retryable_failure_at_max_attempts_becomes_dead() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 503 }),
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 503 }),
        ],
    );
    let sinks = durable_sink_set(&outbox_path, sink, retry_config(2, 10));
    let clock = FakeClock::new(6_000);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("schedule final retry");
    clock.advance(10);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("dead-letter exhausted retry");

    let outbox = Outbox::open(&outbox_path).expect("reopen exhausted outbox");
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("dead row");
    assert_eq!(row.state, DeliveryState::Dead);
    assert_eq!(row.next_attempt_at, None);
    assert_eq!(row.attempts, 2);
    assert_eq!(
        row.last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 503 })
    );
    assert_eq!(calls.lock().expect("calls lock").len(), 2);
}

#[test]
fn durable_sinks_keep_success_and_blocked_states_independent() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["healthy", "blocked"]).expect("seed multi-sink event");

    let (healthy, healthy_calls) = ScriptedDurableSink::new("healthy", [ScriptedOutcome::Success]);
    let (blocked, blocked_calls) = ScriptedDurableSink::new(
        "blocked",
        [ScriptedOutcome::Failure(
            DeliveryErrorClass::AuthenticationBlocked { status: 403 },
        )],
    );
    let mut sinks = SinkSet::new();
    sinks.add_best_effort_with_retry("synthetic", Box::new(healthy), retry_config(3, 10));
    sinks.add_best_effort_with_retry("synthetic", Box::new(blocked), retry_config(3, 10));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["healthy".to_string(), "blocked".to_string()],
        CapacityLimits::default(),
    );
    let clock = FakeClock::new(7_000);

    let failures = sinks
        .dispatch_durable_with_clock(&clock)
        .expect("independent sink dispatch");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].name, "blocked");
    assert_eq!(healthy_calls.lock().expect("healthy calls").len(), 1);
    assert_eq!(blocked_calls.lock().expect("blocked calls").len(), 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen multi-sink outbox");
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "healthy")
            .expect("healthy delivery")
            .expect("healthy row")
            .state,
        DeliveryState::Acked
    );
    let blocked_row = outbox
        .get_delivery(&event.event_id, "blocked")
        .expect("blocked delivery")
        .expect("blocked row");
    assert_eq!(blocked_row.state, DeliveryState::Blocked);
    assert_eq!(
        blocked_row.last_error_class,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 })
    );
}

#[test]
fn crash_after_remote_success_before_ack_replays_without_loss() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [ScriptedOutcome::Success, ScriptedOutcome::Success],
    );
    let ready = {
        let outbox = Outbox::open(&outbox_path).expect("open pending outbox");
        outbox
            .next_ready_delivery("remote", 8_000)
            .expect("ready lookup")
            .expect("ready delivery")
    };
    sink.emit_canonical_once(&ready.payload)
        .expect("simulate receiver success");
    assert_eq!(calls.lock().expect("calls lock").len(), 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen after simulated crash");
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("pending row")
            .state,
        DeliveryState::Pending
    );
    drop(outbox);

    let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
    sinks
        .dispatch_durable_with_clock(&FakeClock::new(8_000))
        .expect("replay after restart");
    let calls = calls.lock().expect("calls lock");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
    drop(calls);

    let outbox = Outbox::open(&outbox_path).expect("reopen acknowledged outbox");
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("acked row")
            .state,
        DeliveryState::Acked
    );
}
