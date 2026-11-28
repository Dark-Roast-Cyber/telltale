use super::*;

#[test]
fn unknown_persisted_error_class_fails_closed_without_rewriting_row() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("private/outbox.sqlite");
    let event = marked_event("TT_SYNTHETIC_EVENT");
    let mut outbox = Outbox::open(&path).unwrap();
    outbox.insert_event(&event, &["remote"]).unwrap();
    drop(outbox);
    let connection = Connection::open(&path).unwrap();
    connection.execute(
            "UPDATE deliveries SET last_error_class = 'future_application_class' WHERE sink_id = 'remote'",
            [],
        ).unwrap();
    drop(connection);

    let outbox = Outbox::open(&path).unwrap();
    let error = outbox.get_delivery(&event.event_id, "remote").unwrap_err();
    assert_eq!(
        error.downcast_ref::<DeliveryError>().unwrap().class,
        DeliveryErrorClass::DurableStorage
    );
    assert!(
        error
            .to_string()
            .contains("stored delivery error class is invalid")
    );
    assert!(!error.to_string().contains("future_application_class"));
    drop(outbox);
    let connection = Connection::open(&path).unwrap();
    let (state, class): (String, String) = connection
        .query_row(
            "SELECT state, last_error_class FROM deliveries WHERE sink_id = 'remote'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "pending");
    assert_eq!(class, "future_application_class");
}

#[test]
fn stores_canonical_terminal_event_bytes_and_reuses_them_for_retry_and_dead_state() {
    let marker = "TT_PRIVACY_OUTBOX_26";
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let event = marked_event(marker);
    let expected = canonical_bytes(&event);
    let expected_hash: [u8; 32] = Sha256::digest(&expected).into();

    let mut outbox = Outbox::open(&path).expect("open outbox");
    outbox
        .insert_event(&event, &["sink-a"])
        .expect("insert event");

    let stored = outbox
        .get_event(&event.event_id)
        .expect("get event")
        .expect("stored event");
    assert_eq!(stored.event_id, event.event_id);
    assert_eq!(stored.payload, expected);
    assert_eq!(stored.payload_hash, expected_hash);
    assert_payload_is_safe(&stored.payload, marker, "outbox-event-payload");

    record_delivery_for_test(
        &mut outbox,
        &event.event_id,
        "sink-a",
        DeliveryState::Pending,
        1,
        Some(1_700_000_000),
        Some(DeliveryErrorClass::HttpStatus { status: 503 }),
    )
    .expect("record retry state");
    let retry_payload = outbox
        .get_event(&event.event_id)
        .expect("get retry payload")
        .expect("retry event")
        .payload;
    assert_eq!(retry_payload, expected);
    assert_payload_is_safe(&retry_payload, marker, "outbox-retry-payload");

    record_delivery_for_test(
        &mut outbox,
        &event.event_id,
        "sink-a",
        DeliveryState::Dead,
        2,
        None,
        Some(DeliveryErrorClass::SinkApplicationRejected),
    )
    .expect("record dead state");
    let dead_payload = outbox
        .get_event(&event.event_id)
        .expect("get dead payload")
        .expect("dead event")
        .payload;
    assert_eq!(dead_payload, expected);
    assert_payload_is_safe(&dead_payload, marker, "outbox-dead-payload");
}

#[test]
fn release_blocked_for_sink_releases_matching_rows_without_resetting_history() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let events = [
        marked_event("TT_RELEASE_BLOCKED_FIRST"),
        marked_event("TT_RELEASE_BLOCKED_SECOND"),
        marked_event("TT_RELEASE_PENDING"),
        marked_event("TT_RELEASE_ACKED"),
        marked_event("TT_RELEASE_DEAD"),
    ];
    let mut outbox = Outbox::open(&path).expect("open outbox");
    for event in &events {
        outbox
            .insert_event(event, &["sink-a", "sink-b"])
            .expect("insert event");
    }

    record_delivery_for_test(
        &mut outbox,
        &events[0].event_id,
        "sink-a",
        DeliveryState::Blocked,
        3,
        None,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
    )
    .expect("record first blocked row");
    record_delivery_for_test(
        &mut outbox,
        &events[1].event_id,
        "sink-a",
        DeliveryState::Blocked,
        5,
        None,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 401 }),
    )
    .expect("record second blocked row");
    record_delivery_for_test(
        &mut outbox,
        &events[2].event_id,
        "sink-a",
        DeliveryState::Pending,
        2,
        Some(100),
        Some(DeliveryErrorClass::HttpStatus { status: 429 }),
    )
    .expect("record pending row");
    record_delivery_for_test(
        &mut outbox,
        &events[3].event_id,
        "sink-a",
        DeliveryState::Acked,
        4,
        None,
        None,
    )
    .expect("record acked row");
    record_delivery_for_test(
        &mut outbox,
        &events[4].event_id,
        "sink-a",
        DeliveryState::Dead,
        6,
        None,
        Some(DeliveryErrorClass::SinkApplicationRejected),
    )
    .expect("record dead row");
    record_delivery_for_test(
        &mut outbox,
        &events[0].event_id,
        "sink-b",
        DeliveryState::Blocked,
        7,
        None,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
    )
    .expect("record other sink blocked row");

    let now = 1_700_000_123_456;
    assert_eq!(
        outbox
            .release_blocked_for_sink("sink-a", now)
            .expect("release blocked rows"),
        2
    );
    for (event, attempts, error_class) in [
        (
            &events[0],
            3,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
        ),
        (
            &events[1],
            5,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 401 }),
        ),
    ] {
        let row = outbox
            .get_delivery(&event.event_id, "sink-a")
            .expect("released delivery lookup")
            .expect("released delivery row");
        assert_eq!(row.state, DeliveryState::Pending);
        assert_eq!(row.attempts, attempts);
        assert_eq!(row.next_attempt_at, Some(now));
        assert_eq!(row.last_error_class, error_class);
        assert_eq!(row.updated_at, now);
    }

    let pending = outbox
        .get_delivery(&events[2].event_id, "sink-a")
        .expect("pending delivery lookup")
        .expect("pending delivery row");
    assert_eq!(pending.state, DeliveryState::Pending);
    assert_eq!(pending.attempts, 2);
    assert_eq!(pending.next_attempt_at, Some(100));
    assert_eq!(
        pending.last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 429 })
    );
    assert_eq!(
        outbox
            .get_delivery(&events[3].event_id, "sink-a")
            .expect("acked delivery lookup")
            .expect("acked delivery row")
            .state,
        DeliveryState::Acked
    );
    assert_eq!(
        outbox
            .get_delivery(&events[4].event_id, "sink-a")
            .expect("dead delivery lookup")
            .expect("dead delivery row")
            .state,
        DeliveryState::Dead
    );
    assert_eq!(
        outbox
            .get_delivery(&events[0].event_id, "sink-b")
            .expect("other sink delivery lookup")
            .expect("other sink delivery row")
            .state,
        DeliveryState::Blocked
    );
    assert_eq!(
        outbox
            .release_blocked_for_sink("sink-a", now)
            .expect("repeat release"),
        0
    );
    drop(outbox);

    let reopened = Outbox::open(&path).expect("reopen outbox");
    let row = reopened
        .get_delivery(&events[0].event_id, "sink-a")
        .expect("reopened delivery lookup")
        .expect("reopened delivery row");
    assert_eq!(row.state, DeliveryState::Pending);
    assert_eq!(row.attempts, 3);
    assert_eq!(row.next_attempt_at, Some(now));
    assert_eq!(
        row.last_error_class,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 })
    );
}

#[test]
fn duplicate_event_is_harmless_and_missing_sink_rows_are_added_without_resetting_state() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_DUPLICATE_26");
    let mut outbox = Outbox::open(&path).expect("open outbox");

    outbox
        .insert_event(&event, &["sink-a", "sink-b"])
        .expect("first insert");
    record_delivery_for_test(
        &mut outbox,
        &event.event_id,
        "sink-a",
        DeliveryState::Acked,
        1,
        None,
        None,
    )
    .expect("ack first sink");

    outbox
        .insert_event(&event, &["sink-a", "sink-b", "sink-c"])
        .expect("duplicate insert");

    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "sink-a")
            .expect("get sink a")
            .expect("sink a row")
            .state,
        DeliveryState::Acked
    );
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "sink-b")
            .expect("get sink b")
            .expect("sink b row")
            .state,
        DeliveryState::Pending
    );
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "sink-c")
            .expect("get sink c")
            .expect("sink c row")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn same_event_id_with_different_canonical_bytes_fails_closed_as_payload_collision() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_COLLISION_A_26");
    let mut different = event.clone();
    different.evidence[0].redacted_value = "synthetic second payload".to_string();

    let mut outbox = Outbox::open(&path).expect("open outbox");
    outbox
        .insert_event(&event, &["sink-a"])
        .expect("first insert");
    let error = outbox
        .insert_event(&different, &["sink-b"])
        .expect_err("different bytes for one event ID must fail");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured delivery error");
    assert_eq!(delivery.class, DeliveryErrorClass::PayloadCollision);
    assert!(
        outbox
            .get_delivery(&event.event_id, "sink-b")
            .expect("collision lookup")
            .is_none(),
        "collision must not create a delivery row"
    );
}
