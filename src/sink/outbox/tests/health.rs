use super::*;

#[test]
fn health_is_metadata_only_and_separates_sink_states() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let first = marked_event("TT_HEALTH_FIRST");
    let second = marked_event("TT_HEALTH_SECOND");
    let third = marked_event("TT_HEALTH_THIRD");
    let first_bytes = canonical_bytes(&first);
    let second_bytes = canonical_bytes(&second);
    let mut outbox = Outbox::open(&path).expect("open outbox");
    for event in [&first, &second, &third] {
        outbox
            .insert_event(event, &["sink-a", "sink-b"])
            .expect("insert event");
    }
    outbox
        .connection
        .execute(
            "UPDATE events SET created_at = CASE event_id
                     WHEN ?1 THEN 100 WHEN ?2 THEN 200 WHEN ?3 THEN 300 END",
            params![first.event_id, second.event_id, third.event_id],
        )
        .expect("set deterministic event times");
    outbox
        .record_delivery_at(
            &first.event_id,
            "sink-a",
            super::super::DeliveryUpdate {
                state: DeliveryState::Pending,
                attempts: 1,
                next_attempt_at: Some(9_999),
                last_error_class: Some(DeliveryErrorClass::HttpStatus { status: 429 }),
                updated_at: 1_000,
            },
        )
        .expect("record retry-delayed row");
    outbox
        .record_delivery_at(
            &second.event_id,
            "sink-a",
            super::super::DeliveryUpdate {
                state: DeliveryState::Blocked,
                attempts: 1,
                next_attempt_at: None,
                last_error_class: Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
                updated_at: 1_100,
            },
        )
        .expect("record blocked row");
    outbox
        .record_delivery_at(
            &third.event_id,
            "sink-a",
            super::super::DeliveryUpdate {
                state: DeliveryState::Dead,
                attempts: 1,
                next_attempt_at: None,
                last_error_class: Some(DeliveryErrorClass::SinkApplicationRejected),
                updated_at: 1_200,
            },
        )
        .expect("record dead row");
    outbox
        .record_delivery_at(
            &first.event_id,
            "sink-b",
            super::super::DeliveryUpdate {
                state: DeliveryState::Acked,
                attempts: 1,
                next_attempt_at: None,
                last_error_class: None,
                updated_at: 1_300,
            },
        )
        .expect("record acknowledged row");

    let health = outbox.health(&["sink-a", "sink-b"], 1_000).expect("health");
    assert_eq!(health.sinks.len(), 2);
    let sink_a = &health.sinks[0];
    assert_eq!(sink_a.sink_id, "sink-a");
    assert_eq!(sink_a.pending_depth, 2);
    assert_eq!(
        sink_a.pending_bytes,
        (first_bytes.len() + second_bytes.len()) as u64
    );
    assert_eq!(sink_a.oldest_pending_age_seconds, Some(900));
    assert_eq!(sink_a.dead_count, 1);
    assert_eq!(sink_a.last_error_at, Some(1_200));
    assert_eq!(
        sink_a.last_error_class,
        Some(DeliveryErrorClass::SinkApplicationRejected)
    );
    let sink_b = &health.sinks[1];
    assert_eq!(sink_b.pending_depth, 2);
    assert_eq!(sink_b.dead_count, 0);
    assert_eq!(sink_b.last_success_at, Some(1_300));
    assert!(sink_b.last_error_at.is_none());

    let rendered = crate::sink::durable_health_json_from_path(&path, &["sink-a", "sink-b"]);
    let rendered = serde_json::to_string(&rendered).expect("health JSON");
    assert!(!rendered.contains("TT_HEALTH_FIRST"));
    assert!(!rendered.contains("TT_HEALTH_SECOND"));
    assert!(!rendered.contains("TT_HEALTH_THIRD"));
}

#[test]
fn health_history_survives_restart_and_read_only_lookup_is_bounded() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let event = marked_event("TT_HEALTH_RESTART");
    let mut outbox = Outbox::open(&path).expect("open outbox");
    outbox
        .insert_event(&event, &["sink"])
        .expect("insert event");
    outbox
        .record_delivery_at(
            &event.event_id,
            "sink",
            super::super::DeliveryUpdate {
                state: DeliveryState::Acked,
                attempts: 1,
                next_attempt_at: None,
                last_error_class: None,
                updated_at: 2_000,
            },
        )
        .expect("record success");
    let failed = marked_event("TT_HEALTH_FAILURE");
    outbox
        .insert_event(&failed, &["sink"])
        .expect("insert failed event");
    outbox
        .record_delivery_at(
            &failed.event_id,
            "sink",
            super::super::DeliveryUpdate {
                state: DeliveryState::Dead,
                attempts: 1,
                next_attempt_at: None,
                last_error_class: Some(DeliveryErrorClass::HttpStatus { status: 500 }),
                updated_at: 3_000,
            },
        )
        .expect("record failure");
    drop(outbox);

    let restarted = Outbox::open_read_only(&path).expect("read-only restart lookup");
    let health = restarted.health(&[], 4_000).expect("restart health");
    assert_eq!(health.sinks[0].last_success_at, Some(2_000));
    assert_eq!(health.sinks[0].last_error_at, Some(3_000));
    assert_eq!(
        health.sinks[0].last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 500 })
    );

    let corrupt = temp.path().join("corrupt.sqlite");
    fs::write(&corrupt, b"TT_HEALTH_CORRUPT_SECRET").expect("write corrupt outbox");
    let rendered = crate::sink::durable_health_json_from_path(&corrupt, &[]);
    let rendered = serde_json::to_string(&rendered).expect("unavailable health JSON");
    assert!(rendered.len() < 512);
    assert!(!rendered.contains("TT_HEALTH_CORRUPT_SECRET"));
    assert!(rendered.contains("unavailable"));
}
