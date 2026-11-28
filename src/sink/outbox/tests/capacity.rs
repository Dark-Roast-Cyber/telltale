use super::*;

#[test]
fn full_outbox_fails_closed_without_deleting_accepted_rows() {
    let temp = tempdir().expect("temporary directory");
    let path = private_outbox_path(&temp);
    let accepted = marked_event("TT_OUTBOX_FULL_ACCEPTED_26");
    let mut blocked = marked_event("TT_OUTBOX_FULL_BLOCKED_26");
    blocked.evidence = (0..1_200)
        .map(|index| Evidence {
            field: "tool_result".to_string(),
            redacted_value: format!(
                "synthetic-full-storage-payload-{index:04}-{}",
                "x".repeat(480)
            ),
            hash: None,
            rule_id: None,
        })
        .collect();

    let mut outbox = Outbox::open(&path).expect("open outbox");
    outbox
        .insert_event(&accepted, &["sink-a"])
        .expect("accepted event");
    let page_count: i64 = outbox
        .connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .expect("page count");
    let configured_max: i64 = outbox
        .connection
        .pragma_query_value(None, "max_page_count", |row| row.get(0))
        .expect("maximum page count");
    assert!(configured_max > page_count);
    outbox
        .connection
        .pragma_update(None, "max_page_count", page_count)
        .expect("set deterministic storage limit");

    let error = outbox
        .insert_event(&blocked, &["sink-a"])
        .expect_err("storage limit must reject the new event");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured full-storage error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(
        delivery.message.contains("full"),
        "storage limit must report SQLite full, not a renamed error: {}",
        delivery.message
    );
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_OUTBOX_FULL"));
    assert!(
        outbox
            .get_event(&accepted.event_id)
            .expect("accepted event lookup")
            .is_some()
    );
    assert_eq!(
        outbox
            .get_delivery(&accepted.event_id, "sink-a")
            .expect("accepted delivery lookup")
            .expect("accepted delivery row")
            .state,
        DeliveryState::Pending
    );
    assert!(
        outbox
            .get_event(&blocked.event_id)
            .expect("blocked event lookup")
            .is_none()
    );
}

#[test]
fn capacity_accepts_exact_event_limit_but_rejects_the_next_event() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_EVENT_FIRST_26");
    let second = marked_event("TT_CAPACITY_EVENT_SECOND_26");
    let first_batch =
        event3_durable_batch(std::slice::from_ref(&first)).expect("first canonical batch");
    let both_batch = event3_durable_batch(&[first, second]).expect("two canonical events");
    let outbox = Outbox::open(&outbox_path).expect("open outbox");

    outbox
        .check_capacity_for_payloads(
            &log_path,
            &first_batch.payloads,
            capacity_limits(1, first_batch.payloads[0].bytes.len() as u64),
        )
        .expect("exact event capacity is accepted");
    let error = outbox
        .check_capacity_for_payloads(
            &log_path,
            &both_batch.payloads,
            capacity_limits(1, u64::MAX),
        )
        .expect_err("the next unique event exceeds event capacity");
    assert!(error.to_string().contains("limit_kind=pending_events"));
}

#[test]
fn capacity_accepts_exact_canonical_byte_boundary_but_rejects_the_next_byte() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_BYTES_FIRST_26");
    let second = marked_event("TT_CAPACITY_BYTES_SECOND_26");
    let batch = event3_durable_batch(&[first, second]).expect("canonical batch");
    let bytes = batch
        .payloads
        .iter()
        .map(|payload| payload.bytes.len() as u64)
        .sum::<u64>();
    let outbox = Outbox::open(&outbox_path).expect("open outbox");

    outbox
        .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(2, bytes))
        .expect("exact canonical byte boundary is accepted");
    let error = outbox
        .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(2, bytes - 1))
        .expect_err("one byte below the canonical boundary is rejected");
    assert!(error.to_string().contains("limit_kind=pending_bytes"));
}

#[test]
fn pending_and_blocked_count_but_acked_and_dead_release_capacity() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_PENDING_26");
    let second = marked_event("TT_CAPACITY_BLOCKED_26");
    let third = marked_event("TT_CAPACITY_ACKED_26");
    let fourth = marked_event("TT_CAPACITY_DEAD_26");
    let fifth = marked_event("TT_CAPACITY_RELEASED_26");
    append_jsonl_events(
        &log_path,
        &[first.clone(), second.clone(), third.clone(), fourth.clone()],
    )
    .expect("canonical JSONL");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest events");
    record_delivery_for_test(
        &mut outbox,
        &second.event_id,
        "sink-a",
        DeliveryState::Blocked,
        1,
        None,
        None,
    )
    .expect("blocked state");
    record_delivery_for_test(
        &mut outbox,
        &third.event_id,
        "sink-a",
        DeliveryState::Acked,
        1,
        None,
        None,
    )
    .expect("acked state");
    record_delivery_for_test(
        &mut outbox,
        &fourth.event_id,
        "sink-a",
        DeliveryState::Dead,
        1,
        None,
        None,
    )
    .expect("dead state");
    let batch = event3_durable_batch(std::slice::from_ref(&fifth)).expect("prospective event");
    outbox
        .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(3, u64::MAX))
        .expect("pending and blocked plus one prospective event fit");
}

#[test]
fn multi_sink_event_counts_once_for_capacity() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let existing = marked_event("TT_CAPACITY_MULTI_EXISTING_26");
    let prospective = marked_event("TT_CAPACITY_MULTI_PROSPECTIVE_26");
    append_jsonl_events(&log_path, std::slice::from_ref(&existing)).expect("canonical JSONL");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a", "sink-b"])
        .expect("ingest multi-sink event");
    let batch =
        event3_durable_batch(std::slice::from_ref(&prospective)).expect("prospective event");
    outbox
        .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(2, u64::MAX))
        .expect("one event per sink is counted once");
}

#[test]
fn unread_jsonl_counts_with_empty_sqlite_and_after_reopen() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_UNREAD_FIRST_26");
    let second = marked_event("TT_CAPACITY_UNREAD_SECOND_26");
    append_jsonl_events(&log_path, &[first, second]).expect("committed JSONL");
    let batch = event3_durable_batch(&[marked_event("TT_CAPACITY_UNREAD_NEXT_26")])
        .expect("prospective event");
    let bytes = fs::read_to_string(&log_path)
        .expect("JSONL")
        .lines()
        .map(|line| line.len() as u64)
        .sum::<u64>();

    let outbox = Outbox::open(&outbox_path).expect("open empty outbox");
    let error = outbox
        .check_capacity_for_payloads(
            &log_path,
            &batch.payloads,
            capacity_limits(2, bytes + 1_000),
        )
        .expect_err("unread events plus prospective event exceed count");
    assert!(error.to_string().contains("limit_kind=pending_events"));
    drop(outbox);

    let reopened = Outbox::open(&outbox_path).expect("reopen empty outbox");
    reopened
        .check_capacity_for_payloads(
            &log_path,
            &batch.payloads,
            capacity_limits(3, bytes + batch.payloads[0].bytes.len() as u64),
        )
        .expect("unread capacity is counted after reopen");
}

#[test]
fn already_represented_unread_event_is_not_counted_twice() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let existing = marked_event("TT_CAPACITY_REPRESENTED_26");
    let next = marked_event("TT_CAPACITY_REPRESENTED_NEXT_26");
    append_jsonl_events(&log_path, std::slice::from_ref(&existing)).expect("first JSONL");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("represent first event");
    append_jsonl_events(&log_path, std::slice::from_ref(&existing)).expect("duplicate JSONL");
    let duplicate =
        event3_durable_batch(std::slice::from_ref(&existing)).expect("duplicate payload");
    outbox
        .check_capacity_for_payloads(
            &log_path,
            &duplicate.payloads,
            capacity_limits(1, duplicate.payloads[0].bytes.len() as u64),
        )
        .expect("represented duplicate does not consume capacity");
    let next_batch = event3_durable_batch(std::slice::from_ref(&next)).expect("next payload");
    let error = outbox
        .check_capacity_for_payloads(
            &log_path,
            &next_batch.payloads,
            capacity_limits(1, u64::MAX),
        )
        .expect_err("the next unique event exceeds the one-event limit");
    assert!(error.to_string().contains("limit_kind=pending_events"));
}

#[test]
fn unread_same_id_with_different_bytes_fails_closed() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_COLLISION_FIRST_26");
    let mut different = first.clone();
    different.evidence[0].redacted_value = "safe-different-canonical-payload".to_string();
    append_jsonl_events(&log_path, &[first, different]).expect("collision JSONL");
    let outbox = Outbox::open(&outbox_path).expect("open outbox");
    let error = outbox
        .check_capacity_for_payloads(&log_path, &[], capacity_limits(10, u64::MAX))
        .expect_err("same ID with different bytes must fail closed");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured collision error");
    assert_eq!(delivery.class, DeliveryErrorClass::PayloadCollision);
    assert!(!delivery.message.contains("TT_CAPACITY_COLLISION"));
}

#[test]
fn recovery_reconcile_is_not_gated_by_current_capacity_limits() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_CAPACITY_RECOVERY_FIRST_26");
    let second = marked_event("TT_CAPACITY_RECOVERY_SECOND_26");
    append_jsonl_events(&log_path, &[first, second]).expect("committed JSONL");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    let prospective = marked_event("TT_CAPACITY_RECOVERY_PROSPECTIVE_26");
    let batch = event3_durable_batch(std::slice::from_ref(&prospective))
        .expect("prospective recovery event");
    let error = outbox
        .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(1, u64::MAX))
        .expect_err("existing unread queue is above the current limit");
    assert!(error.to_string().contains("pending_events"));
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("recovery reconciliation remains available");
}
