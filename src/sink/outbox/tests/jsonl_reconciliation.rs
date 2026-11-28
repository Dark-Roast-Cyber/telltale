use super::*;

#[test]
fn restart_reconciles_jsonl_after_the_fsync_before_ingest_gap() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_CRASH_GAP_FSYNC_26");

    LocalJsonlSink::with_rotation(&log_path, crate::sink::RotationConfig::disabled())
        .emit(std::slice::from_ref(&event))
        .expect("canonical JSONL fsync");
    let outbox = Outbox::open(&outbox_path).expect("open before crash");
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("before crash")
            .is_none()
    );
    drop(outbox);

    let mut restarted = Outbox::open(&outbox_path).expect("restart outbox");
    restarted
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("reconcile after restart");

    let stored = restarted
        .get_event(&event.event_id)
        .expect("stored event")
        .expect("event recovered from JSONL");
    assert_payload_is_safe(
        &stored.payload,
        "TT_OUTBOX_CRASH_GAP_FSYNC_26",
        "outbox-restart-recovery",
    );
    assert_eq!(
        restarted
            .get_delivery(&event.event_id, "sink-a")
            .expect("delivery row")
            .expect("pending delivery")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn restart_replays_ingested_pending_rows_before_any_send_attempt() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_CRASH_GAP_INGEST_26");
    append_jsonl_events(&log_path, std::slice::from_ref(&event)).expect("canonical JSONL");

    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest transaction");
    drop(outbox);

    let restarted = Outbox::open(&outbox_path).expect("restart outbox");
    let delivery = restarted
        .get_delivery(&event.event_id, "sink-a")
        .expect("delivery lookup")
        .expect("pending delivery survives restart");
    assert_eq!(delivery.state, DeliveryState::Pending);
    assert_eq!(delivery.attempts, 0);
    assert_eq!(delivery.next_attempt_at, None);
}

#[test]
fn reconcile_leaves_partial_trailing_record_until_the_line_is_complete() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_OUTBOX_PARTIAL_FIRST_26");
    let second = marked_event("TT_OUTBOX_PARTIAL_SECOND_26");
    append_jsonl_events(&log_path, std::slice::from_ref(&first)).expect("first JSONL event");

    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("initial ingest");
    let cursor_before = outbox.ingest_cursor().expect("cursor").expect("cursor row");

    let second_bytes = canonical_bytes(&second);
    let split = second_bytes.len() / 2;
    let mut log = fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .expect("open JSONL for partial append");
    std::io::Write::write_all(&mut log, &second_bytes[..split]).expect("append partial line");
    drop(log);

    let partial = outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("partial tail is deferred");
    assert_eq!(partial.ingested_events, 0);
    assert_eq!(
        outbox.ingest_cursor().expect("cursor after partial"),
        Some(cursor_before)
    );
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("partial event lookup")
            .is_none()
    );

    let mut log = fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .expect("reopen JSONL");
    std::io::Write::write_all(&mut log, &second_bytes[split..]).expect("complete partial line");
    std::io::Write::write_all(&mut log, b"\n").expect("terminate JSONL line");
    drop(log);

    let completed = outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("completed tail ingest");
    assert_eq!(completed.ingested_events, 1);
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("completed event lookup")
            .is_some()
    );
    assert_eq!(
        outbox
            .get_delivery(&second.event_id, "sink-a")
            .expect("completed delivery lookup")
            .expect("completed pending delivery")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn malformed_non_tail_jsonl_does_not_commit_prior_events_or_cursor() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_MALFORMED_NON_TAIL_26");
    let mut bytes = canonical_bytes(&event);
    bytes.extend_from_slice(b"\n{\"not_an_event\":true}\n");
    fs::write(&log_path, bytes).expect("malformed JSONL fixture");

    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    let error = outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect_err("malformed non-tail record must fail closed");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured ingest error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("event lookup")
            .is_none()
    );
    assert!(outbox.ingest_cursor().expect("cursor lookup").is_none());
}

#[test]
fn cursor_rejects_replacement_truncation_and_unsafe_advancement() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let event = marked_event("TT_OUTBOX_CURSOR_INTEGRITY_26");
    append_jsonl_events(&log_path, std::slice::from_ref(&event)).expect("canonical JSONL");

    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("initial ingest");
    let cursor = outbox.ingest_cursor().expect("cursor").expect("cursor row");
    assert_eq!(
        cursor.byte_offset as usize,
        fs::read(&log_path).expect("log").len()
    );

    let replacement = temp.path().join("replacement.jsonl");
    fs::write(&replacement, fs::read(&log_path).expect("original log")).expect("replacement");
    fs::remove_file(&log_path).expect("remove active log");
    fs::rename(&replacement, &log_path).expect("replace active log");
    let error = outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect_err("replacement must fail closed");
    assert!(error.to_string().contains("generation"));

    // Restore the original bytes through a new outbox so the truncation
    // and cursor-boundary checks each exercise the persisted cursor.
    let second_path = named_private_outbox_path(&temp, "second-outbox");
    let original = canonical_bytes(&event);
    fs::write(
        &log_path,
        format!("{}\n", String::from_utf8(original).expect("UTF-8")),
    )
    .expect("restore log");
    let mut second = Outbox::open(&second_path).expect("second outbox");
    second
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("second initial ingest");
    let mut truncated = fs::read(&log_path).expect("read restored log");
    truncated.truncate(truncated.len().saturating_sub(1));
    fs::write(&log_path, truncated).expect("truncate log");
    let error = second
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect_err("truncation must fail closed");
    assert!(error.to_string().contains("truncat"));

    let unsafe_path = named_private_outbox_path(&temp, "unsafe-cursor");
    let log_path = temp.path().join("unsafe-events.jsonl");
    append_jsonl_events(&log_path, std::slice::from_ref(&event)).expect("unsafe log");
    let mut unsafe_outbox = Outbox::open(&unsafe_path).expect("unsafe outbox");
    unsafe_outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("unsafe cursor initial ingest");
    let cursor = unsafe_outbox
        .ingest_cursor()
        .expect("unsafe cursor lookup")
        .expect("unsafe cursor row");
    assert!(cursor.byte_offset > 1);
    unsafe_outbox
        .connection
        .execute("UPDATE ingest_cursor SET byte_offset = 1 WHERE id = 1", [])
        .expect("unsafe cursor fixture");
    let error = unsafe_outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect_err("cursor in the middle of a line must fail closed");
    assert!(error.to_string().contains("line boundary"));
}
