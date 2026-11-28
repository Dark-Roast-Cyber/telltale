use super::*;

#[test]
fn unread_rotated_generation_is_retained_before_reconciliation() {
    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert!(rotated.exists(), "unread rotated bytes must be retained");
    assert!(report.pruned == 0);
    assert!(
        !report.warnings.is_empty(),
        "unregistered identity is fail-safe"
    );
}

#[test]
fn current_cursor_generation_is_protected_even_when_fully_consumed() {
    // The first event is reconciled while it is still active. The second
    // write then renames that file to A and creates active B without
    // reconciling B. The persisted cursor must follow A by filesystem
    // identity, not by the discovery filename.
    let (_temp, log_path, outbox_path, first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    let generations = discover_jsonl_generations(&log_path).expect("discover generations");
    let rotated_generation = generations
        .iter()
        .find(|generation| generation.path == rotated)
        .expect("rotated generation");
    let active = generations
        .iter()
        .find(|generation| generation.is_active)
        .expect("active generation");
    let cursor = outbox
        .ingest_cursor()
        .expect("cursor after rotation")
        .expect("cursor established while A was active");
    let rotated_length = fs::metadata(&rotated).expect("rotated metadata").len();
    assert_eq!(cursor.generation_id, rotated_generation.identity);
    assert_eq!(cursor.byte_offset, rotated_length);
    assert_eq!(cursor.observed_length, rotated_length);
    assert_eq!(cursor.byte_offset, canonical_bytes(&first).len() as u64 + 1);

    // Register the newly discovered active generation without reconciling
    // its bytes. This is the metadata state a rotation restart must be
    // able to validate before deciding whether A is still protected.
    install_generation_state(&mut outbox, &log_path, &generations, None)
        .expect("register rotated and active generations");
    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(rotated.exists(), "the cursor generation remains protected");
    assert_eq!(
        generation_lifecycle(&outbox, &rotated_generation.identity),
        GenerationLifecycle::Present
    );
    assert!(active.path.exists(), "active generation remains present");
}

#[test]
fn older_unread_generation_is_protected_when_cursor_points_to_a_newer_generation() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let older = marked_event("TT_ROTATION_OLDER_UNREAD");
    let active = marked_event("TT_ROTATION_NEWER_ACTIVE");
    let older_path = temp.path().join("events-2020-01-01.jsonl");
    fs::write(
        &older_path,
        [canonical_bytes(&older).as_slice(), b"\n{\"partial\""].concat(),
    )
    .expect("write partial older generation");
    let active_bytes = [canonical_bytes(&active).as_slice(), b"\n"].concat();
    fs::write(&log_path, &active_bytes).expect("write active generation");

    let generations = discover_jsonl_generations(&log_path).expect("discover generations");
    let active_generation = generations
        .iter()
        .find(|generation| generation.is_active)
        .expect("active generation");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    install_generation_state(
        &mut outbox,
        &log_path,
        &generations,
        Some((active_generation, active_bytes.len())),
    )
    .expect("install generation metadata and newer cursor");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert_eq!(report.protected, 1);
    assert!(older_path.exists(), "unread older bytes must remain");
    assert_eq!(
        generation_lifecycle(
            &outbox,
            &generations
                .iter()
                .find(|generation| !generation.is_active)
                .expect("older generation")
                .identity,
        ),
        GenerationLifecycle::Present
    );
}

#[test]
fn newest_rotated_keep_window_is_retained_after_older_consumed_generation_is_pruned() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = private_outbox_path(&temp);
    let first = marked_event("TT_ROTATION_KEEP_OLDEST");
    let second = marked_event("TT_ROTATION_KEEP_NEWEST");
    let third = marked_event("TT_ROTATION_KEEP_ACTIVE");
    let first_path = temp.path().join("events-2020-01-01.jsonl");
    let second_path = temp.path().join("events-2020-01-02.jsonl");
    fs::write(
        &first_path,
        [canonical_bytes(&first).as_slice(), b"\n"].concat(),
    )
    .expect("oldest generation");
    fs::write(
        &second_path,
        [canonical_bytes(&second).as_slice(), b"\n"].concat(),
    )
    .expect("newest rotated generation");
    let active_bytes = [canonical_bytes(&third).as_slice(), b"\n"].concat();
    fs::write(&log_path, &active_bytes).expect("active generation");

    let generations = discover_jsonl_generations(&log_path).expect("discover generations");
    let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("consume every generation");
    let report = outbox.prune_eligible_rotations(&log_path, 1);
    assert_eq!(report.pruned, 1);
    assert!(!first_path.exists(), "oldest consumed generation is pruned");
    assert!(
        second_path.exists(),
        "newest rotated keep window is retained"
    );
    assert!(log_path.exists(), "active generation is retained");
    assert_eq!(
        generation_lifecycle(
            &outbox,
            &generations
                .iter()
                .find(|generation| generation.path == first_path)
                .expect("oldest generation")
                .identity,
        ),
        GenerationLifecycle::Pruned
    );
}

#[test]
fn fully_ingested_generation_prunes_without_downstream_ack_and_keeps_active() {
    let (_temp, log_path, outbox_path, first, second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated and active generations");
    record_delivery_for_test(
        &mut outbox,
        &first.event_id,
        "sink-a",
        DeliveryState::Blocked,
        1,
        None,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
    )
    .expect("block first delivery");
    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 1);
    assert!(
        !rotated.exists(),
        "fully ingested generation should be pruned"
    );
    assert!(log_path.exists(), "active generation must be retained");
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "sink-a")
            .expect("first delivery")
            .expect("first row")
            .state,
        DeliveryState::Blocked
    );
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "sink-a")
            .expect("first delivery")
            .expect("first row")
            .last_error_class,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 })
    );
    assert_eq!(
        outbox
            .get_event(&first.event_id)
            .expect("first event after prune")
            .expect("first event remains replayable")
            .payload,
        canonical_bytes(&first)
    );
    assert_eq!(
        outbox
            .get_delivery(&second.event_id, "sink-a")
            .expect("second delivery")
            .expect("second row")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn pending_consumed_generation_prunes_and_remains_replayable() {
    let (_temp, log_path, outbox_path, first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated and active generations");
    record_delivery_for_test(
        &mut outbox,
        &first.event_id,
        "sink-a",
        DeliveryState::Pending,
        2,
        Some(1_700_000_100_000),
        Some(DeliveryErrorClass::TransportNoResponse),
    )
    .expect("retain pending delivery");
    record_delivery_for_test(
        &mut outbox,
        &_second.event_id,
        "sink-a",
        DeliveryState::Acked,
        1,
        None,
        None,
    )
    .expect("complete active delivery");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 1);
    assert!(!rotated.exists(), "consumed source generation is pruned");

    let delivery = outbox
        .get_delivery(&first.event_id, "sink-a")
        .expect("pending delivery")
        .expect("pending row remains after source prune");
    assert_eq!(delivery.state, DeliveryState::Pending);
    assert_eq!(delivery.attempts, 2);
    assert_eq!(
        delivery.last_error_class,
        Some(DeliveryErrorClass::TransportNoResponse)
    );
    let event = outbox
        .get_event(&first.event_id)
        .expect("replay event")
        .expect("event remains after source prune");
    assert_eq!(event.payload, canonical_bytes(&first));
    let ready = outbox
        .next_ready_delivery("sink-a", 1_700_000_100_001)
        .expect("ready pending delivery")
        .expect("pending delivery remains replayable");
    assert_eq!(ready.row.state, DeliveryState::Pending);
    assert_eq!(ready.payload, event.payload);
}

#[test]
fn replaced_rotated_generation_is_retained_by_identity_mismatch() {
    let (temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let replacement = temp.path().join("replacement.jsonl");
    fs::copy(&rotated, &replacement).expect("copy replacement");
    fs::remove_file(&rotated).expect("remove original generation");
    fs::rename(&replacement, &rotated).expect("replace generation");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(!report.warnings.is_empty());
    assert!(rotated.exists(), "identity replacement must be retained");
}

#[test]
fn changed_bytes_with_the_same_generation_identity_are_retained() {
    use std::io::Write;

    let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
    let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    outbox
        .reconcile_jsonl(&log_path, &["sink-a"])
        .expect("ingest rotated generation");
    let extra = marked_event("TT_ROTATION_APPENDED_AFTER_CURSOR_26");
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&rotated)
        .expect("open rotated generation");
    file.write_all(&canonical_bytes(&extra))
        .expect("append changed bytes");
    file.write_all(b"\n").expect("terminate changed bytes");
    file.sync_all().expect("sync changed bytes");

    let report = outbox.prune_eligible_rotations(&log_path, 0);
    assert_eq!(report.pruned, 0);
    assert!(rotated.exists(), "unproven appended bytes must be retained");
}
