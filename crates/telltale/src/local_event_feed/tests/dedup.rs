use super::*;

#[test]
fn valid_records_are_typed_and_identical_replays_are_suppressed() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let record = br#"{"schema_version":"3.0","event_id":"telltale-12345678-1234-4123-8123-123456789abc","telltale_version":"0.5.0","timestamp":"2026-01-01T00:00:00.000Z","observed_at":"2026-01-01T00:00:00.000Z","ingested_at":"2026-01-01T00:00:00.000Z","time_source":"observed","time_confidence":"high","time_override_reason":"synthetic","severity":"informational","risk_score":0,"risk_contributions":[],"client":"synthetic","session_id":"synthetic-session","tags":[],"evidence":[],"event_type":"activity","source_path_hash":"synthetic-hash"}"#;
    let mut bytes = record.to_vec();
    bytes.push(b'\n');
    fs::write(&path, &bytes).expect("journal");
    let mut feed = LocalEventFeed::new(LocalEventFeedConfig::new(&path, StartupMode::Beginning))
        .expect("config");
    let first = feed.poll().expect("poll");
    assert_eq!(first.records.len(), 1);
    assert_eq!(
        first.records[0].common().event_id,
        "telltale-12345678-1234-4123-8123-123456789abc"
    );
    let second = feed.poll().expect("poll");
    assert!(second.records.is_empty());
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("append")
        .write_all(&bytes)
        .expect("replay");
    let replay = feed.poll().expect("poll");
    assert!(replay.records.is_empty());
    assert_eq!(replay.suppressed_replays, 1);
}

#[test]
fn collision_eviction_rotation_and_truncation_are_explicit() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first = valid_record("telltale-44444444-4444-4444-8444-444444444444");
    let second = valid_record("telltale-55555555-5555-4555-8555-555555555555");
    let mut first_line = first.clone();
    first_line.push(b'\n');
    fs::write(&path, &first_line).expect("journal");
    let limits = FeedLimits {
        max_dedup_entries: 1,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");
    assert_eq!(feed.poll().expect("first poll").records.len(), 1);

    let mut collision = first.clone();
    collision.extend_from_slice(b" ");
    let mut collision_line = collision;
    collision_line.push(b'\n');
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("append collision")
        .write_all(&collision_line)
        .expect("collision");
    let collision_batch = feed.poll().expect("collision poll");
    assert_eq!(collision_batch.event_id_collisions, 1);
    assert!(collision_batch.records.is_empty());

    let rotated = directory.path().join("events-2026-01-02.jsonl");
    fs::rename(&path, &rotated).expect("rotate");
    let mut active = second.clone();
    active.push(b'\n');
    fs::write(&path, &active).expect("new active");
    let rotated_batch = feed.poll().expect("rotation poll");
    assert_eq!(rotated_batch.records.len(), 1);

    fs::write(&path, []).expect("truncate");
    let truncated = feed.poll().expect("truncation poll");
    assert!(
        truncated
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::TruncatedGeneration)
    );
    fs::write(&path, &active).expect("rewrite");
    let replay = feed.poll().expect("replay after truncation");
    assert_eq!(replay.suppressed_replays, 1);
}

#[test]
fn dedup_evicted_identity_can_be_emitted_again() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-a1a2a3a4-a5a6-40a7-80a8-a9aaabacadae";
    let second_id = "telltale-b1b2b3b4-b5b6-40b7-80b8-b9babcbdbebf";
    fs::write(&path, line(first_id)).expect("journal");
    let limits = FeedLimits {
        max_dedup_entries: 1,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");
    assert_eq!(
        event_ids(&feed.poll().expect("first poll")),
        vec![first_id.to_owned()]
    );
    append(&path, &line(second_id));
    let second = feed.poll().expect("second poll");
    append(&path, &line(first_id));
    let third = feed.poll().expect("evicted replay poll");

    assert_eq!(event_ids(&second), vec![second_id]);
    assert!(has_notice(&second, FeedNoticeCode::DedupEvicted));
    assert_eq!(event_ids(&third), vec![first_id.to_owned()]);
}

#[test]
fn dedup_physical_order_wins_over_event_timestamp_order() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-babbbcbc-dbde-40df-80e0-e1e2e3e4e5e6";
    let second_id = "telltale-fafbfcfd-feff-4010-8011-121314151617";
    let later = "2026-01-02T00:00:00.000Z";
    let earlier = "2026-01-01T00:00:00.000Z";
    let first = replace_once(
        replace_once(
            replace_once(valid_record(first_id), "2026-01-01T00:00:00.000Z", later),
            "2026-01-01T00:00:00.000Z",
            later,
        ),
        "2026-01-01T00:00:00.000Z",
        later,
    );
    let second = replace_once(
        replace_once(
            replace_once(valid_record(second_id), "2026-01-01T00:00:00.000Z", earlier),
            "2026-01-01T00:00:00.000Z",
            earlier,
        ),
        "2026-01-01T00:00:00.000Z",
        earlier,
    );
    let mut contents = first;
    contents.push(b'\n');
    contents.extend_from_slice(&second);
    contents.push(b'\n');
    fs::write(&path, contents).expect("journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(
        event_ids(&batch),
        vec![first_id.to_owned(), second_id.to_owned()]
    );
}

#[test]
fn dedup_identical_record_replayed_after_rotation_is_suppressed() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let record = line("telltale-18192021-2223-4024-8025-262728293031");
    fs::write(&path, &record).expect("initial journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
    feed.poll().expect("initial poll");
    fs::rename(&path, directory.path().join("events-2026-02-05.jsonl")).expect("rotate");
    fs::write(&path, &record).expect("replayed active journal");

    let batch = feed.poll().expect("replay poll");

    assert!(batch.records.is_empty());
    assert_eq!(batch.suppressed_replays, 1);
    assert!(has_notice(&batch, FeedNoticeCode::ReplaySuppressed));
}
