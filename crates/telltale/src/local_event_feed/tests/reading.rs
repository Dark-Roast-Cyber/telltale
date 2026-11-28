use super::*;

#[test]
fn missing_path_is_waiting_and_does_not_create_parent() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("missing/events.jsonl");
    let mut feed = LocalEventFeed::new(LocalEventFeedConfig::new(&path, StartupMode::Beginning))
        .expect("config");
    let batch = feed.poll().expect("poll");
    assert!(!batch.caught_up);
    assert!(batch.records.is_empty());
    assert!(
        batch
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::JournalUnavailable)
    );
    assert!(!path.exists());
    assert!(!path.parent().expect("parent").exists());
}

#[test]
fn malformed_complete_lines_are_consumed_and_partial_waits() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    fs::write(&path, b"not-json\npartial").expect("journal");
    let limits = FeedLimits {
        max_bytes_per_poll: 1024,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");
    let batch = feed.poll().expect("poll");
    assert!(batch.records.is_empty());
    assert!(
        batch
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::ParserMalformed)
    );
    assert!(
        batch
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::ActivePartialFrame)
    );
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("append")
        .write_all(b"\n")
        .expect("complete");
    let second = feed.poll().expect("poll");
    assert!(second.records.is_empty());
}

#[test]
fn end_retains_partial_and_recent_returns_newest_records() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first = valid_record("telltale-11111111-1111-4111-8111-111111111111");
    let second = valid_record("telltale-22222222-2222-4222-8222-222222222222");
    let third = valid_record("telltale-33333333-3333-4333-8333-333333333333");
    let mut history = first.clone();
    history.push(b'\n');
    history.extend_from_slice(&second);
    history.push(b'\n');
    history.extend_from_slice(&third);
    fs::write(&path, &history).expect("history");

    let mut end_feed = LocalEventFeed::new(LocalEventFeedConfig::new(&path, StartupMode::End))
        .expect("end config");
    let end_start = end_feed.poll().expect("end start");
    assert!(end_start.records.is_empty());
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("append")
        .write_all(b"\n")
        .expect("complete partial");
    let completed = end_feed.poll().expect("end completion");
    assert_eq!(completed.records.len(), 1);
    assert_eq!(
        completed.records[0].common().event_id,
        "telltale-33333333-3333-4333-8333-333333333333"
    );

    let mut recent_feed = LocalEventFeed::new(LocalEventFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 2,
            max_bytes: history.len() + 1,
        },
    ))
    .expect("recent config");
    let recent = recent_feed.poll().expect("recent start");
    assert_eq!(recent.records.len(), 2);
    assert_eq!(
        recent.records[0].common().event_id,
        "telltale-22222222-2222-4222-8222-222222222222"
    );
    assert_eq!(
        recent.records[1].common().event_id,
        "telltale-33333333-3333-4333-8333-333333333333"
    );
}

#[test]
fn end_non_active_last_byte_peeks_are_bounded_and_counted() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    fs::write(directory.path().join("events-2026-01-01.jsonl"), b"first\n")
        .expect("first rotated generation");
    fs::write(
        directory.path().join("events-2026-01-02.jsonl"),
        b"second\n",
    )
    .expect("second rotated generation");
    fs::write(&path, []).expect("empty active generation");
    let limits = FeedLimits {
        max_bytes_per_poll: 1,
        ..FeedLimits::default()
    };
    let mut feed =
        LocalEventFeed::new(LocalEventFeedConfig::new(&path, StartupMode::End).with_limits(limits))
            .expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(batch.bytes_read, 1);
    assert!(has_notice(&batch, FeedNoticeCode::NonActivePartialFrame));
    assert!(!batch.caught_up);
}
