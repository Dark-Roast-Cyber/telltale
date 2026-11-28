use super::*;

#[test]
fn framing_split_record_across_bounded_reads_is_emitted_once() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let record = line("telltale-08080808-0808-4080-8080-080808080808");
    fs::write(&path, &record).expect("journal");
    let limits = FeedLimits {
        max_bytes_per_poll: record.len() / 2,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");

    let first = feed.poll().expect("first poll");
    let second = feed.poll().expect("second poll");
    let third = feed.poll().expect("third poll");

    assert!(first.records.is_empty());
    assert!(!first.caught_up);
    assert!(second.records.is_empty());
    assert_eq!(
        event_ids(&third),
        vec!["telltale-08080808-0808-4080-8080-080808080808"]
    );
    assert!(third.caught_up);
    assert!(feed.poll().expect("no duplicate poll").records.is_empty());
}

#[test]
fn framing_malformed_line_between_valid_events_does_not_wedge_following_data() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-09090909-0909-4090-8090-090909090909";
    let second_id = "telltale-0a0a0a0a-0a0a-40a0-80a0-0a0a0a0a0a0a";
    let mut contents = line(first_id);
    contents.extend_from_slice(b"{malformed-between-valid}\n");
    contents.extend_from_slice(&line(second_id));
    fs::write(&path, contents).expect("journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(
        event_ids(&batch),
        vec![first_id.to_owned(), second_id.to_owned()]
    );
    assert!(has_notice(&batch, FeedNoticeCode::ParserMalformed));
}

#[test]
fn framing_structural_parser_failure_consumes_line_and_preserves_following_event() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let body = replace_once(
        replace_once(
            valid_record("telltale-0b0b0b0b-0b0b-40b0-80b0-0b0b0b0b0b0b"),
            "\"client\":\"synthetic\",",
            "",
        ),
        "\"source_path_hash\":\"synthetic-hash\"",
        "\"source_path_hash\":\"SYNTHETIC_STRUCTURAL\"",
    );
    assert_eq!(parser_notice(&body), FeedNoticeCode::ParserStructure);
    let following_id = "telltale-0c0c0c0c-0c0c-40c0-80c0-0c0c0c0c0c0c";
    let mut contents = body;
    contents.push(b'\n');
    contents.extend_from_slice(&line(following_id));
    fs::write(&path, contents).expect("journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert!(
        batch
            .records
            .iter()
            .all(|record| record.common().event_id
                != "telltale-0b0b0b0b-0b0b-40b0-80b0-0b0b0b0b0b0b")
    );
    assert_eq!(event_ids(&batch), vec![following_id.to_owned()]);
    assert!(has_notice(&batch, FeedNoticeCode::ParserStructure));
}

#[test]
fn framing_unsupported_event3_version_is_classified_and_following_event_emits() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let body = replace_once(
        valid_record("telltale-0d0d0d0d-0d0d-40d0-80d0-0d0d0d0d0d0d"),
        "\"schema_version\":\"3.0\"",
        "\"schema_version\":\"2.0\"",
    );
    assert_eq!(parser_notice(&body), FeedNoticeCode::ParserVersion);
    let following_id = "telltale-0e0e0e0e-0e0e-40e0-80e0-0e0e0e0e0e0e";
    let mut contents = body;
    contents.push(b'\n');
    contents.extend_from_slice(&line(following_id));
    fs::write(&path, contents).expect("journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(event_ids(&batch), vec![following_id.to_owned()]);
    assert!(has_notice(&batch, FeedNoticeCode::ParserVersion));
}

#[test]
fn framing_unsupported_event_family_is_classified_and_following_event_emits() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let body = replace_once(
        valid_record("telltale-0f0f0f0f-0f0f-40f0-80f0-0f0f0f0f0f0f"),
        "\"event_type\":\"activity\"",
        "\"event_type\":\"unsupported_family\"",
    );
    assert_eq!(parser_notice(&body), FeedNoticeCode::ParserFamily);
    let following_id = "telltale-10111213-1415-4016-8017-181920212223";
    let mut contents = body;
    contents.push(b'\n');
    contents.extend_from_slice(&line(following_id));
    fs::write(&path, contents).expect("journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(event_ids(&batch), vec![following_id.to_owned()]);
    assert!(has_notice(&batch, FeedNoticeCode::ParserFamily));
}

#[test]
fn framing_identity_parser_failure_is_classified_and_following_event_emits() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let body = replace_once(
        valid_record("telltale-22232425-2627-4028-8029-303132333435"),
        "telltale-22232425-2627-4028-8029-303132333435",
        "bad-event-id",
    );
    assert_eq!(parser_notice(&body), FeedNoticeCode::ParserIdentity);
    let following_id = "telltale-36373839-4041-4042-8043-444546474849";
    let mut contents = body;
    contents.push(b'\n');
    contents.extend_from_slice(&line(following_id));
    fs::write(&path, contents).expect("journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(event_ids(&batch), vec![following_id.to_owned()]);
    assert!(has_notice(&batch, FeedNoticeCode::ParserIdentity));
}

#[test]
fn framing_oversized_complete_frame_is_discarded_before_following_event() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let following_id = "telltale-64656667-6869-4070-8071-727374757677";
    let max_frame = valid_record(following_id).len();
    let oversized = vec![b'x'; max_frame + 1];
    let mut contents = oversized;
    contents.push(b'\n');
    contents.extend_from_slice(&line(following_id));
    fs::write(&path, contents).expect("journal");
    let limits = FeedLimits {
        max_frame_bytes: max_frame,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(event_ids(&batch), vec![following_id.to_owned()]);
    assert!(has_notice(&batch, FeedNoticeCode::OversizedFrame));
}

#[test]
fn framing_oversized_partial_frame_stays_bounded_until_lf_then_recovers() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let following_id = "telltale-78798081-8283-4084-8085-868788899091";
    let max_frame = valid_record(following_id).len();
    let oversized = vec![b'x'; max_frame * 8];
    fs::write(&path, &oversized).expect("unterminated oversized frame");
    let limits = FeedLimits {
        max_frame_bytes: max_frame,
        max_bytes_per_poll: 32,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");

    for _ in 0..32 {
        let _ = feed.poll().expect("bounded partial poll");
        let cursor = feed.cursors.values().next().expect("active cursor");
        assert!(cursor.frame.len() <= max_frame);
    }

    let mut completion = vec![b'\n'];
    completion.extend_from_slice(&line(following_id));
    append(&path, &completion);
    let mut emitted = Vec::new();
    let mut saw_oversized = false;
    for _ in 0..128 {
        let batch = feed.poll().expect("recovery poll");
        emitted.extend(event_ids(&batch));
        saw_oversized |= has_notice(&batch, FeedNoticeCode::OversizedFrame);
        if emitted.iter().any(|id| id == following_id) {
            break;
        }
    }

    assert_eq!(emitted, vec![following_id.to_owned()]);
    assert!(saw_oversized);
}

#[test]
fn framing_non_active_partial_never_joins_the_next_generation() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let rotated = directory.path().join("events-2026-02-01.jsonl");
    fs::write(&rotated, b"partial-old-generation").expect("partial rotated generation");
    let active_id = "telltale-92939495-9697-4098-8099-000102030405";
    fs::write(&path, line(active_id)).expect("active generation");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(event_ids(&batch), vec![active_id.to_owned()]);
    assert!(has_notice(&batch, FeedNoticeCode::NonActivePartialFrame));
    assert!(!batch.caught_up);
}
