use super::*;

#[test]
fn recent_byte_floor_skips_clipped_prefix_without_malformed_notice() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-12121212-1212-4121-8121-121212121212";
    let second_id = "telltale-34343434-3434-4343-8434-343434343434";
    let mut first = valid_record(first_id);
    first.push(b'\n');
    let mut second = valid_record(second_id);
    second.push(b'\n');
    let mut history = first.clone();
    history.extend_from_slice(&second);
    let recent_bytes = first.len() / 2 + second.len();

    fs::write(&path, &history).expect("journal");
    let limits = FeedLimits {
        max_bytes_per_poll: history.len() + 1,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 2,
                max_bytes: recent_bytes,
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let batch = feed.poll().expect("poll");
    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].common().event_id, second_id);
    assert!(
        !batch
            .records
            .iter()
            .any(|record| record.common().event_id == first_id)
    );
    assert!(
        !batch
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::ParserMalformed)
    );
    assert!(
        !batch
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::OversizedFrame)
    );
}

#[test]
fn recent_truncation_does_not_skip_record_starting_at_floor() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-56565656-5656-4565-8565-565656565656";
    let second_id = "telltale-78787878-7878-4787-8787-787878787878";
    let replacement_id = "telltale-90909090-9090-4909-8909-909090909090";
    let mut first = valid_record(first_id);
    first.push(b'\n');
    let mut second = valid_record(second_id);
    second.push(b'\n');
    let mut history = first.clone();
    history.extend_from_slice(&second);
    let recent_bytes = first.len() / 2 + second.len();
    let floor_offset = history.len().saturating_sub(recent_bytes);

    fs::write(&path, &history).expect("history");
    let limits = FeedLimits {
        max_bytes_per_poll: history.len() + 1,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 2,
                max_bytes: recent_bytes,
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let initial = feed.poll().expect("initial poll");
    assert_eq!(initial.records.len(), 1);
    assert_eq!(initial.records[0].common().event_id, second_id);

    fs::write(&path, []).expect("truncate");
    let truncated = feed.poll().expect("truncation poll");
    assert!(
        truncated
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::TruncatedGeneration)
    );

    let mut replacement = vec![b'x'; floor_offset];
    replacement[floor_offset - 1] = b'\n';
    replacement.extend_from_slice(&valid_record(replacement_id));
    replacement.push(b'\n');
    fs::write(&path, &replacement).expect("rewrite at floor");

    let mut emitted = Vec::new();
    for _ in 0..8 {
        let batch = feed.poll().expect("replacement poll");
        emitted.extend(
            batch
                .records
                .into_iter()
                .map(|record| record.common().event_id.clone()),
        );
        if batch.caught_up {
            break;
        }
    }
    assert!(emitted.iter().any(|event_id| event_id == replacement_id));
}

#[test]
fn recent_truncation_reestablishes_the_floor_clip() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-11223344-1122-4122-8122-112233445566";
    let second_id = "telltale-22334455-2233-4233-8233-223344556677";
    let mut first = valid_record(first_id);
    first.push(b'\n');
    let mut second = valid_record(second_id);
    second.push(b'\n');
    let mut history = first.clone();
    history.extend_from_slice(&second);
    let recent_bytes = first.len() / 2 + second.len();
    let floor_offset = history.len() - recent_bytes;

    fs::write(&path, &history).expect("history");
    let limits = FeedLimits {
        max_bytes_per_poll: history.len() + 1,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 2,
                max_bytes: recent_bytes,
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let initial = feed.poll().expect("initial poll");
    assert_eq!(
        initial
            .records
            .iter()
            .map(|record| record.common().event_id.as_str())
            .collect::<Vec<_>>(),
        vec![second_id]
    );

    let truncated_length = floor_offset + 4;
    fs::write(&path, vec![b'x'; truncated_length]).expect("truncate and rewrite");
    let truncated = feed.poll().expect("truncation poll");
    assert!(truncated.records.is_empty());
    assert!(
        !truncated
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::ParserMalformed)
    );

    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("append newline")
        .write_all(b"\n")
        .expect("complete clipped prefix");
    let completed = feed.poll().expect("completion poll");
    assert!(completed.records.is_empty());
    assert!(
        !completed
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::ParserMalformed)
    );
}

#[test]
fn recent_scan_target_shrink_reestablishes_the_floor_clip() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-51515151-5151-4515-8515-515151515151";
    let second_id = "telltale-62626262-6262-4626-8626-626262626262";
    let replacement_id = "telltale-73737373-7373-4737-8737-737373737373";
    let mut first = valid_record(first_id);
    first.push(b'\n');
    let mut second = valid_record(second_id);
    second.push(b'\n');
    let mut history = first.clone();
    history.extend_from_slice(&second);
    let recent_bytes = first.len() / 2 + second.len();
    let floor_offset = history.len() - recent_bytes;

    fs::write(&path, &history).expect("history");
    let limits = FeedLimits {
        max_bytes_per_poll: 1,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 1,
                max_bytes: recent_bytes,
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let initial = feed.poll().expect("initial poll");
    assert_eq!(initial.bytes_read, 1);
    assert!(initial.records.is_empty());

    let mut replacement = vec![b'x'; floor_offset];
    replacement[floor_offset - 1] = b'\n';
    replacement.extend_from_slice(&valid_record(replacement_id));
    replacement.push(b'\n');
    fs::write(&path, &replacement).expect("rewrite at floor");

    let mut emitted = Vec::new();
    for _ in 0..1024 {
        let batch = feed.poll().expect("replacement poll");
        emitted.extend(
            batch
                .records
                .into_iter()
                .map(|record| record.common().event_id.clone()),
        );
        if batch.caught_up {
            break;
        }
    }

    assert_eq!(emitted, vec![replacement_id.to_owned()]);
}
