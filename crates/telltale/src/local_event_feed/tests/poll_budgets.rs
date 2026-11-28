use super::*;

#[test]
fn recent_exact_poll_byte_budget_emits_the_only_record() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let event_id = "telltale-66666666-6666-4666-8666-666666666666";
    let mut line = valid_record(event_id);
    line.push(b'\n');

    fs::write(&path, &line).expect("journal");
    let limits = FeedLimits {
        max_bytes_per_poll: line.len(),
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 1,
                max_bytes: line.len(),
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let first = feed.poll().expect("first poll");
    let second = feed.poll().expect("second poll");
    let third = feed.poll().expect("third poll");
    let emitted = first
        .records
        .into_iter()
        .chain(second.records)
        .chain(third.records)
        .collect::<Vec<_>>();

    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].common().event_id, event_id);
}

#[test]
fn recent_debug_does_not_dump_a_partial_frame() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let canary = "SYNTHETIC_FEED_PRIVACY_CANARY";
    fs::write(&path, canary).expect("partial journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    feed.poll().expect("poll");

    assert!(!format!("{feed:?}").contains(canary));
}

#[test]
fn recent_floor_peek_counts_against_the_poll_byte_budget() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let mut line = valid_record("telltale-66666666-6666-4666-8666-666666666666");
    line.push(b'\n');
    fs::write(&path, &line).expect("journal");
    let limits = FeedLimits {
        max_bytes_per_poll: 1,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 1,
                max_bytes: line.len() / 2,
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(batch.bytes_read, 1);
    assert!(batch.records.is_empty());
}

#[test]
fn recent_window_larger_than_poll_budget_drains_without_loss() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let event_ids = [
        "telltale-77777777-7777-4777-8777-777777777777",
        "telltale-88888888-8888-4888-8888-888888888888",
        "telltale-99999999-9999-4999-8999-999999999999",
    ];
    let mut history = Vec::new();
    for event_id in event_ids {
        history.extend_from_slice(&valid_record(event_id));
        history.push(b'\n');
    }
    let line_len = history.len() / event_ids.len();

    fs::write(&path, &history).expect("journal");
    let limits = FeedLimits {
        max_bytes_per_poll: line_len,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: event_ids.len(),
                max_bytes: history.len(),
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let mut emitted = Vec::new();
    for _ in 0..16 {
        let batch = feed.poll().expect("poll");
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

    let expected = event_ids
        .iter()
        .map(|event_id| (*event_id).to_owned())
        .collect::<Vec<_>>();
    assert_eq!(emitted, expected);
}

#[test]
fn event_limit_exhaustion_does_not_forget_remaining_records() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let event_ids = [
        "telltale-aaaaaaa1-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
        "telltale-bbbbbbb2-bbbb-4bbb-8bbb-bbbbbbbbbbb2",
        "telltale-ccccccc3-cccc-4ccc-8ccc-ccccccccccc3",
    ];
    let mut history = Vec::new();
    for event_id in event_ids {
        history.extend_from_slice(&valid_record(event_id));
        history.push(b'\n');
    }

    fs::write(&path, &history).expect("journal");
    let limits = FeedLimits {
        max_events_per_poll: 1,
        max_bytes_per_poll: history.len() + 1,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: event_ids.len(),
                max_bytes: history.len(),
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let mut emitted = Vec::new();
    for _ in 0..16 {
        let batch = feed.poll().expect("poll");
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

    let expected = event_ids
        .iter()
        .map(|event_id| (*event_id).to_owned())
        .collect::<Vec<_>>();
    assert_eq!(emitted, expected);
}

#[test]
fn beginning_event_limit_drains_remaining_records() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let event_ids = [
        "telltale-ddddddd4-dddd-4ddd-8ddd-ddddddddddd4",
        "telltale-eeeeeee5-eeee-4eee-8eee-eeeeeeeeeee5",
        "telltale-fffffff6-ffff-4fff-8fff-fffffffffff6",
    ];
    let mut history = Vec::new();
    for event_id in event_ids {
        history.extend_from_slice(&valid_record(event_id));
        history.push(b'\n');
    }

    fs::write(&path, &history).expect("journal");
    let limits = FeedLimits {
        max_events_per_poll: 1,
        max_bytes_per_poll: history.len() + 1,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");

    let mut emitted = Vec::new();
    for _ in 0..16 {
        let batch = feed.poll().expect("poll");
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

    let expected = event_ids
        .iter()
        .map(|event_id| (*event_id).to_owned())
        .collect::<Vec<_>>();
    assert_eq!(emitted, expected);
}
