use super::*;

#[test]
fn startup_empty_beginning_file_is_caught_up_with_no_records() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    fs::write(&path, []).expect("empty journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert!(batch.records.is_empty());
    assert!(batch.caught_up);
    assert_eq!(batch.bytes_read, 0);
}

#[test]
fn startup_recent_restart_replays_the_same_latest_record() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let mut history = line("telltale-01010101-0101-4010-8010-010101010101");
    history.extend_from_slice(&line("telltale-02020202-0202-4020-8020-020202020202"));
    history.extend_from_slice(&line("telltale-03030303-0303-4030-8030-030303030303"));
    fs::write(&path, history).expect("journal");
    let startup = StartupMode::Recent {
        max_events: 1,
        max_bytes: 1024 * 1024,
    };
    let mut first = LocalEventFeed::from_path(&path, startup).expect("first config");
    let mut second = LocalEventFeed::from_path(&path, startup).expect("second config");

    let first_batch = first.poll().expect("first poll");
    let second_batch = second.poll().expect("second poll");

    assert_eq!(event_ids(&first_batch), event_ids(&second_batch));
    assert_eq!(
        event_ids(&first_batch),
        vec!["telltale-03030303-0303-4030-8030-030303030303"]
    );
}

#[test]
fn startup_missing_path_appears_later_without_feed_creation() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let missing = feed.poll().expect("missing poll");
    assert!(missing.records.is_empty());
    assert!(has_notice(&missing, FeedNoticeCode::JournalUnavailable));
    assert!(!path.exists());

    fs::write(&path, line("telltale-04040404-0404-4040-8040-040404040404"))
        .expect("journal appears");
    let appeared = feed.poll().expect("appeared poll");

    assert_eq!(
        event_ids(&appeared),
        vec!["telltale-04040404-0404-4040-8040-040404040404"]
    );
}

#[test]
fn startup_beginning_discovers_an_extensionless_active_path() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events");
    let event_id = "telltale-41414141-4141-4041-8041-414141414141";
    fs::write(&path, line(event_id)).expect("extensionless journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(event_ids(&batch), vec![event_id.to_owned()]);
    assert!(!has_notice(&batch, FeedNoticeCode::UnsafeFile));
}

#[test]
fn startup_recent_large_journal_reads_only_the_bounded_suffix() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let mut history = Vec::new();
    let mut ids = Vec::new();
    for index in 0..40 {
        let event_id = format!("telltale-{index:08x}-0000-4000-8000-{index:012x}");
        ids.push(event_id.clone());
        history.extend_from_slice(&line(&event_id));
    }
    let recent_bytes = line(&ids[38]).len() + line(&ids[39]).len();
    fs::write(&path, &history).expect("large journal");
    let limits = FeedLimits {
        max_bytes_per_poll: recent_bytes + 1,
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

    assert_eq!(event_ids(&batch), vec![ids[38].clone(), ids[39].clone()]);
    assert!(batch.bytes_read <= recent_bytes + 1);
    assert!(batch.bytes_read < history.len());
    assert!(!event_ids(&batch).iter().any(|id| ids[..38].contains(id)));
}

#[test]
fn startup_beginning_walks_rotated_generations_oldest_to_newest() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let ids = [
        "telltale-05050505-0505-4050-8050-050505050505",
        "telltale-06060606-0606-4060-8060-060606060606",
        "telltale-07070707-0707-4070-8070-070707070707",
    ];
    fs::write(
        directory.path().join("events-2026-01-01.jsonl"),
        line(ids[0]),
    )
    .expect("oldest generation");
    fs::write(
        directory.path().join("events-2026-01-02.jsonl"),
        line(ids[1]),
    )
    .expect("newest rotated generation");
    fs::write(&path, line(ids[2])).expect("active generation");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert_eq!(event_ids(&batch), ids.map(str::to_owned));
}

#[test]
fn api_profile_path_matches_resolver_without_creating_override() {
    let user_path = resolve_log_path(PathProfile::User, None);
    let user_existed = user_path.exists();
    let user = LocalEventFeedConfig::for_profile(PathProfile::User, None, StartupMode::Beginning);
    assert_eq!(user.path, user_path);
    assert_eq!(user.path.exists(), user_existed);

    let directory = tempdir().expect("tempdir");
    let explicit = directory.path().join("missing/events.jsonl");
    let config = LocalEventFeedConfig::for_profile(
        PathProfile::User,
        Some(explicit.clone()),
        StartupMode::Beginning,
    );
    assert_eq!(
        config.path,
        resolve_log_path(PathProfile::User, Some(explicit.clone()))
    );
    assert!(!explicit.exists());
    assert!(!explicit.parent().expect("explicit parent").exists());
}
