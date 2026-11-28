use super::*;

#[test]
fn recent_boundary_rejects_a_replaced_generation_identity() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    fs::write(&path, b"not-json\n").expect("journal");
    let generation = JournalGeneration {
        path: path.clone(),
        identity: "stale-generation-identity".to_owned(),
        is_active: true,
    };
    let mut feed = LocalEventFeed::new(LocalEventFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 1,
            max_bytes: 8,
        },
    ))
    .expect("config");
    feed.cursors
        .insert(generation.identity.clone(), Cursor::new(&generation));
    let mut context = PollContext::new(feed.config.limits);

    feed.initialize_recent(std::slice::from_ref(&generation), 1, 8, &mut context);

    assert!(
        context
            .notices
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::ReplacedGeneration)
    );
    assert!(
        context
            .notices
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::StartupBoundaryUnavailable)
    );
    let recent = feed.recent.as_ref().expect("recent state");
    assert!(!recent.boundary_established);
    assert_eq!(recent.scan_targets.get(&generation.identity), Some(&None));
    assert!(!feed.recent_scan_complete(std::slice::from_ref(&generation)));

    let actual_identity = JournalFile::open(&path)
        .expect("journal open")
        .identity()
        .to_owned();
    assert_ne!(actual_identity, generation.identity);
}

#[test]
fn recent_excluded_generation_never_reenters_polling() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let oldest_path = directory.path().join("events-2026-01-01.jsonl");
    let middle_path = directory.path().join("events-2026-01-02.jsonl");
    let oldest_id = "telltale-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let middle_id = "telltale-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let active_id = "telltale-cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    let mut oldest = valid_record(oldest_id);
    oldest.push(b'\n');
    let mut middle = valid_record(middle_id);
    middle.push(b'\n');
    let mut active = valid_record(active_id);
    active.push(b'\n');

    fs::write(&oldest_path, &oldest).expect("oldest generation");
    fs::write(&middle_path, &middle).expect("middle generation");
    fs::write(&path, &active).expect("active generation");
    let limits = FeedLimits {
        max_events_per_poll: 16,
        max_bytes_per_poll: oldest.len() + middle.len() + active.len(),
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 2,
                max_bytes: middle.len() + active.len(),
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let mut emitted = Vec::new();
    for _ in 0..8 {
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
    let later = feed.poll().expect("later poll");
    emitted.extend(
        later
            .records
            .into_iter()
            .map(|record| record.common().event_id.clone()),
    );

    assert!(!emitted.iter().any(|event_id| event_id == oldest_id));
    assert_eq!(
        emitted
            .iter()
            .filter(|event_id| event_id.as_str() == middle_id || event_id.as_str() == active_id)
            .cloned()
            .collect::<Vec<_>>(),
        vec![middle_id.to_owned(), active_id.to_owned()]
    );
}

#[test]
fn recent_live_rotated_generation_survives_floor_disappearance() {
    assert_recent_live_rotated_generation_survives_floor_disappearance(false);
}

#[test]
fn recent_live_rotated_generation_survives_reused_floor_identity() {
    assert_recent_live_rotated_generation_survives_floor_disappearance(true);
}

#[test]
fn recent_reused_floor_identity_does_not_clip_sole_new_active() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let rotated = directory.path().join("events-2026-01-01.jsonl");
    let first_id = "telltale-10101010-1010-4010-8010-101010101010";
    let second_id = "telltale-20202020-2020-4020-8020-202020202020";
    let fourth_id = "telltale-40404040-4040-4040-8040-404040404040";
    let first = line(first_id);
    fs::write(&path, [first.as_slice(), first.as_slice()].concat()).expect("initial generation");

    let limits = FeedLimits {
        max_events_per_poll: 1,
        max_bytes_per_poll: 4096,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 1,
                max_bytes: first.len(),
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let mut initial_emitted = Vec::new();
    for _ in 0..16 {
        let batch = feed.poll().expect("initial poll");
        initial_emitted.extend(event_ids(&batch));
        if feed.recent.as_ref().expect("recent state").phase == RecentPhase::Live {
            break;
        }
    }
    assert_eq!(initial_emitted, vec![first_id.to_owned()]);
    assert!(feed.recent.as_ref().expect("recent state").floor_offset > 0);

    fs::rename(&path, &rotated).expect("rotate first generation");
    fs::write(&path, line(second_id)).expect("second generation");
    let _ = feed.poll().expect("second generation poll");
    assert!(
        feed.recent
            .as_ref()
            .expect("recent state")
            .floor_seen_non_active
    );

    fs::remove_file(&rotated).expect("remove floor generation");
    fs::remove_file(&path).expect("remove second generation");
    fs::write(&path, line(fourth_id)).expect("new active generation");
    feed.recent.as_mut().expect("recent state").floor_identity = JournalFile::open(&path)
        .expect("new active")
        .identity()
        .to_owned();

    let batch = feed.poll().expect("sole new active poll");
    assert_eq!(event_ids(&batch), vec![fourth_id.to_owned()]);
}

#[test]
fn recent_scan_does_not_wedge_when_the_initial_generation_disappears() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let rotated = directory.path().join("events-2026-01-01.jsonl");
    let event_id = "telltale-50505050-5050-4050-8050-505050505050";
    fs::write(&path, b"initial\n").expect("initial generation");
    let limits = FeedLimits {
        max_bytes_per_poll: 1,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 1,
                max_bytes: "initial\n".len(),
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    let scanning = feed.poll().expect("initial scan");
    assert!(scanning.records.is_empty());
    assert_eq!(
        feed.recent.as_ref().expect("recent state").phase,
        RecentPhase::Scanning
    );

    fs::rename(&path, &rotated).expect("rotate initial generation");
    fs::remove_file(&rotated).expect("delete initial generation");
    fs::write(&path, line(event_id)).expect("new active generation");

    let mut emitted = Vec::new();
    for _ in 0..1024 {
        let batch = feed.poll().expect("follow-up poll");
        emitted.extend(event_ids(&batch));
        if emitted.iter().any(|id| id == event_id) {
            break;
        }
    }

    assert_eq!(emitted, vec![event_id.to_owned()]);
    assert_eq!(
        feed.recent.as_ref().expect("recent state").phase,
        RecentPhase::Live
    );
}

#[test]
fn recent_later_discovered_older_generation_is_ignored() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let middle_path = directory.path().join("events-2026-01-02.jsonl");
    let middle_id = "telltale-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let active_id = "telltale-cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    let older_id = "telltale-20250101-2501-4250-8250-202501012501";
    let mut middle = valid_record(middle_id);
    middle.push(b'\n');
    let mut active = valid_record(active_id);
    active.push(b'\n');

    fs::write(&middle_path, &middle).expect("middle generation");
    fs::write(&path, &active).expect("active generation");
    let limits = FeedLimits {
        max_events_per_poll: 16,
        max_bytes_per_poll: middle.len() + active.len(),
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 2,
                max_bytes: middle.len() + active.len(),
            },
        )
        .with_limits(limits),
    )
    .expect("config");

    for _ in 0..8 {
        if feed.poll().expect("initial poll").caught_up {
            break;
        }
    }

    let older_path = directory.path().join("events-2025-01-01.jsonl");
    let mut older = valid_record(older_id);
    older.push(b'\n');
    fs::write(&older_path, &older).expect("older generation");
    let later = feed.poll().expect("later poll");

    assert!(
        !later
            .records
            .iter()
            .any(|record| record.common().event_id == older_id)
    );
}

#[test]
fn cursor_state_is_pruned_to_the_current_generation_bound() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    fs::write(&path, b"initial\n").expect("active generation");
    let limits = FeedLimits {
        max_generations: 2,
        max_bytes_per_poll: 4096,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");
    feed.poll().expect("initial poll");
    assert!(feed.cursors.len() <= 2);

    for day in 1..=8 {
        let rotated = directory
            .path()
            .join(format!("events-2026-01-{day:02}.jsonl"));
        fs::rename(&path, rotated).expect("rotate");
        fs::write(&path, format!("generation-{day}\n")).expect("new active generation");
        feed.poll().expect("rotation poll");
        assert!(feed.cursors.len() <= 2);
    }
}

#[test]
fn generation_bound_keeps_newest_suffix_and_is_not_caught_up() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let ids = [
        "telltale-a1111111-1111-4111-8111-111111111111",
        "telltale-b2222222-2222-4222-8222-222222222222",
        "telltale-c3333333-3333-4333-8333-333333333333",
        "telltale-d4444444-4444-4444-8444-444444444444",
    ];
    for (index, event_id) in ids.iter().enumerate().take(3) {
        let path = directory
            .path()
            .join(format!("events-2026-01-0{}.jsonl", index + 1));
        let mut record = valid_record(event_id);
        record.push(b'\n');
        fs::write(path, record).expect("rotated generation");
    }
    let mut active = valid_record(ids[3]);
    active.push(b'\n');
    fs::write(&path, &active).expect("active generation");

    let limits = FeedLimits {
        max_generations: 2,
        max_bytes_per_poll: 4096,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");
    let batch = feed.poll().expect("poll");

    let emitted = batch
        .records
        .iter()
        .map(|record| record.common().event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(emitted, vec![ids[2], ids[3]]);
    assert!(!batch.caught_up);
    assert!(
        batch
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::GenerationBound)
    );
}
