use super::*;

#[test]
fn caught_up_recent_scanning_and_draining_states_are_false() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-24252627-2829-4030-8031-323334353637";
    let second_id = "telltale-38394041-4243-4044-8045-464748495051";
    let mut history = line(first_id);
    history.extend_from_slice(&line(second_id));
    let line_len = line(first_id).len();
    fs::write(&path, &history).expect("journal");
    let scanning_limits = FeedLimits {
        max_bytes_per_poll: line_len,
        ..FeedLimits::default()
    };
    let mut scanning = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 2,
                max_bytes: history.len(),
            },
        )
        .with_limits(scanning_limits),
    )
    .expect("scanning config");
    let scanning_batch = scanning.poll().expect("scanning poll");

    let draining_limits = FeedLimits {
        max_events_per_poll: 1,
        max_bytes_per_poll: history.len() + 1,
        ..FeedLimits::default()
    };
    let mut draining = LocalEventFeed::new(
        LocalEventFeedConfig::new(
            &path,
            StartupMode::Recent {
                max_events: 2,
                max_bytes: history.len(),
            },
        )
        .with_limits(draining_limits),
    )
    .expect("draining config");
    let draining_batch = draining.poll().expect("draining poll");

    assert!(scanning_batch.records.is_empty());
    assert!(!scanning_batch.caught_up);
    assert_eq!(
        scanning.recent.as_ref().expect("recent state").phase,
        RecentPhase::Scanning
    );
    assert_eq!(event_ids(&draining_batch), vec![first_id.to_owned()]);
    assert!(!draining_batch.caught_up);
    assert_eq!(
        draining.recent.as_ref().expect("recent state").phase,
        RecentPhase::Draining
    );
}

#[test]
fn caught_up_is_false_for_budget_and_active_partial_frontiers() {
    let directory = tempdir().expect("tempdir");
    let budget_path = directory.path().join("budget-events.jsonl");
    let mut budget_contents = line("telltale-52535455-5657-4058-8059-606162636465");
    budget_contents.extend_from_slice(&line("telltale-66676869-7071-4072-8073-747576777879"));
    fs::write(&budget_path, budget_contents).expect("budget journal");
    let budget_limits = FeedLimits {
        max_events_per_poll: 1,
        ..FeedLimits::default()
    };
    let mut budget_feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&budget_path, StartupMode::Beginning).with_limits(budget_limits),
    )
    .expect("budget config");
    let budget_batch = budget_feed.poll().expect("budget poll");

    let partial_path = directory.path().join("partial-events.jsonl");
    fs::write(&partial_path, b"partial-active-frame").expect("partial journal");
    let mut partial_feed =
        LocalEventFeed::from_path(&partial_path, StartupMode::Beginning).expect("config");
    let partial_batch = partial_feed.poll().expect("partial poll");

    assert!(!budget_batch.caught_up);
    assert!(!partial_batch.caught_up);
    assert!(has_notice(
        &partial_batch,
        FeedNoticeCode::ActivePartialFrame
    ));
}

#[test]
fn caught_up_bytes_read_is_payload_only_and_noop_is_zero() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-80818283-8485-4086-8087-888990919293";
    let second_id = "telltale-94959697-9899-4000-8001-020304050607";
    let first = line(first_id);
    let second = line(second_id);
    let mut contents = first.clone();
    contents.extend_from_slice(&second);
    fs::write(&path, contents).expect("journal");
    let limits = FeedLimits {
        max_bytes_per_poll: first.len(),
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");

    let first_batch = feed.poll().expect("first poll");
    let second_batch = feed.poll().expect("second poll");
    let no_op = feed.poll().expect("no-op poll");

    assert_eq!(first_batch.bytes_read, first.len());
    assert_eq!(second_batch.bytes_read, second.len());
    assert!(!first_batch.caught_up);
    assert!(second_batch.caught_up);
    assert!(no_op.records.is_empty());
    assert_eq!(no_op.bytes_read, 0);
    assert!(no_op.caught_up);
}

#[test]
fn reconciliation_budget_stops_subsequent_reads() {
    let context_limits = FeedLimits {
        max_reconciliations_per_poll: 1,
        ..FeedLimits::default()
    };
    let mut context = PollContext::new(context_limits);

    assert!(context.reconcile());
    assert!(!context.reconcile());
    assert!(!context.can_read());
    assert!(!context.can_read_bytes());
}
