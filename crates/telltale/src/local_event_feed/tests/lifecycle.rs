use super::*;

#[test]
fn lifecycle_append_after_caught_up_emits_new_record_once() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-06070809-1011-4012-8013-141516171819";
    let second_id = "telltale-20212223-2425-4026-8027-282930313233";
    fs::write(&path, line(first_id)).expect("journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let first = feed.poll().expect("initial poll");
    assert!(first.caught_up);
    append(&path, &line(second_id));
    let second = feed.poll().expect("append poll");
    let third = feed.poll().expect("no duplicate poll");

    assert!(third.records.is_empty());
    assert_eq!(event_ids(&second), vec![second_id.to_owned()]);
    assert!(second.caught_up);
}

#[test]
fn lifecycle_multiple_rotations_walk_old_generations_before_new_active() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-34353637-3839-4041-8042-434445464748";
    let second_id = "telltale-49505152-5354-4055-8056-575859606162";
    let third_id = "telltale-63646566-6768-4069-8070-717273747576";
    fs::write(&path, line(first_id)).expect("first active");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
    assert_eq!(
        event_ids(&feed.poll().expect("first poll")),
        vec![first_id.to_owned()]
    );

    fs::rename(&path, directory.path().join("events-2026-02-02.jsonl")).expect("first rotation");
    fs::write(&path, line(second_id)).expect("second active");
    let second = feed.poll().expect("second poll");

    fs::rename(&path, directory.path().join("events-2026-02-03.jsonl")).expect("second rotation");
    fs::write(&path, line(third_id)).expect("third active");
    let third = feed.poll().expect("third poll");

    assert_eq!(event_ids(&second), vec![second_id.to_owned()]);
    assert_eq!(event_ids(&third), vec![third_id.to_owned()]);
}

#[test]
fn lifecycle_replacing_active_identity_is_not_treated_as_append() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-77787980-8182-4083-8084-858687888990";
    let replacement_id = "telltale-91929394-9596-4097-8098-990001020304";
    fs::write(&path, line(first_id)).expect("initial journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
    feed.poll().expect("initial poll");
    fs::remove_file(&path).expect("remove old active");
    fs::write(&path, line(replacement_id)).expect("replacement active");

    let batch = feed.poll().expect("replacement poll");

    assert_eq!(event_ids(&batch), vec![replacement_id.to_owned()]);
    assert!(has_notice(&batch, FeedNoticeCode::ReplacedGeneration));
}

#[test]
fn lifecycle_same_identity_same_size_rewrite_is_not_treated_as_append() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-77787980-8182-4083-8084-858687888990";
    let replacement_id = "telltale-91929394-9596-4097-8098-990001020304";
    let first = line(first_id);
    let replacement = line(replacement_id);
    assert_eq!(first.len(), replacement.len());
    fs::write(&path, &first).expect("initial journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
    assert_eq!(
        event_ids(&feed.poll().expect("initial poll")),
        vec![first_id.to_owned()]
    );

    fs::write(&path, &replacement).expect("same-identity replacement");

    let batch = feed.poll().expect("replacement poll");

    assert_eq!(event_ids(&batch), vec![replacement_id.to_owned()]);
    assert!(has_notice(&batch, FeedNoticeCode::ReplacedGeneration));
}

#[test]
fn lifecycle_delete_then_recreate_reports_unavailable_then_reads_new_identity() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_id = "telltale-05060708-0910-4011-8012-131415161718";
    let replacement_id = "telltale-19202122-2324-4025-8026-272829303132";
    fs::write(&path, line(first_id)).expect("initial journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
    feed.poll().expect("initial poll");
    fs::remove_file(&path).expect("delete active");

    let unavailable = feed.poll().expect("deleted poll");
    assert!(unavailable.records.is_empty());
    assert!(has_notice(&unavailable, FeedNoticeCode::JournalUnavailable));

    fs::write(&path, line(replacement_id)).expect("recreate active");
    let recreated = feed.poll().expect("recreated poll");

    assert_eq!(event_ids(&recreated), vec![replacement_id.to_owned()]);
    assert!(has_notice(&recreated, FeedNoticeCode::ReplacedGeneration));
}

#[test]
fn lifecycle_unread_generation_disappearance_reports_gap_and_continues() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let rotated = directory.path().join("events-2026-02-04.jsonl");
    let first_id = "telltale-33343536-3738-4039-8040-414243444546";
    let unread_id = "telltale-47484950-5152-4053-8054-555657585960";
    let active_id = "telltale-61626364-6566-4067-8068-697071727374";
    let mut initial = line(first_id);
    initial.extend_from_slice(&line(unread_id));
    fs::write(&path, initial).expect("initial journal");
    let limits = FeedLimits {
        max_events_per_poll: 1,
        max_bytes_per_poll: 4096,
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

    fs::rename(&path, &rotated).expect("rotate unread generation");
    fs::write(&path, line(active_id)).expect("new active");
    fs::remove_file(&rotated).expect("lose unread generation");
    let batch = feed.poll().expect("gap poll");

    assert_eq!(event_ids(&batch), vec![active_id.to_owned()]);
    assert!(has_notice(&batch, FeedNoticeCode::GenerationGap));
    assert!(!batch.caught_up);
}

#[test]
fn lifecycle_directory_target_is_rejected_without_panic() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    fs::create_dir(&path).expect("directory target");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert!(batch.records.is_empty());
    assert!(has_notice(&batch, FeedNoticeCode::UnsafeFile));
}

#[cfg(unix)]
#[test]
fn lifecycle_symlink_target_is_rejected_without_following() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let target = directory.path().join("real-events.jsonl");
    let path = directory.path().join("events.jsonl");
    fs::write(
        &target,
        line("telltale-75767778-7980-4081-8082-838485868788"),
    )
    .expect("real journal");
    symlink(&target, &path).expect("symlink journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert!(batch.records.is_empty());
    assert!(has_notice(&batch, FeedNoticeCode::UnsafeFile));
}

#[cfg(unix)]
#[test]
fn lifecycle_hardlink_target_is_rejected_as_ambiguous_identity() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("real-events.jsonl");
    let path = directory.path().join("events.jsonl");
    fs::write(
        &source,
        line("telltale-898a8b8c-8d8e-408f-8090-919293949596"),
    )
    .expect("real journal");
    fs::hard_link(&source, &path).expect("hard link journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");

    assert!(batch.records.is_empty());
    assert!(has_notice(&batch, FeedNoticeCode::UnsafeFile));
}

#[test]
fn lifecycle_directory_bound_is_reported_and_not_caught_up() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    fs::write(&path, line("telltale-97989900-0102-4003-8004-050607080910"))
        .expect("active journal");
    for index in 0..5 {
        fs::write(
            directory.path().join(format!("unrelated-{index}")),
            b"fixture",
        )
        .expect("unrelated fixture");
    }
    let limits = FeedLimits {
        max_directory_entries: 2,
        ..FeedLimits::default()
    };
    let mut feed = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(limits),
    )
    .expect("config");

    let batch = feed.poll().expect("poll");

    assert!(has_notice(&batch, FeedNoticeCode::DirectoryBound));
    assert!(!batch.caught_up);
}

#[test]
fn readonly_feed_operations_preserve_fixture_artifacts_across_lifecycle() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    #[cfg(unix)]
    std::os::unix::fs::symlink("events.jsonl", directory.path().join("synthetic.link")).unwrap();
    let before_missing = snapshot(directory.path());
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
    assert_eq!(snapshot(directory.path()), before_missing);

    let missing = feed.poll().expect("missing poll");
    assert!(has_notice(&missing, FeedNoticeCode::JournalUnavailable));
    assert_eq!(snapshot(directory.path()), before_missing);

    let first_id = "telltale-32333435-3637-4038-8039-404142434445";
    fs::write(&path, line(first_id)).expect("test-created journal");
    let before_append = snapshot(directory.path());
    let first = feed.poll().expect("append poll");
    assert_eq!(event_ids(&first), vec![first_id.to_owned()]);
    assert_eq!(snapshot(directory.path()), before_append);

    append(&path, b"malformed-readonly-fixture\n");
    let before_malformed = snapshot(directory.path());
    let malformed = feed.poll().expect("malformed poll");
    assert!(has_notice(&malformed, FeedNoticeCode::ParserMalformed));
    assert_eq!(snapshot(directory.path()), before_malformed);

    let rotated = directory.path().join("events-2026-02-06.jsonl");
    fs::rename(&path, &rotated).expect("test-created rotation");
    let second_id = "telltale-46474849-5051-4052-8053-545556575859";
    fs::write(&path, line(second_id)).expect("test-created active replacement");
    let before_rotation_poll = snapshot(directory.path());
    let rotated_batch = feed.poll().expect("rotation poll");
    assert_eq!(event_ids(&rotated_batch), vec![second_id.to_owned()]);
    assert_eq!(snapshot(directory.path()), before_rotation_poll);
}
