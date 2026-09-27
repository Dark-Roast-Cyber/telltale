use super::{
    Cursor, FeedLimits, FeedNotice, FeedNoticeCode, LocalEventFeed, LocalEventFeedConfig,
    LocalEventFeedErrorCode, PollContext, RecentPhase, StartupMode,
};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use telltale_schema::event::{Event3ErrorCategory, Event3Record};
use telltale_sources::journal::{JournalFile, JournalGeneration};
use telltale_sources::paths::{PathProfile, resolve_log_path};
use tempfile::tempdir;

fn valid_record(event_id: &str) -> Vec<u8> {
    format!(
        r#"{{"schema_version":"3.0","event_id":"{event_id}","telltale_version":"0.5.0","timestamp":"2026-01-01T00:00:00.000Z","observed_at":"2026-01-01T00:00:00.000Z","ingested_at":"2026-01-01T00:00:00.000Z","time_source":"observed","time_confidence":"high","time_override_reason":"synthetic","severity":"informational","risk_score":0,"risk_contributions":[],"client":"synthetic","session_id":"synthetic-session","tags":[],"evidence":[],"event_type":"activity","source_path_hash":"synthetic-hash"}}"#
    )
    .into_bytes()
}

fn line(event_id: &str) -> Vec<u8> {
    let mut value = valid_record(event_id);
    value.push(b'\n');
    value
}

fn append(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .expect("append")
        .write_all(bytes)
        .expect("append bytes");
}

fn event_ids(batch: &super::FeedBatch) -> Vec<String> {
    batch
        .records
        .iter()
        .map(|record| record.common().event_id.clone())
        .collect()
}

fn has_notice(batch: &super::FeedBatch, code: FeedNoticeCode) -> bool {
    batch.notices.iter().any(|notice| notice.code == code)
}

fn replace_once(bytes: Vec<u8>, from: &str, to: &str) -> Vec<u8> {
    String::from_utf8(bytes)
        .expect("synthetic UTF-8")
        .replacen(from, to, 1)
        .into_bytes()
}

fn parser_notice(body: &[u8]) -> FeedNoticeCode {
    let error = Event3Record::from_json(body).expect_err("synthetic parser failure");
    match error.category() {
        Event3ErrorCategory::Malformed => FeedNoticeCode::ParserMalformed,
        Event3ErrorCategory::Version => FeedNoticeCode::ParserVersion,
        Event3ErrorCategory::Structure => FeedNoticeCode::ParserStructure,
        Event3ErrorCategory::Identity => FeedNoticeCode::ParserIdentity,
        Event3ErrorCategory::Semantic => FeedNoticeCode::ParserSemantic,
        Event3ErrorCategory::Family => FeedNoticeCode::ParserFamily,
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, (&'static str, u64)> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, (&'static str, u64)>) {
        let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
        let kind = if metadata.file_type().is_symlink() {
            "symlink"
        } else if metadata.is_dir() {
            "directory"
        } else if metadata.is_file() {
            "file"
        } else {
            "other"
        };
        result.insert(
            path.strip_prefix(root)
                .expect("snapshot path")
                .to_path_buf(),
            (kind, metadata.len()),
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("snapshot directory") {
                visit(root, &entry.expect("snapshot entry").path(), result);
            }
        }
    }

    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

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
fn notices_are_static_and_do_not_echo_input_canaries() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let canary = "SYNTHETIC_FEED_PRIVACY_CANARY";
    fs::write(&path, format!("{{{canary}\n")).expect("journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
    let batch = feed.poll().expect("poll");
    let display = batch
        .notices
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let debug = format!("{:?}", batch.notices);
    assert!(!display.contains(canary));
    assert!(!debug.contains(canary));
}

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

fn assert_recent_live_rotated_generation_survives_floor_disappearance(
    inject_floor_identity_collision: bool,
) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let first_rotated = directory.path().join("events-2026-01-01.jsonl");
    let second_rotated = directory.path().join("events-2026-01-02.jsonl");
    let first_id = "telltale-10101010-1010-4010-8010-101010101010";
    let second_id = "telltale-20202020-2020-4020-8020-202020202020";
    let third_id = "telltale-30303030-3030-4030-8030-303030303030";
    let fourth_id = "telltale-40404040-4040-4040-8040-404040404040";
    let mut first = valid_record(first_id);
    first.push(b'\n');
    if inject_floor_identity_collision {
        let mut initial_generation = first.clone();
        initial_generation.extend_from_slice(&first);
        fs::write(&path, initial_generation).expect("initial generation with startup prefix");
    } else {
        fs::write(&path, &first).expect("initial generation");
    }

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

    let initial = feed.poll().expect("initial poll");
    assert_eq!(
        initial
            .records
            .iter()
            .map(|record| record.common().event_id.as_str())
            .collect::<Vec<_>>(),
        vec![first_id]
    );

    fs::rename(&path, &first_rotated).expect("rotate first generation");
    let mut second = valid_record(second_id);
    second.push(b'\n');
    let mut third = valid_record(third_id);
    third.push(b'\n');
    let mut second_generation = second.clone();
    second_generation.extend_from_slice(&third);
    fs::write(&path, &second_generation).expect("second generation");

    let partial = feed.poll().expect("partial second generation poll");
    assert_eq!(
        partial
            .records
            .iter()
            .map(|record| record.common().event_id.as_str())
            .collect::<Vec<_>>(),
        vec![second_id]
    );

    fs::rename(&path, &second_rotated).expect("rotate second generation");
    fs::remove_file(&first_rotated).expect("remove floor generation");
    let mut fourth = valid_record(fourth_id);
    fourth.push(b'\n');
    fs::write(&path, &fourth).expect("third generation");

    if inject_floor_identity_collision {
        assert!(feed.recent.as_ref().expect("recent state").floor_offset > 0);
        feed.recent.as_mut().expect("recent state").floor_identity = JournalFile::open(&path)
            .expect("new active")
            .identity()
            .to_owned();
    }

    let mut emitted = Vec::new();
    for _ in 0..16 {
        let batch = feed.poll().expect("post-floor poll");
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

    assert_eq!(emitted, vec![third_id.to_owned(), fourth_id.to_owned()]);
    let recent = feed.recent.as_ref().expect("recent state");
    assert!(
        recent
            .live_seen
            .iter()
            .all(|identity| feed.cursors.contains_key(identity))
    );
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

#[test]
fn readonly_feed_operations_preserve_fixture_artifacts_across_lifecycle() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
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

#[test]
fn privacy_notice_display_and_debug_are_static() {
    let notice = FeedNotice {
        code: FeedNoticeCode::ParserMalformed,
        count: 2,
    };

    assert_eq!(
        notice.to_string(),
        "local event feed notice: parser_malformed (2)"
    );
    let debug = format!("{notice:?}");
    assert!(debug.contains("ParserMalformed"));
    assert!(debug.contains('2'));
    assert!(!debug.contains("SYNTHETIC_FEED_PRIVACY_CANARY"));
}

#[test]
fn privacy_invalid_limit_errors_display_and_debug_without_input_values() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("SYNTHETIC_FEED_PRIVACY_CANARY.jsonl");
    let invalid_limits = FeedLimits {
        max_events_per_poll: 0,
        ..FeedLimits::default()
    };
    let invalid_limit = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(invalid_limits),
    )
    .expect_err("invalid limit");
    let invalid_recent = LocalEventFeed::new(LocalEventFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 0,
            max_bytes: 1,
        },
    ))
    .expect_err("invalid recent limit");

    assert_eq!(invalid_limit.code(), LocalEventFeedErrorCode::InvalidLimit);
    assert_eq!(
        invalid_recent.code(),
        LocalEventFeedErrorCode::InvalidRecentLimit
    );
    assert_eq!(
        invalid_limit.to_string(),
        "local event feed configuration error: invalid_limit"
    );
    assert_eq!(
        invalid_recent.to_string(),
        "local event feed configuration error: invalid_recent_limit"
    );
    for error in [invalid_limit, invalid_recent] {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains("SYNTHETIC_FEED_PRIVACY_CANARY"));
        assert!(!debug.contains("SYNTHETIC_FEED_PRIVACY_CANARY"));
        assert!(!display.contains(path.to_string_lossy().as_ref()));
        assert!(!debug.contains(path.to_string_lossy().as_ref()));
    }
}

#[test]
fn privacy_parser_notice_mappings_redact_canary_body_and_path() {
    let directory = tempdir().expect("tempdir");
    let path = directory
        .path()
        .join("SYNTHETIC_FEED_PRIVACY_CANARY-events.jsonl");
    let canary = "SYNTHETIC_FEED_PRIVACY_CANARY";
    let cases = vec![
        (
            format!(r#"{{"body":"{canary}""#).into_bytes(),
            FeedNoticeCode::ParserMalformed,
        ),
        (
            replace_once(
                valid_record("telltale-60616263-6465-4066-8067-686970717273"),
                "\"schema_version\":\"3.0\"",
                "\"schema_version\":\"2.0\"",
            ),
            FeedNoticeCode::ParserVersion,
        ),
        (
            replace_once(
                replace_once(
                    valid_record("telltale-74757677-7879-4080-8081-828384858687"),
                    "\"client\":\"synthetic\",",
                    "",
                ),
                "\"source_path_hash\":\"synthetic-hash\"",
                &format!("\"source_path_hash\":\"{canary}\""),
            ),
            FeedNoticeCode::ParserStructure,
        ),
        (
            replace_once(
                replace_once(
                    valid_record("telltale-88898a8b-8c8d-408e-808f-909192939495"),
                    "telltale-88898a8b-8c8d-408e-808f-909192939495",
                    "bad-event-id",
                ),
                "\"client\":\"synthetic\"",
                &format!("\"client\":\"{canary}\""),
            ),
            FeedNoticeCode::ParserIdentity,
        ),
        (
            replace_once(
                replace_once(
                    valid_record("telltale-96979899-0001-4002-8003-040506070809"),
                    "\"time_source\":\"observed\"",
                    "\"time_source\":\"invalid\"",
                ),
                "\"client\":\"synthetic\"",
                &format!("\"client\":\"{canary}\""),
            ),
            FeedNoticeCode::ParserSemantic,
        ),
        (
            replace_once(
                replace_once(
                    valid_record("telltale-10111213-1415-4016-8017-181920212223"),
                    "\"event_type\":\"activity\"",
                    "\"event_type\":\"unknown_family\"",
                ),
                "\"client\":\"synthetic\"",
                &format!("\"client\":\"{canary}\""),
            ),
            FeedNoticeCode::ParserFamily,
        ),
    ];
    let mut contents = Vec::new();
    for (body, expected) in &cases {
        assert_eq!(parser_notice(body), *expected);
        contents.extend_from_slice(body);
        contents.push(b'\n');
    }
    fs::write(&path, &contents).expect("privacy journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");
    let display = batch
        .notices
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let debug = format!("{:?}", batch.notices);
    let raw = String::from_utf8(contents).expect("synthetic UTF-8");
    let path_text = path.to_string_lossy();

    assert!(batch.records.is_empty());
    assert!(!display.contains(canary));
    assert!(!debug.contains(canary));
    assert!(!display.contains(&raw));
    assert!(!debug.contains(&raw));
    assert!(!display.contains(path_text.as_ref()));
    assert!(!debug.contains(path_text.as_ref()));
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
