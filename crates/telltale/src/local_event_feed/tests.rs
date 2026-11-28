use super::{
    Cursor, FeedLimits, FeedNotice, FeedNoticeCode, LocalEventFeed, LocalEventFeedConfig,
    LocalEventFeedErrorCode, PollContext, RecentPhase, StartupMode,
};
use crate::test_support::tree_snapshot as snapshot;
use std::fs;
use std::io::Write;
use std::path::Path;
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

mod caught_up;
mod dedup;
mod floor_clip;
mod framing;
mod generations;
mod lifecycle;
mod poll_budgets;
mod privacy;
mod reading;
mod startup;
