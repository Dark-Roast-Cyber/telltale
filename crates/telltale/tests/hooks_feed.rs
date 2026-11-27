use std::io::Write;
use std::path::Path;

use serde_json::{Value, json};
use telltale_core::{
    FeedNoticeCode, HOOKS_RECORD_MAX_INPUT_BYTES, HooksRecordCursor, HooksRecordFeed,
    HooksRecordFeedConfig, StartupMode,
};

fn record(id: usize) -> Value {
    json!({
        "schema": "telltale_hooks.record.v1", "record_id": format!("tth:{id:032x}"),
        "recorded_at": "2026-11-26T00:00:00Z", "kind": "lifecycle",
        "producer": {"name": "telltale-hooks", "version": "0.8.0",
            "telltale_rev": "0123456789012345678901234567890123456789", "semantic_identity": null},
        "harness": {"name": "claude-code", "hook_event": "SessionStart", "permission_mode": null},
        "session": {"session_id": "synthetic-session", "agent_id": null,
            "agent_type": null, "prompt_id": null, "cwd_sha256": null},
        "lifecycle": {"event": "session_start", "source": null}, "telltale": []
    })
}

fn append(path: &Path, bytes: &[u8]) {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn row(path: &Path, id: usize) {
    append(path, format!("{}\n", record(id)).as_bytes());
}

fn rotate(path: &Path, index: usize) {
    std::fs::rename(
        path,
        path.with_file_name(format!("records-2026-11-26.{index}.jsonl")),
    )
    .unwrap();
}

fn ids(feed: &mut HooksRecordFeed) -> Vec<String> {
    feed.poll()
        .records
        .into_iter()
        .map(|record| record.record_id)
        .collect()
}

fn id(n: usize) -> String {
    format!("tth:{n:032x}")
}

#[test]
fn startup_modes_and_serialized_batch_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    row(&path, 1);
    row(&path, 2);
    rotate(&path, 1);
    row(&path, 3);
    let mut config = HooksRecordFeedConfig::new(&path, StartupMode::Beginning);
    config.max_records_per_poll = 1;
    let mut feed = HooksRecordFeed::new(config.clone()).unwrap();
    assert_eq!(ids(&mut feed), [id(1)]);
    let token = serde_json::to_vec(&feed.cursor().unwrap()).unwrap();
    let cursor: HooksRecordCursor = serde_json::from_slice(&token).unwrap();
    let mut resumed = HooksRecordFeed::resume(config, cursor).unwrap();
    assert_eq!(ids(&mut resumed), [id(2)]);
    assert_eq!(ids(&mut resumed), [id(3)]);
    assert!(ids(&mut resumed).is_empty());

    let mut end =
        HooksRecordFeed::new(HooksRecordFeedConfig::new(&path, StartupMode::End)).unwrap();
    assert!(ids(&mut end).is_empty());
    let mut recent = HooksRecordFeed::new(HooksRecordFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 2,
            max_bytes: 4096,
        },
    ))
    .unwrap();
    assert_eq!(ids(&mut recent), [id(2), id(3)]);
    row(&path, 4);
    assert_eq!(ids(&mut end), [id(4)]);
    assert_eq!(ids(&mut recent), [id(4)]);
}

#[test]
fn recent_initial_unterminated_record_is_delivered_when_completed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    append(&path, record(1).to_string().as_bytes());
    let mut feed = HooksRecordFeed::new(HooksRecordFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 2,
            max_bytes: 4096,
        },
    ))
    .unwrap();
    assert!(feed.poll().records.is_empty());
    append(&path, b"\n");
    let batch = feed.poll();
    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].record_id, id(1));
    assert!(batch.rejections.is_empty());
    assert!(batch.notices.is_empty());
    assert!(feed.poll().records.is_empty());
}

#[test]
fn recent_initial_empty_file_delivers_the_next_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    append(&path, b"");
    let mut feed = HooksRecordFeed::new(HooksRecordFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 2,
            max_bytes: 4096,
        },
    ))
    .unwrap();
    assert!(feed.poll().records.is_empty());
    row(&path, 1);
    assert_eq!(ids(&mut feed), [id(1)]);
    assert!(ids(&mut feed).is_empty());
}

#[test]
fn recent_initial_checkpoint_defers_an_unterminated_record_across_resume() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    append(&path, record(1).to_string().as_bytes());
    let config = HooksRecordFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 2,
            max_bytes: 4096,
        },
    );
    let mut feed = HooksRecordFeed::new(config.clone()).unwrap();
    assert!(feed.poll().records.is_empty());
    let token = serde_json::to_vec(&feed.cursor().expect("initial snapshot checkpoint")).unwrap();
    let cursor: HooksRecordCursor = serde_json::from_slice(&token).unwrap();
    let mut resumed = HooksRecordFeed::resume(config, cursor).unwrap();
    append(&path, b"\n");
    assert_eq!(ids(&mut resumed), [id(1)]);
    assert!(ids(&mut resumed).is_empty());
}

#[test]
fn recent_initial_empty_checkpoint_survives_resume() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    append(&path, b"");
    let config = HooksRecordFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 2,
            max_bytes: 4096,
        },
    );
    let mut feed = HooksRecordFeed::new(config.clone()).unwrap();
    assert!(feed.poll().records.is_empty());
    let token = serde_json::to_vec(&feed.cursor().expect("empty snapshot checkpoint")).unwrap();
    let cursor: HooksRecordCursor = serde_json::from_slice(&token).unwrap();
    let mut resumed = HooksRecordFeed::resume(config, cursor).unwrap();
    row(&path, 1);
    assert_eq!(ids(&mut resumed), [id(1)]);
    assert!(ids(&mut resumed).is_empty());
}

#[test]
fn recent_initial_fully_scanned_tail_is_checkpointed_without_a_second_scan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let mut bytes = vec![b' '; HOOKS_RECORD_MAX_INPUT_BYTES / 2 + 1];
    bytes.extend_from_slice(record(1).to_string().as_bytes());
    append(&path, &bytes);
    let mut config = HooksRecordFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 2,
            max_bytes: HOOKS_RECORD_MAX_INPUT_BYTES,
        },
    );
    config.max_bytes_per_poll = HOOKS_RECORD_MAX_INPUT_BYTES;
    let mut feed = HooksRecordFeed::new(config.clone()).unwrap();
    let batch = feed.poll();
    assert!(batch.records.is_empty());
    assert!(batch.bytes_read <= HOOKS_RECORD_MAX_INPUT_BYTES);
    let token = serde_json::to_vec(&feed.cursor().expect("fully scanned tail checkpoint")).unwrap();
    let cursor: HooksRecordCursor = serde_json::from_slice(&token).unwrap();
    let mut resumed = HooksRecordFeed::resume(config, cursor).unwrap();
    append(&path, b"\n");
    assert_eq!(ids(&mut resumed), [id(1)]);
    assert!(ids(&mut resumed).is_empty());
}

#[test]
fn recent_counts_valid_records_and_reports_rejected_lines_in_its_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    row(&path, 1);
    row(&path, 2);
    append(&path, b"synthetic-malformed\n");
    row(&path, 3);
    let mut feed = HooksRecordFeed::new(HooksRecordFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 2,
            max_bytes: 4096,
        },
    ))
    .unwrap();
    let batch = feed.poll();
    assert_eq!(
        batch
            .records
            .into_iter()
            .map(|row| row.record_id)
            .collect::<Vec<_>>(),
        [id(2), id(3)]
    );
    assert_eq!(batch.rejections[0].code, "malformed_json");
}

#[test]
fn cursor_survives_rotations_and_reports_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    row(&path, 1);
    let mut feed =
        HooksRecordFeed::new(HooksRecordFeedConfig::new(&path, StartupMode::Beginning)).unwrap();
    assert_eq!(ids(&mut feed), [id(1)]);
    let checkpoint = feed.cursor().unwrap();
    row(&path, 2);
    rotate(&path, 1);
    row(&path, 3);
    assert_eq!(ids(&mut feed), [id(2), id(3)]);
    row(&path, 4);
    rotate(&path, 2);
    row(&path, 5);
    rotate(&path, 3);
    row(&path, 6);
    assert_eq!(ids(&mut feed), [id(4), id(5), id(6)]);
    std::fs::remove_file(dir.path().join("records-2026-11-26.1.jsonl")).unwrap();
    let mut lost = HooksRecordFeed::resume(
        HooksRecordFeedConfig::new(&path, StartupMode::End),
        checkpoint,
    )
    .unwrap();
    let batch = lost.poll();
    assert!(
        batch
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::GenerationGap)
    );
    assert_eq!(batch.records[0].record_id, id(3));
}

#[test]
fn detects_truncation_and_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    row(&path, 1);
    row(&path, 2);
    let mut feed =
        HooksRecordFeed::new(HooksRecordFeedConfig::new(&path, StartupMode::Beginning)).unwrap();
    assert_eq!(ids(&mut feed), [id(1), id(2)]);
    std::fs::write(&path, format!("{}\n", record(3))).unwrap();
    let truncated = feed.poll();
    assert_eq!(truncated.records[0].record_id, id(3));
    assert!(
        truncated
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::TruncatedGeneration)
    );

    let new = dir.path().join("replacement");
    row(&new, 4);
    std::fs::rename(new, &path).unwrap();
    let replaced = feed.poll();
    assert_eq!(replaced.records[0].record_id, id(4));
    assert!(
        replaced
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::GenerationGap)
    );
}

#[test]
fn changed_head_detects_same_length_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    row(&path, 1);
    let mut feed =
        HooksRecordFeed::new(HooksRecordFeedConfig::new(&path, StartupMode::Beginning)).unwrap();
    assert_eq!(ids(&mut feed), [id(1)]);
    let mut replacement = record(2);
    replacement["harness"]["hook_event"] = json!("DifferentEvt");
    let old_bytes = std::fs::read(&path).unwrap();
    let new_bytes = format!("{replacement}\n");
    assert_eq!(old_bytes.len(), new_bytes.len());
    assert_ne!(&old_bytes[..64], &new_bytes.as_bytes()[..64]);
    std::fs::write(&path, new_bytes).unwrap();
    let batch = feed.poll();
    assert_eq!(batch.records[0].record_id, id(2));
    assert!(
        batch
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::ReplacedGeneration)
    );
    assert!(
        batch
            .notices
            .iter()
            .any(|notice| notice.code == FeedNoticeCode::GenerationGap)
    );
}

#[test]
fn empty_separators_advance_the_checkpoint_without_rejections() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    append(&path, b"\n");
    let config = HooksRecordFeedConfig::new(&path, StartupMode::Beginning);
    let mut feed = HooksRecordFeed::new(config.clone()).unwrap();
    let batch = feed.poll();
    assert!(batch.records.is_empty());
    assert!(batch.rejections.is_empty());
    assert!(batch.caught_up);
    let mut resumed = HooksRecordFeed::resume(config, feed.cursor().unwrap()).unwrap();
    let batch = resumed.poll();
    assert!(batch.rejections.is_empty());
    assert_eq!(batch.bytes_read, 0);
    row(&path, 1);
    assert_eq!(ids(&mut resumed), [id(1)]);
}

#[cfg(feature = "hooks")]
#[test]
fn active_suffix_ignores_empty_separators_but_reports_torn_fragments() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    append(&path, b"\n{\"schema\":\n");
    row(&path, 1);
    let mut file = telltale_sources::journal::JournalFile::open(&path).unwrap();
    let mut results = Vec::new();
    let complete = telltale_core::hooks::telemetry::visit_active_suffix(&mut file, 4096, |row| {
        results.push(row.map(|record| record.record_id));
    })
    .unwrap();
    assert!(complete);
    assert_eq!(results, [Err("malformed_json"), Ok(id(1))]);
}

#[test]
fn skips_rejections_and_waits_for_a_trailing_line_feed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    append(&path, b"synthetic-malformed\n{}\n");
    let mut unsafe_label = record(1);
    unsafe_label["session"]["session_id"] = json!("/home/synthetic/private.txt");
    append(&path, format!("{unsafe_label}\n{}", record(2)).as_bytes());
    let config = HooksRecordFeedConfig::new(&path, StartupMode::Beginning);
    let mut feed = HooksRecordFeed::new(config.clone()).unwrap();
    let batch = feed.poll();
    assert!(batch.records.is_empty());
    assert_eq!(
        batch
            .rejections
            .iter()
            .map(|line| line.code)
            .collect::<Vec<_>>(),
        ["malformed_json", "schema_mismatch", "unredacted_text"]
    );
    assert_eq!(batch.rejections[0].byte_offset, 0);
    assert_eq!(
        batch.rejections[1].byte_offset,
        b"synthetic-malformed\n".len() as u64
    );
    assert!(!format!("{:?}", batch.rejections).contains("synthetic"));
    assert!(!batch.caught_up);
    append(&path, b"\n");
    let mut resumed = HooksRecordFeed::resume(config, feed.cursor().unwrap()).unwrap();
    assert_eq!(ids(&mut resumed), [id(2)]);
    assert_eq!(ids(&mut feed), [id(2)]);
}

#[test]
fn skips_oversized_lines_with_bounded_work_per_poll() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    append(&path, &vec![b'x'; HOOKS_RECORD_MAX_INPUT_BYTES + 20]);
    let mut config = HooksRecordFeedConfig::new(&path, StartupMode::Beginning);
    config.max_bytes_per_poll = HOOKS_RECORD_MAX_INPUT_BYTES;
    let max_bytes = config.max_bytes_per_poll;
    let mut feed = HooksRecordFeed::new(config).unwrap();
    let batch = feed.poll();
    assert!(batch.bytes_read <= max_bytes);
    assert!(batch.rejections.is_empty());
    let checkpoint = serde_json::to_value(feed.cursor().unwrap()).unwrap();
    assert!(!checkpoint.to_string().contains("xxxxxxxx"));
    append(&path, b"\n");
    row(&path, 1);
    let batch = feed.poll();
    assert!(batch.bytes_read <= max_bytes);
    assert_eq!(batch.rejections[0].code, "input_too_large");
    assert_eq!(batch.rejections[0].byte_offset, 0);
    assert_eq!(batch.records[0].record_id, id(1));
}
