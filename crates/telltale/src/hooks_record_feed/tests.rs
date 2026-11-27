use super::*;
use crate::hooks::config::Config;
use crate::hooks::runtime::Runtime;
use crate::hooks::telemetry::RotationConfig;
use serde_json::json;

#[test]
fn rotation_between_discovery_and_open_is_retried_without_a_gap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let runtime = Runtime::new(Config {
        telemetry_path: Some(path.clone()),
        telemetry_rotation: RotationConfig {
            max_size_bytes: 1,
            keep: 4,
        },
        ..Config::default()
    });
    runtime.record_terminal(
        "claude-code",
        json!({"event": "grant_revoked", "grant_id": "g-000000000001"}),
    );
    let mut feed =
        HooksRecordFeed::new(HooksRecordFeedConfig::new(&path, StartupMode::Beginning)).unwrap();
    let first = feed.poll().records.remove(0).record_id;
    let discovery = journal::discover_generations(&path, DEFAULT_MAX_DIRECTORY_ENTRIES).unwrap();

    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                runtime.record_terminal(
                    "claude-code",
                    json!({"event": "grant_revoked", "grant_id": "g-000000000002"}),
                );
            })
            .join()
            .unwrap();
        let racing = feed.poll_discovery(discovery);
        assert!(racing.records.is_empty());
        assert_eq!(racing.notices[0].code, FeedNoticeCode::ReadRace);
    });
    let next = feed.poll();
    assert_eq!(next.records.len(), 1);
    assert_ne!(next.records[0].record_id, first);
    assert!(next.notices.is_empty());
    assert!(feed.poll().records.is_empty());
}
