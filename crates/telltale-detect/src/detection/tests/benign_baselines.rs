use super::*;
use crate::baseline::{
    BaselineDeviationConfig, BaselineSnapshotStore, baseline_snapshot_id, build_baseline_summaries,
};
use crate::detection::{detect_parsed_source_records, summarize_parsed_source_activity};
use telltale_rules::load_default_rule_set;

#[test]
fn benign_baseline_corpus_produces_zero_detections() {
    let sources = discover_sources_best_effort(&crate::test_fixture_path("benign_baselines"));
    assert!(
        !sources.is_empty(),
        "benign baselines directory should contain discoverable sources"
    );
    let detections = detect_sources(&sources);
    assert!(
        detections.is_empty(),
        "benign baseline corpus should produce zero detections, got {} detections: {:?}",
        detections.len(),
        detections
            .iter()
            .map(|(_, e)| (&e.session_id, &e.severity, &e.rule_ids))
            .collect::<Vec<_>>()
    );
}

#[test]
fn routine_powerful_tool_name_and_error_text_have_zero_activity_risk() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from("routine.jsonl"),
    };
    let records = vec![NormalizedRecord {
        session_id: "routine-session".to_string(),
        client: "codex".to_string(),
        agent: Some("build".to_string()),
        model: Some("model".to_string()),
        provider: Some("provider".to_string()),
        timestamp: Some("2026-05-01T00:00:00Z".to_string()),
        kind: RecordKind::ToolCall,
        tool_name: Some("bash".to_string()),
        arguments: Some("{\"command\":\"ls\"}".to_string()),
        content: "completed without error".to_string(),
    }];

    let events = summarize_parsed_source_activity(
        &source,
        &records,
        &BaselineSnapshotStore::default(),
        BaselineDeviationConfig::default(),
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].risk_score, 0);
    assert!(events[0].risk_contributions.is_empty());
    assert_eq!(events[0].severity, "informational");
}

#[test]
fn default_rules_do_not_detect_a_bash_name_with_an_ls_command() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from("routine-defaults.jsonl"),
    };
    let record = NormalizedRecord {
        session_id: "routine-defaults".to_string(),
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        timestamp: Some("2026-05-01T00:00:00Z".to_string()),
        kind: RecordKind::ToolCall,
        tool_name: Some("bash".to_string()),
        arguments: Some("{\"command\":\"ls\"}".to_string()),
        content: "ls".to_string(),
    };

    let activities = summarize_parsed_source_activity(
        &source,
        std::slice::from_ref(&record),
        &BaselineSnapshotStore::default(),
        BaselineDeviationConfig::default(),
    );
    assert_eq!(activities.len(), 1);
    assert_eq!(activities[0].risk_score, 0);
    assert!(activities[0].risk_contributions.is_empty());

    let detections = detect_parsed_source_records(
        &source,
        &load_default_rule_set().expect("default rules"),
        &[record],
    );
    assert!(
        detections.is_empty(),
        "routine bash wrapper should not detect"
    );
}

#[test]
fn enabled_baseline_deviation_is_one_attributable_activity_contribution() {
    let record = |tool_name: &str, arguments: &str| NormalizedRecord {
        session_id: "baseline-session".to_string(),
        client: "codex".to_string(),
        agent: Some("build".to_string()),
        model: Some("model".to_string()),
        provider: Some("provider".to_string()),
        timestamp: Some("2026-05-01T00:00:00Z".to_string()),
        kind: RecordKind::ToolCall,
        tool_name: Some(tool_name.to_string()),
        arguments: Some(arguments.to_string()),
        content: String::new(),
    };
    let previous = (0..6)
        .map(|_| record("read_file", "{\"path\":\"src/lib.rs\"}"))
        .collect::<Vec<_>>();
    let current = vec![record(
        "shell",
        "{\"command\":\"curl https://new.example.test\"}",
    )];
    let baseline = build_baseline_summaries(&previous).remove(0);
    let mut snapshots = BaselineSnapshotStore::default();
    snapshots
        .snapshots
        .insert(baseline_snapshot_id(&baseline.key), baseline);
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from("baseline.jsonl"),
    };

    let enabled = summarize_parsed_source_activity(
        &source,
        &current,
        &snapshots,
        BaselineDeviationConfig {
            enabled: true,
            ..BaselineDeviationConfig::default()
        },
    );
    assert_eq!(enabled[0].risk_score, 10);
    assert_eq!(enabled[0].risk_contributions.len(), 1);
    assert_eq!(enabled[0].risk_contributions[0].id(), "baseline.deviation");

    let disabled = summarize_parsed_source_activity(
        &source,
        &current,
        &snapshots,
        BaselineDeviationConfig::default(),
    );
    assert_eq!(disabled[0].risk_score, 0);
    assert!(disabled[0].risk_contributions.is_empty());
}

#[test]
fn benign_baseline_opencode_sqlite_produces_zero_detections() {
    use rusqlite::Connection;
    use tempfile::tempdir;

    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("opencode.db");
    let conn = Connection::open(&db_path).expect("open db");
    conn.execute_batch(
        "CREATE TABLE message (
            id TEXT,
            sessionID TEXT,
            modelID TEXT,
            providerID TEXT,
            agent TEXT,
            time TEXT,
            type TEXT,
            tool_name TEXT,
            arguments TEXT,
            content TEXT,
            data TEXT
        );",
    )
    .expect("schema");
    conn.execute(
        "INSERT INTO message (id, sessionID, modelID, providerID, agent, time, type, tool_name, arguments, content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        (
            "benign-msg-1",
            "opencode-benign-baseline",
            "claude-sonnet-4",
            "anthropic",
            "build",
            "2026-05-10T09:00:00Z",
            "assistant",
            Option::<&str>::None,
            Option::<&str>::None,
            "Let me check the project structure for you.",
        ),
    )
    .expect("insert assistant");
    conn.execute(
        "INSERT INTO message (id, sessionID, modelID, providerID, agent, time, type, tool_name, arguments, content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        (
            "benign-msg-2",
            "opencode-benign-baseline",
            "claude-sonnet-4",
            "anthropic",
            "build",
            "2026-05-10T09:00:01Z",
            "tool_call",
            "read_file",
            "{\"path\":\"Cargo.toml\"}",
            Option::<&str>::None,
        ),
    )
    .expect("insert tool call");
    conn.execute(
        "INSERT INTO message (id, sessionID, modelID, providerID, agent, time, type, tool_name, arguments, content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        (
            "benign-msg-3",
            "opencode-benign-baseline",
            "claude-sonnet-4",
            "anthropic",
            "build",
            "2026-05-10T09:00:02Z",
            "tool_result",
            "read_file",
            Option::<&str>::None,
            "[package]\nname = \"my-project\"\nversion = \"0.1.0\"",
        ),
    )
    .expect("insert tool result");
    conn.execute(
        "INSERT INTO message (id, sessionID, modelID, providerID, agent, time, type, tool_name, arguments, content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        (
            "benign-msg-4",
            "opencode-benign-baseline",
            "claude-sonnet-4",
            "anthropic",
            "build",
            "2026-05-10T09:00:03Z",
            "assistant",
            Option::<&str>::None,
            Option::<&str>::None,
            "This is a minimal Rust project using the 2021 edition with serde as a dependency.",
        ),
    )
    .expect("insert assistant 2");

    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: db_path,
    };

    let detections = detect_sources(&[source]);
    assert!(
        detections.is_empty(),
        "benign OpenCode SQLite baseline should produce zero detections, got {} detections: {:?}",
        detections.len(),
        detections
            .iter()
            .map(|(_, e)| (&e.session_id, &e.severity, &e.rule_ids))
            .collect::<Vec<_>>()
    );
}
