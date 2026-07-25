use super::*;

#[test]
fn benign_baseline_corpus_produces_zero_detections() {
    let sources = discover_sources(&crate::test_fixture_path("benign_baselines"));
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
