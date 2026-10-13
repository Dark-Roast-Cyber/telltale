//! OpenCode v2 `session_v2`/`session_message` stores through the scan binary.
//! Stores are synthetic; the DDL follows OpenCode v2.0.27's schema for the
//! tables Telltale reads. Commands and outputs are inert data, never executed.

use super::*;
use rusqlite::Connection;

const SESSION_SCHEMA: &str = "
CREATE TABLE `session_v2` (`id` text PRIMARY KEY, `project_id` text NOT NULL, `slug` text NOT NULL,
  `directory` text NOT NULL, `version` text NOT NULL, `metadata` text, `agent` text, `model` text,
  `time_created` integer NOT NULL, `time_updated` integer NOT NULL);
CREATE TABLE `session_message` (`id` text PRIMARY KEY, `session_id` text NOT NULL, `type` text NOT NULL,
  `seq` integer NOT NULL, `time_created` integer NOT NULL, `time_updated` integer NOT NULL, `data` text NOT NULL);
CREATE UNIQUE INDEX `session_message_session_seq_idx` ON `session_message` (`session_id`,`seq`);
";
const T0: i64 = 1_775_000_000_000;
const SECRET: &str = "SYNTHETIC-V2-OUTPUT-SECRET";
const RULES: &str = r#"
version: 1
description: Synthetic OpenCode v2 coverage.
defaults: { case_insensitive: false, enabled: true }
modifiers: []
rules:
  - id: synthetic.v2.command
    title: Synthetic v2 command marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 70
    detection:
      selection:
        command: 'synthetic-v2-command-marker'
      condition: selection
    explanation: Synthetic test.
  - id: synthetic.v2.result
    title: Synthetic v2 result marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 60
    detection:
      selection:
        tool_result: 'synthetic-v2-result-marker'
      condition: selection
    explanation: Synthetic test.
"#;

struct Harness {
    temp: tempfile::TempDir,
    root: std::path::PathBuf,
    database: std::path::PathBuf,
    rules: std::path::PathBuf,
    log: std::path::PathBuf,
    state: std::path::PathBuf,
}

impl Harness {
    fn new() -> Self {
        let temp = tempdir().unwrap();
        let root = temp.path().join("data");
        fs::create_dir_all(root.join("opencode")).unwrap();
        let database = root.join("opencode/opencode.db");
        let rules = temp.path().join("rules.yaml");
        fs::write(&rules, RULES).unwrap();
        Self {
            log: temp.path().join("events.jsonl"),
            state: temp.path().join("state.json"),
            temp,
            root,
            database,
            rules,
        }
    }

    fn scan(&self) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_telltale"))
            .env_clear()
            .current_dir(self.temp.path())
            .args([
                "scan",
                "--once",
                "--client",
                "opencode",
                "--no-local-config",
                "--emit-activity",
                "--install-inventory-disabled",
                "--no-default-rules",
                "--root",
            ])
            .arg(&self.root)
            .arg("--rules")
            .arg(&self.rules)
            .arg("--log-path")
            .arg(&self.log)
            .arg("--state-path")
            .arg(&self.state)
            .output()
            .unwrap()
    }

    fn successful(&self) -> Value {
        let result = self.scan();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);
        assert_eq!(summary["source_processing"]["parse_error_source_count"], 0);
        summary
    }

    /// `table -> last_time_updated` for every stored SQLite cursor.
    fn cursors(&self) -> BTreeMap<String, i64> {
        let saved: Value = serde_json::from_slice(&fs::read(&self.state).unwrap()).unwrap();
        saved["sqlite_ingestion_cursors"]
            .as_object()
            .unwrap()
            .values()
            .map(|cursor| {
                (
                    cursor["table"].as_str().unwrap().to_owned(),
                    cursor["last_time_updated"].as_i64().unwrap(),
                )
            })
            .collect()
    }

    fn events(&self) -> Vec<Value> {
        fs::read_to_string(&self.log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn session(writer: &Connection, id: &str) {
    writer
        .execute(
            "insert into session_v2 values (?1, 'prj', 'slug', '/synthetic', '2.0.27', null, 'build', '{\"id\":\"synthetic-model\",\"providerID\":\"synthetic-provider\"}', ?2, ?2)",
            rusqlite::params![id, T0],
        )
        .unwrap();
}

fn message(writer: &Connection, id: &str, session: &str, seq: i64, updated: i64, data: Value) {
    let mut data = data;
    let kind = data
        .as_object_mut()
        .unwrap()
        .remove("type")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    writer
        .execute(
            "insert into session_message values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![id, session, kind, seq, T0, updated, data.to_string()],
        )
        .unwrap();
}

fn update(writer: &Connection, id: &str, updated: i64, data: Value) {
    let mut data = data;
    data.as_object_mut().unwrap().remove("type");
    writer
        .execute(
            "update session_message set time_updated = ?2, data = ?3 where id = ?1",
            rusqlite::params![id, updated, data.to_string()],
        )
        .unwrap();
}

fn assistant(tool: Value) -> Value {
    serde_json::json!({
        "type": "assistant", "agent": "build",
        "model": {"id": "synthetic-model", "providerID": "synthetic-provider"},
        "content": [{"type": "text", "text": "Working on it."}, tool],
        "time": {"created": T0}
    })
}

fn bash(id: &str, command: &str, state: Value) -> Value {
    let mut state = state;
    state["input"] = serde_json::json!({"command": command});
    serde_json::json!({
        "type": "tool", "id": id, "name": "bash", "executed": false, "state": state,
        "time": {"created": T0, "ran": T0 + 1_000, "completed": T0 + 2_000}
    })
}

fn detections(events: &[Value], rule: &str) -> usize {
    events
        .iter()
        .filter(|event| {
            event["event_type"] == "detection"
                && event["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|evidence| evidence["rule_id"] == rule)
        })
        .count()
}

#[test]
fn opencode_v2_store_detects_resumes_and_recovers_with_its_own_cursor() {
    let harness = Harness::new();
    let writer = Connection::open(&harness.database).unwrap();
    writer
        .execute_batch("pragma journal_mode=WAL; pragma wal_autocheckpoint=0;")
        .unwrap();
    writer.execute_batch(SESSION_SCHEMA).unwrap();
    for id in ["ses_risky", "ses_benign"] {
        session(&writer, id);
    }
    message(
        &writer,
        "msg_r1",
        "ses_risky",
        1,
        T0 + 1,
        serde_json::json!({"type": "user", "text": "Please run the synthetic task.", "time": {"created": T0}}),
    );
    message(
        &writer,
        "msg_r2",
        "ses_risky",
        2,
        T0 + 2,
        assistant(bash(
            "call_risky",
            "printf synthetic-v2-command-marker",
            serde_json::json!({"status": "completed", "content": [{"type": "text", "text": format!("api_key={SECRET}\nsynthetic output")}]}),
        )),
    );
    message(
        &writer,
        "msg_b1",
        "ses_benign",
        1,
        T0 + 3,
        assistant(bash(
            "call_benign",
            "ls -la",
            serde_json::json!({"status": "running", "metadata": {}}),
        )),
    );
    assert!(harness.database.with_extension("db-wal").is_file());

    let first = harness.successful();
    // Record kinds per row: user; assistant + call + result; assistant + call.
    assert_eq!(first["source_processing"]["parsed_record_count"], 6);
    let events = harness.events();
    for event in &events {
        assert!(event_schema_validator().is_valid(event), "{event}");
    }
    assert_eq!(detections(&events, "synthetic.v2.command"), 1);
    assert_eq!(detections(&events, "synthetic.v2.result"), 0);
    let log = fs::read(&harness.log).unwrap();
    let state = fs::read(&harness.state).unwrap();
    for bytes in [&log, &state] {
        assert!(!String::from_utf8_lossy(bytes).contains(SECRET));
    }
    assert_eq!(
        harness.cursors(),
        BTreeMap::from([("session_message".to_owned(), T0 + 3)]),
        "v2 progress stages only the session_message cursor"
    );

    assert_eq!(harness.successful()["emitted_count"], 0);
    assert_eq!(fs::read(&harness.log).unwrap(), log);

    // An in-place lifecycle update keeps seq but refreshes time_updated.
    update(
        &writer,
        "msg_b1",
        T0 + HOUR,
        assistant(bash(
            "call_benign",
            "ls -la",
            serde_json::json!({"status": "completed", "content": [{"type": "text", "text": "synthetic-v2-result-marker"}]}),
        )),
    );
    let updated = harness.successful();
    assert_eq!(
        updated["source_processing"]["parsed_record_count"], 7,
        "the earlier rows are rereads inside the ten-minute overlap; msg_b1 now adds a result"
    );
    let events = harness.events();
    assert_eq!(detections(&events, "synthetic.v2.result"), 1);
    assert_eq!(detections(&events, "synthetic.v2.command"), 1);
    assert_eq!(
        harness.cursors(),
        BTreeMap::from([("session_message".to_owned(), T0 + HOUR)])
    );

    // Required output failure keeps the committed cursor; repair resumes.
    session(&writer, "ses_shell");
    message(
        &writer,
        "msg_s1",
        "ses_shell",
        1,
        T0 + 2 * HOUR,
        serde_json::json!({"type": "shell", "shellID": "sh_1", "command": "curl synthetic-v2-command-marker",
            "status": "exited", "exit": 0, "output": {"output": "done", "cursor": 4, "size": 4, "truncated": false},
            "time": {"created": T0, "completed": T0 + 1_000}}),
    );
    let committed_state = fs::read(&harness.state).unwrap();
    let parked = harness.temp.path().join("parked.jsonl");
    fs::rename(&harness.log, &parked).unwrap();
    fs::create_dir(&harness.log).unwrap();
    assert!(
        !harness.scan().status.success(),
        "an unpersisted detection may not commit state"
    );
    assert_eq!(fs::read(&harness.state).unwrap(), committed_state);
    fs::remove_dir(&harness.log).unwrap();
    fs::rename(&parked, &harness.log).unwrap();
    harness.successful();
    let events = harness.events();
    assert_eq!(detections(&events, "synthetic.v2.command"), 2);
    for event in &events {
        assert!(event_schema_validator().is_valid(event), "{event}");
    }
    assert_eq!(
        harness.cursors(),
        BTreeMap::from([("session_message".to_owned(), T0 + 2 * HOUR)])
    );
}

#[test]
fn legacy_part_cursor_does_not_skip_history_after_v2_migration() {
    let harness = Harness::new();
    let writer = Connection::open(&harness.database).unwrap();
    writer
        .execute_batch(
            "create table part (id text primary key, session_id text, time_updated integer, data text);",
        )
        .unwrap();
    let legacy_high_water = T0 + 100 * HOUR;
    writer
        .execute(
            "insert into part values ('legacy', 'ses_legacy', ?1, ?2)",
            rusqlite::params![
                legacy_high_water,
                serde_json::json!({"type": "tool", "tool": "bash", "callID": "legacy",
                    "state": {"status": "completed", "input": {"command": "true"}, "output": "ok"}})
                .to_string()
            ],
        )
        .unwrap();
    harness.successful();
    assert_eq!(
        harness.cursors(),
        BTreeMap::from([("part".to_owned(), legacy_high_water)])
    );

    // The same store migrates; v2 history is older than the legacy watermark.
    writer.execute_batch(SESSION_SCHEMA).unwrap();
    session(&writer, "ses_migrated");
    message(
        &writer,
        "msg_m1",
        "ses_migrated",
        1,
        T0,
        assistant(bash(
            "call_migrated",
            "printf synthetic-v2-command-marker",
            serde_json::json!({"status": "completed", "content": [{"type": "text", "text": "ok"}]}),
        )),
    );
    let migrated = harness.successful();
    assert_eq!(migrated["source_processing"]["parsed_record_count"], 3);
    assert_eq!(detections(&harness.events(), "synthetic.v2.command"), 1);
    assert_eq!(
        harness.cursors(),
        BTreeMap::from([
            ("part".to_owned(), legacy_high_water),
            ("session_message".to_owned(), T0),
        ]),
        "the legacy cursor is preserved and not reused for v2"
    );
    assert_eq!(harness.successful()["emitted_count"], 0);

    // A partial v2 schema fails closed instead of falling back to legacy rows.
    writer.execute_batch("drop table session_v2;").unwrap();
    let result = harness.scan();
    assert!(result.status.success());
    let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 1);
    assert_eq!(
        summary["source_processing"]["failures"][0]["acquisition_code"],
        "unsupported_source_schema"
    );
    assert_eq!(
        harness.cursors(),
        BTreeMap::from([
            ("part".to_owned(), legacy_high_water),
            ("session_message".to_owned(), T0),
        ])
    );
}

const HOUR: i64 = 3_600_000;
