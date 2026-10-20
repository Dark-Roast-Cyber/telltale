//! Synthetic stores only. Maintenance never opens the source database or emits events.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const T0: i64 = 1_775_002_000_000;
const SECRET: &str = "SYNTHETIC-CURSOR-RESET-PRIVATE";

struct Harness {
    temp: TempDir,
    root: PathBuf,
    database: PathBuf,
    state: PathBuf,
    log: PathBuf,
    rules: PathBuf,
    table: &'static str,
}

impl Harness {
    fn new(table: &'static str) -> Self {
        let temp = tempdir().unwrap();
        let root = temp.path().join("stores");
        fs::create_dir_all(root.join("opencode")).unwrap();
        let database = root.join("opencode/opencode.db");
        let connection = Connection::open(&database).unwrap();
        if table == "part" {
            connection.execute_batch("CREATE TABLE part (id TEXT PRIMARY KEY, session_id TEXT, time_updated INTEGER, data TEXT);").unwrap();
        } else {
            connection.execute_batch("CREATE TABLE session_v2 (id TEXT PRIMARY KEY, agent TEXT, model TEXT);
                INSERT INTO session_v2 VALUES ('ses', 'build', NULL);
                CREATE TABLE session_message (id TEXT PRIMARY KEY, session_id TEXT, type TEXT, seq INTEGER, time_created INTEGER, time_updated INTEGER, data TEXT);").unwrap();
        }
        let rules = temp.path().join("rules.yaml");
        fs::write(
            &rules,
            r#"
version: 1
description: Synthetic cursor reset coverage.
defaults: { case_insensitive: false, enabled: true }
modifiers: []
rules:
  - id: synthetic.reset
    title: Synthetic cursor reset marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 70
    detection:
      selection:
        command: 'synthetic-reset-marker'
      condition: selection
    explanation: Synthetic test.
"#,
        )
        .unwrap();
        Self {
            database,
            state: temp.path().join("state.json"),
            log: temp.path().join("events.jsonl"),
            rules,
            temp,
            root,
            table,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
        command.env_clear().current_dir(self.temp.path());
        command
    }

    fn insert(&self, id: &str, seq: i64, time: i64) {
        let connection = Connection::open(&self.database).unwrap();
        if self.table == "part" {
            let data = json!({"type":"tool", "tool":"bash", "callID":id,
                "state":{"status":"completed", "input":{"command":"echo synthetic-reset-marker"},
                "output":SECRET, "time":{"start":time,"end":time}}});
            connection
                .execute(
                    "INSERT INTO part VALUES (?1, 'ses', ?2, ?3)",
                    params![id, time, data.to_string()],
                )
                .unwrap();
        } else {
            let data = json!({"agent":"build", "content":[{"type":"tool", "id":id,
                "name":"bash", "executed":false, "state":{"status":"running", "metadata":{},
                "input":{"command":"echo synthetic-reset-marker"}}}], "time":{"created":time}});
            connection
                .execute(
                    "INSERT INTO session_message VALUES (?1,'ses','assistant',?2,?3,?3,?4)",
                    params![id, seq, time, data.to_string()],
                )
                .unwrap();
        }
    }

    fn scan(&self, extra: &[&str]) -> Output {
        self.command()
            .args([
                "scan",
                "--once",
                "--client",
                "opencode",
                "--no-local-config",
                "--emit-activity",
                "--no-default-rules",
                "--install-inventory-disabled",
                "--root",
            ])
            .arg(&self.root)
            .arg("--rules")
            .arg(&self.rules)
            .arg("--state-path")
            .arg(&self.state)
            .arg("--log-path")
            .arg(&self.log)
            .args(extra)
            .output()
            .unwrap()
    }

    fn list(&self) -> Output {
        self.command()
            .args(["cursor", "list", "--state-path"])
            .arg(&self.state)
            .output()
            .unwrap()
    }

    fn selected(&self) -> Value {
        success(self.list())["cursors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|cursor| cursor["table"] == self.table)
            .unwrap()
            .clone()
    }

    fn reset(&self, cursor: &Value, extra: &[&str]) -> Output {
        self.command()
            .args(["cursor", "reset", "--state-path"])
            .arg(&self.state)
            .arg("--source-instance-id")
            .arg(cursor["source_instance_id"].as_str().unwrap())
            .arg("--table")
            .arg(cursor["table"].as_str().unwrap())
            .arg("--expect-cursor")
            .arg(cursor["cursor_digest"].as_str().unwrap())
            .args(extra)
            .output()
            .unwrap()
    }

    fn saved(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.state).unwrap()).unwrap()
    }

    fn private(&self, output: &Output) {
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(self.temp.path().to_str().unwrap()), "{text}");
            assert!(!text.contains(SECRET), "{text}");
        }
    }
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn cursor_key(cursor: &Value) -> String {
    format!(
        "opencode\u{1f}opencode.sqlite\u{1f}{}\u{1f}{}",
        cursor["source_instance_id"].as_str().unwrap(),
        cursor["table"].as_str().unwrap()
    )
}

#[test]
fn cursor_reset_quiet_store_retains_dedup_and_changes_only_exact_selection() {
    for table in ["part", "session_message"] {
        let h = Harness::new(table);
        h.insert("old", 0, T0 - 1_200_000);
        h.insert("recent", 1, T0);
        success(h.scan(&[]));
        success(h.scan(&[]));
        assert_eq!(success(h.scan(&[]))["emitted_count"], 0);
        let selected = h.selected();
        let mut before = h.saved();
        // Other schema, another OpenCode instance, and another client are all preserved.
        let cursors = before["sqlite_ingestion_cursors"].as_object_mut().unwrap();
        let original = cursors[&cursor_key(&selected)].clone();
        let mut other = original.clone();
        other["table"] = if table == "part" {
            "session_message"
        } else {
            "part"
        }
        .into();
        let key = format!(
            "opencode\u{1f}opencode.sqlite\u{1f}{}\u{1f}{}",
            other["source_instance_id"].as_str().unwrap(),
            other["table"].as_str().unwrap()
        );
        cursors.insert(key, other);
        let mut other = original.clone();
        other["source_instance_id"] = "a".repeat(64).into();
        cursors.insert(
            format!(
                "opencode\u{1f}opencode.sqlite\u{1f}{}\u{1f}{table}",
                "a".repeat(64)
            ),
            other,
        );
        let mut other = original;
        other["client"] = "codex".into();
        other["source_id"] = "codex.sessions".into();
        cursors.insert("unrelated-synthetic-client".into(), other);
        fs::write(&h.state, serde_json::to_vec(&before).unwrap()).unwrap();
        let source = fs::read(&h.database).unwrap();
        let log = fs::read(&h.log).unwrap();
        let listed = h.list();
        h.private(&listed);
        success(listed);
        assert_eq!(h.saved(), before);
        let output = h.reset(&selected, &["--accept-history-gap"]);
        h.private(&output);
        let result = success(output);
        assert_eq!(result["history_recovered"], false);
        assert_eq!(result["baseline_changed"], false);
        before["sqlite_ingestion_cursors"]
            .as_object_mut()
            .unwrap()
            .remove(&cursor_key(&selected));
        assert_eq!(h.saved(), before);
        assert_eq!(fs::read(&h.database).unwrap(), source);
        assert_eq!(fs::read(&h.log).unwrap(), log);
        assert_eq!(
            success(h.scan(&[]))["emitted_count"],
            0,
            "both prior selected-window projections remain suppressed"
        );
        assert_eq!(h.selected()["last_time_updated"], T0);
    }
}

#[test]
fn cursor_reset_regressed_empty_and_missing_stores_remain_truthful() {
    for table in ["part", "session_message"] {
        for scenario in ["restored", "deleted", "empty", "missing"] {
            let h = Harness::new(table);
            h.insert("old", 0, T0 - 3_600_000);
            let old_store = fs::read(&h.database).unwrap();
            h.insert("recent", 1, T0);
            success(h.scan(&[]));
            if scenario == "restored" {
                fs::write(&h.database, old_store).unwrap();
            } else {
                let connection = Connection::open(&h.database).unwrap();
                let sql = match scenario {
                    "deleted" => format!("DELETE FROM {table} WHERE id = 'recent'"),
                    "empty" => format!("DELETE FROM {table}"),
                    _ => format!("DROP TABLE {table}"),
                };
                connection.execute_batch(&sql).unwrap();
            }
            let cursor = h.selected();
            let failed = h.scan(&[]);
            h.private(&failed);
            let failure = success(failed);
            let code = if scenario == "missing" && table == "session_message" {
                "unsupported_source_schema"
            } else {
                "resume_regressed"
            };
            assert_eq!(
                failure["source_processing"]["failures"][0]["acquisition_code"], code,
                "{table}/{scenario}: {failure}"
            );
            assert_eq!(h.selected(), cursor);
            success(h.scan(&["--backfill"]));
            assert_eq!(h.selected(), cursor, "backfill is not reset");
            let log = fs::read(&h.log).unwrap();
            let source = fs::read(&h.database).unwrap();
            success(h.reset(&cursor, &["--accept-history-gap"]));
            assert_eq!(fs::read(&h.log).unwrap(), log);
            assert_eq!(fs::read(&h.database).unwrap(), source);
            if matches!(scenario, "restored" | "deleted") {
                let after_reset = fs::read(&h.state).unwrap();
                let lock_path = h.log.with_file_name("events.jsonl.lock");
                let lock = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(lock_path)
                    .unwrap();
                fs4::FileExt::lock(&lock).unwrap();
                let blocked = h.scan(&[]);
                assert!(!blocked.status.success(), "{table}/{scenario}");
                assert_eq!(
                    fs::read(&h.state).unwrap(),
                    after_reset,
                    "output failure must not install new progress"
                );
                assert_eq!(fs::read(&h.log).unwrap(), log);
                fs4::FileExt::unlock(&lock).unwrap();
            }
            let resumed = success(h.scan(&[]));
            if matches!(scenario, "restored" | "deleted") {
                assert_eq!(
                    resumed["source_processing"]["parse_error_source_count"], 0,
                    "{resumed}"
                );
                assert_eq!(h.selected()["last_time_updated"], T0 - 3_600_000);
            } else {
                assert!(
                    h.saved()["sqlite_ingestion_cursors"]
                        .as_object()
                        .unwrap()
                        .is_empty()
                );
                if table == "session_message" && scenario == "missing" {
                    assert_eq!(
                        resumed["source_processing"]["failures"][0]["acquisition_code"],
                        "unsupported_source_schema"
                    );
                }
            }
        }
    }
}

#[test]
fn cursor_reset_confirmation_stale_retry_and_lock_failures_preserve_state() {
    let h = Harness::new("session_message");
    h.insert("recent", 0, T0);
    success(h.scan(&[]));
    let cursor = h.selected();
    let before = fs::read(&h.state).unwrap();
    let missing_ack = h.reset(&cursor, &[]);
    assert!(!missing_ack.status.success());
    assert_eq!(
        String::from_utf8_lossy(&missing_ack.stderr).trim(),
        "cursor_history_gap_acceptance_required"
    );
    assert_eq!(fs::read(&h.state).unwrap(), before);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(h.state.with_file_name("state.json.lock"))
        .unwrap();
    fs4::FileExt::lock(&lock).unwrap();
    for output in [h.list(), h.reset(&cursor, &["--accept-history-gap"])] {
        assert!(!output.status.success());
        h.private(&output);
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim(),
            "cursor_state_unavailable"
        );
        assert_eq!(fs::read(&h.state).unwrap(), before);
    }
    fs4::FileExt::unlock(&lock).unwrap();
    h.insert("newer", 1, T0 + 1000);
    success(h.scan(&[]));
    let before = fs::read(&h.state).unwrap();
    let stale = h.reset(&cursor, &["--accept-history-gap"]);
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).starts_with("cursor_changed;"));
    assert_eq!(fs::read(&h.state).unwrap(), before);
    let fresh = h.selected();
    success(h.reset(&fresh, &["--accept-history-gap"]));
    let before = fs::read(&h.state).unwrap();
    let absent = h.reset(&fresh, &["--accept-history-gap"]);
    assert!(!absent.status.success());
    assert!(String::from_utf8_lossy(&absent.stderr).starts_with("cursor_not_found;"));
    assert_eq!(fs::read(&h.state).unwrap(), before);
}

#[test]
fn cursor_reset_bare_relative_state_path_commits_and_acknowledges() {
    let h = Harness::new("part");
    h.insert("recent", 0, T0);
    success(h.scan(&[]));
    let selected = success(
        h.command()
            .args(["cursor", "list", "--state-path", "state.json"])
            .output()
            .unwrap(),
    )["cursors"][0]
        .clone();
    let output = h
        .command()
        .args(["cursor", "reset", "--state-path", "state.json"])
        .arg("--source-instance-id")
        .arg(selected["source_instance_id"].as_str().unwrap())
        .args(["--table", "part", "--expect-cursor"])
        .arg(selected["cursor_digest"].as_str().unwrap())
        .arg("--accept-history-gap")
        .output()
        .unwrap();
    assert_eq!(success(output)["status"], "committed");
    assert!(
        h.saved()["sqlite_ingestion_cursors"]
            .as_object()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn cursor_reset_interrupted_drain_requires_explicit_abandonment_and_restarts_safely() {
    let h = Harness::new("session_message");
    h.insert("prior", 0, T0);
    success(h.scan(&[]));
    let connection = Connection::open(&h.database).unwrap();
    connection
        .execute(
            "WITH RECURSIVE rows(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM rows WHERE i<25000)
        INSERT INTO session_message SELECT 'late-'||i,'ses','system',i,?1+i,?1+i,'{}' FROM rows",
            [T0 - 500_000],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO session_message VALUES ('broken','ses','system',25001,?1,?1,'not-json')",
            [T0 - 400_000],
        )
        .unwrap();
    drop(connection);
    h.insert("unseen", 25002, T0 - 300_000);
    let interrupted = success(h.scan(&[]));
    assert_eq!(
        interrupted["source_processing"]["evaluated_window_count"], 1,
        "{interrupted}"
    );
    assert_eq!(
        interrupted["source_processing"]["incomplete_window_source_count"],
        1
    );
    let cursor = h.selected();
    assert_eq!(cursor["last_time_updated"], T0);
    assert_eq!(cursor["continue_after_time_updated"], T0 - 475_000);
    assert_eq!(cursor["draining"], true);
    // Another process resumes the interrupted raw continuation, still failing closed.
    let failed_restart = success(h.scan(&[]));
    assert_eq!(
        failed_restart["source_processing"]["parse_error_source_count"],
        1
    );
    assert_eq!(h.selected(), cursor);
    let before = fs::read(&h.state).unwrap();
    let log = fs::read(&h.log).unwrap();
    let refused = h.reset(&cursor, &["--accept-history-gap"]);
    assert!(!refused.status.success());
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr).trim(),
        "cursor_drain_abandonment_required"
    );
    assert_eq!(fs::read(&h.state).unwrap(), before);
    assert_eq!(fs::read(&h.log).unwrap(), log);
    let reset = success(h.reset(
        &cursor,
        &["--accept-history-gap", "--abandon-incomplete-drain"],
    ));
    assert_eq!(reset["abandoned_incomplete_drain"], true);
    assert_eq!(reset["whole_store_evaluated"], false);
    assert!(
        h.saved()["sqlite_ingestion_cursors"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    let after_reset = h.saved();
    assert_eq!(
        after_reset["seen_detection_fingerprints"],
        serde_json::from_slice::<Value>(&before).unwrap()["seen_detection_fingerprints"]
    );
    // Reset does not bypass invalid input: bootstrap must still fail without progress.
    let rejected_bootstrap = success(h.scan(&[]));
    assert_eq!(
        rejected_bootstrap["source_processing"]["parse_error_source_count"],
        1
    );
    assert!(
        h.saved()["sqlite_ingestion_cursors"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    Connection::open(&h.database)
        .unwrap()
        .execute("UPDATE session_message SET data='{}' WHERE id='broken'", [])
        .unwrap();
    let bootstrap = success(h.scan(&[]));
    assert_eq!(
        bootstrap["source_processing"]["parse_error_source_count"],
        0
    );
    assert!(
        h.saved()["sqlite_ingestion_cursors"]
            .as_object()
            .unwrap()
            .values()
            .all(|cursor| cursor.get("continue_after_time_updated").is_none())
    );
    let continued = success(h.scan(&[]));
    assert_eq!(
        continued["source_processing"]["parse_error_source_count"],
        0
    );
    assert_eq!(h.selected()["last_time_updated"], T0);
}

#[test]
fn cursor_reset_rejects_invalid_native_state_and_binding_without_leaks() {
    let h = Harness::new("part");
    h.insert("recent", 0, T0);
    success(h.scan(&[]));
    let selected = h.selected();
    let original = h.saved();
    for field in [
        "source_instance_id",
        "source_id",
        "client",
        "table",
        "map_key",
        "unknown_field",
        "version",
    ] {
        let mut state = original.clone();
        let key = cursor_key(&selected);
        if field == "version" {
            state["state_schema_version"] = SECRET.into();
        } else if field == "map_key" {
            let cursor = state["sqlite_ingestion_cursors"]
                .as_object_mut()
                .unwrap()
                .remove(&key)
                .unwrap();
            state["sqlite_ingestion_cursors"][SECRET] = cursor;
        } else {
            state["sqlite_ingestion_cursors"][&key][field] = SECRET.into();
        }
        let before = serde_json::to_vec(&state).unwrap();
        fs::write(&h.state, &before).unwrap();
        for output in [h.list(), h.reset(&selected, &["--accept-history-gap"])] {
            assert!(!output.status.success(), "{field}");
            assert!(output.stdout.is_empty());
            h.private(&output);
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(matches!(
                error.trim(),
                "cursor_state_invalid" | "cursor_binding_invalid"
            ));
            assert_eq!(fs::read(&h.state).unwrap(), before);
        }
    }
    fs::write(&h.state, serde_json::to_vec(&original).unwrap()).unwrap();
    let before = fs::read(&h.state).unwrap();
    for field in ["source_instance_id", "table", "cursor_digest"] {
        let mut invalid = selected.clone();
        invalid[field] = SECRET.into();
        let output = h.reset(&invalid, &["--accept-history-gap"]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        h.private(&output);
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim(),
            "cursor_selection_invalid"
        );
        assert_eq!(fs::read(&h.state).unwrap(), before);
    }
    let mut duplicate = b"{\"state_schema_version\":\"1.0\",".to_vec();
    duplicate.extend_from_slice(&before[1..]);
    fs::write(&h.state, &duplicate).unwrap();
    let output = h.reset(&selected, &["--accept-history-gap"]);
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "cursor_state_invalid"
    );
    assert_eq!(fs::read(&h.state).unwrap(), duplicate);
    fs::remove_file(&h.state).unwrap();
    let missing = h.list();
    assert!(!missing.status.success());
    assert!(!h.state.exists());
}

#[test]
fn cursor_reset_bootstrap_still_omits_old_history() {
    for table in ["part", "session_message"] {
        let h = Harness::new(table);
        h.insert("omitted-oldest", 0, T0 - 7_200_000);
        let connection = Connection::open(&h.database).unwrap();
        let sql = if table == "part" {
            "WITH RECURSIVE rows(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM rows WHERE i<5000)
             INSERT INTO part SELECT 'row-'||i,'ses',?1+i,
               json_object('type','tool','tool','bash','callID','call-'||i,
                 'state',json_object('status','running','input',json_object('command','echo synthetic benign')))
             FROM rows"
        } else {
            "WITH RECURSIVE rows(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM rows WHERE i<5000)
             INSERT INTO session_message SELECT 'row-'||i,'ses','system',i,?1+i,?1+i,'{}' FROM rows"
        };
        connection.execute(sql, [T0 - 7_000_000]).unwrap();
        drop(connection);
        h.insert("recent", 5001, T0);
        let initial = success(h.scan(&[]));
        assert_eq!(
            initial["source_processing"]["parse_error_source_count"], 0,
            "{table}: {initial}"
        );
        Connection::open(&h.database)
            .unwrap()
            .execute(&format!("DELETE FROM {table} WHERE id='recent'"), [])
            .unwrap();
        let selected = h.selected();
        success(h.reset(&selected, &["--accept-history-gap"]));
        let resumed = success(h.scan(&[]));
        assert_eq!(
            resumed["source_processing"]["parsed_record_count"], 5000,
            "{resumed}"
        );
        assert_eq!(
            resumed["detection_count"], 0,
            "oldest detection is outside bootstrap: {resumed}"
        );
        assert_eq!(h.selected()["last_time_updated"], T0 - 7_000_000 + 5000);
    }
}

#[cfg(unix)]
#[test]
fn cursor_reset_rejects_linked_state_targets() {
    let h = Harness::new("part");
    h.insert("recent", 0, T0);
    success(h.scan(&[]));
    let cursor = h.selected();
    let original = fs::read(&h.state).unwrap();
    let other = h.temp.path().join("other.json");
    fs::rename(&h.state, &other).unwrap();
    for symlink in [true, false] {
        if symlink {
            std::os::unix::fs::symlink(&other, &h.state).unwrap();
        } else {
            fs::hard_link(&other, &h.state).unwrap();
        }
        let output = h.reset(&cursor, &["--accept-history-gap"]);
        assert!(!output.status.success());
        h.private(&output);
        assert_eq!(fs::read(&other).unwrap(), original);
        fs::remove_file(&h.state).unwrap();
    }
}
