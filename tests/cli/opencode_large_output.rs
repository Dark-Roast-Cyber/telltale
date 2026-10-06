use super::*;
use rusqlite::Connection;

#[test]
fn opencode_large_output_wal_restart_and_persistence_recovery() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("data");
    fs::create_dir_all(root.join("opencode")).unwrap();
    let database = root.join("opencode/opencode.db");
    let writer = Connection::open(&database).unwrap();
    writer
        .execute_batch(
            "pragma journal_mode=WAL; pragma wal_autocheckpoint=0;
        create table part (id text primary key, session_id text, time_updated integer, data text);",
        )
        .unwrap();
    let rules = temp.path().join("rules.yaml");
    fs::write(
        &rules,
        r#"
version: 1
description: Synthetic full output coverage.
defaults: { case_insensitive: false, enabled: true }
modifiers: []
rules:
  - id: synthetic.output.suffix
    title: Synthetic output suffix
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 70
    detection:
      selection:
        tool_result: 'synthetic-output-suffix-marker'
      condition: selection
    explanation: Synthetic test.
  - id: synthetic.output.second
    title: Second synthetic output attribution
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 10
    detection:
      selection:
        tool_result: 'synthetic-output-suffix-marker'
      condition: selection
    explanation: Synthetic repeated evidence material.
"#,
    )
    .unwrap();
    let log = temp.path().join("events.jsonl");
    let state = temp.path().join("state.json");
    let secret = "SYNTHETIC-OUTPUT-SECRET";
    let output = format!(
        "api_key={secret}\n{}\nsynthetic-output-suffix-marker api_key={secret}",
        "compiler diagnostic\n".repeat(2500)
    );
    let data = |output: &str| {
        serde_json::json!({"type":"tool","tool":"bash","state":{"status":"completed","input":{"command":"cargo check"},"output":output}}).to_string()
    };
    let insert = |id: &str, session: &str, time: i64, text: &str| {
        writer
            .execute(
                "insert into part values (?1,?2,?3,?4)",
                rusqlite::params![id, session, time, data(text)],
            )
            .unwrap();
    };
    insert("first", "session-first", 1_775_000_000_000, &output);
    let patch = format!(
        "*** Begin Patch\n*** Add File: synthetic.txt\n{}*** End Patch\n",
        "+synthetic authored text\n".repeat(400)
    );
    writer.execute("insert into part values ('patch','session-first',1775000000000,?1)",
        [serde_json::json!({"type":"tool","tool":"apply_patch","state":{"status":"completed","input":{"patchText":patch},"output":"ok"}}).to_string()]).unwrap();
    assert!(database.with_extension("db-wal").is_file());
    let scan = || {
        Command::new(env!("CARGO_BIN_EXE_telltale"))
            .env_clear()
            .current_dir(temp.path())
            .args([
                "scan",
                "--once",
                "--client",
                "opencode",
                "--no-local-config",
                "--emit-activity",
                "--install-inventory-disabled",
                "--root",
            ])
            .arg(&root)
            .args(["--no-default-rules", "--rules"])
            .arg(&rules)
            .arg("--log-path")
            .arg(&log)
            .arg("--state-path")
            .arg(&state)
            .output()
            .unwrap()
    };
    let successful = || {
        let result = scan();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);
        summary
    };
    let cursor = || {
        let saved: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        let mut cursors = saved["sqlite_ingestion_cursors"].clone();
        for value in cursors.as_object_mut().unwrap().values_mut() {
            value.as_object_mut().unwrap().remove("observed_at_unix_ms");
        }
        cursors
    };
    let first = successful();
    assert_eq!(first["source_processing"]["parse_error_source_count"], 0);
    assert_eq!(first["source_processing"]["parsed_record_count"], 2);
    let first_log = fs::read(&log).unwrap();
    let first_state = fs::read(&state).unwrap();
    let first_cursor = cursor();
    let events: Vec<Value> = std::str::from_utf8(&first_log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let detection = events
        .iter()
        .find(|event| event["event_type"] == "detection")
        .expect("suffix beyond 4096 was evaluated");
    for id in ["synthetic.output.suffix", "synthetic.output.second"] {
        assert!(
            detection["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["rule_id"] == id && e["hash"] == evidence_hash(&output))
        );
    }
    assert!(
        detection["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["hash"] == evidence_hash(&output))
    );
    for event in &events {
        assert!(event_schema_validator().is_valid(event));
    }
    for bytes in [&first_log, &first_state] {
        assert!(!String::from_utf8_lossy(bytes).contains(secret));
    }
    assert_eq!(successful()["emitted_count"], 0);
    // Full scan --once refreshes observation times by existing policy. Its
    // persisted cursor coordinate, dedup sets and baseline material must stay
    // unchanged; this does not claim byte-identical state files.
    let stable_state = |bytes: &[u8]| {
        let mut saved: Value = serde_json::from_slice(bytes).unwrap();
        for (key, timestamp) in [
            ("sqlite_ingestion_cursors", "observed_at_unix_ms"),
            ("source_observations", "last_seen_unix_ms"),
        ] {
            for value in saved[key].as_object_mut().unwrap().values_mut() {
                value.as_object_mut().unwrap().remove(timestamp);
            }
        }
        saved
    };
    let repeated_state = fs::read(&state).unwrap();
    assert_eq!(stable_state(&repeated_state), stable_state(&first_state));
    assert_eq!(cursor(), first_cursor);
    assert_eq!(fs::read(&log).unwrap(), first_log);

    // The writer remains open: every committed append is in the WAL. Every scan
    // is a fresh process and must recover from the last durably saved cursor.
    insert("second", "session-second", 1_775_000_100_000, &output);
    let parked_log = temp.path().join("parked.jsonl");
    fs::rename(&log, &parked_log).unwrap();
    fs::create_dir(&log).unwrap();
    assert!(
        !scan().status.success(),
        "unpersisted detection may not commit state"
    );
    assert_eq!(fs::read(&state).unwrap(), repeated_state);
    fs::remove_dir(&log).unwrap();
    fs::rename(&parked_log, &log).unwrap();
    let recovered = successful();
    assert_eq!(
        recovered["source_processing"]["parse_error_source_count"],
        0
    );
    assert_ne!(cursor(), first_cursor);
    let recovered_log = fs::read(&log).unwrap();
    assert!(recovered_log.starts_with(&first_log));
    assert_eq!(successful()["emitted_count"], 0);
    assert_eq!(fs::read(&log).unwrap(), recovered_log);

    let recovered_cursor = cursor();
    insert(
        "oversized",
        "session-third",
        1_775_000_200_000,
        &"x".repeat(65_537),
    );
    let rejected = successful();
    assert_eq!(rejected["source_processing"]["parse_error_source_count"], 1);
    assert_eq!(rejected["source_processing"]["parsed_record_count"], 0);
    assert_eq!(cursor(), recovered_cursor);
    writer
        .execute(
            "update part set data=?1 where id='oversized'",
            [data(&output)],
        )
        .unwrap();
    let repaired = successful();
    assert_eq!(repaired["source_processing"]["parse_error_source_count"], 0);
    assert_ne!(cursor(), recovered_cursor);
    let repaired_log = fs::read(&log).unwrap();
    assert!(!String::from_utf8_lossy(&repaired_log).contains(secret));
    assert_eq!(successful()["emitted_count"], 0);
    assert_eq!(fs::read(&log).unwrap(), repaired_log);
}
