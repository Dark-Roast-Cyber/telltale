use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fs4::fs_std::FileExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn hold_lock_child(target: &std::path::Path) -> std::process::Child {
    let ready = target.with_extension("ready");
    let _ = fs::remove_file(&ready);
    let child = Command::new(std::env::current_exe().expect("test executable"))
        .arg("migration::migration_lock_holder")
        .arg("--exact")
        .env("TELLTALE_LOCK_HOLDER_TARGET", target)
        .env("TELLTALE_LOCK_HOLDER_READY", &ready)
        .spawn()
        .expect("lock holder");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "lock holder did not start");
        thread::sleep(Duration::from_millis(10));
    }
    child
}

#[test]
fn migration_and_scan_reject_real_cross_process_state_contention() {
    let temp = tempdir().expect("tempdir");
    let state = temp.path().join("state.json");
    let destination = temp.path().join("destination.json");
    fs::write(
        &state,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/state/legacy-scan-state.json"
        )),
    )
    .expect("legacy state");

    let mut holder = hold_lock_child(&state);
    let migration = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["migrate", "state", "--from"])
        .arg(&state)
        .args(["--to"])
        .arg(&destination)
        .output()
        .expect("migration");
    assert!(!migration.status.success());
    assert!(String::from_utf8_lossy(&migration.stderr).contains("resource busy"));
    holder.kill().expect("kill lock holder");
    holder.wait().expect("wait lock holder");

    let log = temp.path().join("events.jsonl");
    let mut holder = hold_lock_child(&state);
    let scan = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--state-path",
        ])
        .arg(&state)
        .args(["--log-path"])
        .arg(&log)
        .output()
        .expect("scan");
    assert!(!scan.status.success());
    assert!(String::from_utf8_lossy(&scan.stderr).contains("resource busy"));
    holder.kill().expect("kill lock holder");
    holder.wait().expect("wait lock holder");

    let log2 = temp.path().join("events-locked.jsonl");
    let state2 = temp.path().join("state-locked.json");
    let mut holder = hold_lock_child(&log2);
    let log_scan = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--emit-activity",
            "--root",
            "tests/fixtures/session_stores",
            "--state-path",
        ])
        .arg(&state2)
        .args(["--log-path"])
        .arg(&log2)
        .output()
        .expect("log contention scan");
    assert!(!log_scan.status.success());
    assert!(String::from_utf8_lossy(&log_scan.stderr).contains("resource busy"));
    holder.kill().expect("kill log holder");
    holder.wait().expect("wait log holder");
}

#[test]
fn migration_manifest_lock_fails_without_installing_or_mutating_state() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("legacy.json");
    let destination = temp.path().join("destination.json");
    let manifest = temp.path().join("destination.json.migration.json");
    let source_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/state/legacy-scan-state.json"
    ));
    fs::write(&source, source_bytes).expect("legacy state");

    let mut holder = hold_lock_child(&manifest);
    let migration = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["migrate", "state", "--from"])
        .arg(&source)
        .args(["--to"])
        .arg(&destination)
        .output()
        .expect("migration");
    assert!(!migration.status.success());
    assert!(String::from_utf8_lossy(&migration.stderr).contains("resource busy"));
    assert_eq!(fs::read(&source).expect("source bytes"), source_bytes);
    assert!(!destination.exists(), "destination must not be installed");
    assert!(!manifest.exists(), "manifest must not be installed");
    assert!(
        !fs::read_dir(temp.path())
            .expect("migration directory")
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .contains(".telltale-tmp-")),
        "migration must not leave a prepared data file"
    );
    holder.kill().expect("kill lock holder");
    holder.wait().expect("wait lock holder");
}

#[test]
fn migration_lock_holder() {
    let Ok(target) = std::env::var("TELLTALE_LOCK_HOLDER_TARGET") else {
        return;
    };
    let ready = std::env::var("TELLTALE_LOCK_HOLDER_READY").expect("ready path");
    let path = format!("{target}.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .expect("lock file");
    file.lock_exclusive().expect("exclusive lock");
    File::create(ready)
        .expect("ready file")
        .write_all(b"ready")
        .expect("ready marker");
    thread::sleep(Duration::from_secs(30));
}

#[test]
fn dry_run_does_not_create_state_or_log_targets() {
    let temp = tempdir().expect("tempdir");
    let state = temp.path().join("nested/state.json");
    let log = temp.path().join("nested/events.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--state-path",
        ])
        .arg(&state)
        .args(["--log-path"])
        .arg(&log)
        .output()
        .expect("dry run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!state.exists());
    assert!(!state.with_file_name("state.json.lock").exists());
    assert!(!log.exists());
    assert!(!log.with_file_name("events.jsonl.lock").exists());
}

#[test]
fn configured_local_output_namespace_is_validated_before_scan() {
    let temp = tempdir().expect("tempdir");
    let config_dir = temp.path().join("config");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs directory");
    let state = temp.path().join("state.json");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        format!(
            "version: 1\nsinks:\n  - name: local\n    type: jsonl\n    path: {}\n",
            state.with_file_name("state.json.migration.json").display()
        ),
    )
    .expect("outputs config");
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--dry-run", "--config-dir"])
        .arg(&config_dir)
        .args(["--root", "empty-root", "--state-path"])
        .arg(&state)
        .args(["--log-path"])
        .arg(temp.path().join("fallback.jsonl"))
        .current_dir(temp.path())
        .output()
        .expect("scan");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must not overlap"));
}

#[test]
fn rotation_namespace_collision_is_rejected_before_log_mutation() {
    let temp = tempdir().expect("tempdir");
    let config_dir = temp.path().join("config");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs directory");
    let state = temp.path().join("events-2026-06-21.jsonl");
    let log = temp.path().join("events.jsonl");
    fs::write(&state, b"state-sentinel").expect("state sentinel");
    fs::write(&log, b"{}\n").expect("log sentinel");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        format!(
            "version: 1\nsinks:\n  - name: local\n    type: jsonl\n    path: {}\n    rotation:\n      max_size_bytes: 1\n      keep: 0\n",
            log.display()
        ),
    )
    .expect("outputs config");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--emit-activity",
            "--config-dir",
        ])
        .arg(&config_dir)
        .args(["--root", "tests/fixtures/session_stores", "--state-path"])
        .arg(&state)
        .args(["--log-path"])
        .arg(&log)
        .output()
        .expect("scan");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rotation namespace"));
    assert_eq!(fs::read(&state).expect("state bytes"), b"state-sentinel");
    assert_eq!(fs::read(&log).expect("log bytes"), b"{}\n");
    let state_name = state.file_name().expect("state name");
    assert!(
        !fs::read_dir(temp.path())
            .expect("log directory")
            .filter_map(Result::ok)
            .any(|entry| {
                entry.file_name() != state_name
                    && entry.file_name().to_string_lossy().starts_with("events-")
            }),
        "preflight must prevent rotated-file deletion or creation"
    );
}

#[test]
fn migrated_state_preserves_detection_deduplication() {
    let temp = tempdir().expect("tempdir");
    let legacy_source = temp.path().join("legacy-state.json");
    let first_state = temp.path().join("first-state.json");
    let first_log = temp.path().join("first-events.jsonl");
    let migrated_state = temp.path().join("migrated-state.json");
    let second_log = temp.path().join("second-events.jsonl");
    let fixture_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session_stores");

    let first = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
        ])
        .arg(&fixture_root)
        .args(["--client", "codex", "--emit-activity", "--state-path"])
        .arg(&first_state)
        .args(["--log-path"])
        .arg(&first_log)
        .output()
        .expect("first scan");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let mut legacy: Value =
        serde_json::from_slice(&fs::read(&first_state).expect("state")).expect("native state");
    legacy
        .as_object_mut()
        .expect("state object")
        .remove("state_schema_version");
    fs::write(
        &legacy_source,
        serde_json::to_vec_pretty(&legacy).expect("legacy bytes"),
    )
    .expect("legacy source");
    run_migration(&legacy_source, &migrated_state);

    let second = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
        ])
        .arg(&fixture_root)
        .args(["--client", "codex", "--emit-activity", "--state-path"])
        .arg(&migrated_state)
        .args(["--log-path"])
        .arg(&second_log)
        .output()
        .expect("second scan");
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let summary: Value = serde_json::from_slice(&second.stdout).expect("summary");
    assert!(
        summary["detection_flow"]["state_deduplicated_detection_count"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert_eq!(summary["detection_flow"]["emitted_detection_count"], 0);
}

#[test]
fn native_migration_manifest_counts_malformed_host_normalization() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("native-canary.json");
    let destination = temp.path().join("migrated-native.json");
    let mut value: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/state/legacy-scan-state.json"
    )))
    .expect("fixture state");
    value["state_schema_version"] = Value::String("1.0".to_string());
    let bytes = serde_json::to_vec(&value).expect("native JSON");
    let bytes = String::from_utf8(bytes)
        .expect("native UTF-8")
        .replace("internal.example.test", "sha256:ABC");
    fs::write(&source, bytes.as_bytes()).expect("native source");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["migrate", "state", "--from"])
        .arg(&source)
        .args(["--to"])
        .arg(&destination)
        .output()
        .expect("migration");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: Value = serde_json::from_slice(&output.stdout).expect("manifest");
    assert_eq!(manifest["normalization_count"], 1);

    let canonical_host = format!("sha256:{:x}", Sha256::digest(b"sha256:abc"));
    let migrated = fs::read_to_string(&destination).expect("migrated state");
    assert!(!migrated.contains("sha256:ABC"));
    assert!(migrated.contains(&canonical_host));
}

#[cfg(target_os = "linux")]
#[test]
fn migrated_state_preserves_sqlite_cursor_continuity() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("home");
    let database_dir = root.join(".local/share/opencode");
    fs::create_dir_all(&database_dir).expect("database directory");
    let database = database_dir.join("opencode.db");
    let connection = rusqlite::Connection::open(&database).expect("database");
    connection
        .execute_batch(
            "create table message (
                id text primary key,
                session_id text not null,
                time_created integer not null,
                time_updated integer not null,
                data text not null
            );
            create table part (
                id text primary key,
                message_id text not null,
                session_id text not null,
                time_created integer not null,
                time_updated integer not null,
                data text not null
            );",
        )
        .expect("schema");
    insert_sqlite_row(&connection, "a", 1_775_000_000_000);
    drop(connection);

    let native = temp.path().join("native-state.json");
    let first_log = temp.path().join("first-events.jsonl");
    let first = scan_opencode(&root, &native, &first_log);
    assert!(
        first["source_processing"]["parsed_record_count"]
            .as_u64()
            .expect("first parsed count")
            > 0
    );
    let first_cursor = cursor_time(&native);
    let mut legacy: Value =
        serde_json::from_slice(&fs::read(&native).expect("native state")).expect("native value");
    legacy
        .as_object_mut()
        .expect("state object")
        .remove("state_schema_version");
    let legacy_path = temp.path().join("legacy-state.json");
    fs::write(
        &legacy_path,
        serde_json::to_vec_pretty(&legacy).expect("legacy bytes"),
    )
    .expect("legacy state");
    let migrated = temp.path().join("migrated-state.json");
    run_migration(&legacy_path, &migrated);
    assert_eq!(cursor_time(&migrated), first_cursor);

    let connection = rusqlite::Connection::open(&database).expect("database");
    insert_sqlite_row(&connection, "b", 1_775_000_002_000);
    drop(connection);
    let second = scan_opencode(&root, &migrated, &temp.path().join("second-events.jsonl"));
    assert!(
        second["source_processing"]["parsed_record_count"]
            .as_u64()
            .expect("second parsed count")
            > 0
    );
    assert!(cursor_time(&migrated) > first_cursor);
}

#[cfg(target_os = "linux")]
#[test]
fn migrated_sqlite_cursor_emits_only_newly_appended_sessions() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("home");
    let database_dir = root.join(".local/share/opencode");
    fs::create_dir_all(&database_dir).expect("database directory");
    let database = database_dir.join("opencode.db");
    let connection = rusqlite::Connection::open(&database).expect("database");
    connection
        .execute_batch(
            "create table part (
                id text primary key,
                message_id text not null,
                session_id text not null,
                time_created integer not null,
                time_updated integer not null,
                data text not null
            );",
        )
        .expect("schema");
    insert_sqlite_part_row(&connection, "a", "session-a", 1_775_000_001_000);
    drop(connection);

    let native = temp.path().join("native-state.json");
    let first_log = temp.path().join("first-events.jsonl");
    let first = scan_opencode(&root, &native, &first_log);
    assert_eq!(first["source_processing"]["parsed_record_count"], 1);

    let mut legacy: Value =
        serde_json::from_slice(&fs::read(&native).expect("native state")).expect("native value");
    legacy
        .as_object_mut()
        .expect("state object")
        .remove("state_schema_version");
    let legacy_path = temp.path().join("legacy-state.json");
    fs::write(
        &legacy_path,
        serde_json::to_vec_pretty(&legacy).expect("legacy bytes"),
    )
    .expect("legacy state");
    let migrated = temp.path().join("migrated-state.json");
    run_migration(&legacy_path, &migrated);

    let connection = rusqlite::Connection::open(&database).expect("database");
    insert_sqlite_part_row(&connection, "b", "session-b", 1_775_000_602_000);
    drop(connection);

    let second_log = temp.path().join("second-events.jsonl");
    let second = scan_opencode(&root, &migrated, &second_log);
    // The parser's overlap rereads the old row; state deduplication must keep
    // that row out of durable delivery while the appended session is emitted.
    assert_eq!(second["source_processing"]["parsed_record_count"], 2);
    let events = fs::read_to_string(&second_log)
        .expect("second log")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1, "the first session must be deduplicated");
    assert_eq!(events[0]["event_type"], "activity");
    assert_eq!(events[0]["session_id"], "session-b");
}

#[cfg(target_os = "linux")]
fn insert_sqlite_row(connection: &rusqlite::Connection, suffix: &str, time: i64) {
    connection
        .execute(
            "insert into message (id, session_id, time_created, time_updated, data)
             values (?1, ?2, ?3, ?4, ?5)",
            (
                format!("message-{suffix}"),
                "session-a",
                time,
                time,
                serde_json::json!({"role": "assistant"}).to_string(),
            ),
        )
        .expect("message row");
    connection
        .execute(
            "insert into part (id, message_id, session_id, time_created, time_updated, data)
             values (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                format!("part-{suffix}"),
                format!("message-{suffix}"),
                "session-a",
                time + 1_000,
                time + 1_000,
                serde_json::json!({"type": "text", "text": "new row"}).to_string(),
            ),
        )
        .expect("part row");
}

#[cfg(target_os = "linux")]
fn insert_sqlite_part_row(
    connection: &rusqlite::Connection,
    suffix: &str,
    session_id: &str,
    time: i64,
) {
    connection
        .execute(
            "insert into part (id, message_id, session_id, time_created, time_updated, data)
             values (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                format!("part-{suffix}"),
                format!("message-{suffix}"),
                session_id,
                time,
                time,
                serde_json::json!({"type": "text", "text": format!("row-{suffix}")}).to_string(),
            ),
        )
        .expect("part row");
}

#[cfg(target_os = "linux")]
fn scan_opencode(root: &std::path::Path, state: &std::path::Path, log: &std::path::Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--no-local-config",
            "--emit-activity",
            "--client",
            "opencode",
            "--root",
        ])
        .arg(root)
        .args(["--state-path"])
        .arg(state)
        .args(["--log-path"])
        .arg(log)
        .output()
        .expect("scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("scan summary")
}

#[cfg(target_os = "linux")]
fn cursor_time(state: &std::path::Path) -> i64 {
    let value: Value = serde_json::from_slice(&fs::read(state).expect("state")).expect("state");
    value["sqlite_ingestion_cursors"]
        .as_object()
        .expect("cursor map")
        .values()
        .next()
        .and_then(|cursor| cursor["last_time_updated"].as_i64())
        .expect("cursor time")
}

#[test]
fn two_scan_processes_contend_on_the_same_state_lock() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("large-fixture-root");
    let sessions = root.join("codex/sessions");
    fs::create_dir_all(&sessions).expect("sessions");
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl");
    for index in 0..2000 {
        fs::copy(&fixture, sessions.join(format!("session-{index}.jsonl"))).expect("fixture copy");
    }
    let state = temp.path().join("shared-state.json");
    let log = temp.path().join("shared-events.jsonl");
    let first = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--emit-activity",
            "--root",
        ])
        .arg(&root)
        .args(["--state-path"])
        .arg(&state)
        .args(["--log-path"])
        .arg(&log)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("first scan");
    let lock = state.with_file_name("shared-state.json.lock");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !lock.exists() {
        assert!(
            Instant::now() < deadline,
            "first scan did not acquire state lock"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let second = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--emit-activity",
            "--root",
        ])
        .arg(&root)
        .args(["--state-path"])
        .arg(&state)
        .args(["--log-path"])
        .arg(&log)
        .output()
        .expect("second scan");
    let first_output = first.wait_with_output().expect("first scan wait");
    let first_busy = String::from_utf8_lossy(&first_output.stderr).contains("resource busy");
    let second_busy = String::from_utf8_lossy(&second.stderr).contains("resource busy");
    assert!(
        first_busy || second_busy,
        "neither scan observed contention"
    );
    assert!(
        first_output.status.success() || second.status.success(),
        "first: {} / second: {}",
        String::from_utf8_lossy(&first_output.stderr),
        String::from_utf8_lossy(&second.stderr)
    );
}

#[test]
fn concurrent_scans_produce_parseable_jsonl_with_rotation() {
    // This exercises a shared append/rotation target, but does not force a
    // deterministic inter-process lock collision.
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("large-fixture-root");
    let sessions = root.join("codex/sessions");
    fs::create_dir_all(&sessions).expect("sessions");
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl");
    for index in 0..500 {
        fs::copy(&fixture, sessions.join(format!("session-{index}.jsonl"))).expect("fixture copy");
    }
    let log = temp.path().join("shared-events.jsonl");
    let first = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--emit-activity",
            "--root",
        ])
        .arg(&root)
        .args(["--state-path"])
        .arg(temp.path().join("state-one.json"))
        .args(["--log-path"])
        .arg(&log)
        .args(["--log-rotate-max-size", "1000", "--log-rotate-keep", "100"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("first scan");
    let first_state_lock = temp.path().join("state-one.json.lock");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !first_state_lock.exists() {
        assert!(Instant::now() < deadline, "first scan did not start");
        thread::sleep(Duration::from_millis(5));
    }
    let second = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--emit-activity",
            "--root",
        ])
        .arg(&root)
        .args(["--state-path"])
        .arg(temp.path().join("state-two.json"))
        .args(["--log-path"])
        .arg(&log)
        .args(["--log-rotate-max-size", "1000", "--log-rotate-keep", "100"])
        .output()
        .expect("second scan");
    let first_output = first.wait_with_output().expect("first scan wait");
    assert!(first_output.status.success());
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let first_summary: Value = serde_json::from_slice(&first_output.stdout).expect("first summary");
    let second_summary: Value = serde_json::from_slice(&second.stdout).expect("second summary");
    let expected_records = first_summary["emitted_count"]
        .as_u64()
        .expect("first emitted count")
        + second_summary["emitted_count"]
            .as_u64()
            .expect("second emitted count")
        + 2;
    let mut actual_records = 0;
    for entry in fs::read_dir(temp.path()).expect("log directory") {
        let path = entry.expect("log entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "jsonl")
        {
            for line in fs::read_to_string(path).expect("log bytes").lines() {
                serde_json::from_str::<Value>(line).expect("complete JSONL record");
                actual_records += 1;
            }
        }
    }
    assert_eq!(actual_records, expected_records);
}

fn run_migration(source: &std::path::Path, destination: &std::path::Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["migrate", "state", "--from"])
        .arg(source)
        .args(["--to"])
        .arg(destination)
        .output()
        .expect("migration");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
