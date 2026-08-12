use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
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
    let migration = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    let scan = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    let log_scan = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    let migration = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
fn retired_runtime_environment_blocks_migration_before_path_activity() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("not-created/source.env");
    let destination = temp.path().join("not-created/destination.env");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .env("ADR_LOG_PATH", "/retired/runtime/canary")
        .current_dir(temp.path())
        .args(["migrate", "env", "--from"])
        .arg(&source)
        .args(["--to"])
        .arg(&destination)
        .output()
        .expect("migration");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ADR_LOG_PATH"), "stderr: {stderr}");
    assert!(!source.exists());
    assert!(!destination.exists());
    assert!(!temp.path().join("not-created").exists());
}

#[test]
fn canonical_runtime_ignores_preseeded_legacy_default_log_and_state_files() {
    let temp = tempdir().expect("tempdir");
    let old_log = temp.path().join("logs/adr-events.jsonl");
    let old_state = temp.path().join("state/adr-state.json");
    fs::create_dir_all(old_log.parent().expect("old log parent")).expect("old log parent");
    fs::create_dir_all(old_state.parent().expect("old state parent")).expect("old state parent");
    let old_log_bytes = b"legacy-log-canary\n";
    let old_state_bytes = b"legacy-state-canary\n";
    fs::write(&old_log, old_log_bytes).expect("old log");
    fs::write(&old_state, old_state_bytes).expect("old state");

    let fixture_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session_stores");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .env_clear()
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--path-profile",
            "project",
            "--client",
            "codex",
            "--root",
        ])
        .arg(&fixture_root)
        .output()
        .expect("scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(fs::read(&old_log).expect("old log bytes"), old_log_bytes);
    assert_eq!(
        fs::read(&old_state).expect("old state bytes"),
        old_state_bytes
    );
    assert!(temp.path().join("logs/telltale-events.jsonl").exists());
    assert!(temp.path().join("state/telltale-state.json").exists());
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
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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

    let first = Command::new(env!("CARGO_BIN_EXE_telltale"))
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

    let second = Command::new(env!("CARGO_BIN_EXE_telltale"))
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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    let first = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    let second = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    let first = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    let second = Command::new(env!("CARGO_BIN_EXE_telltale"))
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

#[test]
fn event_migration_cli_preserves_mixed_versions_framing_and_manifest_repair() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("legacy-events.jsonl");
    let destination = temp.path().join("telltale-events.jsonl");
    let first = compact_historical_fixture("event-1.0.json");
    let second = compact_historical_fixture("event-2.0.json");
    let third = serde_json::to_vec(&super::native_test_event(
        "activity",
        "telltale-00000000-0000-4000-8000-000000000003",
        "2026-05-01T00:00:00.000Z",
        "low",
        "codex",
        "migration-session",
        &[],
    ))
    .expect("native event");
    let mut source_bytes = first.clone();
    source_bytes.extend_from_slice(b"\r\n\r\n");
    source_bytes.extend_from_slice(&second);
    source_bytes.push(b'\n');
    source_bytes.extend_from_slice(&third);
    fs::write(&source, &source_bytes).expect("source");

    let output = run_event_pairs(&[(&source, &destination)]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&destination).expect("destination"), source_bytes);
    let manifest_path = destination.with_file_name("telltale-events.jsonl.migration.json");
    let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).expect("manifest"))
        .expect("manifest JSON");
    assert_eq!(manifest["record_count"], 3);
    assert_eq!(manifest["blank_frame_count"], 1);
    assert_eq!(manifest["schema_versions"]["1.0"], 1);
    assert_eq!(manifest["schema_versions"]["2.0"], 1);
    assert_eq!(manifest["schema_versions"]["3.0"], 1);
    assert!(
        !String::from_utf8_lossy(&output.stdout)
            .contains("telltale-00000000-0000-4000-8000-000000000003")
    );

    let first_manifest = fs::read(&manifest_path).expect("manifest bytes");
    #[cfg(windows)]
    let source_before = fs::read(&source).expect("source bytes");
    let rerun = run_event_pairs(&[(&source, &destination)]);
    #[cfg(unix)]
    assert!(rerun.status.success());
    #[cfg(windows)]
    {
        assert_windows_existing_target_unsupported(&rerun);
        assert_eq!(fs::read(&source).expect("source bytes"), source_before);
        assert_eq!(
            fs::read(&destination).expect("destination bytes"),
            source_bytes
        );
    }
    assert_eq!(
        fs::read(&manifest_path).expect("manifest bytes"),
        first_manifest
    );
    fs::remove_file(&manifest_path).expect("remove manifest");
    let repair = run_event_pairs(&[(&source, &destination)]);
    #[cfg(unix)]
    assert!(repair.status.success());
    #[cfg(windows)]
    {
        assert_windows_existing_target_unsupported(&repair);
        assert_eq!(fs::read(&source).expect("source bytes"), source_before);
        assert_eq!(
            fs::read(&destination).expect("destination bytes"),
            source_bytes
        );
        assert!(!manifest_path.exists());
    }
    #[cfg(unix)]
    assert_eq!(
        fs::read(&manifest_path).expect("repaired manifest"),
        first_manifest
    );

    fs::write(&manifest_path, b"manifest-conflict\n").expect("manifest conflict");
    let conflict = run_event_pairs(&[(&source, &destination)]);
    assert!(!conflict.status.success());
    #[cfg(windows)]
    {
        assert_windows_existing_target_unsupported(&conflict);
        assert_eq!(fs::read(&source).expect("source bytes"), source_before);
        assert_eq!(
            fs::read(&destination).expect("destination bytes"),
            source_bytes
        );
        assert_eq!(
            fs::read(&manifest_path).expect("manifest bytes"),
            b"manifest-conflict\n"
        );
    }
    assert_eq!(
        fs::read(&destination).expect("destination bytes"),
        source_bytes
    );
}

#[test]
fn event_migration_rejects_same_id_byte_collision_before_destination_mutation() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("collision.jsonl");
    let destination = temp.path().join("destination.jsonl");
    let first = compact_historical_fixture("event-1.0.json");
    let mut source_bytes = first.clone();
    source_bytes.push(b'\n');
    source_bytes.extend_from_slice(&first);
    source_bytes.insert(first.len() + 1 + first.len(), b' ');
    fs::write(&source, &source_bytes).expect("collision source");
    #[cfg(unix)]
    {
        fs::write(&destination, b"destination-sentinel\n").expect("destination sentinel");
        set_mode(&destination, 0o640);
    }

    let output = run_event_pairs(&[(&source, &destination)]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("event_id collision"));
    #[cfg(unix)]
    assert_eq!(
        fs::read(&destination).expect("destination bytes"),
        b"destination-sentinel\n"
    );
    #[cfg(windows)]
    assert!(!destination.exists());
    assert!(
        !destination
            .with_file_name("destination.jsonl.migration.json")
            .exists()
    );
}

#[test]
fn event_migration_preserves_exact_duplicate_records_in_order() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("duplicates.jsonl");
    let destination = temp.path().join("duplicates-new.jsonl");
    let record = compact_historical_fixture("event-1.0.json");
    let mut source_bytes = record.clone();
    source_bytes.push(b'\n');
    source_bytes.extend_from_slice(&record);
    source_bytes.extend_from_slice(b"\n");
    fs::write(&source, &source_bytes).expect("duplicate source");

    let output = run_event_pairs(&[(&source, &destination)]);
    assert!(output.status.success());
    assert_eq!(fs::read(&destination).expect("destination"), source_bytes);
    let manifest: Value = serde_json::from_slice(
        &fs::read(destination.with_file_name("duplicates-new.jsonl.migration.json"))
            .expect("manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(manifest["record_count"], 2);

    fs::write(&destination, b"destination-conflict\n").expect("destination conflict");
    let conflict = run_event_pairs(&[(&source, &destination)]);
    assert!(!conflict.status.success());
    assert_eq!(
        fs::read(&destination).expect("destination"),
        b"destination-conflict\n"
    );
}

#[test]
fn event_migration_rejects_malformed_versions_duplicate_keys_and_partial_records_without_values() {
    let cases = [
        (
            "{\"event_id\":\"missing-canary\"}\n",
            "missing schema version",
        ),
        (
            "{\"schema_version\":\"unknown-canary\"}\n",
            "unknown schema version",
        ),
        (
            "{\"schema_version\":7,\"event_id\":\"type-canary\"}\n",
            "schema version type invalid",
        ),
        (
            "{\"schema_version\":\"1.0\",\"schema_version\":\"1.0\"}\n",
            "duplicate JSON key",
        ),
        (
            "{\"schema_version\":\"1.0\",\"event_id\":\"partial-canary\"",
            "invalid JSON",
        ),
    ];
    for (index, (contents, expected_error)) in cases.into_iter().enumerate() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join(format!("invalid-{index}.jsonl"));
        let destination = temp.path().join(format!("destination-{index}.jsonl"));
        fs::write(&source, contents.as_bytes()).expect("invalid source");
        #[cfg(unix)]
        {
            fs::write(&destination, b"untouched\n").expect("destination");
            set_mode(&destination, 0o640);
        }
        let output = run_event_pairs(&[(&source, &destination)]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        assert!(stderr.contains(expected_error), "stderr: {stderr}");
        assert!(!stderr.contains("canary"), "stderr leaked input: {stderr}");
        #[cfg(unix)]
        assert_eq!(fs::read(&destination).expect("destination"), b"untouched\n");
        #[cfg(windows)]
        assert!(!destination.exists());
    }
}

#[test]
fn event_migration_supports_multiple_explicit_destination_mappings() {
    let temp = tempdir().expect("tempdir");
    let source_one = temp.path().join("old-one.jsonl");
    let source_two = temp.path().join("old-two.jsonl");
    let destination_one = temp.path().join("new-one.jsonl");
    let destination_two = temp.path().join("new-two.jsonl");
    let first = compact_historical_fixture("event-1.0.json");
    let second = compact_historical_fixture("event-2.0.json");
    let mut first_with_newline = first.clone();
    first_with_newline.push(b'\n');
    fs::write(&source_one, &first_with_newline).expect("source one");
    fs::write(&source_two, &second).expect("source two");

    let output = run_event_pairs(&[
        (&source_one, &destination_one),
        (&source_two, &destination_two),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(&destination_one).expect("destination one"),
        first_with_newline
    );
    assert_eq!(fs::read(&destination_two).expect("destination two"), second);
    assert!(
        destination_one
            .with_file_name("new-one.jsonl.migration.json")
            .exists()
    );
    assert!(
        !destination_two
            .with_file_name("new-two.jsonl.migration.json")
            .exists()
    );
    let manifest: Value = serde_json::from_slice(
        &fs::read(destination_one.with_file_name("new-one.jsonl.migration.json"))
            .expect("canonical manifest"),
    )
    .expect("canonical manifest JSON");
    assert_eq!(manifest["destinations"].as_array().map(Vec::len), Some(2));
    let manifest_text = serde_json::to_string(&manifest).expect("manifest text");
    assert!(!manifest_text.contains(&destination_one.display().to_string()));
    assert!(!manifest_text.contains(&destination_two.display().to_string()));

    #[cfg(unix)]
    {
        fs::remove_file(&destination_two).expect("remove secondary destination");
        let repaired = run_event_pairs(&[
            (&source_one, &destination_one),
            (&source_two, &destination_two),
        ]);
        assert!(repaired.status.success());
        assert_eq!(
            fs::read(&destination_two).expect("repaired destination"),
            second
        );

        fs::write(&destination_two, b"secondary-conflict\n").expect("secondary conflict");
        set_mode(&destination_two, 0o640);
        let conflict = run_event_pairs(&[
            (&source_one, &destination_one),
            (&source_two, &destination_two),
        ]);
        assert!(!conflict.status.success());
        assert_eq!(
            fs::read(&destination_two).expect("secondary conflict bytes"),
            b"secondary-conflict\n"
        );
    }
    #[cfg(windows)]
    {
        let source_one_bytes = fs::read(&source_one).expect("source one bytes");
        let source_two_bytes = fs::read(&source_two).expect("source two bytes");
        let destination_one_bytes = fs::read(&destination_one).expect("primary destination bytes");
        let manifest_path = manifest_path_for(&destination_one);
        let manifest_bytes = fs::read(&manifest_path).expect("manifest bytes");
        fs::remove_file(&destination_two).expect("remove secondary destination");
        let repaired = run_event_pairs(&[
            (&source_one, &destination_one),
            (&source_two, &destination_two),
        ]);
        assert_windows_existing_target_unsupported(&repaired);
        assert_eq!(
            fs::read(&source_one).expect("source one bytes"),
            source_one_bytes
        );
        assert_eq!(
            fs::read(&source_two).expect("source two bytes"),
            source_two_bytes
        );
        assert_eq!(
            fs::read(&destination_one).expect("primary destination bytes"),
            destination_one_bytes
        );
        assert!(!destination_two.exists());
        assert_eq!(
            fs::read(&manifest_path).expect("manifest bytes"),
            manifest_bytes
        );

        fs::write(&destination_two, b"secondary-conflict\n").expect("secondary conflict");
        let conflict = run_event_pairs(&[
            (&source_one, &destination_one),
            (&source_two, &destination_two),
        ]);
        assert_windows_existing_target_unsupported(&conflict);
        assert_eq!(
            fs::read(&source_one).expect("source one bytes"),
            source_one_bytes
        );
        assert_eq!(
            fs::read(&source_two).expect("source two bytes"),
            source_two_bytes
        );
        assert_eq!(
            fs::read(&destination_one).expect("primary destination bytes"),
            destination_one_bytes
        );
        assert_eq!(
            fs::read(&destination_two).expect("secondary conflict bytes"),
            b"secondary-conflict\n"
        );
        assert_eq!(
            fs::read(&manifest_path).expect("manifest bytes"),
            manifest_bytes
        );
    }
}

#[test]
fn event_migration_validates_same_destination_lf_boundaries_and_gzip_members() {
    let temp = tempdir().expect("tempdir");
    let first = compact_historical_fixture("event-1.0.json");
    let second = compact_historical_fixture("event-2.0.json");

    let source_one = temp.path().join("join-one.jsonl");
    let source_two = temp.path().join("join-two.jsonl");
    let destination = temp.path().join("joined.jsonl");
    let mut first_with_lf = first.clone();
    first_with_lf.push(b'\n');
    fs::write(&source_one, &first_with_lf).expect("first source");
    fs::write(&source_two, &second).expect("second source");
    let output = run_event_pairs(&[(&source_one, &destination), (&source_two, &destination)]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut expected = first_with_lf.clone();
    expected.extend_from_slice(&second);
    assert_eq!(
        fs::read(&destination).expect("joined destination"),
        expected
    );

    let invalid_source_one = temp.path().join("invalid-join-one.jsonl");
    let invalid_source_two = temp.path().join("invalid-join-two.jsonl");
    let invalid_destination = temp.path().join("invalid-joined.jsonl");
    fs::write(&invalid_source_one, &first).expect("invalid first source");
    fs::write(&invalid_source_two, &second).expect("invalid second source");
    let output = run_event_pairs(&[
        (&invalid_source_one, &invalid_destination),
        (&invalid_source_two, &invalid_destination),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("LF boundary"));
    assert!(!invalid_destination.exists());
    assert!(
        !invalid_destination
            .with_file_name("invalid-joined.jsonl.migration.json")
            .exists()
    );

    let gzip_source_one = temp.path().join("gzip-one.jsonl.gz");
    let gzip_source_two = temp.path().join("gzip-two.jsonl.gz");
    let gzip_destination = temp.path().join("gzip-joined.jsonl.gz");
    let mut first_gzip_plain = first.clone();
    first_gzip_plain.push(b'\n');
    fs::write(&gzip_source_one, gzip_bytes(&first_gzip_plain)).expect("gzip first source");
    fs::write(&gzip_source_two, gzip_bytes(&second)).expect("gzip second source");
    let output = run_event_pairs(&[
        (&gzip_source_one, &gzip_destination),
        (&gzip_source_two, &gzip_destination),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut expected_plain = first_gzip_plain;
    expected_plain.extend_from_slice(&second);
    assert_eq!(
        decompress_gzip(&fs::read(&gzip_destination).expect("gzip destination")),
        expected_plain
    );

    let concatenated_source = temp.path().join("gzip-concatenated.jsonl.gz");
    let concatenated_destination = temp.path().join("gzip-concatenated-new.jsonl.gz");
    let split = first.len() / 2;
    let mut second_member_plain = first[split..].to_vec();
    second_member_plain.push(b'\n');
    let mut concatenated = gzip_bytes(&first[..split]);
    concatenated.extend_from_slice(&gzip_bytes(&second_member_plain));
    fs::write(&concatenated_source, &concatenated).expect("concatenated gzip source");
    let output = run_event_pairs(&[(&concatenated_source, &concatenated_destination)]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut concatenated_expected = first[0..split].to_vec();
    concatenated_expected.extend_from_slice(&second_member_plain);
    assert_eq!(
        fs::read(&concatenated_destination).expect("concatenated gzip destination"),
        concatenated
    );
    assert_eq!(
        decompress_gzip(&concatenated),
        concatenated_expected,
        "concatenated members are one explicit source contribution"
    );

    let gzip_invalid_one = temp.path().join("gzip-invalid-one.jsonl.gz");
    let gzip_invalid_two = temp.path().join("gzip-invalid-two.jsonl.gz");
    let gzip_invalid_destination = temp.path().join("gzip-invalid-joined.jsonl.gz");
    fs::write(&gzip_invalid_one, gzip_bytes(&first)).expect("gzip invalid first");
    fs::write(&gzip_invalid_two, gzip_bytes(&second)).expect("gzip invalid second");
    let output = run_event_pairs(&[
        (&gzip_invalid_one, &gzip_invalid_destination),
        (&gzip_invalid_two, &gzip_invalid_destination),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("LF boundary"));
    assert!(!gzip_invalid_destination.exists());
}

#[test]
fn event_migration_accepts_framing_only_duplicate_differences() {
    let first = compact_historical_fixture("event-1.0.json");
    for first_ending in [b"\n".as_slice(), b"\r\n".as_slice()] {
        for second_ending in [b"\n".as_slice(), b"\r\n".as_slice(), b"".as_slice()] {
            let temp = tempdir().expect("tempdir");
            let source = temp.path().join("framed-duplicates.jsonl");
            let destination = temp.path().join("framed-destination.jsonl");
            let mut bytes = first.clone();
            bytes.extend_from_slice(first_ending);
            bytes.extend_from_slice(&first);
            bytes.extend_from_slice(second_ending);
            fs::write(&source, &bytes).expect("framed duplicate source");
            let output = run_event_pairs(&[(&source, &destination)]);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(fs::read(&destination).expect("framed destination"), bytes);
        }
    }
}

#[test]
fn migration_cli_exposes_only_explicit_event_and_environment_inputs() {
    let help = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["migrate", "events", "--help"])
        .output()
        .expect("events help");
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help.status.success());
    assert!(help_text.contains("--pair <OLD> <NEW>"));
    assert!(help_text.contains("64 pairs"));
    assert!(help_text.contains("32 unique destinations"));
    assert!(!help_text.contains("fail-after-destination-install"));

    let no_pair = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["migrate", "events"])
        .output()
        .expect("empty event migration");
    assert!(!no_pair.status.success());
    assert!(String::from_utf8_lossy(&no_pair.stderr).contains("at least one pair"));

    let env_help = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["migrate", "env", "--help"])
        .output()
        .expect("environment help");
    let env_help_text = String::from_utf8_lossy(&env_help.stdout);
    assert!(env_help.status.success());
    assert!(env_help_text.contains("--from <FROM>"));
    assert!(env_help_text.contains("--to <TO>"));
}

#[test]
fn event_migration_preserves_explicit_gzip_bytes_and_validates_decompressed_records() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("old-events.jsonl.gz");
    let destination = temp.path().join("new-events.jsonl.gz");
    let record = compact_historical_fixture("event-1.0.json");
    let mut plain = record;
    plain.extend_from_slice(b"\r\n\r\n");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&plain).expect("gzip input");
    let compressed = encoder.finish().expect("gzip bytes");
    fs::write(&source, &compressed).expect("compressed source");

    let output = run_event_pairs(&[(&source, &destination)]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(&destination).expect("compressed destination"),
        compressed
    );
    let mut decoder = MultiGzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut decompressed).expect("decompress destination");
    assert_eq!(decompressed, plain);
}

#[test]
fn event_migration_rejects_gzip_trailing_garbage_truncation_and_crc_corruption() {
    let record = compact_historical_fixture("event-1.0.json");
    let valid = gzip_bytes(&[record.as_slice(), b"\n"].concat());
    let mut trailing_garbage = valid.clone();
    trailing_garbage.extend_from_slice(b"trailing-garbage");
    let mut truncated = valid.clone();
    truncated.truncate(truncated.len().saturating_sub(2));
    let mut crc_corrupt = valid.clone();
    let last = crc_corrupt.last_mut().expect("gzip trailer");
    *last ^= 0x01;

    for (index, bytes) in [trailing_garbage, truncated, crc_corrupt]
        .into_iter()
        .enumerate()
    {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join(format!("invalid-{index}.jsonl.gz"));
        let destination = temp.path().join(format!("invalid-{index}-new.jsonl.gz"));
        fs::write(&source, bytes).expect("invalid gzip source");
        #[cfg(unix)]
        {
            fs::write(&destination, b"destination-sentinel\n").expect("destination sentinel");
            set_mode(&destination, 0o640);
        }
        let output = run_event_pairs(&[(&source, &destination)]);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("invalid gzip"),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        #[cfg(unix)]
        assert_eq!(
            fs::read(&destination).expect("destination bytes"),
            b"destination-sentinel\n"
        );
        #[cfg(not(unix))]
        assert!(!destination.exists());
        assert!(!manifest_path_for(&destination).exists());
    }
}

#[test]
fn event_migration_rejects_frame_and_blank_frame_budgets_before_destination_mutation() {
    let cases = [
        (
            "oversize.jsonl",
            vec![b'x'; 16 * 1024 * 1024 + 1],
            "record exceeds bounded frame limit",
        ),
        (
            "many-blank.jsonl",
            vec![b'\n'; 100_001],
            "blank frame budget exceeded",
        ),
    ];
    for (name, bytes, expected_error) in cases {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join(name);
        let destination = temp.path().join(format!("{name}-new"));
        fs::write(&source, bytes).expect("budget source");
        #[cfg(unix)]
        {
            fs::write(&destination, b"destination-sentinel\n").expect("destination sentinel");
            set_mode(&destination, 0o640);
        }
        let output = run_event_pairs(&[(&source, &destination)]);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected_error),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        #[cfg(unix)]
        assert_eq!(
            fs::read(&destination).expect("destination bytes"),
            b"destination-sentinel\n"
        );
        #[cfg(not(unix))]
        assert!(!destination.exists());
        assert!(!manifest_path_for(&destination).exists());
    }
}

#[test]
fn environment_migration_maps_exact_keys_and_preserves_opaque_bytes_and_framing() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("adr.env");
    let destination = temp.path().join("telltale.env");
    let canary = "opaque-rhs-canary";
    let source_bytes = format!(
        "# keep this\r\n\r\nADR_LOG_PATH={canary}\r\nADR_STATE_PATH=/old/state\nADR_RISK_THRESHOLD_TRIAGE= 70 \r\nADR_RISK_THRESHOLD_ALERT='90'\r\nADR_TEST_VENDOR=third-party\r\nUNRELATED=keep\n"
    )
    .into_bytes();
    fs::write(&source, &source_bytes).expect("environment source");

    let output = run_env_migration(&source, &destination);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = format!(
        "# keep this\r\n\r\nTELLTALE_LOG_PATH={canary}\r\nTELLTALE_STATE_PATH=/old/state\nTELLTALE_RISK_THRESHOLD_HIGH= 70 \r\nTELLTALE_RISK_THRESHOLD_CRITICAL='90'\r\nADR_TEST_VENDOR=third-party\r\nUNRELATED=keep\n"
    )
    .into_bytes();
    assert_eq!(fs::read(&source).expect("source bytes"), source_bytes);
    assert_eq!(fs::read(&destination).expect("destination bytes"), expected);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(canary));
    let manifest_path = destination.with_file_name("telltale.env.migration.json");
    let first_manifest = fs::read(&manifest_path).expect("manifest bytes");
    #[cfg(windows)]
    let source_before = fs::read(&source).expect("source bytes");
    let rerun = run_env_migration(&source, &destination);
    #[cfg(unix)]
    assert!(rerun.status.success());
    #[cfg(windows)]
    {
        assert_windows_existing_target_unsupported(&rerun);
        assert_eq!(fs::read(&source).expect("source bytes"), source_before);
        assert_eq!(fs::read(&destination).expect("destination bytes"), expected);
    }
    assert_eq!(
        fs::read(&manifest_path).expect("manifest bytes"),
        first_manifest
    );
    fs::remove_file(&manifest_path).expect("remove manifest");
    let repair = run_env_migration(&source, &destination);
    #[cfg(unix)]
    assert!(repair.status.success());
    #[cfg(windows)]
    {
        assert_windows_existing_target_unsupported(&repair);
        assert_eq!(fs::read(&source).expect("source bytes"), source_before);
        assert_eq!(fs::read(&destination).expect("destination bytes"), expected);
        assert!(!manifest_path.exists());
    }
    #[cfg(unix)]
    assert_eq!(
        fs::read(&manifest_path).expect("repaired manifest"),
        first_manifest
    );
    fs::write(&manifest_path, b"manifest-conflict\n").expect("manifest conflict");
    let conflict = run_env_migration(&source, &destination);
    assert!(!conflict.status.success());
    #[cfg(windows)]
    {
        assert_windows_existing_target_unsupported(&conflict);
        assert_eq!(fs::read(&source).expect("source bytes"), source_before);
        assert_eq!(fs::read(&destination).expect("destination bytes"), expected);
        assert_eq!(
            fs::read(&manifest_path).expect("manifest bytes"),
            b"manifest-conflict\n"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&destination)
                .expect("destination metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&manifest_path)
                .expect("manifest metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn environment_migration_covers_the_complete_audited_inventory_without_canary_leaks() {
    let mappings = [
        ("ADR_LOG_PATH", "TELLTALE_LOG_PATH"),
        ("ADR_STATE_PATH", "TELLTALE_STATE_PATH"),
        ("ADR_SCAN_ROOT", "TELLTALE_SCAN_ROOT"),
        ("ADR_PROJECT_CONFIG", "TELLTALE_PROJECT_CONFIG"),
        ("ADR_LOG_ROTATE_MAX_SIZE", "TELLTALE_LOG_ROTATE_MAX_SIZE"),
        ("ADR_LOG_ROTATE_KEEP", "TELLTALE_LOG_ROTATE_KEEP"),
        (
            "ADR_INSTALL_INVENTORY_INTERVAL_SECONDS",
            "TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS",
        ),
        (
            "ADR_PROCESS_CHAIN_DETECTIONS",
            "TELLTALE_PROCESS_CHAIN_DETECTIONS",
        ),
        (
            "ADR_OP_ALERT_MAX_SCANNER_ERRORS",
            "TELLTALE_OP_ALERT_MAX_SCANNER_ERRORS",
        ),
        (
            "ADR_OP_ALERT_MAX_SCAN_DURATION_MS",
            "TELLTALE_OP_ALERT_MAX_SCAN_DURATION_MS",
        ),
        ("ADR_RISK_THRESHOLD_LOW", "TELLTALE_RISK_THRESHOLD_LOW"),
        (
            "ADR_RISK_THRESHOLD_MEDIUM",
            "TELLTALE_RISK_THRESHOLD_MEDIUM",
        ),
        ("ADR_RISK_THRESHOLD_TRIAGE", "TELLTALE_RISK_THRESHOLD_HIGH"),
        (
            "ADR_RISK_THRESHOLD_ALERT",
            "TELLTALE_RISK_THRESHOLD_CRITICAL",
        ),
        ("ADR_INDEX", "TELLTALE_INDEX"),
        ("ADR_SOURCETYPE", "TELLTALE_SOURCETYPE"),
        ("ADR_ATLAS_PATH", "TELLTALE_ATLAS_PATH"),
        ("ADR_GIT_HASH", "TELLTALE_GIT_HASH"),
        (
            "ADR_LIVETEST_ES_CONTAINER",
            "TELLTALE_LIVETEST_ES_CONTAINER",
        ),
        (
            "ADR_LIVETEST_SPLUNK_CONTAINER",
            "TELLTALE_LIVETEST_SPLUNK_CONTAINER",
        ),
        ("ADR_LIVETEST_ES_INDEX", "TELLTALE_LIVETEST_ES_INDEX"),
        ("ADR_LIVETEST_ES_PASSWORD", "TELLTALE_LIVETEST_ES_PASSWORD"),
        ("ADR_LIVETEST_HEC_TOKEN", "TELLTALE_LIVETEST_HEC_TOKEN"),
    ];
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("inventory.env");
    let destination = temp.path().join("inventory-telltale.env");
    let mut source_text = String::new();
    let mut expected_text = String::new();
    for (index, (old, new)) in mappings.iter().enumerate() {
        let value = format!("migration-inventory-canary-{index}");
        source_text.push_str(&format!("{old}={value}\n"));
        expected_text.push_str(&format!("{new}={value}\n"));
    }
    source_text.push_str(
        "ADR_TEST_UNRELATED=preserve\nADR_LOGISTICS_PATH=preserve\nADR_VENDOR_MODE=preserve\nADR_LOG_CUSTOM=preserve\nADR_TRIAGE_OTHER=preserve\n",
    );
    expected_text.push_str(
        "ADR_TEST_UNRELATED=preserve\nADR_LOGISTICS_PATH=preserve\nADR_VENDOR_MODE=preserve\nADR_LOG_CUSTOM=preserve\nADR_TRIAGE_OTHER=preserve\n",
    );
    fs::write(&source, source_text.as_bytes()).expect("inventory source");
    let output = run_env_migration(&source, &destination);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(&destination).expect("inventory destination"),
        expected_text.as_bytes()
    );
    let output_text = String::from_utf8_lossy(&output.stdout);
    let error_text = String::from_utf8_lossy(&output.stderr);
    assert!(!output_text.contains("migration-inventory-canary"));
    assert!(!error_text.contains("migration-inventory-canary"));
}

#[cfg(windows)]
#[test]
fn migration_rejects_existing_manifest_without_destination_without_mutation() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("orphan-source.jsonl");
    let destination = temp.path().join("orphan-destination.jsonl");
    let manifest_path = manifest_path_for(&destination);
    let source_bytes = compact_historical_fixture("event-1.0.json");
    let manifest_bytes = b"existing-orphan-manifest\n";
    fs::write(&source, &source_bytes).expect("source");
    fs::write(&manifest_path, manifest_bytes).expect("orphan manifest");

    let output = run_event_pairs(&[(&source, &destination)]);
    assert_windows_existing_target_unsupported(&output);
    assert!(!destination.exists());
    assert_eq!(fs::read(&source).expect("source bytes"), source_bytes);
    assert_eq!(
        fs::read(&manifest_path).expect("manifest bytes"),
        manifest_bytes
    );
}

#[cfg(unix)]
#[test]
fn migration_rerun_rejects_broader_existing_event_env_and_manifest_modes() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().expect("tempdir");
    let event_source = temp.path().join("mode-events.jsonl");
    let event_destination = temp.path().join("mode-events-new.jsonl");
    fs::write(&event_source, compact_historical_fixture("event-1.0.json")).expect("event source");
    assert!(
        run_event_pairs(&[(&event_source, &event_destination)])
            .status
            .success()
    );
    let event_manifest = event_destination.with_file_name("mode-events-new.jsonl.migration.json");
    set_mode(&event_destination, 0o644);
    let event_conflict = run_event_pairs(&[(&event_source, &event_destination)]);
    assert!(!event_conflict.status.success());
    assert_eq!(
        fs::metadata(&event_destination)
            .expect("event mode")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    set_mode(&event_destination, 0o640);
    set_mode(&event_manifest, 0o644);
    let manifest_conflict = run_event_pairs(&[(&event_source, &event_destination)]);
    assert!(!manifest_conflict.status.success());
    assert_eq!(
        fs::metadata(&event_manifest)
            .expect("event manifest mode")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );

    let env_source = temp.path().join("mode.env");
    let env_destination = temp.path().join("mode-telltale.env");
    fs::write(&env_source, b"ADR_LOG_PATH=/old\n").expect("env source");
    assert!(
        run_env_migration(&env_source, &env_destination)
            .status
            .success()
    );
    let env_manifest = env_destination.with_file_name("mode-telltale.env.migration.json");
    set_mode(&env_destination, 0o640);
    let env_conflict = run_env_migration(&env_source, &env_destination);
    assert!(!env_conflict.status.success());
    assert_eq!(
        fs::metadata(&env_destination)
            .expect("env mode")
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    set_mode(&env_destination, 0o600);
    set_mode(&env_manifest, 0o644);
    let env_manifest_conflict = run_env_migration(&env_source, &env_destination);
    assert!(!env_manifest_conflict.status.success());
    assert_eq!(
        fs::metadata(&env_manifest)
            .expect("env manifest mode")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[cfg(unix)]
#[test]
fn migration_rejects_foreign_owned_existing_event_env_and_manifest_targets() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    fn make_foreign(path: &std::path::Path) -> bool {
        let current = unsafe { libc::geteuid() };
        let foreign = if current == 0 {
            1000
        } else {
            current.saturating_add(1)
        };
        let path = CString::new(path.as_os_str().as_bytes()).expect("path");
        unsafe { libc::chown(path.as_ptr(), foreign, u32::MAX) == 0 }
    }

    let temp = tempdir().expect("tempdir");
    let event_source = temp.path().join("foreign-events.jsonl");
    let event_destination = temp.path().join("foreign-events-new.jsonl");
    fs::write(&event_source, compact_historical_fixture("event-1.0.json")).expect("source");
    fs::write(&event_destination, b"event-destination-sentinel\n").expect("destination");
    if !make_foreign(&event_destination) {
        return;
    }
    let event_output = run_event_pairs(&[(&event_source, &event_destination)]);
    assert!(!event_output.status.success());
    assert!(
        String::from_utf8_lossy(&event_output.stderr).contains("not owned by the effective user")
    );
    assert_eq!(
        fs::read(&event_destination).expect("event destination"),
        b"event-destination-sentinel\n"
    );

    let env_source = temp.path().join("foreign.env");
    let env_destination = temp.path().join("foreign-telltale.env");
    fs::write(&env_source, b"ADR_LOG_PATH=/old\n").expect("environment source");
    fs::write(&env_destination, b"env-destination-sentinel\n").expect("environment destination");
    assert!(make_foreign(&env_destination));
    let env_output = run_env_migration(&env_source, &env_destination);
    assert!(!env_output.status.success());
    assert!(
        String::from_utf8_lossy(&env_output.stderr).contains("not owned by the effective user")
    );
    assert_eq!(
        fs::read(&env_destination).expect("environment destination"),
        b"env-destination-sentinel\n"
    );

    let owned_destination = temp.path().join("owned-telltale.env");
    assert!(
        run_env_migration(&env_source, &owned_destination)
            .status
            .success()
    );
    let manifest = manifest_path_for(&owned_destination);
    assert!(make_foreign(&manifest));
    let manifest_output = run_env_migration(&env_source, &owned_destination);
    assert!(!manifest_output.status.success());
    assert!(
        String::from_utf8_lossy(&manifest_output.stderr)
            .contains("not owned by the effective user")
    );
}

#[test]
fn environment_migration_rejects_duplicates_coexistence_unmapped_and_malformed_inputs() {
    let cases = [
        "ADR_LOG_PATH=one\nADR_LOG_PATH=two\n",
        "ADR_LOG_PATH=one\nTELLTALE_LOG_PATH=two\n",
        "ADR_TRIAGE_TIMEOUT_MS=secret-canary\n",
        "ADR_TRIAGE_MAX_RETRIES=secret-canary\n",
        "ADR_LOG_PATH=one\\\ncontinued\n",
        "not-an-assignment\n",
    ];
    for (index, contents) in cases.into_iter().enumerate() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join(format!("source-{index}.env"));
        let destination = temp.path().join(format!("destination-{index}.env"));
        fs::write(&source, contents.as_bytes()).expect("source");
        #[cfg(unix)]
        {
            fs::write(&destination, b"destination-sentinel\n").expect("destination");
        }
        let output = run_env_migration(&source, &destination);
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-canary"));
        #[cfg(unix)]
        assert_eq!(
            fs::read(&destination).expect("destination"),
            b"destination-sentinel\n"
        );
        #[cfg(windows)]
        assert!(!destination.exists());
    }

    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("nul.env");
    let destination = temp.path().join("nul-destination.env");
    fs::write(&source, b"ADR_LOG_PATH=before\0after\n").expect("NUL source");
    let output = run_env_migration(&source, &destination);
    assert!(!output.status.success());
    assert!(!destination.exists());

    let alias = run_env_migration(&source, &source);
    assert!(!alias.status.success());
}

#[cfg(unix)]
#[test]
fn environment_migration_refuses_symlink_hardlink_and_nonregular_paths() {
    use std::fs::{hard_link, read_link};
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("source.env");
    fs::write(&source, b"ADR_LOG_PATH=/old\n").expect("source");

    let symlink_destination = temp.path().join("symlink.env");
    let symlink_target = temp.path().join("symlink-target.env");
    fs::write(&symlink_target, b"target\n").expect("symlink target");
    symlink(&symlink_target, &symlink_destination).expect("symlink");
    let output = run_env_migration(&source, &symlink_destination);
    assert!(!output.status.success());
    assert_eq!(
        read_link(&symlink_destination).expect("symlink remains"),
        symlink_target
    );

    let hardlink_source = temp.path().join("hardlink-source.env");
    hard_link(&source, &hardlink_source).expect("hardlink source");
    let hardlink_destination = temp.path().join("hardlink-destination.env");
    let output = run_env_migration(&hardlink_source, &hardlink_destination);
    assert!(!output.status.success());
    assert!(!hardlink_destination.exists());

    let hardlink_destination = temp.path().join("hardlink-existing.env");
    fs::write(&hardlink_destination, b"target\n").expect("hardlink target");
    let hardlink_alias = temp.path().join("hardlink-alias.env");
    hard_link(&hardlink_destination, &hardlink_alias).expect("hardlink destination");
    let output = run_env_migration(&source, &hardlink_destination);
    assert!(!output.status.success());

    let directory_destination = temp.path().join("directory.env");
    fs::create_dir(&directory_destination).expect("directory destination");
    let output = run_env_migration(&source, &directory_destination);
    assert!(!output.status.success());

    let alias = run_env_migration(&source, &source);
    assert!(!alias.status.success());
}

fn compact_historical_fixture(name: &str) -> Vec<u8> {
    serde_json::to_vec(
        &serde_json::from_slice::<Value>(match name {
            "event-1.0.json" => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/historical_events/event-1.0.json"
            )),
            "event-2.0.json" => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/historical_events/event-2.0.json"
            )),
            _ => panic!("unknown fixture {name}"),
        })
        .expect("historical fixture"),
    )
    .expect("compact fixture")
}

fn gzip_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).expect("gzip bytes");
    encoder.finish().expect("finish gzip")
}

fn decompress_gzip(bytes: &[u8]) -> Vec<u8> {
    let mut decoder = MultiGzDecoder::new(bytes);
    let mut decompressed = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut decompressed).expect("decompress gzip");
    decompressed
}

fn manifest_path_for(path: &std::path::Path) -> std::path::PathBuf {
    path.with_file_name(format!(
        "{}.migration.json",
        path.file_name()
            .expect("migration target filename")
            .to_string_lossy()
    ))
}

fn run_event_pairs(pairs: &[(&std::path::Path, &std::path::Path)]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command.args(["migrate", "events"]);
    for (source, destination) in pairs {
        command.args(["--pair"]).arg(source).arg(destination);
    }
    command.output().expect("event migration")
}

fn run_env_migration(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["migrate", "env", "--from"])
        .arg(source)
        .args(["--to"])
        .arg(destination)
        .output()
        .expect("environment migration")
}

#[cfg(windows)]
fn assert_windows_existing_target_unsupported(output: &std::process::Output) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("existing migration target ownership is unsupported on Windows")
    );
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path).expect("mode metadata").permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).expect("set mode");
}

fn run_migration(source: &std::path::Path, destination: &std::path::Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
