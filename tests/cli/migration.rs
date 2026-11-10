use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use fs4::FileExt;
use serde_json::Value;
use tempfile::tempdir;

struct TestChild(Child);

impl TestChild {
    fn output(mut self) -> Output {
        self.0.stdin.take();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        // CLI summaries are small; drain both pipes concurrently so diagnostics
        // cannot block the process while the parent waits for its summary.
        let mut error_pipe = self.0.stderr.take().expect("stderr pipe");
        let errors = thread::spawn(move || {
            error_pipe.read_to_end(&mut stderr).expect("stderr");
            stderr
        });
        self.0
            .stdout
            .take()
            .expect("stdout pipe")
            .read_to_end(&mut stdout)
            .expect("stdout");
        let status = self.0.wait().expect("child wait");
        Output {
            status,
            stdout,
            stderr: errors.join().expect("stderr reader"),
        }
    }
}

impl Drop for TestChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_lock_child(target: &std::path::Path) -> (TestChild, std::path::PathBuf) {
    let ready = target.with_extension("ready");
    let _ = fs::remove_file(&ready);
    let child = Command::new(std::env::current_exe().expect("test executable"))
        .arg("migration::migration_lock_holder")
        .arg("--exact")
        .env("TELLTALE_LOCK_HOLDER_TARGET", target)
        .env("TELLTALE_LOCK_HOLDER_READY", &ready)
        .env(
            "TELLTALE_LOCK_HOLDER_STARTED",
            target.with_extension("started"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lock holder");
    (TestChild(child), ready)
}

fn acknowledge_lock(child: &mut TestChild, ready: &std::path::Path) {
    child
        .0
        .stdin
        .as_mut()
        .expect("control pipe")
        .write_all(b"acquire\n")
        .expect("acquire command");
    while !ready.exists() {
        if let Some(status) = child.0.try_wait().expect("holder status") {
            let mut stderr = String::new();
            child
                .0
                .stderr
                .take()
                .expect("stderr pipe")
                .read_to_string(&mut stderr)
                .expect("holder diagnostics");
            let mut stdout = String::new();
            child
                .0
                .stdout
                .take()
                .expect("stdout pipe")
                .read_to_string(&mut stdout)
                .expect("holder test diagnostics");
            panic!("lock holder exited before acknowledgement: {status}: {stderr}{stdout}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        child.0.try_wait().expect("holder status").is_none(),
        "acknowledged holder exited"
    );
}

fn hold_lock_child(target: &std::path::Path) -> TestChild {
    let (mut child, ready) = spawn_lock_child(target);
    acknowledge_lock(&mut child, &ready);
    child
}

fn release_lock_child(child: TestChild) {
    let output = child.output();
    assert!(
        output.status.success(),
        "holder: {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_busy(output: &Output) {
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("resource busy; retry later"),
        "{}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn lock_holder_waits_for_parent_and_releases_on_eof() {
    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("controlled.json");
    let (mut child, ready) = spawn_lock_child(&target);
    // Wait until the holder is running and blocked on its control pipe, so the
    // absence checks below would catch a lock taken before the command.
    let started = target.with_extension("started");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !started.exists() {
        assert!(
            child.0.try_wait().expect("holder status").is_none(),
            "holder exited before start"
        );
        assert!(std::time::Instant::now() < deadline, "holder did not start");
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!ready.exists());
    assert!(!target.with_extension("json.lock").exists());
    assert!(child.0.try_wait().expect("waiting child").is_none());
    acknowledge_lock(&mut child, &ready);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(target.with_extension("json.lock"))
        .expect("sidecar");
    assert!(matches!(
        FileExt::try_lock(&file),
        Err(fs4::TryLockError::WouldBlock)
    ));
    release_lock_child(child);
    FileExt::try_lock(&file).expect("released lock");
}

#[test]
fn lock_holder_reports_early_exit_and_cleans_up_on_panic() {
    let temp = tempdir().expect("tempdir");
    let failure = std::panic::catch_unwind(|| hold_lock_child(&temp.path().join("missing/target")));
    let panic = match failure {
        Ok(_) => panic!("invalid holder succeeded"),
        Err(panic) => panic,
    };
    let message = panic
        .downcast_ref::<String>()
        .expect("holder panic message");
    assert!(
        message.contains("exited before acknowledgement"),
        "{message}"
    );
    assert!(message.contains("lock file"), "{message}");

    let target = temp.path().join("panic.json");
    let failure = std::panic::catch_unwind(|| {
        let _holder = hold_lock_child(&target);
        panic!("forced parent assertion failure");
    });
    assert!(failure.is_err());
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(target.with_extension("json.lock"))
        .expect("sidecar");
    FileExt::try_lock(&file)
        .expect("panic cleanup must terminate and reap holder before returning");
}

#[test]
fn scan_rejects_real_cross_process_state_and_log_contention() {
    let temp = tempdir().expect("tempdir");
    let root = synthetic_scan_root(temp.path());
    let state = temp.path().join("state.json");
    let log = temp.path().join("events.jsonl");
    assert_eq!(
        successful_summary(&spawn_synthetic_scan(&root, &state, &log).output())["emitted_count"],
        1
    );
    let state_bytes = fs::read(&state).expect("current state");
    assert!(
        std::str::from_utf8(&state_bytes)
            .expect("state utf8")
            .contains("\"state_schema_version\"")
    );

    let holder = hold_lock_child(&state);
    let blocked_log = temp.path().join("blocked-events.jsonl");
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
        .arg(&blocked_log)
        .output()
        .expect("scan");
    assert_busy(&scan);
    assert!(!blocked_log.exists());
    assert_eq!(fs::read(&state).expect("unchanged state"), state_bytes);
    release_lock_child(holder);

    // Replaces the timing-dependent two-scan state test: a real process owns
    // the actual lock, and CLI rejection, unchanged state, release and recovery
    // are all observed rather than inferred from sidecar creation.
    let root = synthetic_scan_root(temp.path());
    let fresh_state = temp.path().join("fresh-state.json");
    let fresh_log = temp.path().join("fresh-events.jsonl");
    let holder = hold_lock_child(&fresh_state);
    assert_busy(&spawn_synthetic_scan(&root, &fresh_state, &fresh_log).output());
    assert!(!fresh_state.exists());
    assert!(!fresh_log.exists());
    release_lock_child(holder);
    assert_eq!(
        successful_summary(&spawn_synthetic_scan(&root, &fresh_state, &fresh_log).output())["emitted_count"],
        1
    );

    let log2 = temp.path().join("events-locked.jsonl");
    let state2 = temp.path().join("state-locked.json");
    let holder = hold_lock_child(&log2);
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
    assert_busy(&log_scan);
    assert!(!state2.exists());
    assert!(!log2.exists());
    release_lock_child(holder);
}

#[test]
fn migration_lock_holder() {
    let Ok(target) = std::env::var("TELLTALE_LOCK_HOLDER_TARGET") else {
        return;
    };
    let ready = std::env::var("TELLTALE_LOCK_HOLDER_READY").expect("ready path");
    // Best effort: invalid-target cases must still fail at the lock file.
    if let Ok(started) = std::env::var("TELLTALE_LOCK_HOLDER_STARTED") {
        let _ = File::create(started);
    }
    let mut control = std::io::stdin().lock();
    let mut command = String::new();
    control.read_line(&mut command).expect("acquire command");
    assert_eq!(command, "acquire\n");
    let path = format!("{target}.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .expect("lock file");
    FileExt::try_lock(&file).expect("exclusive lock");
    File::create(ready)
        .expect("ready file")
        .write_all(b"ready")
        .expect("ready marker");
    std::io::copy(&mut control, &mut std::io::sink()).expect("release EOF");
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
fn canonical_runtime_ignores_preseeded_legacy_default_log_and_state_files() {
    let temp = tempdir().expect("tempdir");
    let old_log = temp.path().join("unrelated/logs/events.jsonl");
    let old_state = temp.path().join("unrelated/state/state.json");
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
fn concurrent_scans_produce_parseable_jsonl_with_rotation() {
    let temp = tempdir().expect("tempdir");
    let root = synthetic_scan_root(temp.path());
    let log = temp.path().join("shared-events.jsonl");
    let states = [
        temp.path().join("state-one.json"),
        temp.path().join("state-two.json"),
    ];
    // Both real CLI processes must fail closed while an acknowledged process
    // owns the shared log, regardless of startup or rule-compilation duration.
    let holder = hold_lock_child(&log);
    let first = spawn_synthetic_scan(&root, &states[0], &log);
    let second = spawn_synthetic_scan(&root, &states[1], &log);
    assert_busy(&first.output());
    assert_busy(&second.output());
    assert!(!log.exists());
    assert!(states.iter().all(|state| !state.exists()));
    release_lock_child(holder);

    let first = spawn_synthetic_scan(&root, &states[0], &log);
    let second = spawn_synthetic_scan(&root, &states[1], &log);
    let outputs = [first.output(), second.output()];
    assert!(
        outputs.iter().any(|output| output.status.success()),
        "neither scan recovered"
    );
    let mut expected_records = 0;
    for (state, output) in states.iter().zip(outputs) {
        let accepted = if output.status.success() {
            output
        } else {
            assert_busy(&output);
            assert!(!state.exists(), "rejected delivery must not commit state");
            spawn_synthetic_scan(&root, state, &log).output()
        };
        let summary = successful_summary(&accepted);
        assert_eq!(summary["source_processing"]["parsed_record_count"], 2);
        assert_eq!(summary["emitted_count"], 1);
        expected_records += summary["emitted_count"].as_u64().expect("emitted count") + 1;
        let bytes = fs::read(state).expect("committed state");
        let value: Value = serde_json::from_slice(&bytes).expect("state JSON");
        assert_eq!(
            value["seen_source_fingerprints"]
                .as_array()
                .expect("source fingerprints")
                .len(),
            1
        );
        assert_eq!(
            value["source_observations"]
                .as_object()
                .expect("source observations")
                .len(),
            1
        );
        let repeated = successful_summary(&spawn_synthetic_scan(&root, state, &log).output());
        assert_eq!(
            repeated["emitted_count"], 0,
            "accepted source must be deduplicated"
        );
    }
    let mut actual_records = 0;
    let mut activities = 0;
    let mut health = 0;
    let mut generations = 0;
    for entry in fs::read_dir(temp.path()).expect("log directory") {
        let path = entry.expect("log entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "jsonl")
        {
            generations += 1;
            let bytes = fs::read_to_string(path).expect("log bytes");
            assert!(bytes.ends_with('\n'), "complete JSONL framing");
            for line in bytes.lines() {
                let event: Value = serde_json::from_str(line).expect("complete JSONL record");
                assert_eq!(event["schema_version"], "3.0");
                match event["event_type"].as_str().expect("event type") {
                    "activity" => {
                        activities += 1;
                        assert_eq!(event["session_id"], "lock-test-session");
                    }
                    "health" => {
                        health += 1;
                        assert_eq!(event["emitted_count"], 1);
                    }
                    other => panic!("unexpected event: {other}"),
                }
                actual_records += 1;
            }
        }
    }
    assert_eq!(actual_records, expected_records);
    assert_eq!(activities, 2);
    assert_eq!(health, 2);
    assert_eq!(
        generations, 2,
        "second accepted batch must rotate the first"
    );
}

fn synthetic_scan_root(directory: &std::path::Path) -> std::path::PathBuf {
    let root = directory.join("synthetic-root");
    let sessions = root.join("codex/sessions");
    fs::create_dir_all(&sessions).expect("sessions");
    fs::write(sessions.join("session.jsonl"), concat!(
        "{\"type\":\"session_meta\",\"session_id\":\"lock-test-session\",\"timestamp\":\"2026-04-03T00:00:00Z\",\"payload\":{\"source\":\"cli\"}}\n",
        "{\"type\":\"event_msg\",\"timestamp\":\"2026-04-03T00:00:01Z\",\"payload\":{\"type\":\"user_message\",\"message\":\"Summarize repository health.\"}}\n"
    )).expect("synthetic session");
    root
}

fn spawn_synthetic_scan(
    root: &std::path::Path,
    state: &std::path::Path,
    log: &std::path::Path,
) -> TestChild {
    TestChild(
        Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--emit-activity",
                "--client",
                "codex",
                "--root",
            ])
            .arg(root)
            .arg("--state-path")
            .arg(state)
            .arg("--log-path")
            .arg(log)
            .args(["--log-rotate-max-size", "1", "--log-rotate-keep", "10"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("scan"),
    )
}

fn successful_summary(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("scan summary")
}

fn directory_names(path: &std::path::Path) -> Vec<String> {
    let mut names = fs::read_dir(path)
        .expect("directory")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn removed_migrate_commands_exit_before_mutation() {
    let temp = tempdir().expect("tempdir");
    let source = temp.path().join("old-state.json");
    let destination = temp.path().join("new-state.json");
    let events = temp.path().join("events.jsonl");
    let relocated = temp.path().join("relocated.jsonl");
    let source_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/state/legacy-scan-state.json"
    ));
    let event_bytes = b"{\"schema_version\":\"1.0\",\"event_id\":\"synthetic\"}\n";
    fs::write(&source, source_bytes).expect("older state");
    fs::write(&events, event_bytes).expect("historical events");
    let before = directory_names(temp.path());

    let reject = |args: &[&std::ffi::OsStr]| {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args(args)
            .output()
            .expect("removed migrate command");
        assert_eq!(
            output.status.code(),
            Some(2),
            "args {args:?}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unrecognized subcommand"),
            "args {args:?}: {stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("listening"),
            "args {args:?} reached a handler"
        );
    };
    reject(&[
        std::ffi::OsStr::new("migrate"),
        std::ffi::OsStr::new("--help"),
    ]);
    reject(&[
        std::ffi::OsStr::new("migrate"),
        std::ffi::OsStr::new("state"),
        std::ffi::OsStr::new("--help"),
    ]);
    reject(&[
        std::ffi::OsStr::new("migrate"),
        std::ffi::OsStr::new("events"),
        std::ffi::OsStr::new("--help"),
    ]);
    reject(&[std::ffi::OsStr::new("migrate")]);
    reject(&[
        std::ffi::OsStr::new("migrate"),
        std::ffi::OsStr::new("state"),
        std::ffi::OsStr::new("--from"),
        source.as_os_str(),
        std::ffi::OsStr::new("--to"),
        destination.as_os_str(),
    ]);
    reject(&[
        std::ffi::OsStr::new("migrate"),
        std::ffi::OsStr::new("events"),
        std::ffi::OsStr::new("--pair"),
        events.as_os_str(),
        relocated.as_os_str(),
    ]);

    let help = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("--help")
        .output()
        .expect("top-level help");
    assert!(
        help.status.success(),
        "{}",
        String::from_utf8_lossy(&help.stderr)
    );
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(
        !help_text.contains("migrate"),
        "top-level help still advertises migrate:\n{help_text}"
    );

    assert_eq!(fs::read(&source).expect("source"), source_bytes);
    assert_eq!(fs::read(&events).expect("events"), event_bytes);
    assert!(!destination.exists());
    assert!(!relocated.exists());
    assert!(!source.with_extension("json.migration.json").exists());
    assert_eq!(directory_names(temp.path()), before);
}

#[test]
fn scan_rejects_older_state_without_rewriting_it() {
    let temp = tempdir().expect("tempdir");
    let state = temp.path().join("state.json");
    let log = temp.path().join("events.jsonl");
    let older = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/state/legacy-scan-state.json"
    ));
    fs::write(&state, older).expect("older state");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
        .expect("scan older state");
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("older format"), "{stderr}");
    assert!(stderr.contains("was not changed"), "{stderr}");
    assert!(stderr.contains("v0.7.0"), "{stderr}");
    assert!(!stderr.contains("v0.7.1"), "{stderr}");
    assert!(!stderr.contains("internal.example.test"), "{stderr}");
    assert_eq!(fs::read(&state).expect("unchanged state"), older);
    assert!(!log.exists());
    assert!(
        !fs::read_dir(temp.path())
            .expect("scan directory")
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .contains(".telltale-tmp-")
                || entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".migration.json")),
        "rejection must not install state or a migration companion"
    );

    let missing = temp.path().join("missing-state.json");
    let missing_log = temp.path().join("missing-events.jsonl");
    let root = synthetic_scan_root(temp.path());
    let created = successful_summary(&spawn_synthetic_scan(&root, &missing, &missing_log).output());
    assert_eq!(created["emitted_count"], 1);
    let created_bytes = fs::read(&missing).expect("initialized state");
    assert!(
        std::str::from_utf8(&created_bytes)
            .expect("state utf8")
            .contains("\"state_schema_version\"")
    );
}

#[test]
fn scan_rejects_malformed_state_without_resetting_it() {
    let temp = tempdir().expect("tempdir");
    let state = temp.path().join("state.json");
    let log = temp.path().join("events.jsonl");
    fs::write(&state, b"").expect("empty state");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
        .expect("scan empty state");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid"), "{stderr}");
    assert!(stderr.contains("was not changed"), "{stderr}");
    assert!(!stderr.contains("v0.7.0"), "{stderr}");
    assert_eq!(fs::read(&state).expect("unchanged empty state"), b"");
    assert!(!log.exists());
}
