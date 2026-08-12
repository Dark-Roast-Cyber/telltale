use super::*;

use telltale_detect::allowlist::{SuppressionMatch, suppress_detection};

const RETIRED_RUNTIME_ENV_NAMES: &[&str] = &[
    "ADR_GIT_HASH",
    "ADR_INSTALL_INVENTORY_INTERVAL_SECONDS",
    "ADR_LOG_PATH",
    "ADR_LOG_ROTATE_KEEP",
    "ADR_LOG_ROTATE_MAX_SIZE",
    "ADR_OP_ALERT_MAX_SCAN_DURATION_MS",
    "ADR_OP_ALERT_MAX_SCANNER_ERRORS",
    "ADR_PROCESS_CHAIN_DETECTIONS",
    "ADR_PROJECT_CONFIG",
    "ADR_RISK_THRESHOLD_ALERT",
    "ADR_RISK_THRESHOLD_LOW",
    "ADR_RISK_THRESHOLD_MEDIUM",
    "ADR_RISK_THRESHOLD_TRIAGE",
    "ADR_SCAN_ROOT",
    "ADR_STATE_PATH",
    "ADR_TRIAGE_MAX_RETRIES",
    "ADR_TRIAGE_TIMEOUT_MS",
];

fn clean_telltale_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    for name in RETIRED_RUNTIME_ENV_NAMES {
        command.env_remove(name);
    }
    command
}

#[test]
fn retired_runtime_environment_tombstones_are_sorted_and_private() {
    let mut command = clean_telltale_command();
    command.arg("--help");
    for (index, name) in RETIRED_RUNTIME_ENV_NAMES.iter().enumerate() {
        command.env(name, format!("tombstone-canary-{index}"));
    }
    let output = command.output().expect("run tombstoned help");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut names = RETIRED_RUNTIME_ENV_NAMES.to_vec();
    names.sort_unstable();
    let expected = format!(
        "retired environment variables are set: {}; remediation: unset these variables and use canonical TELLTALE_* variables or explicit migration commands",
        names.join(", ")
    );
    assert_eq!(stderr.trim(), expected);
    assert!(!stderr.contains("tombstone-canary"));
}

#[test]
fn retired_runtime_environment_presence_includes_empty_and_old_new_conflicts() {
    let mut empty = clean_telltale_command();
    empty.arg("--version").env("ADR_LOG_PATH", "");
    let output = empty.output().expect("run empty tombstone");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ADR_LOG_PATH"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("tombstone-secret"));

    let mut conflict = clean_telltale_command();
    conflict
        .arg("--version")
        .env("ADR_LOG_PATH", "old-tombstone-secret")
        .env("TELLTALE_LOG_PATH", "new-path");
    let output = conflict.output().expect("run old/new conflict");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ADR_LOG_PATH"));
    assert!(!stderr.contains("old-tombstone-secret"));
    assert!(!stderr.contains("new-path"));
}

#[test]
fn unrelated_adr_environment_names_are_not_tombstoned() {
    let mut command = clean_telltale_command();
    command
        .arg("--help")
        .env("ADR_TEST_UNRELATED", "third-party-canary")
        .env("ADR_VENDOR_MODE", "third-party-mode");
    let output = command.output().expect("run unrelated ADR environment");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("retired environment"));
}

#[test]
fn export_help_mentions_client_for_ambiguous_timeline_session_ids() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["export", "--help"])
        .output()
        .expect("run telltale export help");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Requires --session-id to select a single session"));
    assert!(stdout.contains("add --client when a session id is ambiguous across clients"));
}

#[test]
fn top_level_version_prints_canonical_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("--version")
        .output()
        .expect("run telltale --version");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        format!(
            "telltale {} ({})",
            env!("CARGO_PKG_VERSION"),
            env!("TELLTALE_GIT_HASH")
        )
    );
    assert!(
        output.stderr.is_empty(),
        "telltale --version should not write stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn top_level_help_uses_canonical_invocation_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("--help")
        .output()
        .expect("run telltale --help");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with(
            "Telltale detection layer for AI coding agent sessions\n\nUsage: telltale"
        )
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn parse_errors_use_canonical_invocation_name_without_deprecation_warning() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("--not-a-real-option")
        .output()
        .expect("run telltale with invalid option");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage: telltale"), "stderr: {stderr}");
    assert!(
        !stderr.to_lowercase().contains("deprecat"),
        "stderr: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn executable_has_deterministic_safe_rule_listing_behavior() {
    let args = ["rules", "list", "--no-local-config"];
    let first = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(args)
        .output()
        .expect("run telltale rules list");
    let second = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(args)
        .output()
        .expect("run telltale rules list");

    assert_eq!(first.status, second.status);
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);
}

#[test]
fn status_reports_latest_health_event() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let scan = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale scan");
    assert!(
        scan.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&scan.stderr)
    );

    let status = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("status")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(&state_path)
        .output()
        .expect("run telltale status");
    assert!(
        status.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let summary: Value = serde_json::from_slice(&status.stdout).expect("status json");

    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["log_path"], log_path.display().to_string());
    assert_eq!(summary["state_path"], state_path.display().to_string());
    assert!(summary["last_scan_time"].as_str().is_some());
    assert_eq!(summary["health_component"], "scanner");
    assert_eq!(summary["health_check_name"], "source_discovery");
    assert_eq!(summary["health_check_status"], "ok");
    assert_eq!(summary["active_policy_name"], Value::Null);
    assert_eq!(summary["rule_count"], 18);
    assert!(
        summary["detection_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert_eq!(summary["threshold_config"]["low"], 20);
    assert_eq!(summary["threshold_config"]["medium"], 50);
    assert_eq!(summary["threshold_config"]["high"], 70);
    assert_eq!(summary["threshold_config"]["critical"], 90);
    assert_eq!(summary["source_counts"]["codex.jsonl"], 40);
    assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);
    assert_eq!(summary["source_counts"]["copilot.copilot_process_log"], 5);
}

#[test]
fn status_distinguishes_empty_historical_native_and_mixed_logs() {
    let historical = serde_json::json!({
        "schema_version": "1.0",
        "event_id": "historical-status",
        "event_type": "activity",
        "timestamp": "2026-05-01T00:00:00Z",
        "severity": "informational",
        "risk_score": 0,
        "client": "codex",
        "session_id": "historical-session"
    })
    .to_string();
    let native_activity = native_test_event(
        "activity",
        "telltale-00000000-0000-4000-8000-000000000012",
        "2026-05-01T00:00:00.000Z",
        "informational",
        "codex",
        "native-session",
        &[],
    )
    .to_string();
    let native_health_before = native_test_event(
        "health",
        "telltale-00000000-0000-4000-8000-000000000014",
        "2026-05-01T00:00:00.000Z",
        "informational",
        "scanner",
        "scanner",
        &[],
    )
    .to_string();
    let native_detection_after_first_health = native_test_event(
        "detection",
        "telltale-00000000-0000-4000-8000-000000000015",
        "2026-05-01T00:01:00.000Z",
        "critical",
        "codex",
        "native-session",
        &["rule.status"],
    )
    .to_string();
    let native_health_last = native_test_event(
        "health",
        "telltale-00000000-0000-4000-8000-000000000016",
        "2026-05-01T00:02:00.000Z",
        "informational",
        "scanner",
        "scanner",
        &[],
    )
    .to_string();

    let run_status = |contents: &[u8]| {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");
        let state_path = temp.path().join("state.json");
        fs::write(&log_path, contents).expect("write status fixture");
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args(["status", "--log-path"])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run status");
        (temp, output)
    };

    let (_empty_temp, empty) = run_status(b"");
    assert!(!empty.status.success());
    assert!(String::from_utf8_lossy(&empty.stderr).contains("no_native_health"));

    let (_historical_temp, historical_only) = run_status(historical.as_bytes());
    assert!(historical_only.status.success());
    let historical_summary: Value =
        serde_json::from_slice(&historical_only.stdout).expect("historical status JSON");
    assert_eq!(historical_summary["status"], "historical_only");

    let (_native_temp, native_without_health) = run_status(native_activity.as_bytes());
    assert!(!native_without_health.status.success());
    assert!(String::from_utf8_lossy(&native_without_health.stderr).contains("no_native_health"));

    let mixed = format!(
        "{historical}\r\n{native_health_before}\r\n{native_detection_after_first_health}\r\n{native_health_last}"
    );
    let (_mixed_temp, mixed_status) = run_status(mixed.as_bytes());
    assert!(mixed_status.status.success());
    let mixed_summary: Value =
        serde_json::from_slice(&mixed_status.stdout).expect("mixed status JSON");
    assert_eq!(mixed_summary["status"], "ok");
    assert_eq!(mixed_summary["last_scan_time"], "2026-05-01T00:02:00.000Z");
    assert_eq!(mixed_summary["detection_count"], 0);
}

#[test]
fn status_dispatch_rejects_unknown_schema_versions_strictly() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let state_path = temp.path().join("state.json");
    fs::write(
        &log_path,
        serde_json::json!({
            "schema_version": "9.0",
            "event_id": "unknown-version",
            "event_type": "health",
            "timestamp": "2026-05-01T00:00:00Z",
            "severity": "informational",
            "risk_score": 0,
            "client": "scanner",
            "session_id": "scanner"
        })
        .to_string(),
    )
    .expect("write unknown-version log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["status", "--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run status");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown_requested_schema_version"));
}

#[test]
fn status_rejects_invalid_jsonl() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    fs::write(
        &log_path,
        [
            native_test_event(
                "health",
                "telltale-00000000-0000-4000-8000-000000000001",
                "2026-05-01T00:00:00.000Z",
                "informational",
                "scanner",
                "scanner",
                &[],
            )
            .to_string(),
            "{not-json".to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let status = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("status")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(&state_path)
        .output()
        .expect("run telltale status");

    assert!(!status.status.success());
    assert!(
        String::from_utf8_lossy(&status.stderr).contains("invalid JSONL"),
        "stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn export_rejects_invalid_jsonl() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        [
            native_test_event(
                "detection",
                "telltale-00000000-0000-4000-8000-000000000002",
                "2026-05-01T00:00:00.000Z",
                "critical",
                "codex",
                "session-a",
                &["mcp.test"],
            )
            .to_string(),
            "{not-json".to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .output()
        .expect("run telltale export");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid JSONL"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn export_filters_jsonl_by_event_fields() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        [
            native_test_event(
                "detection",
                "telltale-00000000-0000-4000-8000-000000000013",
                "2026-05-01T00:00:00.000Z",
                "critical",
                "codex",
                "session-a",
                &["mcp.test"],
            )
            .to_string(),
            native_test_event(
                "detection",
                "telltale-00000000-0000-4000-8000-000000000003",
                "2026-05-01T00:10:00.000Z",
                "high",
                "opencode",
                "session-b",
                &["secret.test"],
            )
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args([
            "--severity",
            "CRITICAL",
            "--client",
            "codex",
            "--session-id",
            "session-a",
            "--rule-id",
            "mcp.test",
            "--since",
            "2026-05-01T00:00:00Z",
            "--until",
            "2026-05-01T00:00:00Z",
        ])
        .output()
        .expect("run telltale export");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("exported json"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["session_id"], "session-a");
    assert_eq!(lines[0]["rule_ids"][0], "mcp.test");
}

#[test]
fn export_time_filters_accept_canonical_millisecond_timestamps() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        native_test_event(
            "detection",
            "telltale-00000000-0000-4000-8000-000000000004",
            "2026-05-01T00:00:00.000Z",
            "critical",
            "codex",
            "session-a",
            &["mcp.test"],
        )
        .to_string(),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "2026-05-01T00:00:00Z"])
        .args(["--until", "2026-05-01T00:00:00Z"])
        .output()
        .expect("run telltale export with canonical timestamp filters");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("exported json"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["timestamp"], "2026-05-01T00:00:00.000Z");
}

#[test]
fn export_time_filters_accept_offset_rfc3339_inputs() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        native_test_event(
            "detection",
            "telltale-00000000-0000-4000-8000-000000000005",
            "2026-05-01T10:00:00.000Z",
            "critical",
            "codex",
            "session-a",
            &["mcp.test"],
        )
        .to_string(),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "2026-05-01T12:00:00+02:00"])
        .args(["--until", "2026-05-01T12:00:00+02:00"])
        .output()
        .expect("run telltale export with offset timestamp filters");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("exported json"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["timestamp"], "2026-05-01T10:00:00.000Z");
}

#[test]
fn export_rejects_invalid_time_filters() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let since_output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "not-a-timestamp"])
        .output()
        .expect("run telltale export with invalid since");
    assert!(!since_output.status.success());
    assert!(
        String::from_utf8_lossy(&since_output.stderr)
            .contains("--since requires a valid RFC3339 timestamp")
    );

    let until_output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--until", "still-not-a-timestamp"])
        .output()
        .expect("run telltale export with invalid until");
    assert!(!until_output.status.success());
    assert!(
        String::from_utf8_lossy(&until_output.stderr)
            .contains("--until requires a valid RFC3339 timestamp")
    );
}

#[test]
fn export_rejects_inverted_time_filter_window() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "2026-05-01T00:01:00Z"])
        .args(["--until", "2026-05-01T00:00:00Z"])
        .output()
        .expect("run telltale export with inverted time window");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--since must be less than or equal to --until")
    );
}

#[test]
fn export_summary_reports_filtered_counts() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        [
            native_test_event(
                "health",
                "telltale-00000000-0000-4000-8000-000000000006",
                "2026-05-01T00:00:00.000Z",
                "informational",
                "codex,opencode",
                "scanner",
                &[],
            )
            .to_string(),
            native_test_event(
                "detection",
                "telltale-00000000-0000-4000-8000-000000000007",
                "2026-05-01T00:01:00.000Z",
                "critical",
                "codex",
                "session-a",
                &["mcp.test", "secret.test"],
            )
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--client", "codex", "--format", "summary"])
        .output()
        .expect("run telltale export summary");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("events: 1"));
    assert!(stdout.contains("  detection: 1"));
    assert!(stdout.contains("  critical: 1"));
    assert!(stdout.contains("  codex: 1"));
    assert!(stdout.contains("  mcp.test: 1"));
    assert!(stdout.contains("  secret.test: 1"));
}

#[test]
fn export_elastic_bulk_wraps_canonical_events_without_rewriting_fields() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        [
            native_test_event(
                "health",
                "telltale-00000000-0000-4000-8000-000000000008",
                "2026-05-01T00:00:00.000Z",
                "informational",
                "codex",
                "scanner",
                &[],
            )
            .to_string(),
            native_test_event(
                "detection",
                "telltale-00000000-0000-4000-8000-000000000009",
                "2026-05-01T00:01:00.000Z",
                "critical",
                "codex",
                "session-a",
                &["mcp.test"],
            )
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--severity", "critical", "--format", "elastic-bulk"])
        .output()
        .expect("run telltale elastic bulk export");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("elastic bulk json"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["index"]["_index"], "telltale-events");
    assert_eq!(
        lines[0]["index"]["_id"],
        "telltale-00000000-0000-4000-8000-000000000009"
    );
    assert_eq!(lines[1]["event_type"], "detection");
    assert_eq!(
        lines[1]["event_id"],
        "telltale-00000000-0000-4000-8000-000000000009"
    );
    assert_eq!(lines[1]["rule_ids"][0], "mcp.test");
    assert!(lines[1].get("_index").is_none());
    assert!(lines[1].get("index").is_none());
}

#[test]
fn export_correlate_emits_cross_session_event() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-a",
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "detection",
                "severity": "critical",
                "risk_score": 95,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "session-a",
                "rule_ids": ["mcp.test"],
                "categories": ["mcp_prompt_injection"],
                "tags": ["mcp"],
                "evidence": [],
            })
            .to_string(),
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-b",
                "timestamp": "2026-05-01T00:20:00Z",
                "event_type": "detection",
                "severity": "high",
                "risk_score": 80,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "session-b",
                "rule_ids": ["mcp.test", "network.test"],
                "categories": ["mcp_prompt_injection", "exfiltration"],
                "tags": ["mcp"],
                "evidence": [],
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--correlate")
        .output()
        .expect("run telltale export correlate");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("exported json"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 1);
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(
        validator.is_valid(&lines[0]),
        "correlation event failed schema validation"
    );
    assert_eq!(lines[0]["event_type"], "correlation");
    assert_eq!(lines[0]["client"], "codex");
    assert_eq!(lines[0]["session_id"], "correlation");
    assert_eq!(lines[0]["rule_ids"][0], "mcp.test");
    assert_eq!(lines[0]["categories"][0], "cross_session_correlation");
    assert_eq!(lines[0]["risk_score"], 95);
    assert_eq!(
        lines[0]["evidence"]
            .as_array()
            .expect("evidence array")
            .iter()
            .filter(|item| item["field"] == "related_detection")
            .count(),
        2
    );
}

#[test]
fn export_timeline_produces_redacted_session_timeline() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-activity-a",
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "activity",
                "severity": "low",
                "risk_score": 15,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "session-a",
                "rule_ids": [],
                "categories": [],
                "tags": [],
                "evidence": [
                    {
                        "field": "record_counts",
                        "redacted_value": "{\"tool_call\":2,\"tool_result\":1,\"user_message\":1}",
                        "hash": "sha256:activity-counts"
                    }
                ],
            })
            .to_string(),
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-a",
                "timestamp": "2026-05-01T00:01:00Z",
                "event_type": "detection",
                "severity": "critical",
                "risk_score": 95,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "session-a",
                "tool_name": "shell",
                "rule_ids": ["mcp.tool_metadata.prompt_injection"],
                "categories": ["mcp_prompt_injection"],
                "tags": ["mcp"],
                "evidence": [
                    {
                        "field": "tool_result",
                        "redacted_value": "[REDACTED]",
                        "hash": "sha256:abc123",
                        "rule_id": "mcp.tool_metadata.prompt_injection"
                    }
                ],
                "triage": {
                    "verdict": "malicious",
                    "confidence": 0.95,
                    "reason": "MCP prompt injection detected"
                },
                "response": {
                    "recommended_action": "investigate",
                    "response_playbook": "mcp_injection",
                    "investigation_summary": "Agent received injected MCP instructions",
                    "escalation": "security_review_required"
                }
            })
            .to_string(),
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-b",
                "timestamp": "2026-05-01T00:00:30Z",
                "event_type": "detection",
                "severity": "high",
                "risk_score": 80,
                "client": "codex",
                "session_id": "session-a",
                "rule_ids": ["network.controlled_test_domain.darkroast"],
                "categories": ["exfiltration"],
                "tags": ["network"],
                "evidence": []
            })
            .to_string(),
            // Different session — should not appear in session-a timeline.
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-c",
                "timestamp": "2026-05-01T00:02:00Z",
                "event_type": "detection",
                "severity": "medium",
                "risk_score": 50,
                "client": "opencode",
                "session_id": "session-b",
                "rule_ids": ["secret.test"],
                "categories": ["credential_access"],
                "tags": [],
                "evidence": []
            })
            .to_string(),
            // Same session_id on a different client — should force client disambiguation.
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-d",
                "timestamp": "2026-05-01T00:00:45Z",
                "event_type": "detection",
                "severity": "medium",
                "risk_score": 40,
                "client": "opencode",
                "agent": "opencode",
                "model": "claude-sonnet",
                "provider": "anthropic",
                "session_id": "session-a",
                "rule_ids": ["secret.test"],
                "categories": ["credential_access"],
                "tags": [],
                "evidence": []
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    // Test 1: --timeline requires --session-id.
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .output()
        .expect("run telltale export timeline without session-id");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--timeline requires --session-id"),
        "expected validation error, got: {stderr}"
    );

    // Test 2: ambiguous cross-client session ids require --client disambiguation.
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "session-a"])
        .output()
        .expect("run telltale export timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--timeline resolved 2 sessions for session_id 'session-a'; add --client to disambiguate"),
        "expected ambiguity error, got: {stderr}"
    );

    // Test 3: adding --client selects a single timeline.
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "session-a"])
        .args(["--client", "codex"])
        .output()
        .expect("run telltale export timeline with client filter");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("timeline json"))
        .collect();

    assert_eq!(lines.len(), 1, "expected one selected timeline");
    let codex_timeline = &lines[0];

    // Timeline metadata.
    assert_eq!(codex_timeline["event_type"], "timeline");
    assert_eq!(codex_timeline["session_id"], "session-a");
    assert_eq!(codex_timeline["client"], "codex");
    assert_eq!(codex_timeline["agent"], "codex");
    assert_eq!(codex_timeline["model"], "gpt-5");
    assert_eq!(codex_timeline["provider"], "openai");
    assert_eq!(codex_timeline["entry_count"], 3);
    assert_eq!(codex_timeline["detection_count"], 2);
    assert_eq!(codex_timeline["max_severity"], "critical");
    assert_eq!(codex_timeline["has_triage"], true);
    assert_eq!(codex_timeline["risk_summary"]["tool_call_count"], 2);
    assert_eq!(codex_timeline["risk_summary"]["risky_action_count"], 2);
    assert_eq!(codex_timeline["risk_summary"]["max_severity"], "critical");
    assert_eq!(codex_timeline["risk_summary"]["triage_ran"], true);
    assert!(
        codex_timeline["risk_summary"]["top_rule_ids"]
            .as_array()
            .expect("top rule ids")
            .contains(&Value::String(
                "mcp.tool_metadata.prompt_injection".to_string()
            ))
    );
    assert!(
        codex_timeline["risk_summary"]["top_rule_ids"]
            .as_array()
            .expect("top rule ids")
            .contains(&Value::String(
                "network.controlled_test_domain.darkroast".to_string()
            ))
    );
    assert!(
        codex_timeline["risk_summary"]["top_categories"]
            .as_array()
            .expect("top categories")
            .contains(&Value::String("mcp_prompt_injection".to_string()))
    );
    assert!(
        codex_timeline["risk_summary"]["top_categories"]
            .as_array()
            .expect("top categories")
            .contains(&Value::String("exfiltration".to_string()))
    );
    // Entries sorted by timestamp.
    let entries = codex_timeline["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["timestamp"], "2026-05-01T00:00:00Z");
    assert_eq!(entries[0]["event_type"], "activity");
    assert_eq!(entries[1]["timestamp"], "2026-05-01T00:00:30Z");
    assert_eq!(entries[1]["event_type"], "detection");
    assert_eq!(entries[1]["severity"], "high");
    assert_eq!(entries[2]["timestamp"], "2026-05-01T00:01:00Z");
    assert_eq!(entries[2]["event_type"], "detection");
    assert_eq!(entries[2]["severity"], "critical");
    assert_eq!(entries[2]["tool_name"], "shell");

    // Evidence is redacted: field + hash only, no redacted_value.
    let evidence = entries[2]["evidence"].as_array().expect("evidence");
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0]["field"], "tool_result");
    assert_eq!(evidence[0]["hash"], "sha256:abc123");
    assert!(
        evidence[0].get("redacted_value").is_none(),
        "redacted_value should not appear in timeline"
    );

    // Triage and response are included.
    assert_eq!(entries[2]["triage"]["verdict"], "malicious");
    assert_eq!(entries[2]["triage"]["confidence"], 0.95);
    assert_eq!(entries[2]["response"]["recommended_action"], "investigate");

    // Rule ids are preserved.
    assert_eq!(
        entries[2]["rule_ids"][0],
        "mcp.tool_metadata.prompt_injection"
    );
}

#[test]
fn export_timeline_requires_session_id() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .output()
        .expect("run telltale export timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--timeline requires --session-id"));
}

#[test]
fn export_timeline_text_requires_timeline() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--format", "timeline-text"])
        .output()
        .expect("run telltale export timeline text without timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format timeline-text requires --timeline"));
}

#[test]
fn export_timeline_rejects_multiple_session_ids() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "session-a"])
        .args(["--session-id", "session-b"])
        .output()
        .expect("run telltale export timeline with multiple session ids");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--timeline requires exactly one --session-id"));
}

#[test]
fn export_timeline_rejects_summary_format() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "schema_version": "1.0",
            "event_type": "activity",
            "session_id": "timeline-summary-session",
            "client": "codex",
            "timestamp": "2026-05-01T00:00:00Z",
            "severity": "low",
            "risk_score": 20,
            "evidence": []
        })
        .to_string(),
    )
    .expect("write log event");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "timeline-summary-session"])
        .args(["--format", "summary"])
        .output()
        .expect("run telltale export timeline summary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format summary does not support --timeline"));
}

#[test]
fn native_schema_is_closed_and_historical_schemas_remain_separate() {
    let native_schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema");
    let native_validator = validator_for(&native_schema).expect("native validator");

    let native_activity = native_test_event(
        "activity",
        "telltale-00000000-0000-4000-8000-000000000010",
        "2026-05-01T00:00:00.000Z",
        "informational",
        "codex",
        "session",
        &[],
    );
    assert!(native_validator.is_valid(&native_activity));

    for (index, (event_type, severity, rule_ids)) in [
        ("activity", "informational", &[][..]),
        ("detection", "high", &["rule.test"][..]),
        ("session_risk_summary", "medium", &["rule.test"][..]),
        ("health", "informational", &[][..]),
        ("scanner_error", "informational", &[][..]),
        ("operational_alert", "warning", &[][..]),
        ("process_chain", "low", &["rule.test"][..]),
        ("correlation", "high", &["rule.test"][..]),
    ]
    .into_iter()
    .enumerate()
    {
        let event = native_test_event(
            event_type,
            &format!("telltale-00000000-0000-4000-8000-0000000000{index:02}"),
            "2026-05-01T00:00:00.000Z",
            severity,
            "codex",
            "session",
            rule_ids,
        );
        assert!(
            native_validator.is_valid(&event),
            "native {event_type} fixture should validate: {event}"
        );
    }

    let mut forbidden_triage = native_activity.clone();
    forbidden_triage["triage"] = serde_json::json!({"verdict": "pending"});
    assert!(!native_validator.is_valid(&forbidden_triage));

    let mut activity_with_process = native_activity.clone();
    activity_with_process["process"] = serde_json::json!({
        "source_process_name": "parent",
        "target_process_name": "child",
        "source_process_inferred": true,
        "rule_name": "synthetic",
        "dedup_key": "synthetic",
        "suppression_window_seconds": 0,
        "rule_severity": "low"
    });
    assert!(!native_validator.is_valid(&activity_with_process));

    let mut activity_with_health_field = native_activity.clone();
    activity_with_health_field["component"] = serde_json::json!("scanner");
    assert!(!native_validator.is_valid(&activity_with_health_field));

    let mut nullable_native_optional = native_activity.clone();
    nullable_native_optional["agent"] = serde_json::Value::Null;
    assert!(!native_validator.is_valid(&nullable_native_optional));

    let mut unknown_property = native_activity.clone();
    unknown_property["future_field"] = serde_json::json!(true);
    assert!(!native_validator.is_valid(&unknown_property));

    let install_inventory = serde_json::to_value(
        install_inventory_event(vec![telltale_schema::event::Evidence {
            field: "install_inventory_summary".to_string(),
            redacted_value: "agents=0; installed=0; partial=0; absent=0".to_string(),
            hash: Some("0".repeat(64)),
            rule_id: None,
        }])
        .expect("install inventory event"),
    )
    .expect("serialize install inventory event");
    assert!(native_validator.is_valid(&install_inventory));

    let mut install_with_source_hash = install_inventory.clone();
    install_with_source_hash["source_path_hash"] = serde_json::json!("not-emitted");
    assert!(!native_validator.is_valid(&install_with_source_hash));

    let mut suppressed = detection_event(DetectionEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "suppressed-session".to_string(),
        source_path_hash: "synthetic-source-hash".to_string(),
        tool_name: Some("shell".to_string()),
        rule_ids: vec!["rule.suppressed".to_string()],
        categories: vec!["synthetic".to_string()],
        detection_classes: vec!["security_detection".to_string()],
        signal_types: vec!["atomic".to_string()],
        analytic_intents: vec!["alert".to_string()],
        atlas_tags: Vec::new(),
        tags: vec!["synthetic".to_string()],
        evidence: vec![telltale_schema::event::Evidence {
            field: "synthetic".to_string(),
            redacted_value: "fixture".to_string(),
            hash: None,
            rule_id: Some("rule.suppressed".to_string()),
        }],
        risk_contributions: Vec::new(),
        event_time: Some("2026-05-01T00:00:00Z".to_string()),
    })
    .expect("suppressed detection");
    suppressed.timeline_anchors = vec![telltale_schema::event::TimelineAnchor {
        entry_index: 4,
        rule_ids: vec!["rule.suppressed".to_string()],
        categories: vec!["synthetic".to_string()],
        evidence_fields: vec!["synthetic".to_string()],
    }];
    suppress_detection(
        &mut suppressed,
        &SuppressionMatch {
            name: "synthetic-suppression".to_string(),
        },
    );
    let suppressed = serde_json::to_value(suppressed).expect("serialize suppressed detection");
    assert!(native_validator.is_valid(&suppressed), "{suppressed}");
    assert!(suppressed["timeline_anchors"].is_null());
    assert!(suppressed.get("response").is_none());

    let mut legacy_id = native_test_event(
        "detection",
        "telltale-00000000-0000-4000-8000-000000000011",
        "2026-05-01T00:00:00.000Z",
        "critical",
        "codex",
        "session",
        &["rule.valid"],
    );
    legacy_id["event_id"] = serde_json::json!("adr-legacy");
    assert!(!native_validator.is_valid(&legacy_id));

    let historical_schema: Value = serde_json::from_str(include_str!(
        "../../schemas/historical/event-1.0.schema.json"
    ))
    .expect("historical schema");
    let historical_validator = validator_for(&historical_schema).expect("historical validator");
    let historical = serde_json::json!({
        "schema_version": "1.0",
        "event_id": "historical",
        "event_type": "activity",
        "timestamp": "2026-05-01T00:00:00Z",
        "severity": "informational",
        "risk_score": 0,
        "client": "codex",
        "session_id": "session",
        "rule_ids": ["Legacy Rule ID"]
    });
    assert!(historical_validator.is_valid(&historical));
    assert!(!native_validator.is_valid(&historical));

    let v2_schema: Value = serde_json::from_str(include_str!(
        "../../schemas/historical/event-2.0.schema.json"
    ))
    .expect("Event 2.0 schema");
    let v2_validator = validator_for(&v2_schema).expect("Event 2.0 validator");
    let missing_ledger = serde_json::json!({
        "schema_version": "2.0",
        "event_id": "current",
        "event_type": "activity",
        "timestamp": "2026-05-01T00:00:00Z",
        "severity": "informational",
        "risk_score": 0,
        "client": "codex",
        "session_id": "session"
    });
    assert!(!v2_validator.is_valid(&missing_ledger));

    let valid_rule_id = serde_json::json!({
        "schema_version": "2.0",
        "event_id": "valid-rule-id",
        "event_type": "detection",
        "timestamp": "2026-05-01T00:00:00Z",
        "severity": "informational",
        "risk_score": 0,
        "client": "codex",
        "session_id": "session",
        "risk_contributions": [],
        "rule_ids": ["rule.valid"]
    });
    assert!(v2_validator.is_valid(&valid_rule_id));
}

#[test]
fn export_rejects_schema_two_overflowing_contribution_ledger() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "schema_version": "2.0",
            "event_id": "overflow",
            "event_type": "detection",
            "timestamp": "2026-05-01T00:00:00Z",
            "severity": "critical",
            "risk_score": 18446744073709551615_u64,
            "client": "codex",
            "session_id": "overflow-session",
            "risk_contributions": [
                {"id": "rule.max", "type": "deterministic_rule", "points": 18446744073709551615_u64, "rationale": "max"},
                {"id": "rule.one", "type": "deterministic_rule", "points": 1, "rationale": "one"}
            ]
        })
        .to_string(),
    )
    .expect("write overflow event");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["export", "--log-path"])
        .arg(&log_path)
        .output()
        .expect("run export");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("overflowed u64"));
}

#[test]
fn export_rejects_schema_two_contribution_outside_event_scope() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "schema_version": "2.0",
            "event_id": "invalid-scope",
            "event_type": "detection",
            "timestamp": "2026-05-01T00:00:00Z",
            "severity": "low",
            "risk_score": 1,
            "client": "codex",
            "session_id": "invalid-scope-session",
            "risk_contributions": [
                {"id": "rule.missing", "type": "deterministic_rule", "points": 1, "rationale": "missing rule link"}
            ]
        })
        .to_string(),
    )
    .expect("write invalid scope event");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["export", "--log-path"])
        .arg(&log_path)
        .output()
        .expect("run export");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing from rule_ids"));
}

#[test]
fn export_rejects_schema_two_invalid_rule_ids_even_with_empty_ledger() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "schema_version": "2.0",
            "event_id": "invalid-rule-id",
            "event_type": "detection",
            "timestamp": "2026-05-01T00:00:00Z",
            "severity": "informational",
            "risk_score": 0,
            "client": "codex",
            "session_id": "invalid-rule-id-session",
            "rule_ids": ["rule"],
            "risk_contributions": []
        })
        .to_string(),
    )
    .expect("write invalid rule-id event");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["export", "--log-path"])
        .arg(&log_path)
        .output()
        .expect("run export");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("historical_schema_violation"));
}

#[test]
fn export_fails_when_legacy_invalid_rule_ids_are_promoted_to_correlation() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "legacy-a",
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "detection",
                "severity": "critical",
                "risk_score": 95,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "legacy-session-a",
                "rule_ids": ["rule"],
                "categories": ["test"],
                "evidence": []
            }),
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "legacy-b",
                "timestamp": "2026-05-01T00:20:00Z",
                "event_type": "detection",
                "severity": "high",
                "risk_score": 80,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "legacy-session-b",
                "rule_ids": ["rule"],
                "categories": ["test"],
                "evidence": []
            }),
        ]
        .into_iter()
        .map(|event| event.to_string())
        .collect::<Vec<_>>()
        .join("\n"),
    )
    .expect("write legacy events");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["export", "--log-path"])
        .arg(&log_path)
        .arg("--correlate")
        .output()
        .expect("run correlation export");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rule id rule is not canonical"));
}

#[test]
fn export_timeline_rejects_elastic_bulk_format() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "timeline-elastic-session"])
        .args(["--format", "elastic-bulk"])
        .output()
        .expect("run telltale export timeline elastic bulk");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format elastic-bulk does not support --timeline"));
}

#[test]
fn export_timeline_rejects_correlate() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "schema_version": "1.0",
            "event_type": "detection",
            "event_id": "adr-detection-correlate",
            "session_id": "timeline-correlate-session",
            "client": "codex",
            "timestamp": "2026-05-01T00:00:00Z",
            "severity": "high",
            "risk_score": 80,
            "rule_ids": ["secret.env.read"],
            "categories": ["secret_access"],
            "evidence": []
        })
        .to_string(),
    )
    .expect("write log event");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "timeline-correlate-session"])
        .arg("--correlate")
        .output()
        .expect("run telltale export timeline correlate");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--correlate does not support --timeline"));
}

#[test]
fn export_source_root_requires_timeline() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--source-root")
        .arg(temp.path())
        .output()
        .expect("run telltale export source-root without timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--source-root requires --timeline"));
}

#[test]
fn export_source_root_rejects_summary_format() {
    let temp = tempdir().expect("tempdir");
    let source_dir = temp.path().join("codex/sessions/2026/05");
    fs::create_dir_all(&source_dir).expect("create fixture source dir");
    fs::write(
        source_dir.join("source-backed-summary.jsonl"),
        serde_json::json!({
            "type": "user",
            "timestamp": "2026-05-01T00:01:00Z",
            "session_id": "source-summary-session",
            "agent": "codex",
            "model": "gpt-5",
            "provider": "openai",
            "content": "Summarize the repository status"
        })
        .to_string(),
    )
    .expect("write source fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-summary-session"])
        .args(["--format", "summary"])
        .output()
        .expect("run telltale export source-root timeline summary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format summary does not support --timeline"));
}

#[test]
fn export_source_root_rejects_jsonl_only_filters() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let severity_output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--severity", "critical"])
        .output()
        .expect("run telltale export source-root with severity filter");
    assert!(!severity_output.status.success());
    assert!(
        String::from_utf8_lossy(&severity_output.stderr)
            .contains("--source-root does not support --severity filters")
    );

    let rule_output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--rule-id", "secret.env.read"])
        .output()
        .expect("run telltale export source-root with rule filter");
    assert!(!rule_output.status.success());
    assert!(
        String::from_utf8_lossy(&rule_output.stderr)
            .contains("--source-root does not support --rule-id filters")
    );

    let time_output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--since", "2026-05-01T00:00:00Z"])
        .output()
        .expect("run telltale export source-root with time filter");
    assert!(!time_output.status.success());
    assert!(
        String::from_utf8_lossy(&time_output.stderr)
            .contains("--source-root does not support --since/--until filters")
    );

    let correlate_output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .arg("--correlate")
        .output()
        .expect("run telltale export source-root with correlate");
    assert!(!correlate_output.status.success());
    assert!(
        String::from_utf8_lossy(&correlate_output.stderr)
            .contains("--correlate does not support --timeline")
    );
}

#[test]
fn export_source_root_rejects_unknown_client_filter() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--client", "unknown-agent"])
        .output()
        .expect("run telltale export source-root with unknown client");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--source-root does not support unknown client 'unknown-agent'"),
        "{stderr}"
    );
    assert!(stderr.contains("codex"), "{stderr}");
}

#[test]
fn export_timeline_text_produces_human_readable_session_timeline() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-activity-text",
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "activity",
                "severity": "low",
                "risk_score": 15,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "text-session",
                "rule_ids": [],
                "categories": [],
                "tags": [],
                "evidence": [
                    {
                        "field": "record_counts",
                        "redacted_value": "{\"tool_call\":1,\"tool_result\":1,\"user_message\":1}",
                        "hash": "sha256:activity-counts"
                    }
                ]
            })
            .to_string(),
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-text",
                "timestamp": "2026-05-01T00:00:30Z",
                "event_type": "detection",
                "severity": "critical",
                "risk_score": 95,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "text-session",
                "tool_name": "shell",
                "rule_ids": ["mcp.tool_metadata.prompt_injection"],
                "categories": ["mcp_prompt_injection"],
                "tags": ["mcp"],
                "evidence": [
                    {
                        "field": "tool_result",
                        "redacted_value": "[REDACTED]",
                        "hash": "sha256:abc123",
                        "rule_id": "mcp.tool_metadata.prompt_injection"
                    }
                ],
                "triage": {
                    "verdict": "malicious",
                    "confidence": 0.95,
                    "reason": "MCP prompt injection detected"
                },
                "response": {
                    "recommended_action": "investigate",
                    "response_playbook": "mcp_injection",
                    "investigation_summary": "Agent received injected MCP instructions",
                    "escalation": "security_review_required"
                }
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "text-session"])
        .args(["--format", "timeline-text"])
        .output()
        .expect("run telltale export timeline text");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Timeline text-session (codex)"));
    assert!(stdout.contains("Agent: codex | Model: gpt-5 | Provider: openai"));
    assert!(stdout.contains("Entries: 2 | Detections: 1 | Max severity: critical | Triage: yes"));
    assert!(
        stdout.contains("Risk: tool_calls=1 risky_actions=1 max_severity=critical triage_ran=yes")
    );
    assert!(stdout.contains("[0] 2026-05-01T00:00:00Z low activity"));
    assert!(stdout.contains("[1] 2026-05-01T00:00:30Z critical detection tool=shell"));
    assert!(stdout.contains("Rules: mcp.tool_metadata.prompt_injection"));
    assert!(stdout.contains("Categories: mcp_prompt_injection"));
    assert!(stdout.contains("Evidence: tool_result hash=sha256:abc123"));
    assert!(
        stdout.contains("Triage: malicious confidence=0.95 reason=MCP prompt injection detected")
    );
    assert!(stdout.contains("Recommended action: investigate"));
    assert!(stdout.contains("Playbook: mcp_injection"));
    assert!(stdout.contains("Summary: Agent received injected MCP instructions"));
    assert!(!stdout.contains("\"event_type\""));
}

#[test]
fn export_timeline_from_source_root_uses_parsed_session_records() {
    let temp = tempdir().expect("tempdir");
    let source_dir = temp.path().join("codex/sessions/2026/05");
    fs::create_dir_all(&source_dir).expect("create fixture source dir");
    fs::write(
        source_dir.join("source-backed-timeline.jsonl"),
        [
            serde_json::json!({
                "type": "tool_result",
                "timestamp": "2026-05-01T00:03:00Z",
                "session_id": "source-session",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "tool_name": "shell",
                "content": "read /home/alice/project/.env and returned ghp_1234567890abcdefghijklmnop"
            })
            .to_string(),
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-05-01T00:01:00Z",
                "session_id": "source-session",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "content": "Summarize the repository status"
            })
            .to_string(),
            serde_json::json!({
                "type": "tool_call",
                "timestamp": "2026-05-01T00:02:00Z",
                "session_id": "source-session",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "tool_name": "shell",
                "arguments": {"cmd": "cat /home/alice/project/.env"}
            })
            .to_string(),
            serde_json::json!({
                "type": "assistant",
                "timestamp": "2026-05-01T00:04:00Z",
                "session_id": "other-session",
                "agent": "codex",
                "content": "This different session should not export"
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write source fixture");
    let opencode_dir = temp
        .path()
        .join("opencode/storage/message/session-source-session");
    fs::create_dir_all(&opencode_dir).expect("create opencode fixture dir");
    fs::write(
        opencode_dir.join("messages.json"),
        serde_json::json!([
            {
                "type": "assistant",
                "timestamp": "2026-05-01T00:01:30Z",
                "session_id": "source-session",
                "agent": "opencode",
                "model": "claude-sonnet",
                "provider": "anthropic",
                "content": "OpenCode session sharing the same id should require client disambiguation"
            }
        ])
        .to_string(),
    )
    .expect("write opencode source fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .output()
        .expect("run telltale source-backed timeline export");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--timeline resolved 2 sessions for session_id 'source-session'; add --client to disambiguate"),
        "expected ambiguity error, got: {stderr}"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--client", "codex"])
        .output()
        .expect("run telltale source-backed timeline export with client filter");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("timeline json"))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    let timeline = &lines[0];
    assert_eq!(timeline["event_type"], "timeline");
    assert_eq!(timeline["session_id"], "source-session");
    assert_eq!(timeline["client"], "codex");
    assert_eq!(timeline["agent"], "codex");
    assert_eq!(timeline["model"], "gpt-5");
    assert_eq!(timeline["provider"], "openai");
    assert_eq!(timeline["entry_count"], 3);
    assert_eq!(timeline["detection_count"], 1);
    assert_eq!(timeline["max_severity"], "medium");
    assert_eq!(timeline["has_triage"], false);
    assert_eq!(timeline["risk_summary"]["tool_call_count"], 1);
    assert_eq!(timeline["risk_summary"]["risky_action_count"], 1);
    assert_eq!(timeline["risk_summary"]["max_severity"], "medium");
    assert_eq!(timeline["risk_summary"]["triage_ran"], false);
    assert!(
        timeline["risk_summary"]["top_rule_ids"]
            .as_array()
            .expect("top rule ids")
            .contains(&Value::String("secret.env.read".to_string()))
    );
    assert!(
        timeline["risk_summary"]["top_categories"]
            .as_array()
            .expect("top categories")
            .contains(&Value::String("secret_access".to_string()))
    );
    let entries = timeline["entries"].as_array().expect("entries array");
    assert_eq!(entries[0]["event_type"], "user_message");
    assert_eq!(entries[0]["timestamp"], "2026-05-01T00:01:00Z");
    assert_eq!(entries[1]["event_type"], "tool_call");
    assert_eq!(entries[1]["tool_name"], "shell");
    assert_eq!(entries[2]["event_type"], "tool_result");
    assert_eq!(entries[2]["tool_name"], "shell");

    let arguments = entries[1]["evidence"]
        .as_array()
        .expect("tool call evidence")
        .iter()
        .find(|item| item["field"] == "arguments")
        .expect("arguments evidence");
    assert_eq!(
        arguments["redacted_value"],
        "{\"cmd\":\"cat /home/alice/project/[sensitive-path]\"}"
    );
    assert!(arguments["hash"].as_str().expect("hash").len() >= 64);

    let result = entries[2]["evidence"]
        .as_array()
        .expect("tool result evidence")
        .iter()
        .find(|item| item["field"] == "tool_result")
        .expect("tool result evidence");
    let redacted_result = result["redacted_value"].as_str().expect("redacted value");
    assert!(redacted_result.contains("[sensitive-path]"));
    assert!(redacted_result.contains("[redacted-secret]"));
    assert!(!redacted_result.contains("ghp_1234567890abcdefghijklmnop"));
}

#[test]
fn export_timeline_text_from_source_root_includes_risk_summary() {
    let temp = tempdir().expect("tempdir");
    let source_dir = temp.path().join("codex/sessions/2026/05");
    fs::create_dir_all(&source_dir).expect("create fixture source dir");
    fs::write(
        source_dir.join("source-backed-timeline-text.jsonl"),
        [
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-05-01T00:01:00Z",
                "session_id": "source-text-session",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "content": "Inspect secrets exposure"
            })
            .to_string(),
            serde_json::json!({
                "type": "tool_call",
                "timestamp": "2026-05-01T00:02:00Z",
                "session_id": "source-text-session",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "tool_name": "shell",
                "arguments": {"cmd": "cat /home/alice/project/.env"}
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write source fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-text-session"])
        .args(["--format", "timeline-text"])
        .output()
        .expect("run source-backed timeline text export");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Timeline source-text-session (codex)"));
    assert!(stdout.contains("Entries: 2 | Detections: 1 | Max severity: low | Triage: no"));
    assert!(stdout.contains(
        "Risk: tool_calls=1 risky_actions=1 max_severity=low triage_ran=no top_rules=secret.env.read top_categories=secret_access"
    ));
}
