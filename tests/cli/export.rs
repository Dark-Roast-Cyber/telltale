use super::*;

#[test]
fn export_help_mentions_client_for_ambiguous_timeline_session_ids() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["export", "--help"])
        .output()
        .expect("run adr export help");

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
fn top_level_version_prints_package_version_for_both_aliases() {
    for (name, path) in [
        ("telltale", env!("CARGO_BIN_EXE_telltale")),
        ("adr", env!("CARGO_BIN_EXE_adr")),
    ] {
        let output = Command::new(path)
            .arg("--version")
            .output()
            .unwrap_or_else(|error| panic!("run {name} --version: {error}"));
        assert!(
            output.status.success(),
            "{name} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.trim(),
            format!(
                "{name} {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("ADR_GIT_HASH")
            )
        );
        assert!(
            output.stderr.is_empty(),
            "{name} --version should not write stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn top_level_help_uses_invocation_name_for_both_aliases() {
    for (name, path) in [
        ("telltale", env!("CARGO_BIN_EXE_telltale")),
        ("adr", env!("CARGO_BIN_EXE_adr")),
    ] {
        let output = Command::new(path)
            .arg("--help")
            .output()
            .unwrap_or_else(|error| panic!("run {name} --help: {error}"));
        assert!(
            output.status.success(),
            "{name} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.starts_with(&format!(
            "Telltale detection layer for AI coding agent sessions\n\nUsage: {name}"
        )));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn parse_errors_use_invocation_name_without_deprecation_warning() {
    for (name, path) in [
        ("telltale", env!("CARGO_BIN_EXE_telltale")),
        ("adr", env!("CARGO_BIN_EXE_adr")),
    ] {
        let output = Command::new(path)
            .arg("--not-a-real-option")
            .output()
            .unwrap_or_else(|error| panic!("run {name} with invalid option: {error}"));
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("Usage: {name}")),
            "stderr: {stderr}"
        );
        assert!(
            !stderr.to_lowercase().contains("deprecat"),
            "stderr: {stderr}"
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn executable_aliases_have_identical_safe_rule_listing_behavior() {
    let args = ["rules", "list", "--no-local-config"];
    let telltale = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(args)
        .output()
        .expect("run telltale rules list");
    let adr = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(args)
        .output()
        .expect("run adr rules list");

    assert_eq!(telltale.status, adr.status);
    assert_eq!(telltale.stdout, adr.stdout);
    assert_eq!(telltale.stderr, adr.stderr);
}

#[test]
fn status_reports_latest_health_event() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let scan = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr scan");
    assert!(
        scan.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&scan.stderr)
    );

    let status = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("status")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(&state_path)
        .output()
        .expect("run adr status");
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
    assert_eq!(summary["threshold_config"]["triage"], 70);
    assert_eq!(summary["threshold_config"]["alert"], 90);
    assert_eq!(summary["source_counts"]["codex.jsonl"], 40);
    assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);
    assert_eq!(summary["source_counts"]["copilot.copilot_process_log"], 5);
}

#[test]
fn status_rejects_invalid_jsonl() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "health",
                "severity": "informational",
                "client": "scanner",
                "session_id": "scanner",
                "rule_ids": [],
            })
            .to_string(),
            "{not-json".to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let status = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("status")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(&state_path)
        .output()
        .expect("run adr status");

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
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "detection",
                "severity": "critical",
                "client": "codex",
                "session_id": "session-a",
                "rule_ids": ["mcp.test"],
            })
            .to_string(),
            "{not-json".to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .output()
        .expect("run adr export");

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
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "detection",
                "severity": "critical",
                "client": "codex",
                "session_id": "session-a",
                "rule_ids": ["mcp.test"],
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-05-01T00:10:00Z",
                "event_type": "detection",
                "severity": "high",
                "client": "opencode",
                "session_id": "session-b",
                "rule_ids": ["secret.test"],
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr export");
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
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "timestamp": "2026-05-01T00:00:00.000Z",
            "event_type": "detection",
            "severity": "critical",
            "client": "codex",
            "session_id": "session-a",
            "rule_ids": ["mcp.test"],
        })
        .to_string(),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "2026-05-01T00:00:00Z"])
        .args(["--until", "2026-05-01T00:00:00Z"])
        .output()
        .expect("run adr export with canonical timestamp filters");
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
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "timestamp": "2026-05-01T10:00:00.000Z",
            "event_type": "detection",
            "severity": "critical",
            "client": "codex",
            "session_id": "session-a",
            "rule_ids": ["mcp.test"],
        })
        .to_string(),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "2026-05-01T12:00:00+02:00"])
        .args(["--until", "2026-05-01T12:00:00+02:00"])
        .output()
        .expect("run adr export with offset timestamp filters");
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
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let since_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "not-a-timestamp"])
        .output()
        .expect("run adr export with invalid since");
    assert!(!since_output.status.success());
    assert!(
        String::from_utf8_lossy(&since_output.stderr)
            .contains("--since requires a valid RFC3339 timestamp")
    );

    let until_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--until", "still-not-a-timestamp"])
        .output()
        .expect("run adr export with invalid until");
    assert!(!until_output.status.success());
    assert!(
        String::from_utf8_lossy(&until_output.stderr)
            .contains("--until requires a valid RFC3339 timestamp")
    );
}

#[test]
fn export_rejects_inverted_time_filter_window() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "2026-05-01T00:01:00Z"])
        .args(["--until", "2026-05-01T00:00:00Z"])
        .output()
        .expect("run adr export with inverted time window");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--since must be less than or equal to --until")
    );
}

#[test]
fn export_summary_reports_filtered_counts() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "health",
                "severity": "informational",
                "client": "codex,opencode",
                "session_id": "scanner",
                "rule_ids": [],
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-05-01T00:01:00Z",
                "event_type": "detection",
                "severity": "critical",
                "client": "codex",
                "session_id": "session-a",
                "rule_ids": ["mcp.test", "secret.test"],
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--client", "codex", "--format", "summary"])
        .output()
        .expect("run adr export summary");
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
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "timestamp": "2026-05-01T00:00:00Z",
                "event_id": "event-a",
                "event_type": "health",
                "severity": "informational",
                "client": "codex",
                "session_id": "scanner",
                "rule_ids": [],
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-05-01T00:01:00Z",
                "event_id": "event-b",
                "event_type": "detection",
                "severity": "critical",
                "client": "codex",
                "session_id": "session-a",
                "rule_ids": ["mcp.test"],
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--severity", "critical", "--format", "elastic-bulk"])
        .output()
        .expect("run adr elastic bulk export");
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
    assert_eq!(lines[0]["index"]["_index"], "adr-events");
    assert_eq!(lines[0]["index"]["_id"], "event-b");
    assert_eq!(lines[1]["event_type"], "detection");
    assert_eq!(lines[1]["event_id"], "event-b");
    assert_eq!(lines[1]["rule_ids"][0], "mcp.test");
    assert!(lines[1].get("_index").is_none());
    assert!(lines[1].get("index").is_none());
}

#[test]
fn export_correlate_emits_cross_session_event() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--correlate")
        .output()
        .expect("run adr export correlate");
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
    let log_path = temp.path().join("adr-events.jsonl");
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
                    "recommended_action": "investigate_session",
                    "response_playbook": "mcp_injection",
                    "investigation_summary": "Agent received injected MCP instructions"
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
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .output()
        .expect("run adr export timeline without session-id");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--timeline requires --session-id"),
        "expected validation error, got: {stderr}"
    );

    // Test 2: ambiguous cross-client session ids require --client disambiguation.
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "session-a"])
        .output()
        .expect("run adr export timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--timeline resolved 2 sessions for session_id 'session-a'; add --client to disambiguate"),
        "expected ambiguity error, got: {stderr}"
    );

    // Test 3: adding --client selects a single timeline.
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "session-a"])
        .args(["--client", "codex"])
        .output()
        .expect("run adr export timeline with client filter");
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
    assert_eq!(
        entries[2]["response"]["recommended_action"],
        "investigate_session"
    );

    // Rule ids are preserved.
    assert_eq!(
        entries[2]["rule_ids"][0],
        "mcp.tool_metadata.prompt_injection"
    );
}

#[test]
fn export_timeline_requires_session_id() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .output()
        .expect("run adr export timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--timeline requires --session-id"));
}

#[test]
fn export_timeline_text_requires_timeline() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--format", "timeline-text"])
        .output()
        .expect("run adr export timeline text without timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format timeline-text requires --timeline"));
}

#[test]
fn export_timeline_rejects_multiple_session_ids() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "session-a"])
        .args(["--session-id", "session-b"])
        .output()
        .expect("run adr export timeline with multiple session ids");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--timeline requires exactly one --session-id"));
}

#[test]
fn export_timeline_rejects_summary_format() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "timeline-summary-session"])
        .args(["--format", "summary"])
        .output()
        .expect("run adr export timeline summary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format summary does not support --timeline"));
}

#[test]
fn export_timeline_rejects_elastic_bulk_format() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "timeline-elastic-session"])
        .args(["--format", "elastic-bulk"])
        .output()
        .expect("run adr export timeline elastic bulk");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format elastic-bulk does not support --timeline"));
}

#[test]
fn export_timeline_rejects_correlate() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "timeline-correlate-session"])
        .arg("--correlate")
        .output()
        .expect("run adr export timeline correlate");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--correlate does not support --timeline"));
}

#[test]
fn export_source_root_requires_timeline() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--source-root")
        .arg(temp.path())
        .output()
        .expect("run adr export source-root without timeline");
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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-summary-session"])
        .args(["--format", "summary"])
        .output()
        .expect("run adr export source-root timeline summary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format summary does not support --timeline"));
}

#[test]
fn export_source_root_rejects_jsonl_only_filters() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let severity_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--severity", "critical"])
        .output()
        .expect("run adr export source-root with severity filter");
    assert!(!severity_output.status.success());
    assert!(
        String::from_utf8_lossy(&severity_output.stderr)
            .contains("--source-root does not support --severity filters")
    );

    let rule_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--rule-id", "secret.env.read"])
        .output()
        .expect("run adr export source-root with rule filter");
    assert!(!rule_output.status.success());
    assert!(
        String::from_utf8_lossy(&rule_output.stderr)
            .contains("--source-root does not support --rule-id filters")
    );

    let time_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--since", "2026-05-01T00:00:00Z"])
        .output()
        .expect("run adr export source-root with time filter");
    assert!(!time_output.status.success());
    assert!(
        String::from_utf8_lossy(&time_output.stderr)
            .contains("--source-root does not support --since/--until filters")
    );

    let correlate_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .arg("--correlate")
        .output()
        .expect("run adr export source-root with correlate");
    assert!(!correlate_output.status.success());
    assert!(
        String::from_utf8_lossy(&correlate_output.stderr)
            .contains("--correlate does not support --timeline")
    );
}

#[test]
fn export_source_root_rejects_unknown_client_filter() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--client", "unknown-agent"])
        .output()
        .expect("run adr export source-root with unknown client");
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
    let log_path = temp.path().join("adr-events.jsonl");
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
                    "recommended_action": "investigate_session",
                    "response_playbook": "mcp_injection",
                    "investigation_summary": "Agent received injected MCP instructions"
                }
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "text-session"])
        .args(["--format", "timeline-text"])
        .output()
        .expect("run adr export timeline text");
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
    assert!(stdout.contains("Recommended action: investigate_session"));
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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .output()
        .expect("run adr source-backed timeline export");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--timeline resolved 2 sessions for session_id 'source-session'; add --client to disambiguate"),
        "expected ambiguity error, got: {stderr}"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--client", "codex"])
        .output()
        .expect("run adr source-backed timeline export with client filter");
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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
