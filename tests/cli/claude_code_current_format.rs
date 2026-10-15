//! Current Claude Code (2.1.x) transcripts through the scan binary. The
//! records are synthetic but keep the shapes Claude Code and the Claude
//! desktop app write today: bookkeeping records between turns, thinking
//! blocks, nested tool inputs, large authored file bodies, and text-array tool
//! results. Commands and outputs are inert data, never executed.

use super::*;

const SESSION: &str = "11111111-2222-4333-8444-555555555555";
const SECRET: &str = "SYNTHETIC-CLAUDE-OUTPUT-SECRET";
const RULES: &str = r#"
version: 1
description: Synthetic Claude Code coverage.
defaults: { case_insensitive: false, enabled: true }
modifiers: []
rules:
  - id: synthetic.claude.command
    title: Synthetic Claude command marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 70
    detection:
      selection:
        command: 'synthetic-claude-command-marker'
      condition: selection
    explanation: Synthetic test.
  - id: synthetic.claude.result
    title: Synthetic Claude result marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 60
    detection:
      selection:
        tool_result: 'synthetic-claude-result-marker'
      condition: selection
    explanation: Synthetic test.
  - id: synthetic.claude.path
    title: Synthetic Claude write path marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 50
    detection:
      selection:
        file_path: 'synthetic-claude-path-marker'
      condition: selection
    explanation: Synthetic test.
"#;

fn record(kind: &str, uuid: &str, body: Value) -> String {
    let mut value = serde_json::json!({
        "type": kind,
        "uuid": uuid,
        "sessionId": SESSION,
        "timestamp": "2026-10-14T19:50:00.000Z",
        "cwd": "C:\\Users\\synthetic\\repo",
        "version": "2.1.295",
        "entrypoint": "claude-desktop",
        "userType": "external",
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(body.as_object().unwrap().clone());
    value.to_string()
}

fn assistant(uuid: &str, content: Value) -> String {
    record(
        "assistant",
        uuid,
        serde_json::json!({"message": {"role": "assistant", "model": "claude-synthetic", "content": content}}),
    )
}

fn user(uuid: &str, content: Value) -> String {
    record(
        "user",
        uuid,
        serde_json::json!({"message": {"role": "user", "content": content}}),
    )
}

fn transcript() -> Vec<String> {
    let body = format!("{}\nsynthetic file body\n", "line ".repeat(2_000));
    vec![
        record(
            "queue-operation",
            "q1",
            serde_json::json!({"operation": "enqueue"}),
        ),
        user("u1", serde_json::json!("Please audit the synthetic repo.")),
        record(
            "attachment",
            "a1",
            serde_json::json!({"attachment": {"type": "hook_additional_context", "content": ["synthetic"]}}),
        ),
        assistant(
            "m1",
            serde_json::json!([
                {"type": "thinking", "thinking": "Synthetic private reasoning.", "signature": "sig"},
                {"type": "text", "text": "Planning the audit."},
                {"type": "tool_use", "id": "toolu_plan", "name": "mcp__ccd_turn__update_plan",
                 "input": {"items": [{"content": "Look around", "status": "in_progress"}], "scope": "first_task"}}
            ]),
        ),
        user(
            "u2",
            serde_json::json!([{"type": "tool_result", "tool_use_id": "toolu_plan", "content": "Plan shown."}]),
        ),
        assistant(
            "m2",
            serde_json::json!([
                {"type": "tool_use", "id": "toolu_ps", "name": "PowerShell",
                 "input": {"command": "Write-Output synthetic-claude-command-marker", "description": "Synthetic"}}
            ]),
        ),
        user(
            "u3",
            serde_json::json!([{"type": "tool_result", "tool_use_id": "toolu_ps",
                "content": [{"type": "text", "text": format!("token={SECRET}")},
                            {"type": "text", "text": "synthetic-claude-result-marker"}]}]),
        ),
        assistant(
            "m3",
            serde_json::json!([
                {"type": "tool_use", "id": "toolu_write", "name": "Write",
                 "input": {"file_path": "C:\\Users\\synthetic\\repo\\synthetic-claude-path-marker.txt", "content": body}}
            ]),
        ),
        // A search pattern is not authored text: over 4 KB it is quarantined
        // by itself, and the records after it still map.
        assistant(
            "m4",
            serde_json::json!([
                {"type": "tool_use", "id": "toolu_grep", "name": "Grep",
                 "input": {"pattern": format!("{SECRET}{}", "p".repeat(5_000))}}
            ]),
        ),
        record(
            "last-prompt",
            "l1",
            serde_json::json!({"lastPrompt": "synthetic"}),
        ),
        record(
            "custom-title",
            "t1",
            serde_json::json!({"customTitle": "synthetic"}),
        ),
        record(
            "agent-name",
            "n1",
            serde_json::json!({"agentName": "synthetic"}),
        ),
        record("atis-latch", "x1", serde_json::json!({"latched": true})),
        record(
            "file-history-snapshot",
            "f1",
            serde_json::json!({"snapshot": {"trackedFileBackups": {}}}),
        ),
        assistant(
            "m5",
            serde_json::json!([{"type": "text", "text": "Synthetic audit complete."}]),
        ),
    ]
}

#[test]
fn current_claude_code_transcript_is_parsed_and_detected() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("home");
    let project = root.join(".claude/projects/C--Users-synthetic-repo");
    fs::create_dir_all(&project).unwrap();
    fs::write(
        project.join(format!("{SESSION}.jsonl")),
        transcript().join("\n") + "\n",
    )
    .unwrap();
    let rules = temp.path().join("rules.yaml");
    fs::write(&rules, RULES).unwrap();
    let log = temp.path().join("events.jsonl");

    let result = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .env_clear()
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--client",
            "claude",
            "--no-local-config",
            "--emit-activity",
            "--install-inventory-disabled",
            "--no-default-rules",
            "--root",
        ])
        .arg(&root)
        .arg("--rules")
        .arg(&rules)
        .arg("--log-path")
        .arg(&log)
        .arg("--state-path")
        .arg(temp.path().join("state.json"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
    let processing = &summary["source_processing"];
    assert_eq!(processing["parse_success_source_count"], 1, "{summary}");
    assert_eq!(processing["parse_error_source_count"], 0, "{summary}");
    assert_eq!(processing["selected_source_coverage"], "partial");
    assert_eq!(
        processing["quarantined_units"],
        serde_json::json!([{
            "source": "claude.projects",
            "session_id": SESSION,
            "native_id": "m4",
            "source_sequence": 8,
            "code": "unbounded_value",
            "bound_category": "ToolArguments",
            "bound_dimension": "StringBytes",
        }])
    );

    let events = fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    for event in &events {
        assert!(event_schema_validator().is_valid(event), "{event}");
    }
    let detected = |rule: &str| {
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
    };
    assert_eq!(detected("synthetic.claude.command"), 1);
    assert_eq!(detected("synthetic.claude.result"), 1);
    assert_eq!(detected("synthetic.claude.path"), 1);
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "activity" && event["session_id"] == SESSION),
        "the session reports activity"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event_type"] == "scanner_error")
            .count(),
        1,
        "one content-free quarantine marker"
    );
    for bytes in [
        fs::read(&log).unwrap(),
        serde_json::to_vec(&summary).unwrap(),
    ] {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(SECRET));
        assert!(!text.contains("Synthetic private reasoning"));
    }
}

#[test]
fn claude_config_dir_relocated_transcripts_are_discovered() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let config_dir = temp.path().join("relocated-claude");
    let project = config_dir.join("projects/C--Users-synthetic-repo");
    fs::create_dir_all(&project).unwrap();
    fs::write(
        project.join(format!("{SESSION}.jsonl")),
        transcript().join("\n") + "\n",
    )
    .unwrap();
    let rules = temp.path().join("rules.yaml");
    fs::write(&rules, RULES).unwrap();

    let scan = |config_dir: Option<&std::path::Path>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
        command
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .current_dir(temp.path())
            .args([
                "scan",
                "--once",
                "--client",
                "claude",
                "--no-local-config",
                "--dry-run",
                "--install-inventory-disabled",
                "--no-default-rules",
                "--rules",
            ])
            .arg(&rules)
            .arg("--log-path")
            .arg(temp.path().join("events.jsonl"))
            .arg("--state-path")
            .arg(temp.path().join("state.json"));
        if let Some(config_dir) = config_dir {
            command.env("CLAUDE_CONFIG_DIR", config_dir);
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice::<Value>(&result.stdout).unwrap()
    };

    let unset = scan(None);
    assert_eq!(
        unset["source_processing"]["selected_source_count"], 0,
        "{unset}"
    );
    let relocated = scan(Some(&config_dir));
    let processing = &relocated["source_processing"];
    assert_eq!(processing["selected_source_count"], 1, "{relocated}");
    assert_eq!(processing["parse_success_source_count"], 1, "{relocated}");
}
