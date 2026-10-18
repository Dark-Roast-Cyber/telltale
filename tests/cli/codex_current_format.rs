//! Current Codex rollouts through the scan binary. The records are synthetic
//! but keep the shapes Codex writes on Windows today: a paginated parent
//! rollout with code-mode `exec` calls, text-array tool output, completed
//! command items with long output, bookkeeping records, an unmapped MCP item
//! and a parent's copy of a subagent item; and a forked rollout whose ordinals
//! continue from its parent's history. Commands are inert data, never run.

use super::*;

const PARENT: &str = "01a10000-0000-7000-8000-00000000000a";
const FORK: &str = "01a10000-0000-7000-8000-00000000000b";
const SUBAGENT: &str = "01a10000-0000-7000-8000-00000000000c";
const SECRET: &str = "SYNTHETIC-CODEX-OUTPUT-SECRET";
const RULES: &str = r#"
version: 1
description: Synthetic Codex coverage.
defaults: { case_insensitive: false, enabled: true }
modifiers: []
rules:
  - id: synthetic.codex.exec_result
    title: Synthetic Codex exec result marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 60
    detection:
      selection:
        tool_result: 'synthetic-codex-exec-result-marker'
      condition: selection
    explanation: Synthetic test.
  - id: synthetic.codex.command_output
    title: Synthetic Codex command output marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 50
    detection:
      selection:
        tool_result: 'synthetic-codex-command-output-marker'
      condition: selection
    explanation: Synthetic test.
"#;

fn rollout(first: u64, records: Vec<Value>) -> String {
    records
        .into_iter()
        .enumerate()
        .map(|(offset, mut record)| {
            record["ordinal"] = serde_json::json!(first + offset as u64);
            record["timestamp"] = serde_json::json!("2026-10-14T19:50:00.000Z");
            record.to_string() + "\n"
        })
        .collect()
}

fn event(payload: Value) -> Value {
    serde_json::json!({"type": "event_msg", "payload": payload})
}

fn item(thread: &str, item: Value) -> Value {
    event(
        serde_json::json!({"type": "item_completed", "thread_id": thread, "turn_id": "turn-a", "item": item}),
    )
}

fn response(payload: Value) -> Value {
    serde_json::json!({"type": "response_item", "payload": payload})
}

fn parent() -> String {
    let script = format!(
        "const out = await tools.shell({{command: 'Get-ChildItem'}});\n{}",
        "// synthetic padding\n".repeat(400)
    );
    let exec_output = format!(
        "token={SECRET}\nsynthetic-codex-exec-result-marker\n{}",
        "row ".repeat(1_500)
    );
    let command_output = format!(
        "{}\nsynthetic-codex-command-output-marker\n",
        "Mode LastWriteTime Length Name\n".repeat(200)
    );
    rollout(
        0,
        vec![
            serde_json::json!({"type": "session_meta", "payload": {
                "id": PARENT, "session_id": PARENT, "history_mode": "paginated",
                "source": "exec", "cwd": "C:\\Users\\synthetic\\repo",
                "model_provider": "openai"}}),
            event(
                serde_json::json!({"type": "thread_settings_applied", "thread_id": PARENT,
                "thread_settings": {"model": "synthetic", "approval_policy": "never"}}),
            ),
            event(serde_json::json!({"type": "task_started", "turn_id": "turn-a"})),
            response(serde_json::json!({"type": "message", "role": "user",
                "content": [{"type": "input_text", "text": "Please audit the synthetic repo."}]})),
            response(
                serde_json::json!({"type": "custom_tool_call", "call_id": "call-exec",
                "name": "exec", "input": script, "status": "completed"}),
            ),
            response(
                serde_json::json!({"type": "custom_tool_call_output", "call_id": "call-exec",
                "output": [{"type": "input_text", "text": "Script completed"},
                           {"type": "input_text", "text": exec_output}]}),
            ),
            item(
                PARENT,
                serde_json::json!({"type": "CommandExecution", "id": "call-cmd",
                    "command": ["powershell.exe", "-Command", "Get-ChildItem"],
                    "cwd": "C:\\Users\\synthetic\\repo", "status": "completed",
                    "exit_code": 0, "aggregated_output": command_output}),
            ),
            item(
                PARENT,
                serde_json::json!({"type": "McpToolCall", "id": "mcp-a", "server": "synthetic",
                    "tool": "search", "arguments": {"query": SECRET}, "status": "completed"}),
            ),
            item(
                SUBAGENT,
                serde_json::json!({"type": "CommandExecution", "id": "call-sub",
                    "command": ["powershell.exe", "-Command", SECRET], "status": "completed"}),
            ),
            serde_json::json!({"type": "token_usage_record", "payload": {
                "session_id": PARENT, "thread_id": PARENT, "turn_id": "turn-a",
                "usage": {"input_tokens": 10, "output_tokens": 2}}}),
            serde_json::json!({"type": "compacted", "payload": {"message": SECRET,
                "replacement_history": []}}),
            event(
                serde_json::json!({"type": "turn_aborted", "turn_id": "turn-a",
                "reason": "interrupted"}),
            ),
            event(serde_json::json!({"type": "task_complete", "turn_id": "turn-a"})),
        ],
    )
}

fn fork() -> String {
    rollout(
        13,
        vec![
            serde_json::json!({"type": "session_meta", "payload": {
                "id": FORK, "session_id": PARENT, "history_mode": "paginated",
                "history_base": {"thread_id": PARENT, "end_ordinal_exclusive": 13,
                                 "end_byte_offset": 4096}}}),
            response(serde_json::json!({"type": "message", "role": "user",
                "content": [{"type": "input_text", "text": "Continue in the fork."}]})),
            response(serde_json::json!({"type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": "Fork done."}]})),
        ],
    )
}

#[test]
fn current_codex_rollouts_are_parsed_and_detected() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("stores");
    let day = root.join("codex/sessions/2026/10/14");
    fs::create_dir_all(&day).unwrap();
    fs::write(day.join(format!("rollout-parent-{PARENT}.jsonl")), parent()).unwrap();
    fs::write(
        day.join(format!("rollout-fork-{PARENT}_{FORK}.jsonl")),
        fork(),
    )
    .unwrap();
    let rules = temp.path().join("rules.yaml");
    fs::write(&rules, RULES).unwrap();
    let log = temp.path().join("events.jsonl");

    let result = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .env_clear()
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("XDG_STATE_HOME", temp.path().join("state-home"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--client",
            "codex",
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
    assert_eq!(
        processing["selected_source_coverage"], "partial",
        "{summary}"
    );
    assert_eq!(processing["parse_success_source_count"], 2, "{summary}");
    assert_eq!(processing["parse_error_source_count"], 0, "{summary}");
    assert_eq!(processing["failures"], serde_json::json!([]), "{summary}");
    let quarantined = processing["quarantined_units"]
        .as_array()
        .unwrap()
        .iter()
        .map(|unit| {
            (
                unit["session_id"].as_str().unwrap(),
                unit["native_id"].as_str().unwrap(),
                unit["source_sequence"].as_u64().unwrap(),
                unit["code"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        quarantined,
        [
            (PARENT, "mcp-a", 7, "unsupported_completed_item"),
            (PARENT, "call-sub", 8, "foreign_thread_item"),
        ],
        "{summary}"
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
    assert_eq!(detected("synthetic.codex.exec_result"), 1);
    assert_eq!(detected("synthetic.codex.command_output"), 1);
    for session in [PARENT, FORK] {
        assert!(
            events
                .iter()
                .any(|event| event["event_type"] == "activity" && event["session_id"] == session),
            "{session} reports activity"
        );
    }
    assert!(
        !events.iter().any(|event| event["session_id"] == SUBAGENT),
        "a parent's copy of a subagent item is never attributed"
    );
    for bytes in [
        fs::read(&log).unwrap(),
        serde_json::to_vec(&summary).unwrap(),
    ] {
        assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    }
}
