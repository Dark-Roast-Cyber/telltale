//! Native hook contract tests: replay payloads captured from a real Claude Code
//! 2.1.318 session (tests/fixtures/claude-code/2.1.318/README.md) and check the
//! adapter, outcome correlation and telemetry against what actually happened.

use crate::common;

use common::{Harness, fixture};
use telltale_core::ActionRecordV1;

#[test]
fn captured_lifecycle_replays_without_interference() {
    let mut h = Harness::new();
    for payload in fixture("tool-lifecycle-subagent.jsonl") {
        let output = h.send(&payload);
        assert!(
            output.is_none(),
            "benign capture got an opinion: {output:?}"
        );
    }
    let telemetry = h.telemetry();
    assert!(
        telemetry
            .iter()
            .all(|r| r["schema"] == "telltale_hooks.record.v1")
    );
    assert!(
        telemetry.iter().all(|r| r["kind"] != "error"),
        "{telemetry:#?}"
    );

    // Every requested call (4 Bash + Read + Agent, one Bash inside the subagent).
    let decisions = h.records("decision");
    assert_eq!(decisions.len(), 6);
    assert!(
        decisions
            .iter()
            .all(|d| d["decision"]["verdict"] == "allow")
    );
    assert!(decisions.iter().all(|d| d["decision"]["returned"] == false));

    // What actually happened, as the harness reported it.
    let result = |id: &str| {
        h.outcome_for(id)["outcome"]["result"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(result("toolu_01EukvSvDQbJ3Ryyd5unokFu"), "completed"); // echo > out.txt
    assert_eq!(result("toolu_01AJSarRMJ3xJUphJhZmCWs7"), "completed"); // Read
    assert_eq!(result("toolu_01E7ktr1poXdhup3VnwLvNTn"), "failed"); // ls nonexistent
    assert_eq!(result("toolu_01EpekcPm8T37vLRsLK5TDee"), "completed"); // Agent
    assert_eq!(result("toolu_01Vh6C2XY26zwcBSpA76wUZy"), "completed"); // subagent pwd

    // `rm` hit a harness deny rule: PreToolUse fired, no PostToolUse, settled by the batch.
    let rm = h.outcome_for("toolu_015vZCDECduaASwB3W8azo75");
    assert_eq!(rm["outcome"]["result"], "not_executed");
    assert_eq!(rm["outcome"]["established_by"], "PostToolBatch");
    assert_eq!(rm["outcome"]["enforcement"], "not_returned");

    // The subagent's own call keeps its agent identity.
    let sub = h
        .records("decision")
        .into_iter()
        .find(|d| d["session"]["agent_id"] == "a71adbed9b5ebe8c5")
        .expect("subagent decision");
    assert_eq!(sub["session"]["agent_type"], "general-purpose");
    let lifecycle: Vec<_> = h
        .records("lifecycle")
        .into_iter()
        .map(|r| r["lifecycle"]["event"].as_str().unwrap_or("").to_owned())
        .collect();
    for event in [
        "session_start",
        "user_prompt",
        "subagent_start",
        "subagent_stop",
        "session_end",
    ] {
        assert!(
            lifecycle.iter().any(|e| e == event),
            "missing {event}: {lifecycle:?}"
        );
    }
    let end = h
        .records("lifecycle")
        .into_iter()
        .find(|r| r["lifecycle"]["event"] == "session_end")
        .unwrap();
    assert_eq!(end["lifecycle"]["unsettled_calls"], 0);
    assert_eq!(end["lifecycle"]["subagents"], 1);
}

#[test]
fn telemetry_never_carries_prompt_or_raw_input() {
    let mut h = Harness::new();
    for payload in fixture("tool-lifecycle-subagent.jsonl") {
        h.send(&payload);
    }
    let text = std::fs::read_to_string(h.telemetry_path()).unwrap();
    for needle in [
        "automated hook-contract capture",
        "echo hello",
        "/home/synthetic/run",
    ] {
        assert!(!text.contains(needle), "telemetry leaked {needle:?}");
    }
}

#[test]
fn headless_permission_prompt_is_recorded_and_call_not_executed() {
    let mut h = Harness::new();
    for payload in fixture("headless-default-permission-request.jsonl") {
        assert!(h.send(&payload).is_none());
    }
    let prompt = h
        .records("lifecycle")
        .into_iter()
        .find(|r| r["lifecycle"]["event"] == "permission_prompt")
        .expect("permission prompt lifecycle");
    assert_eq!(prompt["action"]["tool_name"], "Bash");
    let decision = h.decision_for("toolu_01QEzB5FCBBXNixZYYWVP9Pi");
    // The prompt and the decision describe the same call (no tool_use_id on PermissionRequest).
    assert_eq!(
        prompt["action"]["input_sha256"],
        decision["action"]["input_sha256"]
    );
    let outcome = h.outcome_for("toolu_01QEzB5FCBBXNixZYYWVP9Pi");
    assert_eq!(outcome["outcome"]["result"], "not_executed");
}

#[test]
fn forwarded_telltale_records_pass_strict_validation() {
    let mut h = Harness::new();
    h.pre_bash("toolu_t1", "cat ~/.aws/credentials");
    let decision = h.decision_for("toolu_t1");
    let actions = decision["telltale"].as_array().unwrap();
    assert!(!actions.is_empty());
    for action in actions {
        let bytes = serde_json::to_vec(&action["record"]).unwrap();
        let record = ActionRecordV1::from_json(&bytes).expect("strict ActionRecordV1");
        assert_eq!(action["delivery_key"], record.delivery_key());
        assert_eq!(record.client, "claude");
        assert_eq!(record.stage.as_str(), "requested");
        assert_eq!(record.session_id.as_deref(), Some(h.session_id.as_str()));
    }
}

/// MCP tool calls (`mcp__<server>__<tool>`, payload field `mcp_server`) fire
/// PreToolUse/PostToolUse like built-ins; the model first loads the deferred
/// tool through `ToolSearch`. Captured from a disposable stdio server
/// (scripts/hooks/harness/mcp-canary-server.js).
#[test]
fn mcp_tool_lifecycle_replays_and_arguments_are_evaluated() {
    let mut h = Harness::new();
    for payload in fixture("mcp-tool-benign.jsonl") {
        assert!(h.send(&payload).is_none());
    }
    let tools: Vec<_> = h
        .records("decision")
        .iter()
        .map(|d| d["action"]["tool_name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(tools, ["ToolSearch", "mcp__tth-canary__touch_canary"]);
    assert_eq!(
        h.outcome_for("toolu_01YVGKkdLG6F9Ct2rJCF6EPL")["outcome"]["result"],
        "completed"
    );

    // The same flow with a marker in a tool argument: evaluated as
    // `arguments`, denied, and settled by the batch as honored.
    let markers = common::marker_rules();
    let mut h = Harness::with(|c| c.telltale.rules = vec![markers]);
    let mut denied = None;
    for payload in fixture("mcp-tool-denied.jsonl") {
        let output = h.send(&payload);
        if payload["tool_name"] == "mcp__tth-canary__touch_canary"
            && payload["hook_event_name"] == "PreToolUse"
        {
            assert_eq!(payload["mcp_server"]["name"], "tth-canary");
            denied = output;
        } else {
            assert!(output.is_none(), "{output:?}");
        }
    }
    assert_eq!(common::verdict(&denied), Some("deny"));
    let outcome = h.outcome_for("toolu_01PSnP1FZApYeuNwoVbdtvkU");
    assert_eq!(outcome["outcome"]["result"], "not_executed");
    assert_eq!(outcome["outcome"]["enforcement"], "honored");
    assert_eq!(outcome["outcome"]["established_by"], "PostToolBatch");
}
