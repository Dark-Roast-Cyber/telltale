//! Request-only pilot: real native payload wrapped by the plugin, through the
//! integrated process; explicit no-op, real client identity, detect-only gate.
use crate::hooks_common as common;
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn request() -> Value {
    json!({
        "protocol": "telltale.opencode-v2.v1", "hook_event": "execute.before",
        "occurrence": "tth-occ-request-one", "cwd": "/synthetic",
        "event": {"sessionID": "synthetic-session", "messageID": "message-one",
                  "agent": "build", "id": "outer-id", "tool": "shell",
                  "input": {"command": "echo TTH_E2E_DENY_MARKER"}}
    })
}

fn invoke(root: &std::path::Path, payload: Value, detect: bool) -> Value {
    let config = common::config_root(
        root,
        "hooks:\n  mode: enforce\n  evaluator:\n    enabled: false\n",
    );
    std::fs::create_dir_all(config.join("rules.d")).unwrap();
    std::fs::copy(common::marker_rules(), config.join("rules.d/markers.yaml")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_telltale"));
    cmd.args(["hooks", "opencode", "hook", "--json-reply", "--config-dir"])
        .arg(config)
        .env("TELLTALE_HOOKS_STATE_DIR", root.join("state"))
        .env("TELLTALE_HOOKS_EVALUATOR", "0");
    if detect {
        cmd.arg("--detect-only");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn opencode_framed_deny_keeps_real_identity_and_does_not_fabricate_settlement() {
    let dir = tempfile::tempdir().unwrap();
    let reply = invoke(dir.path(), request(), false);
    assert_eq!(reply["protocol"], "telltale.hook-reply.v1");
    assert_eq!(reply["mode"], "enforce");
    assert_eq!(reply["output"]["decision"], "deny");
    let records: Vec<Value> = std::fs::read_to_string(dir.path().join("state/telemetry.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["harness"]["name"], "opencode");
    assert_eq!(records[0]["action"]["tool_use_id"], "tth-occ-request-one");
    assert_eq!(records[0]["telltale"][0]["record"]["client"], "opencode");
    assert_eq!(
        records[0]["telltale"][0]["record"]["source_id"],
        "opencode.hooks"
    );
    assert_eq!(records[0]["decision"]["returned"], true);
}

#[test]
fn opencode_detect_only_is_an_explicit_noop_and_records_not_returned() {
    let dir = tempfile::tempdir().unwrap();
    let reply = invoke(dir.path(), request(), true);
    assert_eq!(
        reply,
        json!({"protocol":"telltale.hook-reply.v1","mode":"detect_only","output":null})
    );
    let records: Vec<Value> = std::fs::read_to_string(dir.path().join("state/telemetry.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(records[0]["decision"]["verdict"], "deny");
    assert_eq!(records[0]["decision"]["returned"], false);
}

#[test]
fn opencode_benign_call_returns_explicit_noop() {
    let dir = tempfile::tempdir().unwrap();
    let mut payload = request();
    payload["event"]["input"]["command"] = json!("echo benign");
    assert_eq!(
        invoke(dir.path(), payload, false),
        json!({"protocol":"telltale.hook-reply.v1","mode":"enforce","output":null})
    );
}

#[test]
fn opencode_captured_nested_calls_use_occurrences_not_reused_native_ids() {
    use telltale_core::hooks::harness::{Harness, Parsed};
    use telltale_core::hooks::runtime::Event;
    let capture =
        std::fs::read_to_string(common::fixtures("opencode/2.2.5").join("mcp-codemode.jsonl"))
            .unwrap();
    let events: Vec<Value> = capture
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|line: &Value| line["event"] == "tool.execute.before")
        .collect();
    let mut outer = request();
    outer["event"] = events[2]["payload"].clone();
    outer["occurrence"] = json!("tth-occ-outer");
    let mut inner = request();
    inner["event"] = events[3]["payload"].clone();
    inner["occurrence"] = json!("tth-occ-inner");
    assert_eq!(outer["event"]["id"], inner["event"]["id"]);
    let Parsed::Event(ctx, Event::ToolRequested(outer_call)) =
        Harness::OpenCode.parse(outer.to_string().as_bytes())
    else {
        panic!()
    };
    let Parsed::Event(_, Event::ToolRequested(inner_call)) =
        Harness::OpenCode.parse(inner.to_string().as_bytes())
    else {
        panic!()
    };
    assert_eq!(ctx.agent_id, None);
    assert_eq!(ctx.agent_type.as_deref(), Some("build"));
    assert_eq!(ctx.prompt_id, None);
    assert_eq!(outer_call.tool_use_id.as_deref(), Some("tth-occ-outer"));
    assert_eq!(inner_call.tool_use_id.as_deref(), Some("tth-occ-inner"));
    assert_eq!(inner_call.tool_name, "tthmock_echo");
    inner["hook_event"] = json!("execute.after");
    assert!(matches!(
        Harness::OpenCode.parse(inner.to_string().as_bytes()),
        Parsed::Invalid(_)
    ));
}
