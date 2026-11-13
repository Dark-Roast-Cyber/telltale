//! The `hooks` feature as an external embedder sees it: present when enabled,
//! absent from the graph otherwise (checked by scripts/embedding-contract-check,
//! which also asserts that `telltale-core` enables it by default).
#![cfg(feature = "hooks")]

use serde_json::json;
use telltale_core::hooks::claude_code;
use telltale_core::hooks::config::Config;
use telltale_core::hooks::runtime::Runtime;

fn decide(command: &str) -> Option<serde_json::Value> {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        state_dir: Some(dir.path().join("state")),
        telemetry_path: Some(dir.path().join("telemetry.jsonl")),
        ..Config::default()
    };
    let payload = json!({
        "session_id": "synthetic-session-0001",
        "transcript_path": "/home/synthetic/transcript.jsonl",
        "cwd": "/home/synthetic/work",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "toolu_synthetic_1"
    });
    let input = claude_code::parse(&serde_json::to_vec(&payload).unwrap()).unwrap();
    let (ctx, event) = claude_code::to_event(&input).unwrap();
    let mut runtime = Runtime::new(config);
    let response = runtime.handle(&ctx, event);
    claude_code::render(&ctx.hook_event, &response)
}

#[test]
fn hooks_evaluate_through_the_embedding_facade() {
    assert!(decide("ls -la").is_none());
    let output = decide("rm -f ~/.claude/settings.json").expect("a verdict");
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
}
