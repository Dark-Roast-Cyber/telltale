//! What every hook entry point answers when it cannot use a payload. No exit
//! code means the same on every harness: exit 1 blocks a Copilot `preToolUse`
//! but runs the call on Codex and is a non-blocking error on Claude Code, and
//! exit 2 on a `Stop` is a prompt to continue. So a tool call is answered on
//! stdout, and a payload that names no event gets each harness's own block.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

const ENTRY_POINTS: [&str; 3] = ["claude-code", "codex-cli", "copilot-cli"];
const ON_ERROR_DENY: &str = "on_error = \"deny\"\n";
const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// The installed binary with no reachable default config or state: exit code and stdout.
fn hook(entry_point: &str, settings: &str, payload: &[u8]) -> (i32, String) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, settings).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command.arg("hooks");
    for var in ["HOME", "APPDATA", "LOCALAPPDATA"] {
        command.env(var, "/nonexistent-home-for-test");
    }
    let mut child = command
        .args([entry_point, "hook"])
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env("TELLTALE_HOOKS_CONFIG", &config)
        .env("TELLTALE_HOOKS_STATE_DIR", dir.path())
        .env("TELLTALE_HOOKS_EVALUATOR", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(payload).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
    )
}

fn oversized(prefix: &[u8]) -> Vec<u8> {
    let mut payload = prefix.to_vec();
    payload.resize(MAX_PAYLOAD_BYTES + 64, b'a');
    payload
}

/// The permission decision in stdout: `claude` and `codex-cli` nest it in
/// `hookSpecificOutput`, Copilot's own form is flat.
fn decision(stdout: &str, nested: bool) -> String {
    let output: Value = serde_json::from_str(stdout.trim()).unwrap();
    let decision = if nested {
        &output["hookSpecificOutput"]["permissionDecision"]
    } else {
        &output["permissionDecision"]
    };
    decision.as_str().unwrap_or_default().to_owned()
}

#[test]
fn a_damaged_event_that_is_not_pre_execution_never_exits_2() {
    let cut_stop = br#"{"session_id":"s","turn_id":"t","cwd":"/w","hook_event_name":"Stop","last_assistant_message":"do"#;
    let payloads: Vec<Vec<u8>> = vec![
        cut_stop.to_vec(),
        oversized(cut_stop),
        // Mistyped: valid JSON that the adapters cannot read as this event.
        br#"{"session_id":123,"turn_id":"t","cwd":"/w","hook_event_name":"Stop"}"#.to_vec(),
        br#"{"session_id":"s","cwd":"/w","hook_event_name":"SubagentStop","agent_id":"#.to_vec(),
        br#"{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Bash","tool_input":{"command":"ls"#.to_vec(),
        br#"{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"hi"#.to_vec(),
        br#"{"hook_event_name" : "SessionStart","session_id":"s","source":"#.to_vec(),
        // Copilot names this one in `hookName`.
        br#"{"sessionId":"s","timestamp":1,"hookName":"permissionRequest","toolName":"#.to_vec(),
    ];
    for entry_point in ENTRY_POINTS {
        for payload in &payloads {
            let head = String::from_utf8_lossy(&payload[..payload.len().min(90)]).into_owned();
            assert_eq!(
                hook(entry_point, ON_ERROR_DENY, payload),
                (1, String::new()),
                "{entry_point}: {head}"
            );
        }
    }
}

#[test]
fn a_payload_that_names_no_event_blocks_only_when_failing_closed() {
    let payloads: [&[u8]; 8] = [
        b"not json",
        br#"{"session_id":"s","#,
        // The name is cut, of the wrong type, or empty.
        br#"{"session_id":"s","hook_event_name":"Sto"#,
        br#"{"hook_event_name":7,"session_id":"s"#,
        br#"{"hook_event_name":"","session_id":"s"#,
        // Agent-controlled text that only looks like a name: neither may turn
        // the exit into a non-blocking one.
        br#"{"session_id":"s","tool_input":{"hook_event_name":"Stop"},"cwd":"/w"#,
        br#"{"cwd":"\"hook_event_name\":\"Stop\"","session_id":"s"#,
        br#"{"cwd":"hook_event_name","session_id":"s"#,
    ];
    for entry_point in ENTRY_POINTS {
        for payload in payloads {
            let head = String::from_utf8_lossy(payload).into_owned();
            let (code, stdout) = hook(entry_point, ON_ERROR_DENY, payload);
            match entry_point {
                // Claude Code blocks on exit 2 and needs no event to do so.
                "claude-code" => assert_eq!((code, stdout.as_str()), (2, ""), "{head}"),
                // Exit 2 on a Stop would be a prompt to continue, without limit.
                "codex-cli" => {
                    assert_eq!(code, 0, "{head}");
                    assert_eq!(decision(&stdout, true), "deny", "{head}");
                }
                // Copilot blocks a preToolUse on exit 1, and other events continue.
                _ => assert_eq!((code, stdout.as_str()), (1, ""), "{head}"),
            }
            assert_eq!(
                hook(entry_point, "", payload),
                (1, String::new()),
                "{entry_point}: {head}"
            );
        }
    }
}

#[test]
fn a_damaged_pre_tool_use_is_answered_on_stdout() {
    let cut = br#"{"session_id":"s","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"hook_event_name":"Stop","command":"ls"#;
    for payload in [cut.to_vec(), oversized(cut)] {
        for (entry_point, nested) in [
            ("claude-code", true),
            ("codex-cli", true),
            ("copilot-cli", false),
        ] {
            let (code, stdout) = hook(entry_point, ON_ERROR_DENY, &payload);
            assert_eq!(code, 0, "{entry_point}");
            assert_eq!(decision(&stdout, nested), "deny", "{entry_point}");
        }
    }
}

/// A `PreToolUse` that parses but has no `tool_name`. Codex runs the call on
/// exit 1, so with `on_error` allow or ask this used to be a silent fail-open.
#[test]
fn an_unusable_pre_tool_use_gets_the_stricter_policy_on_every_entry_point() {
    let named = br#"{"session_id":"s","turn_id":"t","transcript_path":"/t","cwd":"/w","hook_event_name":"PreToolUse","tool_use_id":"c","tool_input":{"command":"ls"}}"#;
    // A camelCase Copilot payload names nothing; `timestamp` routes it from the
    // Claude Code entry point, which then answers in Copilot's own form.
    let camel = br#"{"timestamp":1,"cwd":"/w","toolName":"bash","toolArgs":{"command":"ls"}}"#;
    let entries: [(&str, &[u8], bool, bool); 5] = [
        ("claude-code", named, true, true),
        ("codex-cli", named, true, false),
        ("copilot-cli", named, false, true),
        ("copilot-cli", camel, false, true),
        ("claude-code", camel, false, true),
    ];
    for (entry_point, payload, nested, can_ask) in entries {
        let ask = if can_ask { "ask" } else { "deny" };
        for (settings, expected) in [
            ("", ask), // default: on_unevaluable = "ask"
            ("on_unevaluable = \"ask\"\n", ask),
            ("on_unevaluable = \"deny\"\n", "deny"),
            ("on_error = \"deny\"\non_unevaluable = \"allow\"\n", "deny"),
            ("on_error = \"ask\"\non_unevaluable = \"allow\"\n", ask),
        ] {
            let (code, stdout) = hook(entry_point, settings, payload);
            assert_eq!(code, 0, "{entry_point}: {settings}");
            assert_eq!(
                decision(&stdout, nested),
                expected,
                "{entry_point}: {settings}"
            );
        }
        // Only an operator's explicit allow on both lets the call through, and
        // that is an empty success, never an `allow` decision.
        assert_eq!(
            hook(entry_point, "on_unevaluable = \"allow\"\n", payload),
            (0, String::new()),
            "{entry_point}"
        );
    }
}
