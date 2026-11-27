//! What every hook entry point answers when it cannot use a payload. No exit
//! code means the same on every harness: exit 1 blocks a Copilot `preToolUse`
//! but runs the call on Codex and is a non-blocking error on Claude Code, and
//! exit 2 on a `Stop` is a prompt to continue. So a tool call is answered on
//! stdout, and a payload that names no event gets each harness's own block.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

const ENTRY_POINTS: [&str; 3] = ["claude-code", "codex-cli", "copilot-cli"];
/// The command-hook entry points and the OpenCode plugin's, which answers
/// through its exit status.
const ALL_ENTRY_POINTS: [&str; 4] = ["claude-code", "codex-cli", "copilot-cli", "opencode"];
const ON_ERROR_DENY: &str = "  on_error: deny\n";
const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// The installed binary, enforcing, with no reachable default config or
/// state: exit code and stdout.
fn hook(entry_point: &str, settings: &str, payload: &[u8]) -> (i32, String) {
    let (code, stdout, _) = hook_with(
        entry_point,
        &format!("  mode: enforce\n{settings}"),
        payload,
    );
    (code, stdout)
}

/// The installed binary on exactly `settings`, the body of the `hooks:`
/// section: exit code, stdout and telemetry.
fn hook_with(entry_point: &str, settings: &str, payload: &[u8]) -> (i32, String, String) {
    hook_env(entry_point, settings, payload, &[])
}

/// [`hook_with`] with more environment for the hook process.
fn hook_env(
    entry_point: &str,
    settings: &str,
    payload: &[u8],
    env: &[(&str, &str)],
) -> (i32, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    std::fs::create_dir_all(config.join("settings.d")).unwrap();
    std::fs::write(
        config.join("settings.d").join("hooks.yaml"),
        format!("version: 1\nhooks:\n{settings}"),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command.arg("hooks");
    for var in ["HOME", "APPDATA", "LOCALAPPDATA"] {
        command.env(var, "/nonexistent-home-for-test");
    }
    let mut child = command
        .args([entry_point, "hook", "--config-dir"])
        .arg(&config)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env("TELLTALE_HOOKS_STATE_DIR", dir.path())
        .env("TELLTALE_HOOKS_EVALUATOR", "0")
        .envs(env.iter().copied())
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
        std::fs::read_to_string(dir.path().join("telemetry.jsonl")).unwrap_or_default(),
    )
}

/// Detect-only cannot block: on every entry point, under the strictest
/// failure policies, no payload gets a decision on stdout or a non-zero exit
/// (which alone blocks a Copilot `preToolUse`). What could not be read is in
/// telemetry instead.
#[test]
fn detect_only_answers_nothing_whatever_the_payload() {
    let strict = "  on_error: deny\n  on_unevaluable: deny\n";
    let hollow = br#"{"session_id":"s","transcript_path":"/t","cwd":"/w","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"mcp__x__y","tool_input":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}}},"tool_use_id":"toolu_h"}"#;
    let payloads: [(&str, Vec<u8>); 9] = [
        ("garbage", b"not json".to_vec()),
        ("empty", Vec::new()),
        (
            "truncated call",
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls""#
                .to_vec(),
        ),
        (
            "call without fields",
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#.to_vec(),
        ),
        (
            "copilot truncated call",
            br#"{"toolName":"bash","toolArgs":"#.to_vec(),
        ),
        ("nameless", br#"{"tool_input":{"command":"ls"}}"#.to_vec()),
        (
            "damaged stop",
            br#"{"hook_event_name":"Stop","session_id":7}"#.to_vec(),
        ),
        ("no scalar value", hollow.to_vec()),
        (
            "oversized call",
            oversized(
                br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":""#,
            ),
        ),
    ];
    for mode in ["", "  mode: observe\n", "  mode: detect\n"] {
        for entry_point in ENTRY_POINTS {
            for (name, payload) in &payloads {
                let settings = format!("{mode}{strict}");
                let (code, stdout, telemetry) = hook_with(entry_point, &settings, payload);
                assert_eq!(
                    (code, stdout.as_str()),
                    (0, ""),
                    "{entry_point}, {name}, {mode:?}"
                );
                assert!(
                    telemetry.contains("\"kind\":\"error\"")
                        || telemetry.contains("\"kind\":\"decision\""),
                    "{entry_point}, {name}: nothing recorded: {telemetry}"
                );
            }
        }
    }
    // The control: enforcing, the same policies answer a call that cannot be read.
    let (code, stdout) = hook("claude-code", strict, &payloads[2].1);
    assert_eq!(code, 0);
    assert_eq!(decision(&stdout, true), "deny");
}

/// Stdin that is not valid UTF-8 is an unreadable payload. Observe mode
/// records it and returns nothing: empty stdout, exit 0, an error record, and
/// no decision. The same bytes while enforcing are a deny, so an empty
/// observe answer is this path and not a payload the hook ignored.
#[test]
fn detect_only_answers_nothing_when_stdin_is_not_utf8() {
    let payload =
        b"{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_use_id\":\"toolu_utf8\",\"tool_input\":{\"command\":\"ls\xff\"}}";
    let (code, stdout) = hook("claude-code", ON_ERROR_DENY, payload);
    assert_eq!(code, 0);
    assert_eq!(decision(&stdout, true), "deny");
    let settings = "  mode: observe\n  on_error: deny\n  on_unevaluable: deny\n";
    for entry_point in ENTRY_POINTS {
        let (code, stdout, telemetry) = hook_with(entry_point, settings, payload);
        assert_eq!((code, stdout.as_str()), (0, ""), "{entry_point}");
        let records: Vec<Value> = telemetry
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(
            records.iter().any(|record| {
                record["kind"] == "error" && record["error_code"] == "payload_invalid_json"
            }),
            "{entry_point}: {telemetry}"
        );
        assert!(
            records
                .iter()
                .all(|record| record.get("decision").is_none()),
            "{entry_point}: {telemetry}"
        );
    }
}

/// A directory descriptor makes the real binary's stdin read fail on Unix.
#[cfg(unix)]
fn stdin_read_failure(entry_point: &str, settings: &str) -> (i32, String, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    std::fs::create_dir_all(config.join("settings.d")).unwrap();
    std::fs::write(
        config.join("settings.d").join("hooks.yaml"),
        format!("version: 1\nhooks:\n{settings}"),
    )
    .unwrap();
    let stdin_dir = dir.path().join("not-a-stream");
    std::fs::create_dir(&stdin_dir).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command.arg("hooks");
    for var in ["HOME", "APPDATA", "LOCALAPPDATA"] {
        command.env(var, "/nonexistent-home-for-test");
    }
    let child = command
        .args([entry_point, "hook", "--config-dir"])
        .arg(&config)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env("TELLTALE_HOOKS_STATE_DIR", dir.path())
        .env("TELLTALE_HOOKS_EVALUATOR", "0")
        .stdin(Stdio::from(std::fs::File::open(&stdin_dir).unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        std::fs::read_to_string(dir.path().join("telemetry.jsonl")).unwrap_or_default(),
    )
}

#[cfg(unix)]
#[test]
fn a_stdin_read_failure_in_enforce_mode_blocks_and_records_the_failure() {
    for entry_point in ALL_ENTRY_POINTS {
        let (code, stdout, stderr, telemetry) =
            stdin_read_failure(entry_point, "  mode: enforce\n  on_error: deny\n");
        assert_nameless_block(entry_point, (code, &stdout), &stderr);
        assert!(stderr.contains("cannot read hook payload"), "{stderr}");
        assert_eq!(telemetry.lines().count(), 1, "{telemetry}");
        let record = telltale_core::HooksRecordV1::from_json(telemetry.as_bytes()).unwrap();
        assert_eq!(record.kind, telltale_core::HooksRecordKind::Error);
        assert_eq!(record.error_code.as_deref(), Some("payload_read_failed"));
        assert!(record.decision.is_none());
    }
}

/// Observe mode still records the read error, but returns no opinion.
#[cfg(unix)]
#[test]
fn a_stdin_read_failure_in_observe_mode_exits_with_no_opinion() {
    for entry_point in ALL_ENTRY_POINTS {
        let (code, stdout, stderr, telemetry) = stdin_read_failure(
            entry_point,
            "  mode: observe\n  on_error: deny\n  on_unevaluable: deny\n",
        );
        assert_eq!((code, stdout.as_str()), (0, ""), "{stderr}");
        assert!(stderr.contains("cannot read hook payload"), "{stderr}");
        assert_eq!(telemetry.lines().count(), 1, "{telemetry}");
        let record = telltale_core::HooksRecordV1::from_json(telemetry.as_bytes()).unwrap();
        assert_eq!(record.kind, telltale_core::HooksRecordKind::Error);
        assert_eq!(record.error_code.as_deref(), Some("payload_read_failed"));
        assert!(record.decision.is_none());
    }
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
            for (settings, _) in POLICIES {
                let (code, stdout, _) = hook_with(entry_point, settings, payload);
                assert_eq!(
                    (code, stdout.as_str()),
                    (1, ""),
                    "{entry_point}, {settings:?}: {head}"
                );
            }
        }
    }
}

/// The failure policies a damaged payload is tried under, as the body of the
/// `hooks:` section, and whether each blocks a payload that names no event.
/// The default is `on_unevaluable: ask`, and such a payload cannot be asked
/// about, so only an explicit allow on both lets it through. A configuration
/// that says `enforce` but does not load blocks.
const POLICIES: [(&str, bool); 8] = [
    ("  mode: enforce\n", true),
    ("  mode: enforce\n  on_unevaluable: deny\n", true),
    ("  mode: enforce\n  on_error: deny\n", true),
    (
        "  mode: enforce\n  on_error: ask\n  on_unevaluable: allow\n",
        true,
    ),
    (
        "  mode: enforce\n  on_error: deny\n  on_unevaluable: allow\n",
        true,
    ),
    ("  mode: enforce\n  bogus: 1\n", true),
    ("  mode: enforce\n  on_unevaluable: allow\n", false),
    (
        "  mode: enforce\n  on_error: allow\n  on_unevaluable: allow\n",
        false,
    ),
];

/// Each entry point's block for a payload that names no event, which could be
/// a tool call: one that needs no event to block it.
fn assert_nameless_block(entry_point: &str, (code, stdout): (i32, &str), context: &str) {
    match entry_point {
        // Claude Code blocks on exit 2 and needs no event to do so.
        "claude-code" => assert_eq!((code, stdout), (2, ""), "{context}"),
        // Exit 2 on a Stop would be a prompt to continue, without limit; a
        // deny on stdout is inert there. Codex ignores a deny without a reason.
        "codex-cli" => {
            assert_eq!(code, 0, "{context}");
            assert_eq!(decision(stdout, true), "deny", "{context}");
            let output: Value = serde_json::from_str(stdout.trim()).unwrap();
            let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap_or_default();
            assert!(!reason.trim().is_empty(), "{context}");
        }
        // Copilot blocks a preToolUse on exit 1, and other events continue.
        // The OpenCode plugin denies the call on any non-zero exit.
        _ => assert_eq!((code, stdout), (1, ""), "{context}"),
    }
}

#[test]
fn a_payload_that_names_no_event_blocks_unless_both_policies_allow() {
    let payloads: [&[u8]; 9] = [
        b"not json",
        br#"{"session_id":"s","#,
        // Valid JSON without a name (schema drift).
        br#"{"tool_input":{"command":"ls"}}"#,
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
    for entry_point in ALL_ENTRY_POINTS {
        for payload in payloads {
            for (settings, blocks) in POLICIES {
                let context = format!(
                    "{entry_point}, {settings:?}: {}",
                    String::from_utf8_lossy(payload)
                );
                let (code, stdout, _) = hook_with(entry_point, settings, payload);
                if blocks {
                    assert_nameless_block(entry_point, (code, &stdout), &context);
                } else {
                    assert_eq!((code, stdout.as_str()), (1, ""), "{context}");
                }
            }
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

/// A `PreToolUse` that parses but has no `tool_name`, or no tool input at
/// all. Codex runs the call on exit 1, so with `on_error` allow or ask a
/// missing name used to be a silent fail-open; a missing input was evaluated
/// as an empty one and allowed.
#[test]
fn an_unusable_pre_tool_use_gets_the_stricter_policy_on_every_entry_point() {
    let named = br#"{"session_id":"s","turn_id":"t","transcript_path":"/t","cwd":"/w","hook_event_name":"PreToolUse","tool_use_id":"c","tool_input":{"command":"ls"}}"#;
    // A camelCase Copilot payload names nothing; `timestamp` routes it from the
    // Claude Code entry point, which then answers in Copilot's own form.
    let camel = br#"{"timestamp":1,"cwd":"/w","toolName":"bash","toolArgs":{"command":"ls"}}"#;
    let no_input = br#"{"session_id":"s","turn_id":"t","transcript_path":"/t","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"c"}"#;
    let camel_no_input = br#"{"sessionId":"s","timestamp":1,"cwd":"/w","toolName":"bash"}"#;
    let entries: [(&str, &[u8], bool, bool); 10] = [
        ("claude-code", named, true, true),
        ("codex-cli", named, true, false),
        ("copilot-cli", named, false, true),
        ("copilot-cli", camel, false, true),
        ("claude-code", camel, false, true),
        ("claude-code", no_input, true, true),
        ("codex-cli", no_input, true, false),
        ("copilot-cli", no_input, false, true),
        ("copilot-cli", camel_no_input, false, true),
        ("claude-code", camel_no_input, false, true),
    ];
    for (entry_point, payload, nested, can_ask) in entries {
        let (code, stdout, telemetry) = hook_with(entry_point, "  mode: enforce\n", payload);
        assert_eq!(code, 0, "{entry_point}");
        assert!(!stdout.is_empty(), "{entry_point}");
        assert!(
            telemetry.contains("\"error_code\":\"payload_missing_field\""),
            "{entry_point}: {telemetry}"
        );
        // A configuration that asks for enforcement and does not load denies.
        let (code, stdout) = hook(entry_point, "  bogus: 1\n", payload);
        assert_eq!(code, 0, "{entry_point}");
        assert_eq!(decision(&stdout, nested), "deny", "{entry_point}");
        let ask = if can_ask { "ask" } else { "deny" };
        for (settings, expected) in [
            ("", ask), // default: on_unevaluable: ask
            ("  on_unevaluable: ask\n", ask),
            ("  on_unevaluable: deny\n", "deny"),
            ("  on_error: deny\n  on_unevaluable: allow\n", "deny"),
            ("  on_error: ask\n  on_unevaluable: allow\n", ask),
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
            hook(entry_point, "  on_unevaluable: allow\n", payload),
            (0, String::new()),
            "{entry_point}"
        );
    }
}

/// The benign twin of a missing tool input: a tool without arguments sends
/// an empty object, which is evaluated like any other input. Only an absent
/// key is unusable.
#[test]
fn an_empty_tool_input_is_evaluated_not_refused() {
    let empty = br#"{"session_id":"s","turn_id":"t","transcript_path":"/t","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"mcp__notes__list","tool_use_id":"c","tool_input":{}}"#;
    let camel_empty =
        br#"{"sessionId":"s","timestamp":1,"cwd":"/w","toolName":"list_notes","toolArgs":{}}"#;
    for (entry_point, payload) in [
        ("claude-code", &empty[..]),
        ("codex-cli", empty),
        ("copilot-cli", empty),
        ("copilot-cli", camel_empty),
    ] {
        let (code, stdout, telemetry) = hook_with(entry_point, "  mode: enforce\n", payload);
        assert_eq!((code, stdout.as_str()), (0, ""), "{entry_point}");
        assert!(
            telemetry.contains("\"kind\":\"decision\"")
                && !telemetry.contains("\"kind\":\"error\""),
            "{entry_point}: {telemetry}"
        );
    }
}

/// The debug-build-only switch that makes the hook panic at the named sites
/// (comma-separated). Release builds do not read it.
const FORCE_PANIC: &str = "TELLTALE_HOOKS_TEST_PANIC";

/// The decision on stdout in any harness's form: nested (Claude Code, Codex),
/// flat (Copilot) or the OpenCode plugin's.
fn verdict(stdout: &str) -> String {
    let output: Value = serde_json::from_str(stdout.trim()).unwrap();
    [
        &output["hookSpecificOutput"]["permissionDecision"],
        &output["permissionDecision"],
        &output["decision"],
    ]
    .into_iter()
    .find_map(Value::as_str)
    .unwrap_or_default()
    .to_owned()
}

fn panic_records(telemetry: &str) -> usize {
    telemetry
        .lines()
        .filter(|line| {
            line.contains("\"kind\":\"error\"") && line.contains("\"error_code\":\"hook_panicked\"")
        })
        .count()
}

const OPENCODE_CALL: &[u8] = br#"{"protocol":"telltale.opencode-v2.v1","hook_event":"execute.before","occurrence":"occ-1","cwd":"/w","event":{"sessionID":"s","messageID":"m","agent":"build","id":"c","tool":"shell","input":{"command":"ls"}}}"#;
const CALL: &[u8] = br#"{"session_id":"s","turn_id":"t","transcript_path":"/t","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"toolu_p","tool_input":{"command":"ls"}}"#;
const CAMEL_CALL: &[u8] =
    br#"{"sessionId":"s","timestamp":1,"cwd":"/w","toolName":"bash","toolArgs":{"command":"ls"}}"#;

/// A tool call whose evaluation panics gets the stricter of `on_error` and
/// `on_unevaluable` and an `error` record, as an unreadable one does. A panic
/// while recording that cannot take the answer back.
#[test]
fn a_panic_while_evaluating_gets_the_strict_policy_and_a_record() {
    let calls: [(&str, &[u8], bool); 5] = [
        ("claude-code", CALL, true),
        ("codex-cli", CALL, false),
        ("copilot-cli", CALL, true),
        ("copilot-cli", CAMEL_CALL, true),
        ("opencode", OPENCODE_CALL, false),
    ];
    for (entry_point, payload, can_ask) in calls {
        let ask = if can_ask { "ask" } else { "deny" };
        for (settings, expected) in [
            ("  mode: enforce\n", ask),
            ("  mode: enforce\n  on_unevaluable: deny\n", "deny"),
            ("  mode: enforce\n  on_error: deny\n", "deny"),
        ] {
            let context = format!("{entry_point}, {settings:?}");
            let (code, stdout, telemetry) =
                hook_env(entry_point, settings, payload, &[(FORCE_PANIC, "evaluate")]);
            assert_eq!(code, 0, "{context}");
            assert_eq!(verdict(&stdout), expected, "{context}");
            assert_eq!(panic_records(&telemetry), 1, "{context}: {telemetry}");
            // The control: the same call without the panic is allowed.
            let (code, stdout, _) = hook_env(entry_point, settings, payload, &[]);
            assert_eq!((code, stdout.as_str()), (0, ""), "{context}");
            // A second panic, while recording the first, keeps the answer.
            let (code, stdout, _) = hook_env(
                entry_point,
                settings,
                payload,
                &[(FORCE_PANIC, "evaluate,record")],
            );
            assert_eq!(code, 0, "{context}");
            assert_eq!(verdict(&stdout), expected, "{context}");
        }
    }
    // An event that is not pre-execution is not blocked: a non-blocking exit.
    let post = br#"{"session_id":"s","cwd":"/w","hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"toolu_p","tool_input":{"command":"ls"},"tool_response":{"stdout":""}}"#;
    let (code, stdout, telemetry) = hook_env(
        "claude-code",
        "  mode: enforce\n  on_error: deny\n",
        post,
        &[(FORCE_PANIC, "evaluate")],
    );
    assert_eq!((code, stdout.as_str()), (1, ""));
    assert_eq!(panic_records(&telemetry), 1, "{telemetry}");
}

/// Detect-only holds through a panic: nothing on stdout, exit 0, and the
/// panic is still recorded.
#[test]
fn a_panic_in_detect_only_mode_blocks_nothing_and_is_recorded() {
    let strict = "  on_error: deny\n  on_unevaluable: deny\n";
    for (entry_point, payload) in [
        ("claude-code", CALL),
        ("codex-cli", CALL),
        ("copilot-cli", CAMEL_CALL),
        ("opencode", OPENCODE_CALL),
    ] {
        for sites in ["evaluate", "read", "evaluate,record"] {
            let (code, stdout, telemetry) =
                hook_env(entry_point, strict, payload, &[(FORCE_PANIC, sites)]);
            assert_eq!((code, stdout.as_str()), (0, ""), "{entry_point}, {sites}");
            if !sites.contains("record") {
                assert_eq!(panic_records(&telemetry), 1, "{entry_point}, {sites}");
            }
        }
    }
}

/// A panic before evaluation starts gets the same strict answer. While
/// reading the payload, the payload is lost, so it gets each harness's block
/// for a payload that names no event. While loading the configuration, it is
/// a configuration that did not load: denied when the settings ask for
/// enforcement, detect-only when they do not. A panic while asking whether
/// they do cannot turn enforcement off.
#[test]
fn a_panic_before_evaluation_gets_the_strict_answer() {
    for entry_point in ALL_ENTRY_POINTS {
        let payload = match entry_point {
            "opencode" => OPENCODE_CALL,
            _ => CALL,
        };
        let context = |what: &str| format!("{entry_point}: {what}");
        let (code, stdout, telemetry) = hook_env(
            entry_point,
            "  mode: enforce\n",
            payload,
            &[(FORCE_PANIC, "read")],
        );
        assert_nameless_block(entry_point, (code, &stdout), &context("read"));
        assert_eq!(panic_records(&telemetry), 1, "{}", context("read"));

        for sites in ["config", "config,declare"] {
            let (code, stdout, _) = hook_env(
                entry_point,
                "  mode: enforce\n",
                payload,
                &[(FORCE_PANIC, sites)],
            );
            assert_eq!(code, 0, "{}", context(sites));
            assert_eq!(verdict(&stdout), "deny", "{}", context(sites));
        }
        let (code, stdout, telemetry) = hook_env(
            entry_point,
            "  on_error: deny\n",
            payload,
            &[(FORCE_PANIC, "config")],
        );
        assert_eq!(
            (code, stdout.as_str()),
            (0, ""),
            "{}",
            context("config, detect-only")
        );
        assert!(
            telemetry.contains("\"error_code\":\"config_invalid\""),
            "{}: {telemetry}",
            context("config, detect-only")
        );
    }
}
