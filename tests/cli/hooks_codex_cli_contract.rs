//! Codex CLI adapter contract, driven by every payload captured from the real
//! Codex 0.166.0 binary (tests/fixtures/codex-cli/0.166.0): parse to runtime
//! events, the composite correlation key, the exact deny bytes Codex honored,
//! ask returned as deny, Stop/SubagentStop settlement scoping, and the
//! mapping of post events. Payloads go through the registry exactly as the
//! `telltale hooks codex-cli hook` binary sends them.

use crate::hooks_common as common;

use std::path::{Path, PathBuf};

use common::Harness;
use serde_json::{Value, json};
use telltale_core::hooks::codex_cli;
use telltale_core::hooks::harness::{Harness as Registry, Parsed};
use telltale_core::hooks::runtime::{CANNOT_ASK_NOTE, Completion, Event};

fn fixtures() -> PathBuf {
    common::fixtures("codex-cli/0.166.0")
}
const CODEX: Registry = Registry::CodexCli;
/// Scores ask under the default policy (crates/telltale/tests/hooks/harness_contract.rs).
const HARVEST: &str = "cat ~/.aws/credentials";

/// Every fixture file, sorted.
fn fixture_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(fixtures())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 11, "{files:?}");
    files
}

/// `(stub mode, payload)` per captured line.
fn capture(name: &str) -> Vec<(String, Value)> {
    std::fs::read_to_string(fixtures().join(name))
        .unwrap()
        .lines()
        .map(|line| {
            let line: Value = serde_json::from_str(line).unwrap();
            (
                line["stub"].as_str().unwrap().to_owned(),
                line["payload"].clone(),
            )
        })
        .collect()
}

/// A rules file that scores the capture canary (`... && echo TTH_CANARY`) as
/// deny, the way the capture stubs denied it.
fn canary_rules(dir: &Path) -> PathBuf {
    let path = dir.join("canary-rules.yaml");
    std::fs::write(
        &path,
        "version: 1\ndescription: test canary\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: tth.test.canary\n    title: Capture canary\n    category: e2e_test\n    severity: critical\n    score: 95\n    targets: [command]\n    regex: 'TTH_CANARY'\n    tags: [test-only]\n    explanation: Test-only canary.\nmodifiers: []\n",
    )
    .unwrap();
    path
}

/// Send one native payload through the registry and render the answer.
fn send(h: &mut Harness, payload: &Value) -> Option<Value> {
    match CODEX.parse(payload.to_string().as_bytes()) {
        Parsed::Event(ctx, event) => {
            let response = h.runtime.handle(&ctx, event);
            CODEX.render(&ctx.hook_event, &response)
        }
        other => panic!("{other:?} for {payload}"),
    }
}

fn key(payload: &Value) -> String {
    codex_cli::call_key(
        payload["session_id"].as_str().unwrap(),
        payload["agent_id"].as_str(),
        payload["turn_id"].as_str(),
        payload["tool_use_id"].as_str().unwrap(),
    )
}

fn deny_bytes(reason: &str) -> String {
    json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }})
    .to_string()
}

#[test]
fn every_captured_payload_parses_to_the_expected_event() {
    let mut seen = std::collections::BTreeSet::new();
    for file in fixture_files() {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        for (_, payload) in capture(&name) {
            let event_name = payload["hook_event_name"].as_str().unwrap().to_owned();
            let Parsed::Event(ctx, event) = CODEX.parse(payload.to_string().as_bytes()) else {
                panic!("{name}: {payload}");
            };
            assert_eq!(ctx.harness, "codex-cli");
            assert!(!ctx.can_ask, "Codex runs a returned ask");
            assert_eq!(ctx.session_id, payload["session_id"]);
            assert_eq!(ctx.prompt_id.as_deref(), payload["turn_id"].as_str());
            assert_eq!(ctx.agent_id.as_deref(), payload["agent_id"].as_str());
            match (event_name.as_str(), &event) {
                ("PreToolUse", Event::ToolRequested(call)) => {
                    assert!(CODEX.is_pre_tool_use(&ctx.hook_event));
                    assert_eq!(call.tool_use_id.as_deref(), Some(key(&payload).as_str()));
                    assert_eq!(call.tool_name, payload["tool_name"]);
                    // Reported as Codex sent it; the runtime normalizes.
                    assert_eq!(call.input, payload["tool_input"]);
                }
                ("PostToolUse", Event::ToolFinished { call, .. }) => {
                    assert_eq!(call.tool_use_id.as_deref(), Some(key(&payload).as_str()));
                }
                ("Stop" | "SubagentStop", Event::TurnSettled) => {}
                ("SubagentStart", Event::SubagentStart { agent_id, .. }) => {
                    assert_eq!(agent_id, payload["agent_id"].as_str().unwrap());
                }
                ("UserPromptSubmit", Event::UserPrompt { prompt }) => {
                    assert_eq!(prompt, payload["prompt"].as_str().unwrap());
                }
                ("SessionStart", Event::SessionStart { .. })
                | ("SessionEnd", Event::SessionEnd { .. }) => {}
                (other, event) => panic!("{name}: {other} -> {event:?}"),
            }
            seen.insert(event_name);
        }
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [
            "PostToolUse",
            "PreToolUse",
            "SessionEnd",
            "SessionStart",
            "Stop",
            "SubagentStart",
            "SubagentStop",
            "UserPromptSubmit"
        ]
    );
}

/// The subagent's first call and a parent's first call share the
/// model-supplied `tool_use_id`; only the composite key tells them apart.
#[test]
fn the_correlation_key_is_composite_and_stable_from_pre_to_post() {
    let subagent = capture("subagent.jsonl");
    let child = subagent
        .iter()
        .map(|(_, p)| p)
        .find(|p| p["hook_event_name"] == "PreToolUse" && p.get("agent_id").is_some())
        .unwrap();
    let parent = capture("lifecycle.jsonl")
        .into_iter()
        .map(|(_, p)| p)
        .find(|p| p["hook_event_name"] == "PreToolUse")
        .unwrap();
    assert_eq!(child["tool_use_id"], parent["tool_use_id"]);
    let mut same_session_parent = parent.clone();
    same_session_parent["session_id"] = child["session_id"].clone();
    same_session_parent["turn_id"] = child["turn_id"].clone();
    assert_ne!(key(child), key(&same_session_parent));
    assert!(key(child).contains(child["agent_id"].as_str().unwrap()));

    // Pre and post of every captured call build the same key.
    for file in fixture_files() {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let lines = capture(&name);
        for (_, post) in lines
            .iter()
            .filter(|(_, p)| p["hook_event_name"] == "PostToolUse")
        {
            let pre = lines
                .iter()
                .map(|(_, p)| p)
                .find(|p| {
                    p["hook_event_name"] == "PreToolUse"
                        && p["tool_use_id"] == post["tool_use_id"]
                        && p["agent_id"] == post["agent_id"]
                        && p["turn_id"] == post["turn_id"]
                })
                .unwrap_or_else(|| panic!("{name}: no pre for {post}"));
            assert_eq!(key(pre), key(post), "{name}");
        }
    }
}

/// The deny the stub returned in `deny-hso.jsonl` was honored by Codex (the
/// canary did not run). The adapter renders the same form, byte for byte
/// apart from the reason, and never `allow` or `ask`.
#[test]
fn a_deny_renders_the_form_codex_honored() {
    let rules_dir = tempfile::tempdir().unwrap();
    let rules = canary_rules(rules_dir.path());
    for name in [
        "deny-hso.jsonl",
        "subagent.jsonl",
        "lifecycle-failures.jsonl",
    ] {
        let mut h = Harness::with(|c| c.telltale.rules = vec![rules.clone()]);
        for (stub, payload) in capture(name) {
            let out = send(&mut h, &payload);
            if payload["hook_event_name"] == "PreToolUse" && stub == "deny-hso" {
                let out = out.expect("a deny for the canary");
                let reason = out["hookSpecificOutput"]["permissionDecisionReason"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                assert!(reason.contains("tth.test.canary"), "{reason}");
                assert_eq!(out.to_string(), deny_bytes(&reason), "{name}");
            } else {
                assert_eq!(out, None, "{name}: {payload}");
            }
        }
    }
    // The capture stub's honored bytes have the same shape.
    assert_eq!(
        deny_bytes("TTH stub deny: canary command blocked by capture hook"),
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"TTH stub deny: canary command blocked by capture hook"}}"#
    );
}

/// `ask-hso.jsonl`: Codex ran the call the stub asked about. A policy ask on
/// the same payload is returned as deny, with the reason saying why, and
/// telemetry keeps the policy verdict.
#[test]
fn a_policy_ask_is_returned_as_deny() {
    let (_, mut payload) = capture("ask-hso.jsonl")
        .into_iter()
        .find(|(stub, _)| stub == "ask-hso")
        .unwrap();
    payload["tool_input"]["command"] = HARVEST.into();
    let mut h = Harness::new();
    let out = send(&mut h, &payload).expect("a decision");
    let reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.ends_with(CANNOT_ASK_NOTE), "{reason}");
    assert_eq!(out.to_string(), deny_bytes(reason));
    assert!(!out.to_string().contains("\"ask\""));
    let record = h.decision_for(&key(&payload));
    assert_eq!(record["decision"]["verdict"], "ask");
    assert_eq!(record["decision"]["returned_verdict"], "deny");
    assert_eq!(record["harness"]["name"], "codex-cli");

    // Allowed calls print nothing (no allow, which Codex ignores anyway).
    let (_, allowed) = capture("allow-hso.jsonl")
        .into_iter()
        .find(|(stub, _)| stub == "allow-hso")
        .unwrap();
    assert_eq!(send(&mut Harness::new(), &allowed), None);
}

/// A subagent's calls are settled by its own SubagentStop (agent and turn
/// scoped), never by the parent's Stop, in either order.
#[test]
fn stop_and_subagent_stop_settle_only_their_own_agent_and_turn() {
    let rules_dir = tempfile::tempdir().unwrap();
    let rules = canary_rules(rules_dir.path());
    let lines: Vec<Value> = capture("subagent.jsonl")
        .into_iter()
        .map(|(_, p)| p)
        .collect();
    let child_call = lines
        .iter()
        .find(|p| p["hook_event_name"] == "PreToolUse" && p.get("agent_id").is_some())
        .unwrap();
    let child_key = key(child_call);
    let parent_stop = lines
        .iter()
        .find(|p| p["hook_event_name"] == "Stop")
        .unwrap();
    let child_stop = lines
        .iter()
        .find(|p| p["hook_event_name"] == "SubagentStop")
        .unwrap();

    // As captured: SubagentStop, then the parent's Stop.
    let mut h = Harness::with(|c| c.telltale.rules = vec![rules.clone()]);
    for payload in &lines {
        send(&mut h, payload);
    }
    let outcome = h.outcome_for(&child_key);
    assert_eq!(outcome["outcome"]["result"], "not_executed");
    assert_eq!(outcome["outcome"]["enforcement"], "honored");
    assert_eq!(outcome["outcome"]["established_by"], "SubagentStop");
    assert_eq!(outcome["session"]["agent_id"], child_call["agent_id"]);
    // Every parent call got its result before the parent's Stop.
    let outcomes = h.records("outcome");
    assert_eq!(outcomes.len(), 3, "{outcomes:#?}");
    assert!(
        outcomes
            .iter()
            .filter(|o| o["action"]["tool_use_id"] != child_key.as_str())
            .all(|o| o["outcome"]["result"] == "completed")
    );

    // Parent's Stop first: the child's call stays pending until its own stop.
    let mut h = Harness::with(|c| c.telltale.rules = vec![rules.clone()]);
    for payload in lines
        .iter()
        .take_while(|p| p["hook_event_name"] != "SubagentStop")
    {
        send(&mut h, payload);
    }
    send(&mut h, parent_stop);
    assert!(
        h.records("outcome")
            .iter()
            .all(|o| o["action"]["tool_use_id"] != child_key.as_str())
    );
    send(&mut h, child_stop);
    let outcome = h.outcome_for(&child_key);
    assert_eq!(outcome["outcome"]["enforcement"], "honored");
    assert_eq!(outcome["outcome"]["established_by"], "SubagentStop");
}

/// Post events: every executed call has a PostToolUse (any exit code), so it
/// completes; Stop settles what got none. Results reach the journal as text.
#[test]
fn post_events_map_to_outcomes_and_stop_settles_the_rest() {
    let mut h = Harness::new();
    for (_, payload) in capture("lifecycle.jsonl") {
        assert_eq!(send(&mut h, &payload), None);
    }
    let outcomes = h.records("outcome");
    assert_eq!(outcomes.len(), 7);
    assert!(
        outcomes
            .iter()
            .all(|o| o["outcome"]["result"] == "completed" && o["harness"]["name"] == "codex-cli")
    );
    // A shell call with a failing command still completed: Codex reports
    // no exit code for shell calls.
    let ls = capture("lifecycle.jsonl")
        .into_iter()
        .map(|(_, p)| p)
        .find(|p| p["tool_input"]["command"] == "ls /nonexistent-dir-for-capture")
        .unwrap();
    assert_eq!(h.outcome_for(&key(&ls))["outcome"]["result"], "completed");

    // MCP isError maps to failed.
    let mut mcp = capture("lifecycle.jsonl")
        .into_iter()
        .map(|(_, p)| p)
        .find(|p| p["hook_event_name"] == "PostToolUse" && p["tool_name"] == "mcp__tthmock__echo")
        .unwrap();
    mcp["tool_response"]["isError"] = true.into();
    match CODEX.parse(mcp.to_string().as_bytes()) {
        Parsed::Event(
            _,
            Event::ToolFinished {
                completion,
                result_text,
                ..
            },
        ) => {
            assert_eq!(completion, Completion::Failed);
            assert_eq!(result_text, "echo: hi from mcp");
        }
        other => panic!("{other:?}"),
    }

    // Deny hook active: the denied canary is honored at Stop; the patch that
    // failed verification (no PostToolUse, no decision) is unknown; the
    // missing binary and the canary's parallel sibling completed.
    let rules_dir = tempfile::tempdir().unwrap();
    let rules = canary_rules(rules_dir.path());
    let mut h = Harness::with(|c| c.telltale.rules = vec![rules.clone()]);
    let lines = capture("lifecycle-failures.jsonl");
    for (_, payload) in &lines {
        send(&mut h, payload);
    }
    let by_id = |id: &str| {
        let payload = lines
            .iter()
            .map(|(_, p)| p)
            .find(|p| p["hook_event_name"] == "PreToolUse" && p["tool_use_id"] == id)
            .unwrap();
        h.outcome_for(&key(payload))
    };
    let canary = by_id("call_0_3_0");
    assert_eq!(canary["outcome"]["result"], "not_executed");
    assert_eq!(canary["outcome"]["enforcement"], "honored");
    assert_eq!(canary["outcome"]["established_by"], "Stop");
    let patch = by_id("call_0_0_0");
    assert_eq!(patch["outcome"]["result"], "unknown");
    assert_eq!(patch["outcome"]["enforcement"], "not_returned");
    assert_eq!(by_id("call_0_1_0")["outcome"]["result"], "completed");
    assert_eq!(by_id("call_0_3_1")["outcome"]["result"], "completed");
}

/// The fail-open captures (exit 1, timeout) and the native-rule capture
/// replay cleanly: our hook answers nothing for the benign calls in them.
#[test]
fn failure_and_rule_captures_replay_without_output() {
    for name in [
        "fail-exit1.jsonl",
        "fail-timeout.jsonl",
        "rule-forbidden-allow.jsonl",
        "deny-flat.jsonl",
        "deny-legacy.jsonl",
    ] {
        let mut h = Harness::new();
        for (_, payload) in capture(name) {
            assert_eq!(send(&mut h, &payload), None, "{name}");
        }
    }
}

/// Codex's `tool_use_id` comes from the model. Telltale rejects a native ID
/// with `/`, `\`, `..` or a line break and fails the whole journal source,
/// which would make that call and every later one in the session unevaluable,
/// and with `on_unevaluable = "allow"` would let a later `curl | sh` through.
/// The composite key encodes everything outside `[A-Za-z0-9_-]`, so hostile
/// IDs are still evaluated normally, and a later risky call is still caught.
#[test]
fn a_hostile_tool_use_id_neither_fails_its_call_nor_poisons_the_session() {
    let call = capture("lifecycle.jsonl")
        .into_iter()
        .map(|(_, p)| p)
        .find(|p| p["hook_event_name"] == "PreToolUse" && p["tool_name"] == "Bash")
        .unwrap();
    let ids = [
        "call/../up/0",
        r"call_\1",
        "a\nb",
        "a\rb",
        "call_0\n",
        "nul\0id",
        "caf\u{e9}-\u{1F600}",
    ];
    let mut h = Harness::new();
    for id in ids {
        let mut payload = call.clone();
        payload["tool_use_id"] = id.into();
        payload["tool_input"]["command"] = "ls".into();
        assert_eq!(send(&mut h, &payload), None, "{id:?}");
    }
    let decisions = h.records("decision");
    assert_eq!(decisions.len(), ids.len());
    for record in &decisions {
        assert_eq!(record["evaluation"]["status"], "complete", "{record:#}");
        assert_eq!(record["decision"]["verdict"], "allow");
    }

    // The session still evaluates: a later harvest gets its real verdict.
    let mut later = call.clone();
    later["tool_use_id"] = "call_later".into();
    later["tool_input"]["command"] = HARVEST.into();
    assert!(send(&mut h, &later).is_some());
    let decisions = h.records("decision");
    let last = decisions.last().unwrap();
    assert_eq!(last["evaluation"]["status"], "complete", "{last:#}");
    assert_ne!(last["decision"]["verdict"], "allow");
}

/// A PreToolUse payload Codex could send that this adapter cannot use is
/// still recognized as one, so it gets a verdict, never an implicit allow.
#[test]
fn unusable_pre_tool_use_payloads_are_recognized() {
    let (_, mut payload) = capture("lifecycle.jsonl")
        .into_iter()
        .find(|(_, p)| p["hook_event_name"] == "PreToolUse")
        .unwrap();
    payload.as_object_mut().unwrap().remove("tool_name");
    match CODEX.parse(payload.to_string().as_bytes()) {
        Parsed::Unusable { hook_event, code } => {
            assert_eq!(hook_event, "PreToolUse");
            assert_eq!(code, "payload_missing_field");
        }
        other => panic!("{other:?}"),
    }
    let text = payload.to_string();
    assert!(CODEX.looks_like_pre_tool_use(&text.as_bytes()[..text.len() / 2]));
}

/// The installed binary, isolated from any default config or state location.
fn binary(args: &[&str], stdin: &[u8], state: &Path) -> (i32, String, String) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command.arg("hooks");
    for var in ["HOME", "APPDATA", "LOCALAPPDATA"] {
        command.env(var, "/nonexistent-home-for-test");
    }
    let mut child = command
        .args(args)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("TELLTALE_HOOKS_CONFIG")
        .env("TELLTALE_HOOKS_EVALUATOR", "0")
        .env("TELLTALE_HOOKS_STATE_DIR", state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn binary_hook_denies_asks_and_stays_silent_over_stdio() {
    let dir = tempfile::tempdir().unwrap();
    let (_, mut payload) = capture("ask-hso.jsonl")
        .into_iter()
        .find(|(stub, _)| stub == "ask-hso")
        .unwrap();
    let hook = ["codex-cli", "hook"];
    // Benign canary command: nothing on stdout, exit 0.
    let (code, stdout, _) = binary(&hook, payload.to_string().as_bytes(), dir.path());
    assert_eq!((code, stdout.as_str()), (0, ""));
    // A policy ask is printed as the deny Codex honors.
    payload["tool_input"]["command"] = HARVEST.into();
    let (code, stdout, _) = binary(&hook, payload.to_string().as_bytes(), dir.path());
    assert_eq!(code, 0);
    let out: Value = serde_json::from_str(stdout.trim()).unwrap();
    let reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert_eq!(out.to_string(), deny_bytes(reason));
    // An unreadable PreToolUse gets on_unevaluable (ask), returned as deny.
    let text = payload.to_string();
    let (code, stdout, _) = binary(&hook, &text.as_bytes()[..text.len() / 2], dir.path());
    assert_eq!(code, 0);
    let out: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn binary_settings_print_hooks_json_and_refuse_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = binary(&["codex-cli", "settings"], b"", dir.path());
    assert_eq!(code, 0);
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(doc, codex_cli::hooks_file("telltale hooks codex-cli hook"));
    assert!(stderr.contains("hooks.json") && stderr.contains("Trust all and continue"));

    let (code, stdout, _) = binary(&["codex-cli", "settings", "/opt/tth hook"], b"", dir.path());
    assert_eq!(code, 0);
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        doc["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "/opt/tth hook"
    );

    let (code, stdout, stderr) =
        binary(&["codex-cli", "settings", "--fail-closed"], b"", dir.path());
    assert_ne!(code, 0);
    assert_eq!(stdout, "");
    assert!(
        stderr.contains("--fail-closed is not available"),
        "{stderr}"
    );

    let (code, stdout, _) = binary(&["codex-cli", "execpolicy"], b"", dir.path());
    assert_eq!(code, 0);
    assert_eq!(stdout, codex_cli::execpolicy_rules());
}

/// The runtime normalizes Codex `apply_patch` (`{"command": patch}`) by the
/// adapter's harness name, so a patch that writes the Codex hook file reaches
/// self-protection through the patch target and is denied, while a benign
/// patch from the same capture is not.
#[test]
fn a_patch_to_the_codex_hook_file_is_denied_after_runtime_normalization() {
    let (_, native) = capture("lifecycle.jsonl")
        .into_iter()
        .find(|(_, p)| p["hook_event_name"] == "PreToolUse" && p["tool_name"] == "apply_patch")
        .unwrap();
    let mut h = Harness::new();
    assert_eq!(send(&mut h, &native), None);

    let mut hostile = native.clone();
    hostile["tool_use_id"] = "call_patch_hooks".into();
    hostile["tool_input"]["command"] =
        "*** Begin Patch\n*** Add File: /home/synthetic/.codex/hooks.json\n+{}\n*** End Patch\n"
            .into();
    let out = send(&mut h, &hostile).expect("a verdict");
    assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
    let decisions = h.records("decision");
    let last = decisions.last().unwrap();
    // Telemetry keeps the call Codex reported.
    assert_eq!(last["action"]["tool_name"], "apply_patch");
    assert_eq!(last["decision"]["verdict"], "deny", "{last:#}");
}
