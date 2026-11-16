//! OpenAI Codex CLI adapter: native hook stdin payload -> runtime event, and
//! runtime response -> native hook stdout.
//!
//! Contract evidence: payloads captured from Codex CLI 0.166.0 in
//! tests/fixtures/codex-cli/0.166.0, the pinned source `rust-v0.166.0`, and
//! docs/harnesses/codex-cli.md. Unknown fields are ignored.
//!
//! What Codex does and does not enforce shapes everything here:
//!
//! - A returned `ask` is an unsupported decision: the hook is marked failed
//!   and **the call runs**. [`CAN_ASK`] is `false`, so the runtime returns
//!   every `ask` as `deny` (`Response::decision`), and [`render`] never
//!   writes `ask` even if one reached it.
//! - Every hook failure (crash, timeout, invalid output, missing binary)
//!   fails open, and there is no option to change that. See
//!   [`execpolicy_rules`] for the native backstop that does not depend on
//!   this hook running.
//! - Tool inputs are reported as Codex sent them (`apply_patch`
//!   `{"command": patch}` included); the runtime normalizes the evaluation
//!   encoding (ADR 0002 addendum), keyed by [`HARNESS`].

use serde::Deserialize;
use serde_json::{Value, json};

use crate::hooks::claude_code;
use crate::hooks::runtime::{Completion, Context, Event, Response, ToolCall, synthetic_call_id};
use crate::hooks::state::Verdict;

/// Matches `normalize::CODEX_CLI`, which keys the runtime's input
/// normalization for this harness.
pub const HARNESS: &str = "codex-cli";
/// The pre-execution hook event: the only enforcement point.
pub const PRE_TOOL_USE: &str = "PreToolUse";
/// Codex 0.166.0 treats a returned `ask` as an unsupported decision and runs
/// the call (E2E, docs/harnesses/codex-cli.md). No run mode prompts, so the
/// registry and every per-event `Context` read `false`.
pub const CAN_ASK: bool = false;

/// Used when a decision carries no reason: Codex ignores a deny whose
/// `permissionDecisionReason` is empty or blank (fails open).
const FALLBACK_REASON: &str = "Telltale Hooks denied this tool call.";

#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    pub hook_event_name: String,
    pub session_id: String,
    /// Per-turn identity; on a subagent's events, the subagent's turn.
    #[serde(default)]
    pub turn_id: Option<String>,
    /// Present on a subagent's events only (the main agent has none).
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub permission_mode: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<Value>,
    /// Model-supplied; unique only together with session, agent and turn.
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub tool_response: Option<Value>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug)]
pub enum ParseError {
    Json,
    MissingField(&'static str),
}

impl ParseError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Json => "payload_invalid_json",
            Self::MissingField(_) => "payload_missing_field",
        }
    }
}

pub fn parse(bytes: &[u8]) -> Result<HookInput, ParseError> {
    serde_json::from_slice(bytes).map_err(|_| ParseError::Json)
}

/// Whether an unparseable payload names the PreToolUse event. Codex writes
/// `hook_event_name` after the session, turn, agent, transcript and cwd
/// fields and before `tool_input` (`PreToolUseCommandInput`), so the
/// bounded prefix scan shared with Claude Code applies.
pub fn looks_like_pre_tool_use(bytes: &[u8]) -> bool {
    claude_code::looks_like_pre_tool_use(bytes)
}

/// The correlation key of one Codex tool call: session, agent, turn and
/// `tool_use_id`. Codex's `tool_use_id` comes from the model and repeats
/// across agents and turns (a subagent's first call and the parent's are
/// both `call_0_0_0` in the captures), so only the composite identifies a
/// call. Built from fields PreToolUse and PostToolUse both carry, so it is
/// stateless; the main agent's component is empty.
///
/// Components are joined with `:`, and every byte outside `[A-Za-z0-9_-]`
/// is percent-encoded, so the key is injective and readable and holds only
/// characters a journal ID can safely carry. The model chooses
/// `tool_use_id`, so it may contain anything. Telltale rejects a native ID
/// with `/`, `\`, `..` or a line break and fails the whole journal source,
/// for that call and for every later call whose window still holds it.
pub fn call_key(
    session_id: &str,
    agent_id: Option<&str>,
    turn_id: Option<&str>,
    tool_use_id: &str,
) -> String {
    let escape = |part: &str| {
        let mut out = String::with_capacity(part.len());
        for byte in part.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' => out.push(byte as char),
                byte => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    };
    [
        session_id,
        agent_id.unwrap_or(""),
        turn_id.unwrap_or(""),
        tool_use_id,
    ]
    .map(escape)
    .join(":")
}

fn tool_call(input: &HookInput) -> Result<ToolCall, ParseError> {
    let tool_name = input
        .tool_name
        .clone()
        .ok_or(ParseError::MissingField("tool_name"))?;
    let tool_input = input.tool_input.clone().unwrap_or(Value::Null);
    let key = match input.tool_use_id.as_deref() {
        Some(id) => call_key(
            &input.session_id,
            input.agent_id.as_deref(),
            input.turn_id.as_deref(),
            id,
        ),
        // PermissionRequest never carries one (its 0.166.0 schema has no
        // `tool_use_id`); PreToolUse and PostToolUse always did in the
        // captures. Should a post event ever lack it, post events repeat the
        // tool input, so the runtime's synthetic key still pairs them (FIFO,
        // never asserted as honored or violated once settled).
        None => synthetic_call_id(
            &input.session_id,
            input.agent_id.as_deref(),
            &tool_name,
            &tool_input,
        ),
    };
    Ok(ToolCall {
        tool_use_id: Some(key),
        tool_name,
        input: tool_input,
    })
}

/// How a PostToolUse report ended. Codex fires PostToolUse for every call
/// that executed, whatever its exit code, and reports no exit code for
/// shell calls (their `tool_response` is the output text only), so a shell
/// call is `Completed`: the harness reported a result. Failures are claimed
/// only where Codex reports one: an MCP result with `isError: true`, or an
/// `apply_patch` result whose Codex-written header says `Exit code: N`
/// with N other than 0.
fn completion(tool_name: &str, response: Option<&Value>) -> Completion {
    match response {
        Some(Value::Object(map)) if map.get("isError") == Some(&Value::Bool(true)) => {
            Completion::Failed
        }
        Some(Value::String(text)) if tool_name == "apply_patch" => {
            match text
                .lines()
                .next()
                .and_then(|line| line.strip_prefix("Exit code: "))
            {
                Some(code) if code.trim() != "0" => Completion::Failed,
                _ => Completion::Completed,
            }
        }
        _ => Completion::Completed,
    }
}

pub fn to_event(input: &HookInput) -> Result<(Context, Event), ParseError> {
    let ctx = Context {
        harness: HARNESS,
        hook_event: input.hook_event_name.clone(),
        session_id: input.session_id.clone(),
        agent_id: input.agent_id.clone(),
        agent_type: input.agent_type.clone(),
        prompt_id: input.turn_id.clone(),
        permission_mode: input.permission_mode.clone(),
        cwd: input.cwd.clone(),
        can_ask: CAN_ASK,
    };
    let event = match input.hook_event_name.as_str() {
        PRE_TOOL_USE => Event::ToolRequested(tool_call(input)?),
        "PostToolUse" => {
            let call = tool_call(input)?;
            Event::ToolFinished {
                completion: completion(&call.tool_name, input.tool_response.as_ref()),
                call,
                result_text: input
                    .tool_response
                    .as_ref()
                    .map(claude_code::result_text)
                    .unwrap_or_default(),
                duration_ms: None,
            }
        }
        // Fires only where Codex itself would prompt; recorded, never answered.
        "PermissionRequest" => Event::PermissionPrompt(tool_call(input)?),
        // Turn end without a call list. The main agent's `Stop` carries no
        // `agent_id` and its own `turn_id`; a subagent ends its turn with
        // `SubagentStop`, which carries the subagent's `agent_id` and
        // `turn_id`. Scoping by both means a parent's Stop never settles a
        // subagent's calls, and a subagent's calls are still settled.
        "Stop" | "SubagentStop" => Event::TurnSettled,
        "UserPromptSubmit" => Event::UserPrompt {
            prompt: input.prompt.clone().unwrap_or_default(),
        },
        "SessionStart" => Event::SessionStart {
            source: input.source.clone(),
        },
        "SessionEnd" => Event::SessionEnd {
            reason: input.reason.clone(),
        },
        "SubagentStart" => Event::SubagentStart {
            agent_id: input
                .agent_id
                .clone()
                .ok_or(ParseError::MissingField("agent_id"))?,
            agent_type: input.agent_type.clone(),
        },
        _ => Event::Other,
    };
    Ok((ctx, event))
}

/// Native stdout for a response, or `None` to print nothing (exit 0, no
/// opinion).
///
/// A pre-execution decision is rendered only as a deny, in the
/// `hookSpecificOutput` form with a non-empty reason (Codex 0.166.0 ignores
/// a deny without one). Never `allow` (unsupported by Codex, and this hook
/// only adds restrictions) and never `ask` (Codex would run the call): an
/// `ask` that reached this point despite [`CAN_ASK`] is written as a deny.
pub fn render(hook_event: &str, response: &Response) -> Option<Value> {
    match response {
        Response::None => None,
        Response::Decision(decision) if hook_event == PRE_TOOL_USE => {
            if decision.verdict() == Verdict::Allow {
                return None;
            }
            let reason = match decision.reason().trim() {
                "" => FALLBACK_REASON,
                reason => reason,
            };
            Some(json!({
                "hookSpecificOutput": {
                    "hookEventName": PRE_TOOL_USE,
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }))
        }
        Response::Decision(_) => None,
        Response::AdditionalContext(text) if hook_event == "PostToolUse" => Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": text,
            }
        })),
        Response::AdditionalContext(_) => None,
    }
}

/// The `hooks.json` document that registers this hook for every event it
/// handles (Claude-style format; no matcher, which matches every tool).
///
/// Codex 0.166.0 has no fail-closed option: a hook that crashes, times out,
/// prints invalid output or is missing lets the call run. The timeouts are
/// therefore generous for tool events (a timeout is an allow) and within
/// Codex's own limits for `SessionEnd` (clamped to at most 3 s).
pub fn hooks_file(command: &str) -> Value {
    let hook = |timeout: u64| json!([{"hooks": [{"type": "command", "command": command, "timeout": timeout}]}]);
    json!({
        "hooks": {
            "PreToolUse": hook(30),
            "PostToolUse": hook(30),
            "PermissionRequest": hook(10),
            "UserPromptSubmit": hook(10),
            "SessionStart": hook(10),
            "SessionEnd": hook(3),
            "SubagentStart": hook(10),
            "SubagentStop": hook(10),
            "Stop": hook(10),
        }
    })
}

/// Install notes for [`hooks_file`], printed to stderr by
/// `telltale hooks codex-cli settings`.
pub const INSTALL_NOTES: &str = "\
Install (Codex CLI 0.166.0):
  1. Save this document as $CODEX_HOME/hooks.json (default ~/.codex/hooks.json),
     or merge its \"hooks\" table into an existing one.
  2. Trust the hooks once: start `codex` interactively in a terminal and choose
     \"Trust all and continue\" (or review them in /hooks). Untrusted user hooks
     never run, and `codex exec` does not ask. Trust is stored per handler in
     $CODEX_HOME/config.toml ([hooks.state]), as a hash of that handler. Changing
     a handler or moving it un-trusts it, and the call then runs unchecked: trust
     again after such a change. Reformatting the file or editing another handler
     does not. The hash covers the command text, not the program it names, so
     replacing the binary at a trusted path keeps trust.
  3. Optional native backstop that holds when this hook fails. It only refuses
     plain nested Codex launches, and it is a file the agent can delete:
     mkdir -p $CODEX_HOME/rules
     telltale hooks codex-cli execpolicy > $CODEX_HOME/rules/telltale-hooks.rules
Limits: Codex runs a tool call whenever a hook fails (crash, timeout, invalid
output, missing binary), and there is no option to change that. Managed hooks
(requirements.toml, allow_managed_hooks_only) need no trust step and cannot be
removed by the user: see managed deployment.";

/// Why `codex-cli settings --fail-closed` refuses instead of printing.
pub const NO_FAIL_CLOSED: &str = "\
telltale hooks: --fail-closed is not available for Codex CLI. Codex 0.166.0 runs
a tool call whenever a hook fails (crash, timeout, invalid output, missing
binary) and has no option to change that, so no hooks.json can make this hook
fail closed. Nothing was printed. Run `telltale hooks codex-cli settings` for
the hook config, and see `telltale hooks codex-cli execpolicy` (a native
backstop for nested Codex launches) and managed requirements.";

/// Codex exec-policy rules (`$CODEX_HOME/rules/*.rules`, Starlark
/// `prefix_rule`) that refuse the highest-risk hook bypass natively,
/// independently of this hook: starting another Codex session, which can
/// run without hooks (`--disable hooks`, `-c features.hooks=false`, another
/// `CODEX_HOME`, `--dangerously-bypass-hook-trust`).
///
/// Codex 0.166.0 applies `forbidden` before running a shell command, in
/// every approval and sandbox mode, whether or not any hook ran, and a hook
/// `allow` cannot override it (E2E). The coverage is literal by design:
/// prefix rules match the program and leading arguments of each plain
/// command Codex parses out of the shell script (split at `&&`, `||`, `;`,
/// `|`; an absolute path to a `codex` binary resolves to its name). A
/// script Codex cannot parse as plain commands (a variable assignment
/// prefix, redirection, substitution, subshell) is matched as a whole and
/// escapes these rules, as do indirect launches (`env codex`, `sh -c`,
/// interpreters). `apply_patch` edits never pass through exec policy. The
/// `match`/`not_match` examples are checked by Codex when it loads the file.
pub fn execpolicy_rules() -> String {
    const JUSTIFICATION: &str = "Telltale Hooks: the agent may not start another Codex session, \
        because it can run without the hooks that monitor this one. Ask the user to run it.";
    let rule = |pattern: &str, matches: &str, not_matches: &str| {
        format!(
            "prefix_rule(\n    pattern = {pattern},\n    decision = \"forbidden\",\n    \
             justification = \"{JUSTIFICATION}\",\n    match = {matches},\n    \
             not_match = {not_matches},\n)\n"
        )
    };
    let mut text = String::from(
        "# Telltale Hooks exec-policy backstop for Codex CLI (verified on 0.166.0).\n\
         # Generated by `telltale hooks codex-cli execpolicy`. Install as\n\
         # $CODEX_HOME/rules/telltale-hooks.rules (or ship it in managed requirements).\n\
         #\n\
         # Codex refuses these commands natively, before they run, even when the\n\
         # Telltale Hooks hook crashed, timed out or is missing. Coverage is literal:\n\
         # plain commands only (split at && || ; |). A variable-assignment prefix,\n\
         # redirection, substitution or subshell makes Codex match the whole script,\n\
         # which escapes these rules, and so do indirect launches (env, sh -c,\n\
         # interpreters). apply_patch edits are never checked by exec policy, and\n\
         # nothing here protects this file or the hook config from being edited.\n\
         # A syntax error in any rules file makes Codex ignore all user rules: check\n\
         # with `codex execpolicy check --rules <this file> codex exec x`.\n\n",
    );
    text.push_str(&rule(
        r#"["codex"]"#,
        r#"["codex exec --disable hooks x", "codex -c features.hooks=false", "codex"]"#,
        r#"["codexx", "echo codex"]"#,
    ));
    text.push_str(&rule(
        r#"[["npx", "pnpx", "bunx"], ["@openai/codex", "@openai/codex@latest"]]"#,
        r#"["npx @openai/codex exec x", "bunx @openai/codex@latest"]"#,
        r#"["npx prettier"]"#,
    ));
    text.push_str(&rule(
        r#"["npx", ["-y", "--yes"], ["@openai/codex", "@openai/codex@latest"]]"#,
        r#"["npx -y @openai/codex exec x"]"#,
        r#"["npx -y prettier"]"#,
    ));
    text.push_str(&rule(
        r#"[["pnpm", "yarn"], "dlx", ["@openai/codex", "@openai/codex@latest"]]"#,
        r#"["pnpm dlx @openai/codex exec x"]"#,
        r#"["pnpm dlx prettier"]"#,
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_keys_are_composite_injective_readable_and_never_path_like() {
        assert_eq!(call_key("s", None, Some("t"), "call_0"), "s::t:call_0");
        assert_eq!(
            call_key("s", Some("a"), Some("t"), "call_0"),
            "s:a:t:call_0"
        );
        // A separator inside a component cannot forge another key.
        assert_ne!(
            call_key("s", Some("a:b"), Some("t"), "c"),
            call_key("s", Some("a"), Some("b:t"), "c")
        );
        let hostile = call_key("s", None, None, "../x/y\\z%:");
        assert_eq!(hostile, "s:::%2E%2E%2Fx%2Fy%5Cz%25%3A");
        // Line breaks, NUL, whitespace and non-ASCII are encoded byte by byte.
        assert_eq!(
            call_key("s", None, None, "a\nb\rc\0d e\u{e9}"),
            "s:::a%0Ab%0Dc%00d%20e%C3%A9"
        );
        // Readable IDs stay readable.
        assert_eq!(
            call_key("01a1-b2", None, Some("t-1"), "call_0_0_0"),
            "01a1-b2::t-1:call_0_0_0"
        );
        // Distinct inputs stay distinct, including an input that spells an
        // encoding; only the alphabet and the separator ever reach the key.
        let ids = [
            "a\nb", "a%0Ab", "a\rb", "a b", "a+b", "a.b", "\u{e9}", "%C3%A9", "",
        ];
        let keys: std::collections::HashSet<_> =
            ids.iter().map(|id| call_key("s", None, None, id)).collect();
        assert_eq!(keys.len(), ids.len());
        for key in &keys {
            assert!(
                key.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-%:".contains(&b)),
                "{key:?}"
            );
        }
    }

    #[test]
    fn shell_results_complete_and_reported_failures_fail() {
        assert_eq!(
            completion("Bash", Some(&json!("ls: cannot access"))),
            Completion::Completed
        );
        assert_eq!(
            completion("Bash", Some(&json!("Exit code: 1\nOutput:\n"))),
            Completion::Completed
        );
        assert_eq!(
            completion(
                "apply_patch",
                Some(&json!("Exit code: 0\nWall time: 0 seconds\n"))
            ),
            Completion::Completed
        );
        assert_eq!(
            completion(
                "apply_patch",
                Some(&json!("Exit code: 1\nWall time: 0 seconds\n"))
            ),
            Completion::Failed
        );
        assert_eq!(
            completion("mcp__s__t", Some(&json!({"content": [], "isError": true}))),
            Completion::Failed
        );
        assert_eq!(
            completion("mcp__s__t", Some(&json!({"content": [], "isError": false}))),
            Completion::Completed
        );
        assert_eq!(completion("Bash", None), Completion::Completed);
    }

    #[test]
    fn only_deny_is_ever_rendered_and_always_with_a_reason() {
        for verdict in [Verdict::Ask, Verdict::Deny] {
            for can_ask in [false, true] {
                let response = Response::decision(can_ask, verdict, "why".into());
                let out = render(PRE_TOOL_USE, &response).unwrap();
                assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
            }
        }
        let blank = Response::decision(CAN_ASK, Verdict::Deny, "  ".into());
        assert_eq!(
            render(PRE_TOOL_USE, &blank).unwrap()["hookSpecificOutput"]["permissionDecisionReason"],
            FALLBACK_REASON
        );
        let allow = Response::decision(CAN_ASK, Verdict::Allow, "x".into());
        assert_eq!(render(PRE_TOOL_USE, &allow), None);
        let deny = Response::decision(CAN_ASK, Verdict::Deny, "x".into());
        for event in ["PostToolUse", "Stop", "SubagentStop", "PermissionRequest"] {
            assert_eq!(render(event, &deny), None, "{event}");
        }
    }

    #[test]
    fn hooks_file_registers_every_handled_event_without_fail_closed_keys() {
        let doc = hooks_file("x");
        let hooks = doc["hooks"].as_object().unwrap();
        for event in [
            "PreToolUse",
            "PostToolUse",
            "PermissionRequest",
            "UserPromptSubmit",
            "SessionStart",
            "SessionEnd",
            "SubagentStart",
            "SubagentStop",
            "Stop",
        ] {
            let entry = &hooks[event][0];
            assert!(entry.get("matcher").is_none(), "{event}");
            let handler = &entry["hooks"][0];
            assert_eq!(handler["command"], "x");
            assert_eq!(handler["type"], "command");
            // Async handlers cannot block; Codex ignores onFailure.
            assert!(handler.get("async").is_none() && handler.get("onFailure").is_none());
        }
        assert_eq!(hooks.len(), 9);
        assert!(doc["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"].as_u64() <= Some(3));
    }

    #[test]
    fn execpolicy_rules_forbid_nested_codex_only() {
        let rules = execpolicy_rules();
        assert_eq!(rules.matches("prefix_rule(").count(), 4);
        assert_eq!(rules.matches("decision = \"forbidden\"").count(), 4);
        assert!(!rules.contains("\"allow\"") && !rules.contains("\"prompt\""));
        // Parenthesized Starlark calls must balance.
        assert_eq!(rules.matches('(').count(), rules.matches(')').count());
        assert_eq!(rules.matches('[').count(), rules.matches(']').count());
    }
}
