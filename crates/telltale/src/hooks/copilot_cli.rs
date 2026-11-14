//! GitHub Copilot CLI adapter: native hook stdin payload -> runtime event, and
//! runtime response -> native hook stdout.
//!
//! Contract evidence: payloads captured from Copilot CLI 1.0.105 in
//! tests/fixtures/copilot-cli/1.0.105 and docs/harnesses/copilot-cli.md.
//! Unknown fields are ignored so newer harness versions keep working.
//!
//! Copilot speaks two dialects, selected by the casing of the registered event
//! name: camelCase (`preToolUse`: `sessionId`, `toolName`, `toolArgs`) and
//! PascalCase (`PreToolUse`: `hook_event_name`, `session_id`, `tool_name`,
//! `tool_input`, Claude tool names but Copilot argument keys). Some payloads
//! mix them (`permissionRequest`, `SubagentStart`), so every field is read
//! under both spellings. A camelCase payload does not name its event; the
//! event is inferred from the top-level keys Copilot sets (never from tool
//! arguments), and a tool payload that is not positively a post event is a
//! `preToolUse` (see [`hook_event`]).
//!
//! There is no call ID: the correlation key is
//! [`runtime::synthetic_call_id`] over the raw tool arguments, which post
//! events repeat. Inside a subagent `sessionId` is the subagent's ID, so the
//! session is `parentAgentId` when present and the subagent is `agent_id`.
//! Tool names and inputs are passed through as reported; the runtime owns
//! input normalization.

use serde_json::{Map, Value, json};

use crate::hooks::runtime::{self, Completion, Context, Event, Response, ToolCall};
use crate::hooks::state::Verdict;

pub const HARNESS: &str = "copilot-cli";
/// The pre-execution hook event in the camelCase dialect.
pub const PRE_TOOL_USE: &str = "preToolUse";
/// The pre-execution hook event in the PascalCase dialect (also what
/// Copilot sends to a repository's `.claude/settings.json` hooks).
pub const PASCAL_PRE_TOOL_USE: &str = "PreToolUse";
/// A hook `ask` is shown to the user in an interactive session and refused
/// in `-p` and autopilot ("unable to ask user for confirmation"), with or
/// without `--allow-all-tools` and `--yolo` (verified in 1.0.105, see
/// docs/harnesses/copilot-cli.md). The registry and every per-event
/// `Context` read this one value.
pub const CAN_ASK: bool = true;
/// [`HookInput::hook_event`] for a payload that names no event and matches none.
const UNRECOGNIZED: &str = "unknown";

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

/// One hook payload, in either dialect.
#[derive(Debug, Clone)]
pub struct HookInput {
    fields: Map<String, Value>,
}

pub fn parse(bytes: &[u8]) -> Result<HookInput, ParseError> {
    match serde_json::from_slice(bytes) {
        Ok(Value::Object(fields)) => Ok(HookInput { fields }),
        _ => Err(ParseError::Json),
    }
}

impl HookInput {
    fn get(&self, keys: &[&str]) -> Option<&Value> {
        keys.iter().find_map(|key| self.fields.get(*key))
    }

    fn has(&self, keys: &[&str]) -> bool {
        self.get(keys).is_some()
    }

    fn text(&self, keys: &[&str]) -> Option<String> {
        self.get(keys)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    }

    /// The registered event name: named by PascalCase payloads
    /// (`hook_event_name`) and `permissionRequest` (`hookName`), inferred
    /// from the top-level keys otherwise. Inference fails safe: a tool
    /// payload without a result or an error is a `preToolUse`.
    pub fn hook_event(&self) -> String {
        if let Some(name) = self.text(&["hook_event_name", "hookName"]) {
            return name;
        }
        let name = if self.has(&["toolName", "tool_name"]) {
            if self.has(&["toolResult", "tool_result"]) {
                "postToolUse"
            } else if self.has(&["error"]) {
                "postToolUseFailure"
            } else {
                PRE_TOOL_USE
            }
        } else if self.has(&["agentName", "agent_name"]) {
            if self.has(&["stopReason", "stop_reason"]) {
                "subagentStop"
            } else {
                "subagentStart"
            }
        } else if self.has(&["stopReason", "stop_reason"]) {
            "agentStop"
        } else if self.has(&["transformedPrompt"]) {
            "userPromptTransformed"
        } else if self.has(&["prompt"]) {
            "userPromptSubmitted"
        } else if self.has(&["source"]) {
            "sessionStart"
        } else if self.has(&["reason"]) {
            "sessionEnd"
        } else {
            UNRECOGNIZED
        };
        name.to_owned()
    }
}

/// Whether a payload handed to the Claude Code entry point came from Copilot
/// CLI, which also runs a trusted repository's `.claude/settings.json`
/// hooks. Every Copilot payload carries `timestamp` (milliseconds or ISO
/// 8601) and none carries a call or turn ID; Claude Code 2.1.318 sends
/// neither `timestamp` nor `sessionId`, and sends `tool_use_id` on tool
/// events and `prompt_id` on every event but `SessionStart`. A
/// `sessionId` payload cannot be read by the Claude Code adapter at all.
pub fn is_copilot_payload(bytes: &[u8]) -> bool {
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    fields.contains_key("sessionId")
        || (fields.contains_key("timestamp")
            && !fields.contains_key("tool_use_id")
            && !fields.contains_key("prompt_id"))
}

/// Whether `hook_event` is a camelCase (Copilot-native) event name. Claude
/// Code's event names are all PascalCase, so these never collide.
pub fn is_camel_case_event(hook_event: &str) -> bool {
    hook_event.starts_with(|c: char| c.is_ascii_lowercase())
}

/// Whether `hook_event` is the pre-execution event in either dialect.
pub fn is_pre_tool_use(hook_event: &str) -> bool {
    hook_event == PRE_TOOL_USE || hook_event == PASCAL_PRE_TOOL_USE
}

/// Whether an unparseable payload is a pre-execution event. A PascalCase
/// payload names it first (`hook_event_name`). A camelCase tool payload does
/// not, and a prefix cannot tell a `preToolUse` from a post event whose
/// result follows the (possibly huge) arguments, so any payload whose first
/// identifying key is `toolName` counts as one: a verdict on a post event
/// is ignored, a missed pre-execution verdict is not.
pub fn looks_like_pre_tool_use(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(64 * 1024)];
    let text = String::from_utf8_lossy(head);
    let at = |key: &str| text.find(key).unwrap_or(usize::MAX);
    let tool = at("\"toolName\"");
    if tool < at("\"hook_event_name\"") && tool < at("\"hookName\"") {
        return true;
    }
    crate::hooks::claude_code::looks_like_pre_tool_use(bytes)
}

/// The text a tool result gave the model: `textResultForLlm` (camelCase) or
/// `text_result_for_llm` (PascalCase), else the compact JSON.
fn result_text(result: &Value) -> String {
    match result {
        Value::String(text) => text.clone(),
        Value::Object(map) => map
            .get("textResultForLlm")
            .or_else(|| map.get("text_result_for_llm"))
            .and_then(Value::as_str)
            .map_or_else(|| result.to_string(), str::to_owned),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn to_event(input: &HookInput) -> Result<(Context, Event), ParseError> {
    let hook_event = input.hook_event();
    let session_id = input
        .text(&["parentAgentId", "parent_agent_id"])
        .or_else(|| input.text(&["sessionId", "session_id"]))
        .ok_or(ParseError::MissingField("sessionId"))?;
    let agent_id = input.text(&["agentId", "agent_id"]);
    let agent_type = input.text(&["agentType", "agent_type"]);
    let tool_call = |correlate: bool| -> Result<ToolCall, ParseError> {
        let tool_name = input
            .text(&["toolName", "tool_name"])
            .ok_or(ParseError::MissingField("toolName"))?;
        let args = input
            .get(&["toolArgs", "tool_input", "toolInput"])
            .cloned()
            .unwrap_or(Value::Null);
        // `permissionRequest` carries a different input shape (`toolInput`
        // without `description`, edits as diffs), so a key over it would
        // never match the call's: it gets none.
        let tool_use_id = correlate.then(|| {
            runtime::synthetic_call_id(&session_id, agent_id.as_deref(), &tool_name, &args)
        });
        Ok(ToolCall {
            tool_use_id,
            tool_name,
            input: args,
        })
    };
    let event = match hook_event.as_str() {
        "preToolUse" | "PreToolUse" => Event::ToolRequested(tool_call(true)?),
        "postToolUse" | "PostToolUse" => Event::ToolFinished {
            call: tool_call(true)?,
            completion: Completion::Completed,
            result_text: input
                .get(&["toolResult", "tool_result"])
                .map(result_text)
                .unwrap_or_default(),
            duration_ms: None,
        },
        "postToolUseFailure" | "PostToolUseFailure" => Event::ToolFinished {
            call: tool_call(true)?,
            completion: Completion::Failed,
            result_text: input.get(&["error"]).map(result_text).unwrap_or_default(),
            duration_ms: None,
        },
        // Post events of a turn arrive before its stop (every capture).
        "agentStop" | "Stop" => Event::TurnSettled,
        "permissionRequest" | "PermissionRequest" => Event::PermissionPrompt(tool_call(false)?),
        // Inside a subagent the "user prompt" is the task prompt the parent
        // model wrote: not user input, so it is not journaled as such.
        "userPromptSubmitted" | "UserPromptSubmit" if agent_id.is_none() => Event::UserPrompt {
            prompt: input.text(&["prompt"]).unwrap_or_default(),
        },
        "sessionStart" | "SessionStart" => Event::SessionStart {
            source: input.text(&["source"]),
        },
        "sessionEnd" | "SessionEnd" => Event::SessionEnd {
            reason: input.text(&["reason"]),
        },
        "subagentStart" | "SubagentStart" => Event::SubagentStart {
            agent_id: agent_id
                .clone()
                .ok_or(ParseError::MissingField("agentId"))?,
            agent_type: agent_type.clone(),
        },
        "subagentStop" | "SubagentStop" => Event::SubagentStop {
            agent_id: agent_id
                .clone()
                .ok_or(ParseError::MissingField("agentId"))?,
            agent_type: agent_type.clone(),
        },
        // Nameless and unlike any payload Copilot sends: it could be a
        // preToolUse whose fields changed, so exit non-zero (Copilot blocks a
        // preToolUse on that) rather than answer it as a lifecycle event.
        UNRECOGNIZED => return Err(ParseError::MissingField("event")),
        _ => Event::Other,
    };
    let ctx = Context {
        harness: HARNESS,
        hook_event,
        session_id,
        agent_id,
        agent_type,
        // Copilot has no turn ID and no permission mode.
        prompt_id: None,
        permission_mode: None,
        cwd: input.text(&["cwd"]),
        can_ask: CAN_ASK,
    };
    Ok((ctx, event))
}

/// Native stdout for a response, or `None` to print nothing (exit 0, no
/// opinion).
///
/// A pre-execution decision is the flat `permissionDecision` object, the one
/// form Copilot honors on both dialects; Claude's `hookSpecificOutput` is
/// ignored on camelCase events (the call ran). `allow` is never emitted: a
/// Copilot hook `allow` overrides the harness's own permissions, even
/// `--deny-tool`.
pub fn render(hook_event: &str, response: &Response) -> Option<Value> {
    match response {
        Response::Decision(decision) if is_pre_tool_use(hook_event) => {
            let permission = match decision.verdict() {
                Verdict::Deny => "deny",
                Verdict::Ask => "ask",
                Verdict::Allow => return None,
            };
            Some(json!({
                "permissionDecision": permission,
                "permissionDecisionReason": decision.reason(),
            }))
        }
        Response::AdditionalContext(text)
            if matches!(
                hook_event,
                "postToolUse" | "PostToolUse" | "postToolUseFailure" | "PostToolUseFailure"
            ) =>
        {
            Some(json!({"additionalContext": text}))
        }
        Response::Decision(_) | Response::AdditionalContext(_) | Response::None => None,
    }
}

/// Default timeout for the tool events, which evaluate. Copilot lets a call
/// run when a hook times out, whatever the hook's failure policy, so this sits
/// well above the worst case: the evaluator's request deadline (10 s by
/// default), or a cold in-process pipeline build.
pub const TOOL_TIMEOUT_SECS: u64 = 60;
/// Lifecycle events do not evaluate.
pub const LIFECYCLE_TIMEOUT_SECS: u64 = 30;

/// The complete hook file (`version: 1`) that registers this hook for every
/// event it handles, in the camelCase dialect. Install it as
/// `$COPILOT_HOME/hooks/telltale-hooks.json` (user, default `~/.copilot`),
/// `.github/hooks/telltale-hooks.json` (repository), or a root-owned
/// `/etc/github-copilot/policy.d/telltale-hooks.json` (policy, which
/// `disableAllHooks` cannot turn off).
///
/// `command` is the cross-platform field (Copilot copies it to `bash` and
/// `powershell`). `permissionRequest` is not registered: it fires for every
/// call before Copilot's permission service, carries no decision we need, and
/// would add a process per call.
pub fn hooks_file(command: &str) -> Value {
    let hook =
        |timeout: u64| json!([{"type": "command", "command": command, "timeoutSec": timeout}]);
    json!({
        "version": 1,
        "hooks": {
            "preToolUse": hook(TOOL_TIMEOUT_SECS),
            "postToolUse": hook(TOOL_TIMEOUT_SECS),
            "postToolUseFailure": hook(TOOL_TIMEOUT_SECS),
            "agentStop": hook(LIFECYCLE_TIMEOUT_SECS),
            "subagentStart": hook(LIFECYCLE_TIMEOUT_SECS),
            "subagentStop": hook(LIFECYCLE_TIMEOUT_SECS),
            "userPromptSubmitted": hook(LIFECYCLE_TIMEOUT_SECS),
            "sessionStart": hook(LIFECYCLE_TIMEOUT_SECS),
            "sessionEnd": hook(LIFECYCLE_TIMEOUT_SECS),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_of(payload: Value) -> (Context, Event) {
        to_event(&parse(payload.to_string().as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn allow_is_never_rendered() {
        for event in [PRE_TOOL_USE, PASCAL_PRE_TOOL_USE] {
            let allow = Response::decision(CAN_ASK, Verdict::Allow, "x".into());
            assert_eq!(render(event, &allow), None);
            assert_eq!(render(event, &Response::None), None);
        }
    }

    #[test]
    fn decisions_render_flat_on_both_dialects_and_nowhere_else() {
        for event in [PRE_TOOL_USE, PASCAL_PRE_TOOL_USE] {
            for (verdict, word) in [(Verdict::Deny, "deny"), (Verdict::Ask, "ask")] {
                let response = Response::decision(true, verdict, "because".into());
                assert_eq!(
                    render(event, &response),
                    Some(
                        json!({"permissionDecision": word, "permissionDecisionReason": "because"})
                    )
                );
            }
        }
        let deny = Response::decision(CAN_ASK, Verdict::Deny, "x".into());
        for event in [
            "postToolUse",
            "PostToolUse",
            "agentStop",
            "permissionRequest",
        ] {
            assert_eq!(render(event, &deny), None, "{event}");
        }
    }

    #[test]
    fn additional_context_renders_on_post_events_only() {
        let context = Response::AdditionalContext("careful".into());
        for event in ["postToolUse", "PostToolUseFailure"] {
            assert_eq!(
                render(event, &context),
                Some(json!({"additionalContext": "careful"}))
            );
        }
        assert_eq!(render(PRE_TOOL_USE, &context), None);
    }

    #[test]
    fn a_subagent_call_belongs_to_the_parent_session() {
        let (ctx, event) = event_of(json!({
            "sessionId": "child", "timestamp": 1, "cwd": "/w", "toolName": "bash",
            "toolArgs": {"command": "ls"}, "agentId": "child", "agentType": "task",
            "parentAgentId": "root"
        }));
        assert_eq!(ctx.session_id, "root");
        assert_eq!(ctx.agent_id.as_deref(), Some("child"));
        assert_eq!(ctx.hook_event, PRE_TOOL_USE);
        let Event::ToolRequested(call) = event else {
            panic!("{event:?}")
        };
        assert_eq!(
            call.tool_use_id.unwrap(),
            runtime::synthetic_call_id("root", Some("child"), "bash", &json!({"command": "ls"}))
        );
    }

    #[test]
    fn a_subagent_task_prompt_is_not_a_user_prompt() {
        let (_, event) = event_of(json!({
            "sessionId": "child", "timestamp": 1, "prompt": "do it", "agentId": "child",
            "parentAgentId": "root"
        }));
        assert!(matches!(event, Event::Other), "{event:?}");
        let (_, event) = event_of(json!({"sessionId": "root", "timestamp": 1, "prompt": "do it"}));
        assert!(matches!(event, Event::UserPrompt { .. }), "{event:?}");
    }

    #[test]
    fn missing_identity_is_an_error() {
        let input = parse(br#"{"timestamp": 1, "toolName": "bash"}"#).unwrap();
        assert!(matches!(
            to_event(&input),
            Err(ParseError::MissingField("sessionId"))
        ));
        let input = parse(br#"{"sessionId": "s", "timestamp": 1, "toolArgs": {}}"#).unwrap();
        assert_eq!(input.hook_event(), "unknown");
        assert!(matches!(
            to_event(&input),
            Err(ParseError::MissingField("event"))
        ));
        assert!(matches!(parse(b"[1]"), Err(ParseError::Json)));
        assert!(matches!(parse(b"nope"), Err(ParseError::Json)));
    }

    #[test]
    fn unparseable_pre_tool_use_is_recognized_in_both_dialects() {
        assert!(looks_like_pre_tool_use(
            br#"{"sessionId":"s","timestamp":1,"cwd":"/w","toolName":"bash","toolArgs":{"#
        ));
        assert!(looks_like_pre_tool_use(
            br#"{"hook_event_name":"PreToolUse","session_id":"s","tool_input":{"#
        ));
        // Tool arguments cannot name a different event for a camelCase payload.
        assert!(looks_like_pre_tool_use(
            br#"{"sessionId":"s","toolName":"bash","toolArgs":{"command":"\"hook_event_name\":\"Stop\""#
        ));
        assert!(!looks_like_pre_tool_use(
            br#"{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Bash","tool_input":{"toolName":1"#
        ));
        assert!(!looks_like_pre_tool_use(
            br#"{"hookName":"permissionRequest","sessionId":"s","toolName":"bash""#
        ));
        assert!(!looks_like_pre_tool_use(b"not json"));
    }

    #[test]
    fn the_hooks_file_registers_camel_case_events_with_explicit_timeouts() {
        let file = hooks_file("telltale hooks copilot-cli hook");
        assert_eq!(file["version"], 1);
        let hooks = file["hooks"].as_object().unwrap();
        for (event, entries) in hooks {
            assert!(is_camel_case_event(event), "{event}");
            let entry = &entries[0];
            assert_eq!(entry["type"], "command");
            assert_eq!(entry["command"], "telltale hooks copilot-cli hook");
            assert!(entry["timeoutSec"].as_u64().unwrap() >= LIFECYCLE_TIMEOUT_SECS);
        }
        assert_eq!(hooks["preToolUse"][0]["timeoutSec"], TOOL_TIMEOUT_SECS);
        assert!(!hooks.contains_key("permissionRequest"));
    }
}
