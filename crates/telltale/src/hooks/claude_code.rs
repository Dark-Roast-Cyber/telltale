//! Claude Code adapter: native hook stdin payload -> runtime event, and
//! runtime response -> native hook stdout.
//!
//! Contract evidence: payloads captured from Claude Code 2.1.318 in
//! tests/fixtures/claude-code/2.1.318 and docs/harnesses/claude-code.md.
//! Unknown fields are ignored so newer harness versions keep working.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::hooks::runtime::{Completion, Context, Event, Response, SettledCall, ToolCall};
use crate::hooks::state::Verdict;

pub const HARNESS: &str = "claude-code";
/// The pre-execution hook event: the only enforcement point.
pub const PRE_TOOL_USE: &str = "PreToolUse";
/// A hook `ask` is put to the user, and declined in headless `-p` (verified
/// in 2.1.318, docs/harnesses/claude-code.md). The registry and every
/// per-event `Context` read this one value.
pub const CAN_ASK: bool = true;

#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    pub hook_event_name: String,
    pub session_id: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub permission_mode: Option<String>,
    #[serde(default)]
    pub prompt_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<Value>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub tool_response: Option<Value>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub is_interrupt: Option<bool>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub tool_calls: Option<Vec<BatchCall>>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BatchCall {
    pub tool_name: String,
    pub tool_use_id: String,
    #[serde(default)]
    pub tool_response: Option<Value>,
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

/// Whether an unparseable payload names the PreToolUse event. Claude Code
/// writes `hook_event_name` before `tool_input`, so the prefix suffices.
pub fn looks_like_pre_tool_use(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(64 * 1024)];
    let text = String::from_utf8_lossy(head);
    let key = "\"hook_event_name\"";
    text.match_indices(key).any(|(at, _)| {
        let rest = text[at + key.len()..].trim_start();
        rest.strip_prefix(':')
            .map(str::trim_start)
            .is_some_and(|value| value.starts_with("\"PreToolUse\""))
    })
}

/// Text a tool result contributed, in the shape Telltale's `tool_result`
/// target reads. Bash results join stdout and stderr; Read results use the
/// file content; anything else is compact JSON.
pub fn result_text(response: &Value) -> String {
    match response {
        Value::String(text) => text.clone(),
        Value::Object(map) => {
            if map.contains_key("stdout") || map.contains_key("stderr") {
                let stdout = map.get("stdout").and_then(Value::as_str).unwrap_or("");
                let stderr = map.get("stderr").and_then(Value::as_str).unwrap_or("");
                return match (stdout.is_empty(), stderr.is_empty()) {
                    (_, true) => stdout.to_owned(),
                    (true, false) => stderr.to_owned(),
                    (false, false) => format!("{stdout}\n{stderr}"),
                };
            }
            if let Some(content) = map
                .get("file")
                .and_then(|file| file.get("content"))
                .and_then(Value::as_str)
            {
                return content.to_owned();
            }
            if let Some(Value::Array(parts)) = map.get("content") {
                let text: Vec<&str> = parts
                    .iter()
                    .filter_map(|part| part.get("text").and_then(Value::as_str))
                    .collect();
                if !text.is_empty() {
                    return text.join("\n");
                }
            }
            response.to_string()
        }
        other => other.to_string(),
    }
}

fn tool_call(input: &HookInput) -> Result<ToolCall, ParseError> {
    Ok(ToolCall {
        tool_use_id: input.tool_use_id.clone(),
        tool_name: input
            .tool_name
            .clone()
            .ok_or(ParseError::MissingField("tool_name"))?,
        input: input.tool_input.clone().unwrap_or(Value::Null),
    })
}

pub fn to_event(input: &HookInput) -> Result<(Context, Event), ParseError> {
    let ctx = Context {
        harness: HARNESS,
        hook_event: input.hook_event_name.clone(),
        session_id: input.session_id.clone(),
        agent_id: input.agent_id.clone(),
        agent_type: input.agent_type.clone(),
        prompt_id: input.prompt_id.clone(),
        permission_mode: input.permission_mode.clone(),
        cwd: input.cwd.clone(),
        can_ask: CAN_ASK,
    };
    let event = match input.hook_event_name.as_str() {
        "PreToolUse" => Event::ToolRequested(tool_call(input)?),
        "PostToolUse" => Event::ToolFinished {
            call: tool_call(input)?,
            completion: Completion::Completed,
            result_text: input
                .tool_response
                .as_ref()
                .map(result_text)
                .unwrap_or_default(),
            duration_ms: input.duration_ms,
        },
        "PostToolUseFailure" => Event::ToolFinished {
            call: tool_call(input)?,
            completion: if input.is_interrupt == Some(true) {
                Completion::Interrupted
            } else {
                Completion::Failed
            },
            result_text: input.error.clone().unwrap_or_default(),
            duration_ms: input.duration_ms,
        },
        "PostToolBatch" => Event::BatchSettled(
            input
                .tool_calls
                .iter()
                .flatten()
                .map(|call| SettledCall {
                    tool_use_id: call.tool_use_id.clone(),
                    tool_name: call.tool_name.clone(),
                    result_text: call
                        .tool_response
                        .as_ref()
                        .map(result_text)
                        .unwrap_or_default(),
                })
                .collect(),
        ),
        "PermissionRequest" => Event::PermissionPrompt(tool_call(input)?),
        // Auto mode's classifier denied the call (documented shape: tool_name,
        // tool_input, tool_use_id, reason, mcp_server for MCP tools). It fires
        // only for classifier denials, never for a hook deny or a deny rule,
        // so the call did not run: settle it like a one-call batch.
        "PermissionDenied" => Event::BatchSettled(vec![SettledCall {
            tool_use_id: input
                .tool_use_id
                .clone()
                .ok_or(ParseError::MissingField("tool_use_id"))?,
            tool_name: input
                .tool_name
                .clone()
                .ok_or(ParseError::MissingField("tool_name"))?,
            result_text: input.reason.clone().unwrap_or_default(),
        }]),
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
        "SubagentStop" => Event::SubagentStop {
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

/// Native stdout for a response, or `None` to print nothing (exit 0, no opinion).
///
/// `allow` is never emitted: a PreToolUse `allow` would skip Claude Code's
/// own permission prompts, and this hook must only ever add restrictions.
pub fn render(hook_event: &str, response: &Response) -> Option<Value> {
    match response {
        Response::None => None,
        Response::Decision(decision) if hook_event == "PreToolUse" => {
            let permission = match decision.verdict() {
                Verdict::Deny => "deny",
                Verdict::Ask => "ask",
                Verdict::Allow => return None,
            };
            Some(json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": permission,
                    "permissionDecisionReason": decision.reason(),
                }
            }))
        }
        Response::Decision { .. } => None,
        Response::AdditionalContext(text)
            if hook_event == "PostToolUse" || hook_event == "PostToolUseFailure" =>
        {
            Some(json!({
                "hookSpecificOutput": {
                    "hookEventName": hook_event,
                    "additionalContext": text,
                }
            }))
        }
        Response::AdditionalContext(_) => None,
    }
}

/// The settings fragment that registers this hook for every event it handles.
///
/// With `fail_closed`, the PreToolUse hook entry carries `onFailure: "block"`,
/// so a crash, timeout or missing binary blocks the tool call instead of
/// letting it run. Verified against Claude Code 2.1.318: the key is honored on
/// the hook entry and ignored at matcher level (docs/harnesses/claude-code.md).
pub fn settings_fragment(command: &str, fail_closed: bool) -> Value {
    let hook = |timeout: u64, block: bool| {
        let mut entry = json!({"type": "command", "command": command, "timeout": timeout});
        if block {
            entry["onFailure"] = json!("block");
        }
        json!([entry])
    };
    let tool = |timeout: u64, block: bool| json!([{"matcher": "*", "hooks": hook(timeout, block)}]);
    let plain = |timeout: u64| json!([{"hooks": hook(timeout, false)}]);
    json!({
        "hooks": {
            "PreToolUse": tool(30, fail_closed),
            "PostToolUse": tool(30, false),
            "PostToolUseFailure": tool(30, false),
            "PostToolBatch": plain(30),
            "PermissionRequest": tool(10, false),
            "PermissionDenied": tool(10, false),
            "UserPromptSubmit": plain(10),
            "SessionStart": plain(10),
            "SessionEnd": plain(10),
            "SubagentStart": plain(10),
            "SubagentStop": plain(10),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_results_join_streams() {
        let response = json!({"stdout": "out", "stderr": "err", "interrupted": false});
        assert_eq!(result_text(&response), "out\nerr");
        assert_eq!(result_text(&json!({"stdout": "", "stderr": ""})), "");
    }

    #[test]
    fn read_results_use_file_content() {
        let response = json!({"type": "text", "file": {"filePath": "/x", "content": "hello\n"}});
        assert_eq!(result_text(&response), "hello\n");
    }

    /// Shape from the Claude Code hooks reference (not yet captured here: the
    /// auto-mode classifier allowed every headless probe, see
    /// scripts/hooks/harness results). Unknown fields such as `mcp_server` are ignored.
    #[test]
    fn permission_denied_settles_the_call_without_a_result() {
        let payload = json!({
            "session_id": "s", "cwd": "/w", "permission_mode": "auto",
            "hook_event_name": "PermissionDenied", "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /tmp/build"}, "tool_use_id": "toolu_pd",
            "reason": "[Irreversible Local Destruction]",
            "mcp_server": {"name": "x", "source": "dynamic"}
        });
        let input = parse(&serde_json::to_vec(&payload).unwrap()).unwrap();
        let (_, event) = to_event(&input).unwrap();
        match event {
            Event::BatchSettled(calls) => {
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0].tool_use_id, "toolu_pd");
                assert_eq!(calls[0].result_text, "[Irreversible Local Destruction]");
            }
            other => panic!("{other:?}"),
        }
        assert!(settings_fragment("x", false)["hooks"]["PermissionDenied"].is_array());
    }

    #[test]
    fn allow_is_never_rendered() {
        let response = Response::decision(CAN_ASK, Verdict::Allow, "x".into());
        assert_eq!(render("PreToolUse", &response), None);
        assert_eq!(render("PreToolUse", &Response::None), None);
    }

    #[test]
    fn deny_renders_hook_specific_output() {
        let response = Response::decision(CAN_ASK, Verdict::Deny, "because".into());
        let out = render("PreToolUse", &response).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(out["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        // Decisions are meaningless outside PreToolUse and are not rendered there.
        assert_eq!(render("PostToolUse", &response), None);
    }

    #[test]
    fn fail_closed_marks_only_the_pre_tool_use_hook_entry() {
        let open = settings_fragment("x", false);
        assert!(
            open["hooks"]["PreToolUse"][0]["hooks"][0]
                .get("onFailure")
                .is_none()
        );
        let closed = settings_fragment("x", true);
        assert_eq!(
            closed["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"],
            "block"
        );
        assert!(closed["hooks"]["PreToolUse"][0].get("onFailure").is_none());
        assert!(
            closed["hooks"]["PostToolUse"][0]["hooks"][0]
                .get("onFailure")
                .is_none()
        );
    }
}
