//! Harness registry: the one place that maps a harness name to its adapter.
//!
//! The CLI driver (`telltale hooks <harness> hook`) and the long-lived
//! evaluator dispatch through `Harness`, so they hold no adapter-specific
//! code. Adding a harness means one adapter module, one variant here, and its
//! match arms (docs/architecture.md, "Runtime contract for adapters").

use serde_json::Value;

use crate::hooks::claude_code;
use crate::hooks::codex_cli;
use crate::hooks::config::OnError;
use crate::hooks::copilot_cli;
use crate::hooks::runtime::{Context, Event, Response};
use crate::hooks::state::Verdict;

/// A harness with an adapter in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Harness {
    ClaudeCode,
    CodexCli,
    CopilotCli,
}

/// A native hook payload as the adapter understood it.
// One short-lived value per hook event; boxing the common case buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Parsed {
    /// A runtime event for the runtime to handle.
    Event(Context, Event),
    /// The hook event is known, but the payload is not a usable event (for
    /// example a tool call without a tool name).
    Unusable {
        hook_event: String,
        code: &'static str,
    },
    /// Not a payload this adapter can read at all.
    Invalid(&'static str),
}

impl Harness {
    /// Every harness in this build.
    pub const ALL: &'static [Harness] =
        &[Harness::ClaudeCode, Harness::CodexCli, Harness::CopilotCli];

    /// The name used on the command line, on the evaluator wire protocol and
    /// in `Context::harness`.
    pub fn name(self) -> &'static str {
        match self {
            Self::ClaudeCode => claude_code::HARNESS,
            Self::CodexCli => codex_cli::HARNESS,
            Self::CopilotCli => copilot_cli::HARNESS,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|harness| harness.name() == name)
    }

    /// Native hook stdin to a runtime event.
    ///
    /// Copilot CLI also runs a trusted repository's `.claude/settings.json`
    /// hooks, with its own payloads: the Claude Code entry point hands those
    /// to the Copilot CLI adapter, so they are labeled, correlated and
    /// rendered as Copilot's (`copilot_cli::is_copilot_payload`).
    pub fn parse(self, bytes: &[u8]) -> Parsed {
        match self {
            Self::ClaudeCode if copilot_cli::is_copilot_payload(bytes) => {
                Self::CopilotCli.parse(bytes)
            }
            Self::ClaudeCode => match claude_code::parse(bytes) {
                Err(error) => Parsed::Invalid(error.code()),
                Ok(input) => match claude_code::to_event(&input) {
                    Ok((ctx, event)) => Parsed::Event(ctx, event),
                    Err(error) => Parsed::Unusable {
                        hook_event: input.hook_event_name,
                        code: error.code(),
                    },
                },
            },
            Self::CodexCli => match codex_cli::parse(bytes) {
                Err(error) => Parsed::Invalid(error.code()),
                Ok(input) => match codex_cli::to_event(&input) {
                    Ok((ctx, event)) => Parsed::Event(ctx, event),
                    Err(error) => Parsed::Unusable {
                        hook_event: input.hook_event_name,
                        code: error.code(),
                    },
                },
            },
            Self::CopilotCli => match copilot_cli::parse(bytes) {
                Err(error) => Parsed::Invalid(error.code()),
                Ok(input) => match copilot_cli::to_event(&input) {
                    Ok((ctx, event)) => Parsed::Event(ctx, event),
                    Err(error) => Parsed::Unusable {
                        hook_event: input.hook_event(),
                        code: error.code(),
                    },
                },
            },
        }
    }

    /// Native stdout JSON for a response, or `None` to print nothing. Never
    /// renders a pre-execution `allow`.
    pub fn render(self, hook_event: &str, response: &Response) -> Option<Value> {
        match self {
            // A routed Copilot payload (see `parse`) keeps its native event
            // name. Copilot honors Claude Code's output on its PascalCase
            // events, and its camelCase names never collide with Claude Code's.
            Self::ClaudeCode if copilot_cli::is_camel_case_event(hook_event) => {
                copilot_cli::render(hook_event, response)
            }
            Self::ClaudeCode => claude_code::render(hook_event, response),
            Self::CodexCli => codex_cli::render(hook_event, response),
            Self::CopilotCli => copilot_cli::render(hook_event, response),
        }
    }

    /// Whether `hook_event` is the harness's pre-execution enforcement point.
    pub fn is_pre_tool_use(self, hook_event: &str) -> bool {
        match self {
            Self::ClaudeCode => {
                hook_event == claude_code::PRE_TOOL_USE || hook_event == copilot_cli::PRE_TOOL_USE
            }
            Self::CodexCli => hook_event == codex_cli::PRE_TOOL_USE,
            Self::CopilotCli => copilot_cli::is_pre_tool_use(hook_event),
        }
    }

    /// Whether a payload that could not be parsed still names the
    /// pre-execution event, so it gets a verdict rather than a non-blocking
    /// error the harness would treat as allow.
    pub fn looks_like_pre_tool_use(self, bytes: &[u8]) -> bool {
        match self {
            Self::ClaudeCode => claude_code::looks_like_pre_tool_use(bytes),
            Self::CodexCli => codex_cli::looks_like_pre_tool_use(bytes),
            Self::CopilotCli => copilot_cli::looks_like_pre_tool_use(bytes),
        }
    }

    /// Whether a returned `ask` is put to a human on this harness in every
    /// run mode. This serves the payload-less path, which knows no run mode,
    /// so it must be `false` for a harness where *any* run mode auto-approves
    /// or ignores an ask (OpenCode v2 `--auto`, Codex). The adapter sets
    /// `Context::can_ask` per event from the same constant and may only
    /// refine it to `true` for a run mode verified to prompt or refuse.
    pub fn can_ask(self) -> bool {
        match self {
            Self::ClaudeCode => claude_code::CAN_ASK,
            Self::CodexCli => codex_cli::CAN_ASK,
            Self::CopilotCli => copilot_cli::CAN_ASK,
        }
    }

    /// Native stdout answering a pre-execution event with a policy verdict
    /// when no parsed payload is available. `allow` prints nothing, and an
    /// `ask` on a harness that cannot ask is rendered as `deny`
    /// (`Response::decision`).
    pub fn render_verdict(self, policy: OnError, reason: &str) -> Option<Value> {
        let hook_event = match self {
            Self::ClaudeCode => claude_code::PRE_TOOL_USE,
            Self::CodexCli => codex_cli::PRE_TOOL_USE,
            Self::CopilotCli => copilot_cli::PRE_TOOL_USE,
        };
        self.render_event_verdict(hook_event, policy, reason)
    }

    /// [`Self::render_verdict`] for a pre-execution event whose name is known,
    /// so a Copilot camelCase event that reached the Claude Code entry point
    /// gets the form Copilot honors.
    pub fn render_event_verdict(
        self,
        hook_event: &str,
        policy: OnError,
        reason: &str,
    ) -> Option<Value> {
        let verdict = match policy {
            OnError::Allow => return None,
            OnError::Ask => Verdict::Ask,
            OnError::Deny => Verdict::Deny,
        };
        self.render(
            hook_event,
            &Response::decision(self.can_ask(), verdict, reason.to_owned()),
        )
    }
}

/// Whether an unparseable payload names its event: a complete, non-empty string
/// in a top-level `hook_event_name` or `hookName`, in the prefix that
/// `looks_like_pre_tool_use` also reads. Only the top level counts, because a
/// tool input is agent-controlled and may nest a key of the same name.
pub fn names_event(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(64 * 1024)];
    // The quote closing the string opened at `open`, if the prefix holds it.
    let close = |open: usize| {
        let mut at = open + 1;
        while at < head.len() {
            match head[at] {
                b'\\' => at += 2,
                b'"' => return Some(at),
                _ => at += 1,
            }
        }
        None
    };
    let (mut depth, mut at) = (0usize, 0usize);
    while at < head.len() {
        match head[at] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth = depth.saturating_sub(1),
            b'"' => {
                let Some(end) = close(at) else {
                    return false;
                };
                let key = &head[at + 1..end];
                if depth == 1 && (key == b"hook_event_name" || key == b"hookName") {
                    let value = head[end + 1..]
                        .trim_ascii_start()
                        .strip_prefix(b":")
                        .map(<[u8]>::trim_ascii_start);
                    if let Some(value) = value
                        && value.first() == Some(&b'"')
                    {
                        let open = head.len() - value.len();
                        if close(open).is_some_and(|end| end > open + 1) {
                            return true;
                        }
                    }
                }
                at = end;
            }
            _ => {}
        }
        at += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Normalization is keyed by `Context::harness`, which adapters set to
    /// `Harness::name()`. Every registry variant must map to the
    /// `normalize` constant for its harness (or to `None` when the harness
    /// is the identity), so a rename on either side cannot silently stop
    /// normalization. The match is exhaustive: a new variant fails to
    /// compile until it is classified here.
    #[test]
    fn registry_names_match_normalize_constants() {
        use crate::hooks::normalize;
        use crate::hooks::runtime::ToolCall;
        for harness in Harness::ALL {
            let constant: Option<&str> = match harness {
                Harness::ClaudeCode => None,
                Harness::CodexCli => Some(normalize::CODEX_CLI),
                Harness::CopilotCli => Some(normalize::COPILOT_CLI),
            };
            match constant {
                Some(constant) => assert_eq!(harness.name(), constant),
                None => {
                    let call = ToolCall {
                        tool_use_id: None,
                        tool_name: "apply_patch".into(),
                        input: json!({"command": "*** Begin Patch\n*** Add File: x\n+1\n*** End Patch\n"}),
                    };
                    assert_eq!(
                        normalize::tool_call(harness.name(), call.clone()),
                        call,
                        "{} is not the identity",
                        harness.name()
                    );
                }
            }
        }
        // Every normalize constant names a harness that is, or will be, in
        // the registry under exactly that name (checked above once added).
        for constant in [
            normalize::COPILOT_CLI,
            normalize::CODEX_CLI,
            normalize::OPENCODE,
        ] {
            if let Some(harness) = Harness::from_name(constant) {
                assert_eq!(harness.name(), constant);
            }
        }
    }

    #[test]
    fn names_round_trip() {
        for harness in Harness::ALL {
            assert_eq!(Harness::from_name(harness.name()), Some(*harness));
        }
        assert_eq!(Harness::from_name("claude-code"), Some(Harness::ClaudeCode));
        assert_eq!(Harness::from_name("copilot-cli"), Some(Harness::CopilotCli));
        assert_eq!(Harness::from_name("Claude-Code"), None);
        assert_eq!(Harness::from_name("codex-cli"), Some(Harness::CodexCli));
        assert_eq!(Harness::from_name("opencode"), None);
        assert_eq!(Harness::from_name(""), None);
    }

    #[test]
    fn claude_code_parse_distinguishes_unusable_from_invalid() {
        let harness = Harness::ClaudeCode;
        let pre = json!({
            "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_use_id": "t", "tool_input": {"command": "ls"}
        });
        match harness.parse(pre.to_string().as_bytes()) {
            Parsed::Event(ctx, Event::ToolRequested(call)) => {
                assert_eq!(ctx.harness, "claude-code");
                assert!(harness.is_pre_tool_use(&ctx.hook_event));
                assert_eq!(call.tool_name, "Bash");
            }
            other => panic!("{other:?}"),
        }
        let missing = json!({"session_id": "s", "hook_event_name": "PreToolUse"});
        match harness.parse(missing.to_string().as_bytes()) {
            Parsed::Unusable { hook_event, code } => {
                assert_eq!(hook_event, "PreToolUse");
                assert_eq!(code, "payload_missing_field");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            harness.parse(b"not json"),
            Parsed::Invalid("payload_invalid_json")
        ));
        assert!(!harness.is_pre_tool_use("PostToolUse"));
    }

    #[test]
    fn verdicts_without_a_payload_never_allow() {
        let harness = Harness::ClaudeCode;
        assert_eq!(harness.render_verdict(OnError::Allow, "r"), None);
        for (policy, decision) in [(OnError::Ask, "ask"), (OnError::Deny, "deny")] {
            assert_eq!(
                harness.render_verdict(policy, "why"),
                Some(json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": decision,
                        "permissionDecisionReason": "why",
                    }
                }))
            );
        }
    }

    #[test]
    fn codex_verdicts_without_a_payload_are_deny_or_nothing() {
        let harness = Harness::CodexCli;
        assert!(!harness.can_ask());
        assert_eq!(harness.render_verdict(OnError::Allow, "r"), None);
        for policy in [OnError::Ask, OnError::Deny] {
            let out = harness.render_verdict(policy, "why").unwrap();
            assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
            assert_eq!(out["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        }
        assert!(harness.looks_like_pre_tool_use(
            br#"{"session_id":"s","turn_id":"t","cwd":"/w","hook_event_name":"PreToolUse","tool_input":{"#
        ));
    }

    #[test]
    fn unparseable_pre_tool_use_is_recognized_from_its_prefix() {
        let harness = Harness::ClaudeCode;
        assert!(harness.looks_like_pre_tool_use(
            br#"{"session_id":"s","hook_event_name" : "PreToolUse","tool_input":{"#
        ));
        assert!(!harness.looks_like_pre_tool_use(br#"{"hook_event_name":"PostToolUse""#));
        assert!(!harness.looks_like_pre_tool_use(b"not json"));
    }
}
