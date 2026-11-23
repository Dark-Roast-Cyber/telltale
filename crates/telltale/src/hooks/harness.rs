//! Harness registry: the one place that maps a harness name to its adapter.
//!
//! Everything about one harness's hook protocol is in its adapter module under
//! `harnesses/`, which exports one [`Adapter`] descriptor. The CLI driver
//! (`telltale hooks <harness> hook`), the evaluator, the
//! generated self-protection rules and the install output all read that
//! descriptor through [`Harness::adapter`], so they hold no adapter-specific
//! code. Adding a harness means one adapter module, one variant here and one
//! arm in `adapter` (docs/hooks/architecture.md, "Adding an adapter"); the
//! compiler asks for every descriptor field.

use serde_json::Value;

use crate::ClientId;
use crate::hooks::config::{AskRoute, OnError};
use crate::hooks::harnesses::{claude_code, codex_cli, copilot_cli, opencode};
use crate::hooks::runtime::{Context, Event, Response};
use crate::hooks::state::Verdict;

/// A harness with an adapter in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Harness {
    ClaudeCode,
    CodexCli,
    CopilotCli,
    OpenCode,
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

/// Everything the rest of hooks needs to know about one harness. Fixed data
/// and function pointers only, so a descriptor is a `const` and a missing
/// field does not compile.
pub struct Adapter {
    /// The name used on the command line, on the evaluator wire protocol and
    /// in `Context::harness`: `<product>-<cli>`.
    pub name: &'static str,
    /// The product name, for listings and messages.
    pub display_name: &'static str,
    /// The Telltale client this harness is: the client of every Telltale
    /// record of its calls. Its evaluation windows are scanned as that
    /// client's hook journal, `client.hook_journal_source_id()`: host-fed,
    /// never discovered, accepted for this client only (ADR 0002 addendum).
    pub client: ClientId,
    /// The pre-execution (enforcement) event names this entry point receives.
    /// The first answers a tool call whose payload could not be read.
    pub pre_tool_use: &'static [&'static str],
    /// The top-level payload keys that name the hook event.
    pub event_keys: &'static [&'static str],
    /// Whether a returned `ask` is put to a human on this harness in every
    /// run mode. This serves the payload-less path, which knows no run mode,
    /// so it must be `false` for a harness where *any* run mode auto-approves
    /// or ignores an ask. The adapter sets `Context::can_ask` per event from
    /// the same value and may only refine it to `true` for a run mode
    /// verified to prompt or refuse.
    pub can_ask: bool,
    /// Whether the harness raises an event for the prompt of the person using
    /// it, so a grant line typed there reaches the hook as
    /// `Event::UserPrompt` (`Config::grants`). `false` where no such event
    /// exists or a model-written prompt could arrive as one. The adapter sets
    /// `Context::can_grant` per event from the same value.
    pub can_grant: bool,
    /// Native hook stdin to a runtime event.
    pub parse: fn(&[u8]) -> Parsed,
    /// Native stdout JSON for a response to `hook_event`, or `None` to print
    /// nothing. Never renders a pre-execution `allow`.
    pub render: fn(&str, &Response) -> Option<Value>,
    /// Whether a payload that could not be parsed still names the
    /// pre-execution event, so it gets a verdict rather than a non-blocking
    /// error the harness would treat as allow.
    pub looks_like_pre_tool_use: fn(&[u8]) -> bool,
    /// What `telltale hooks <name> settings` prints.
    pub install: Install,
    /// What blocks a tool call when the payload names no event and the
    /// policy for a call the hook could not read (the stricter of `on_error`
    /// and `on_unevaluable`) is `ask` or `deny`, or a configuration that asks
    /// for enforcement did not load.
    pub nameless_block: NamelessBlock,
    /// The environment variable that relocates the harness's config home, if
    /// it has one.
    pub home: Option<Home>,
    /// Where the rules that protect this harness's own hook files live.
    pub rules: HostRules,
    /// The program names an agent launches this harness by.
    pub launchers: &'static [&'static str],
    /// What can block a tool call on this harness without a verdict from the
    /// hook, one line each: what it does and how it comes to be installed.
    /// Each acts inside the harness, so neither `hooks.mode` nor
    /// `hooks.tamper_prevention` turns it on or off (`telltale hooks check`
    /// lists them).
    pub harness_protections: &'static [&'static str],
}

/// The install output of one harness.
pub struct Install {
    /// The `settings` lines of `telltale hooks --help`.
    pub usage: &'static str,
    /// The settings document for `command`. `Err` is why nothing can be
    /// printed for this request (a `--fail-closed` the harness cannot honor).
    pub output: fn(command: &str, fail_closed: bool) -> Result<InstallOutput, &'static str>,
}

/// A settings or hooks-file document, and notes for the operator's terminal.
pub struct InstallOutput {
    pub document: Value,
    pub notes: Option<&'static str>,
}

/// The answer to an unreadable payload that names no event, which could be a
/// tool call. It must block one without turning a stop event into a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamelessBlock {
    /// A deny on stdout, for a harness that honors it on a pre-execution
    /// event and rejects it as invalid output on every other event.
    DenyOnStdout,
    /// This exit status and nothing on stdout.
    Exit(i32),
}

/// A harness's relocatable config home. A harness moved there loads its hooks
/// from that directory, and static rules can only know the variable's name
/// and the default directory, so the engine generates rules for the resolved
/// path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Home {
    /// The environment variable, as the hook inherits it from the harness.
    pub variable: &'static str,
    /// Pattern text for the hook files below the home, the same names as the
    /// harness's static rules. `{{NAME_END}}` stands for the end of a name.
    pub hook_files: &'static str,
}

/// Where the rules that detect an agent disabling this harness's hooks live.
#[derive(Clone, Copy)]
pub enum HostRules {
    /// In the shared self-protection document.
    Shared,
    /// In a rules document of the adapter's own (file name, template), loaded
    /// with the shared one.
    Document(&'static str, &'static str),
}

impl Harness {
    /// Every harness in this build.
    pub const ALL: &'static [Harness] = &[
        Harness::ClaudeCode,
        Harness::CopilotCli,
        Harness::CodexCli,
        Harness::OpenCode,
    ];

    /// The harness's descriptor: the only match on a harness.
    pub const fn adapter(self) -> &'static Adapter {
        match self {
            Self::ClaudeCode => &claude_code::ADAPTER,
            Self::CodexCli => &codex_cli::ADAPTER,
            Self::CopilotCli => &copilot_cli::ADAPTER,
            Self::OpenCode => &opencode::ADAPTER,
        }
    }

    /// The name used on the command line, on the evaluator wire protocol and
    /// in `Context::harness`.
    pub fn name(self) -> &'static str {
        self.adapter().name
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|harness| harness.name() == name)
    }

    /// Native hook stdin to a runtime event.
    pub fn parse(self, bytes: &[u8]) -> Parsed {
        (self.adapter().parse)(bytes)
    }

    /// Native stdout JSON for a response, or `None` to print nothing. Never
    /// renders a pre-execution `allow`.
    pub fn render(self, hook_event: &str, response: &Response) -> Option<Value> {
        (self.adapter().render)(hook_event, response)
    }

    /// Whether `hook_event` is the harness's pre-execution enforcement point.
    pub fn is_pre_tool_use(self, hook_event: &str) -> bool {
        self.adapter().pre_tool_use.contains(&hook_event)
    }

    /// Whether a payload that could not be parsed still names the
    /// pre-execution event, so it gets a verdict rather than a non-blocking
    /// error the harness would treat as allow.
    pub fn looks_like_pre_tool_use(self, bytes: &[u8]) -> bool {
        (self.adapter().looks_like_pre_tool_use)(bytes)
    }

    /// Whether a returned `ask` is put to a human on this harness in every
    /// run mode ([`Adapter::can_ask`]).
    pub fn can_ask(self) -> bool {
        self.adapter().can_ask
    }

    /// Native stdout answering a pre-execution event with a policy verdict
    /// when no parsed payload is available. `allow` prints nothing. `reason`
    /// is the cause: the answer opens with what happened to the call
    /// (`Response::failure`). An `ask` that `ask` or the harness does not put
    /// to a human is rendered as `deny` (`Response::decision`).
    pub fn render_verdict(self, policy: OnError, reason: &str, ask: AskRoute) -> Option<Value> {
        self.render_event_verdict(self.adapter().pre_tool_use[0], policy, reason, ask)
    }

    /// [`Self::render_verdict`] for a pre-execution event whose name is known,
    /// so an entry point that receives two dialects answers in the one the
    /// payload used.
    pub fn render_event_verdict(
        self,
        hook_event: &str,
        policy: OnError,
        reason: &str,
        ask: AskRoute,
    ) -> Option<Value> {
        let verdict = match policy {
            OnError::Allow => return None,
            OnError::Ask => Verdict::Ask,
            OnError::Deny => Verdict::Deny,
        };
        self.render(
            hook_event,
            &Response::failure(ask.prompts_human(self.can_ask()), verdict, reason),
        )
    }
}

/// Whether an unparseable payload names its event: a complete, non-empty string
/// in a top-level event key, in the prefix that `looks_like_pre_tool_use` also
/// reads. The keys are those of every registered harness
/// ([`Adapter::event_keys`]), because one harness's payloads can arrive at
/// another's entry point. Only the top level counts, because a tool input is
/// agent-controlled and may nest a key of the same name.
pub fn names_event(bytes: &[u8]) -> bool {
    let is_event_key = |key: &[u8]| {
        Harness::ALL
            .iter()
            .flat_map(|harness| harness.adapter().event_keys)
            .any(|name| name.as_bytes() == key)
    };
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
                if depth == 1 && is_event_key(key) {
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

    /// Every descriptor is complete, and the registry's lookups by name
    /// (`from_name`, relocated homes) reach the adapter that
    /// declared the value.
    #[test]
    fn every_adapter_is_registered_under_its_own_name() {
        let mut names = std::collections::BTreeSet::new();
        let mut variables = std::collections::BTreeSet::new();
        for harness in Harness::ALL {
            let adapter = harness.adapter();
            let name = adapter.name;
            assert!(names.insert(name), "{name} is registered twice");
            assert!(!adapter.display_name.is_empty(), "{name}");
            assert!(!adapter.pre_tool_use.is_empty(), "{name}");
            assert!(!adapter.event_keys.is_empty(), "{name}");
            assert!(!adapter.launchers.is_empty(), "{name}");
            assert!(
                adapter
                    .install
                    .usage
                    .contains(&format!("telltale hooks {name} settings")),
                "{name}"
            );
            if let Some(home) = adapter.home {
                assert!(variables.insert(home.variable), "{}", home.variable);
            }
        }
    }

    #[test]
    fn unreadable_payloads_name_their_event_by_any_registered_key() {
        for harness in Harness::ALL {
            for key in harness.adapter().event_keys {
                let named = format!(r#"{{"session":"s","{key}":"Stop","x":{{"#);
                assert!(names_event(named.as_bytes()), "{key}");
                // The same key inside a tool input is the agent's.
                let nested = format!(r#"{{"tool_input":{{"{key}":"Stop"}},"x":{{"#);
                assert!(!names_event(nested.as_bytes()), "{key}");
                let empty = format!(r#"{{"{key}":"","x":{{"#);
                assert!(!names_event(empty.as_bytes()), "{key}");
            }
        }
        assert!(!names_event(br#"{"event":"Stop","x":{"#));
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
        assert_eq!(Harness::from_name("opencode"), Some(Harness::OpenCode));
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
        assert_eq!(
            harness.render_verdict(OnError::Allow, "r", AskRoute::Human),
            None
        );
        for (policy, decision, what) in [
            (
                OnError::Ask,
                "ask",
                "this tool call needs approval before it runs",
            ),
            (
                OnError::Deny,
                "deny",
                "this tool call was blocked and has not been executed",
            ),
        ] {
            assert_eq!(
                harness.render_verdict(policy, "why", AskRoute::Human),
                Some(json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": decision,
                        "permissionDecisionReason": format!("Telltale Hooks: {what}. why"),
                    }
                }))
            );
        }
    }

    /// `hooks.ask: model`: a payload-less ask is a deny that asks through
    /// the model on every harness, also one with an approval prompt.
    #[test]
    fn verdicts_without_a_payload_follow_the_ask_route() {
        use crate::hooks::runtime::ASK_THROUGH_MODEL_NOTE;
        for harness in Harness::ALL {
            let out = harness
                .render_verdict(OnError::Ask, "why", AskRoute::Model)
                .unwrap()
                .to_string();
            assert!(out.contains("\"deny\""), "{harness:?}: {out}");
            assert!(!out.contains("\"ask\""), "{harness:?}: {out}");
            assert!(out.contains(ASK_THROUGH_MODEL_NOTE), "{harness:?}: {out}");
            assert_eq!(
                harness.render_verdict(OnError::Allow, "why", AskRoute::Model),
                None
            );
        }
    }

    #[test]
    fn codex_verdicts_without_a_payload_are_deny_or_nothing() {
        let harness = Harness::CodexCli;
        assert!(!harness.can_ask());
        assert_eq!(
            harness.render_verdict(OnError::Allow, "r", AskRoute::Human),
            None
        );
        for policy in [OnError::Ask, OnError::Deny] {
            let out = harness
                .render_verdict(policy, "why", AskRoute::Human)
                .unwrap();
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
