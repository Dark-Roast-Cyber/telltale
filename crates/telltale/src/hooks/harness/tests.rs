use super::*;
use serde_json::json;

/// Advisory context on an event routed to another harness's adapter is
/// printed only where that harness takes context on the event: a
/// Copilot CLI prompt event at the Claude Code entry point gets nothing,
/// a Copilot CLI result event keeps its context, and Claude Code's own
/// prompt event gets it.
#[test]
fn routed_context_is_printed_only_where_its_harness_takes_it() {
    let ctx = |harness: &'static str, hook_event: &str| Context {
        harness,
        hook_event: hook_event.to_owned(),
        session_id: "s".into(),
        agent_id: None,
        agent_type: None,
        prompt_id: None,
        permission_mode: None,
        cwd: None,
        can_ask: true,
        can_grant: true,
    };
    let context = Response::AdditionalContext("told".into());
    let entry = Harness::ClaudeCode;
    assert_eq!(
        entry.render_event(&ctx("copilot-cli", "UserPromptSubmit"), &context),
        None
    );
    assert!(
        entry
            .render_event(&ctx("copilot-cli", "PostToolUse"), &context)
            .is_some()
    );
    assert!(
        entry
            .render_event(&ctx("claude-code", "UserPromptSubmit"), &context)
            .is_some()
    );
    let notice = Response::Notice {
        context: "told".into(),
        user: "shown".into(),
    };
    assert_eq!(
        entry.render_event(&ctx("copilot-cli", "UserPromptSubmit"), &notice),
        None
    );
    assert!(
        entry
            .render_event(&ctx("claude-code", "UserPromptSubmit"), &notice)
            .is_some()
    );
}

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
