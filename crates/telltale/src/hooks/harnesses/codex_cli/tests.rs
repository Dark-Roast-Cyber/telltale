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
