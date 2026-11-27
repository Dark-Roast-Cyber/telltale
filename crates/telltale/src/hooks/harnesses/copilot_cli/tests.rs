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
                Some(json!({"permissionDecision": word, "permissionDecisionReason": "because"}))
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
