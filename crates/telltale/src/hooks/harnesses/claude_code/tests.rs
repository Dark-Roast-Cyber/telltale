use super::*;

#[test]
fn bash_results_join_streams() {
    let response = json!({"stdout": "out", "stderr": "err", "interrupted": false});
    assert_eq!(payload::tool_response_text(&response), "out\nerr");
    assert_eq!(
        payload::tool_response_text(&json!({"stdout": "", "stderr": ""})),
        ""
    );
}

#[test]
fn read_results_use_file_content() {
    let response = json!({"type": "text", "file": {"filePath": "/x", "content": "hello\n"}});
    assert_eq!(payload::tool_response_text(&response), "hello\n");
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

/// What a grant line did is told to the model on `UserPromptSubmit`;
/// context is not rendered on events whose output does not take it.
#[test]
fn user_prompt_context_renders_hook_specific_output() {
    let response = Response::AdditionalContext("told".into());
    let out = render("UserPromptSubmit", &response).unwrap();
    assert_eq!(
        out["hookSpecificOutput"]["hookEventName"],
        "UserPromptSubmit"
    );
    assert_eq!(out["hookSpecificOutput"]["additionalContext"], "told");
    assert_eq!(render("SessionStart", &response), None);
}

/// A notice gives the model the context and the person the user line on
/// `UserPromptSubmit`; elsewhere it is rendered as its context.
#[test]
fn a_notice_shows_the_person_a_system_message() {
    let notice = Response::Notice {
        context: "for the model".into(),
        user: "for the person".into(),
    };
    let out = render("UserPromptSubmit", &notice).unwrap();
    assert_eq!(out["systemMessage"], "for the person");
    assert_eq!(
        out["hookSpecificOutput"]["hookEventName"],
        "UserPromptSubmit"
    );
    assert_eq!(
        out["hookSpecificOutput"]["additionalContext"],
        "for the model"
    );
    assert_eq!(render("SessionStart", &notice), None);
    let post = render("PostToolUse", &notice).unwrap();
    assert_eq!(
        post["hookSpecificOutput"]["additionalContext"],
        "for the model"
    );
    assert!(post.get("systemMessage").is_none());
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
