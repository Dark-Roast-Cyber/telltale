use super::*;

#[test]
fn equivalent_message_vectors_have_equal_canonical_meaning() {
    let (_claude_dir, claude) = project_claude(
        r#"{"type":"user","sessionId":"claude-conformance","message":{"role":"user","content":"Synthetic user message."}}
{"type":"assistant","sessionId":"claude-conformance","message":{"role":"assistant","content":"Synthetic assistant message."}}"#,
    );
    let (_codex_dir, codex) = project_codex(
        r#"{"type":"user","session_id":"codex-conformance","content":"Synthetic user message."}
{"type":"assistant","session_id":"codex-conformance","content":"Synthetic assistant message."}"#,
    );
    let (_openclaw_dir, openclaw) = project_openclaw(
        r#"{"type":"user","sessionId":"openclaw-conformance","content":"Synthetic user message."}
{"type":"assistant","sessionId":"openclaw-conformance","content":"Synthetic assistant message."}"#,
    );
    let (_qwen_dir, qwen) = project_qwen(
        r#"{"type":"user","sessionId":"qwen-conformance","content":"Synthetic user message."}
{"type":"assistant","sessionId":"qwen-conformance","content":"Synthetic assistant message."}"#,
    );
    let claude = claude.expect("Claude message vector");
    let codex = codex.expect("Codex message vector");
    let openclaw = openclaw.expect("OpenClaw message vector");
    let qwen = qwen.expect("Qwen message vector");
    assert_eq!(claude.len(), 2);
    assert_eq!(codex.len(), 2);
    assert_eq!(openclaw.len(), 2);
    assert_eq!(qwen.len(), 2);
    for (left, right) in claude.iter().zip(&codex) {
        assert_semantically_equal(left, right);
    }
    for observations in [&openclaw, &qwen] {
        for (left, right) in observations.iter().zip(&codex) {
            assert_semantically_equal(left, right);
        }
        assert_partial_session_capabilities(observations);
    }
}

#[test]
fn equivalent_tool_request_and_result_vectors_preserve_linkage_and_values() {
    let (_claude_dir, claude) = project_claude(
        r#"{"type":"assistant","sessionId":"claude-tool-conformance","message":{"role":"assistant","content":[{"type":"tool_use","id":"call-conformance","name":"Read","input":{"file_path":"synthetic.txt"}}]}}
{"type":"user","sessionId":"claude-tool-conformance","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-conformance","content":{"status":"ok"},"is_error":false}]}}"#,
    );
    let (_codex_dir, codex) = project_codex(
        r#"{"type":"assistant","session_id":"codex-tool-conformance","content":[{"type":"tool_use","id":"call-conformance","name":"Read","input":{"file_path":"synthetic.txt"}}]}
{"type":"assistant","session_id":"codex-tool-conformance","content":[{"type":"tool_result","call_id":"call-conformance","content":{"status":"ok"},"is_error":false}]}"#,
    );
    let (_openclaw_dir, openclaw) = project_openclaw(
        r#"{"type":"tool_call","sessionId":"openclaw-tool-conformance","call_id":"call-conformance","name":"Read","arguments":{"file_path":"synthetic.txt"}}
{"type":"tool_result","sessionId":"openclaw-tool-conformance","call_id":"call-conformance","content":{"status":"ok"},"is_error":false}"#,
    );
    let (_qwen_dir, qwen) = project_qwen(
        r#"{"type":"tool_call","sessionId":"qwen-tool-conformance","call_id":"call-conformance","name":"Read","arguments":{"file_path":"synthetic.txt"}}
{"type":"tool_result","sessionId":"qwen-tool-conformance","call_id":"call-conformance","content":{"status":"ok"},"is_error":false}"#,
    );
    let claude = claude.expect("Claude tool vector");
    let codex = codex.expect("Codex tool vector");
    let openclaw = openclaw.expect("OpenClaw tool vector");
    let qwen = qwen.expect("Qwen tool vector");
    let claude_tools = claude
        .iter()
        .filter(|item| item.kind() == ObservationFamily::Tool);
    let codex_tools = codex
        .iter()
        .filter(|item| item.kind() == ObservationFamily::Tool);
    for (left, right) in claude_tools.zip(codex_tools) {
        assert_semantically_equal(left, right);
    }
    let openclaw_tools = openclaw
        .iter()
        .filter(|item| item.kind() == ObservationFamily::Tool);
    let qwen_tools = qwen
        .iter()
        .filter(|item| item.kind() == ObservationFamily::Tool);
    for (left, right) in openclaw_tools.zip(qwen_tools) {
        assert_semantically_equal(left, right);
    }
    assert_partial_session_capabilities(&openclaw);
    assert_partial_session_capabilities(&qwen);
}

#[test]
fn missing_call_id_is_absent_or_fails_closed_without_fabrication() {
    let (_claude_dir, claude) = project_claude(
        r#"{"type":"assistant","sessionId":"claude-missing-call","message":{"role":"assistant","content":[{"type":"tool_use","name":"shell","input":{"command":"printf synthetic"}}]}}"#,
    );
    assert_eq!(claude.unwrap_err(), "missing_tool_id");

    let (_codex_dir, codex) = project_codex(
        r#"{"type":"assistant","session_id":"codex-missing-call","content":[{"type":"tool_use","name":"shell","input":{"command":"printf synthetic"}}]}"#,
    );
    let codex = codex.expect("Codex missing-call vector");
    let tool = codex
        .iter()
        .find(|item| item.kind() == ObservationFamily::Tool)
        .expect("tool observation");
    assert_eq!(tool.correlation().call_id(), None);

    let (_openclaw_dir, openclaw) = project_openclaw(
        r#"{"type":"tool_call","sessionId":"openclaw-missing-call","name":"shell","input":{"command":"printf synthetic"}}"#,
    );
    let openclaw = openclaw.expect("OpenClaw missing-call vector");
    let tool = openclaw
        .iter()
        .find(|item| item.kind() == ObservationFamily::Tool)
        .expect("OpenClaw tool observation");
    assert_eq!(tool.correlation().call_id(), None);

    let (_qwen_dir, qwen) = project_qwen(
        r#"{"type":"tool_call","sessionId":"qwen-missing-call","name":"shell","input":{"command":"printf synthetic"}}"#,
    );
    let qwen = qwen.expect("Qwen missing-call vector");
    let tool = qwen
        .iter()
        .find(|item| item.kind() == ObservationFamily::Tool)
        .expect("Qwen tool observation");
    assert_eq!(tool.correlation().call_id(), None);
}
