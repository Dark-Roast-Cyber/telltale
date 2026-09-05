use std::fs;

use rusqlite::Connection;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityId, ContentPartKind, JsonValue,
    MessageRole, ObservationBody, ObservationFamily, ObservationStage, ObservedAt, ToolStatus,
};
use telltale_schema::source::Source;
use tempfile::{TempDir, tempdir};

const OBSERVED_AT: &str = "2026-09-02T12:00:00Z";

fn source(client: ClientId, source_id: &str, kind: SourceKind, path: std::path::PathBuf) -> Source {
    Source {
        client,
        kind,
        source_id: source_id.to_owned(),
        path,
    }
}

fn project_claude(contents: &str) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("claude-vector.jsonl");
    fs::write(&path, contents).expect("Claude vector");
    let result = super::claude::canonical::project_claude_canonical_observations(
        &source(ClientId::Claude, "claude.projects", SourceKind::Jsonl, path),
        super::claude::canonical::ClaudeCanonicalOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn project_codex(contents: &str) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("codex-vector.jsonl");
    fs::write(&path, contents).expect("Codex vector");
    let result = super::codex::canonical::project_codex_canonical_observations(
        &source(ClientId::Codex, "codex.sessions", SourceKind::Jsonl, path),
        super::codex::canonical::CodexCanonicalOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn project_openclaw(contents: &str) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("openclaw-vector.jsonl");
    fs::write(&path, contents).expect("OpenClaw vector");
    let result = super::openclaw::canonical::project_openclaw_canonical_observations(
        &source(
            ClientId::OpenClaw,
            "openclaw.agents",
            SourceKind::Jsonl,
            path,
        ),
        super::openclaw::canonical::OpenClawCanonicalOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn project_qwen(contents: &str) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("qwen-vector.jsonl");
    fs::write(&path, contents).expect("Qwen vector");
    let result = super::qwen::canonical::project_qwen_canonical_observations(
        &source(ClientId::Qwen, "qwen.projects", SourceKind::Jsonl, path),
        super::qwen::canonical::QwenCanonicalOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn project_copilot(contents: &str) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("copilot-vector.log");
    fs::write(&path, contents).expect("Copilot vector");
    let result = super::copilot::canonical::project_copilot_canonical_observations(
        &source(
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            path,
        ),
        super::copilot::canonical::CopilotCanonicalOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn project_opencode(
    messages: &[(&str, &str, serde_json::Value)],
    parts: &[(&str, &str, i64, serde_json::Value)],
) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("opencode-vector.db");
    let connection = Connection::open(&path).expect("OpenCode vector database");
    connection
        .execute_batch(
            "create table message (id text, session_id text, time_created integer, time_updated integer, data text);
             create table part (id text, message_id text, session_id text, time_created integer, time_updated integer, data text);",
        )
        .expect("OpenCode vector schema");
    for (id, session_id, data) in messages {
        connection
            .execute(
                "insert into message values (?1, ?2, ?3, ?4, ?5)",
                (*id, *session_id, 1_000_i64, 1_000_i64, data.to_string()),
            )
            .expect("OpenCode message vector");
    }
    for (id, message_id, updated, data) in parts {
        connection
            .execute(
                "insert into part values (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    *id,
                    *message_id,
                    "opencode-conformance",
                    *updated,
                    *updated,
                    data.to_string(),
                ),
            )
            .expect("OpenCode part vector");
    }
    drop(connection);
    let result = super::opencode::canonical::project_opencode_canonical_observations(
        &source(
            ClientId::OpenCode,
            "opencode.sqlite",
            SourceKind::Sqlite,
            path,
        ),
        super::opencode::canonical::OpenCodeCanonicalOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn assert_semantically_equal(left: &CanonicalObservationV2, right: &CanonicalObservationV2) {
    assert_eq!(left.kind(), right.kind());
    assert_eq!(left.stage(), right.stage());
    assert_eq!(left.body(), right.body());
    assert_eq!(left.facets(), right.facets());
    assert_eq!(left.fact_metadata(), right.fact_metadata());
    assert_eq!(
        left.correlation().call_id().map(|id| id.value()),
        right.correlation().call_id().map(|id| id.value())
    );
}

fn assert_partial_session_capabilities(observations: &[CanonicalObservationV2]) {
    for observation in observations {
        let capabilities = observation.capability_context().expect("capabilities");
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolCall),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::UserContext),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unknown
        );
    }
}

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

#[test]
fn openclaw_and_qwen_tool_facts_keep_unknown_execution_and_parsed_facets() {
    let (_openclaw_dir, openclaw) = project_openclaw(
        r#"{"type":"tool_call","sessionId":"openclaw-facets","call_id":"call-facets","name":"shell","arguments":{"command":"printf synthetic","file_path":"synthetic.txt"}}"#,
    );
    let (_qwen_dir, qwen) = project_qwen(
        r#"{"type":"tool_call","sessionId":"qwen-facets","call_id":"call-facets","name":"shell","arguments":{"command":"printf synthetic","file_path":"synthetic.txt"}}"#,
    );
    let openclaw = openclaw.expect("OpenClaw facet vector");
    let qwen = qwen.expect("Qwen facet vector");
    assert_semantically_equal(&openclaw[0], &qwen[0]);

    for observations in [&openclaw, &qwen] {
        assert_partial_session_capabilities(observations);
        let tool = observations
            .iter()
            .find(|item| item.kind() == ObservationFamily::Tool)
            .expect("tool observation");
        assert_eq!(
            tool.facets()["command.text"].value(),
            &JsonValue::string("printf synthetic")
        );
        assert_eq!(
            tool.facets()["resource.path"].value(),
            &JsonValue::string("synthetic.txt")
        );
        assert_eq!(
            tool.fact_metadata()["command.text"].provenance(),
            telltale_schema::observation::FactProvenance::Parsed
        );
        assert_eq!(
            tool.fact_metadata()["resource.path"].provenance(),
            telltale_schema::observation::FactProvenance::Parsed
        );
        assert!(observations.iter().all(|observation| {
            !matches!(
                observation.kind(),
                ObservationFamily::File | ObservationFamily::Process | ObservationFamily::Network
            ) && !matches!(
                observation.stage(),
                ObservationStage::ToolProposed
                    | ObservationStage::ToolExecutionStarted
                    | ObservationStage::ToolExecutionCompleted
            )
        }));
    }
}

#[test]
fn copilot_vectors_preserve_assistant_tools_arguments_and_capability_gaps() {
    let (_directory, result) = project_copilot(
        "2026-09-02T12:00:00Z [INFO] Workspace initialized: copilot-conformance (checkpoints: 0)\n2026-09-02T12:00:01Z [INFO] Accumulated output items (2): [{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Synthetic assistant output.\"}]},{\"type\":\"function_call\",\"name\":\"shell\",\"call_id\":\"copilot-call\",\"arguments\":\"{\\\"command\\\":\\\"printf synthetic\\\",\\\"path\\\":\\\"synthetic.txt\\\"}\",\"status\":\"completed\",\"message\":\"Synthetic result.\"}]\n",
    );
    let observations = result.expect("Copilot conformance vector");
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].kind(), ObservationFamily::Message);
    assert_eq!(observations[0].stage(), ObservationStage::MessageObserved);
    assert_eq!(observations[1].stage(), ObservationStage::ToolRequested);
    assert_eq!(
        observations[2].stage(),
        ObservationStage::ToolResultReturned
    );

    for observation in &observations {
        let capabilities = observation
            .capability_context()
            .expect("Copilot capabilities");
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolCall),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::UserContext),
            CapabilityAvailability::Unsupported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unknown
        );
        assert_eq!(observation.source().adapter_type(), "copilot");
        assert_eq!(observation.source().adapter_id(), "copilot.process_log");
    }

    let ObservationBody::Message(message) = observations[0].body() else {
        panic!("expected Copilot assistant message")
    };
    assert_eq!(message.role(), Some(MessageRole::Assistant));
    assert_eq!(message.content_parts().len(), 1);
    assert_eq!(message.content_parts()[0].kind(), ContentPartKind::Text);
    let ObservationBody::Tool(tool) = observations[1].body() else {
        panic!("expected Copilot tool request")
    };
    assert_eq!(tool.name(), Some("shell"));
    assert_eq!(
        observations[1].correlation().call_id().unwrap().value(),
        "copilot-call"
    );
    assert_eq!(
        tool.arguments(),
        Some(
            &JsonValue::object([
                ("command".to_owned(), JsonValue::string("printf synthetic")),
                ("path".to_owned(), JsonValue::string("synthetic.txt")),
            ])
            .unwrap(),
        )
    );
    assert_eq!(
        observations[1].fact_metadata()["tool.arguments"].provenance(),
        telltale_schema::observation::FactProvenance::Parsed
    );
    assert_eq!(
        observations[1].fact_metadata()["tool.searchable_arguments"].provenance(),
        telltale_schema::observation::FactProvenance::Reported
    );
    assert_eq!(
        observations[1].facets()["command.text"].value(),
        &JsonValue::string("printf synthetic")
    );
    assert_eq!(
        observations[1].facets()["resource.path"].value(),
        &JsonValue::string("synthetic.txt")
    );
    let ObservationBody::Tool(result) = observations[2].body() else {
        panic!("expected Copilot result")
    };
    assert_eq!(
        result.result(),
        Some(&JsonValue::string("Synthetic result."))
    );
}

#[test]
fn openclaw_and_qwen_generic_tool_states_do_not_claim_execution_lifecycle() {
    let vector = |session: &str| {
        format!(
            r#"{{"type":"tool","sessionId":"{session}","tool":"shell","callID":"call-running","state":{{"status":"running","input":{{"command":"printf synthetic"}}}}}}
{{"type":"tool","sessionId":"{session}","tool":"shell","callID":"call-completed","state":{{"status":"completed","output":{{"status":"ok"}}}}}}
{{"type":"tool","sessionId":"{session}","tool":"shell","callID":"call-error","state":{{"status":"error","error":{{"message":"synthetic failure"}}}}}}"#
        )
    };
    let (_openclaw_dir, openclaw) = project_openclaw(&vector("openclaw-generic"));
    let (_qwen_dir, qwen) = project_qwen(&vector("qwen-generic"));

    for observations in [
        openclaw.expect("OpenClaw generic tool vector"),
        qwen.expect("Qwen generic tool vector"),
    ] {
        assert_partial_session_capabilities(&observations);
        assert!(
            observations
                .iter()
                .any(|observation| { observation.stage() == ObservationStage::ToolResultReturned })
        );
        assert!(observations.iter().all(|observation| {
            observation.kind() == ObservationFamily::Tool
                && !matches!(
                    observation.stage(),
                    ObservationStage::ToolProposed
                        | ObservationStage::ToolExecutionStarted
                        | ObservationStage::ToolExecutionCompleted
                )
        }));
    }
}

#[test]
fn parsed_facets_and_capability_gaps_do_not_claim_activity_or_execution() {
    let (_claude_dir, claude) = project_claude(
        r#"{"type":"assistant","sessionId":"claude-facets","message":{"role":"assistant","content":[{"type":"tool_use","id":"call-facets","name":"Read","input":{"file_path":"synthetic.txt"}}]}}"#,
    );
    let (_codex_dir, codex) = project_codex(
        r#"{"type":"tool_call","session_id":"codex-facets","call_id":"call-facets","name":"Read","arguments":{"command":"printf synthetic","file_path":"synthetic.txt"}}"#,
    );
    let claude = claude.expect("Claude facet vector");
    let codex = codex.expect("Codex facet vector");
    let claude_tool = claude
        .iter()
        .find(|item| item.kind() == ObservationFamily::Tool)
        .expect("Claude tool");
    let codex_tool = codex
        .iter()
        .find(|item| item.kind() == ObservationFamily::Tool)
        .expect("Codex tool");
    assert_eq!(
        claude_tool
            .facets()
            .get("resource.path")
            .map(|facet| facet.value()),
        codex_tool
            .facets()
            .get("resource.path")
            .map(|facet| facet.value())
    );
    assert_eq!(
        codex_tool.facets()["command.text"].value(),
        &telltale_schema::observation::JsonValue::string("printf synthetic")
    );
    assert_eq!(
        claude_tool.fact_metadata()["resource.path"].provenance(),
        telltale_schema::observation::FactProvenance::Parsed
    );
    assert_eq!(
        codex_tool.fact_metadata()["command.text"].provenance(),
        telltale_schema::observation::FactProvenance::Parsed
    );
    for observation in claude
        .iter()
        .chain(&codex)
        .filter(|item| item.kind() == ObservationFamily::Tool)
    {
        assert_eq!(
            observation
                .capability_context()
                .expect("capabilities")
                .resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unsupported
        );
        assert!(!matches!(
            observation.stage(),
            ObservationStage::ToolProposed
                | ObservationStage::ToolExecutionStarted
                | ObservationStage::ToolExecutionCompleted
        ));
        assert!(!matches!(
            observation.kind(),
            ObservationFamily::File | ObservationFamily::Process | ObservationFamily::Network
        ));
    }
}

#[test]
fn opencode_sqlite_messages_join_shared_message_semantics() {
    let (_directory, opencode) = project_opencode(
        &[
            (
                "message-user",
                "opencode-conformance",
                serde_json::json!({
                    "type": "user",
                    "role": "user",
                    "content": "Synthetic user message."
                }),
            ),
            (
                "message-assistant",
                "opencode-conformance",
                serde_json::json!({
                    "type": "assistant",
                    "role": "assistant",
                    "content": "Synthetic assistant message."
                }),
            ),
        ],
        &[],
    );
    let opencode = opencode.expect("OpenCode message vector");
    assert_eq!(opencode.len(), 2);
    assert_eq!(opencode[0].kind(), ObservationFamily::Message);
    assert_eq!(opencode[0].stage(), ObservationStage::MessageObserved);
    assert_eq!(opencode[1].kind(), ObservationFamily::Message);
    assert_eq!(opencode[1].stage(), ObservationStage::MessageObserved);
    let ObservationBody::Message(user) = opencode[0].body() else {
        panic!("expected OpenCode user message")
    };
    assert_eq!(
        user.role(),
        Some(telltale_schema::observation::MessageRole::User)
    );
    let ObservationBody::Message(assistant) = opencode[1].body() else {
        panic!("expected OpenCode assistant message")
    };
    assert_eq!(
        assistant.role(),
        Some(telltale_schema::observation::MessageRole::Assistant)
    );
    assert_eq!(opencode[0].source().native_id(), Some("message-user"));
    assert_eq!(opencode[1].source().native_id(), Some("message-assistant"));
}

#[test]
fn opencode_sqlite_tool_overlap_preserves_call_linkage_values_and_facets() {
    let (_directory, opencode) = project_opencode(
        &[(
            "tool-context",
            "opencode-tool-conformance",
            serde_json::json!({"role":"assistant"}),
        )],
        &[
            (
                "part-request",
                "tool-context",
                1,
                serde_json::json!({
                    "type":"tool","tool":"Read","callID":"call-conformance",
                    "state":{"status":"pending","input":{"file_path":"synthetic.txt"}}
                }),
            ),
            (
                "part-result",
                "tool-context",
                2,
                serde_json::json!({
                    "type":"tool","tool":"Read","callID":"call-conformance",
                    "state":{"status":"completed","input":{"file_path":"synthetic.txt"},"output":{"status":"ok"}}
                }),
            ),
        ],
    );
    let opencode = opencode.expect("OpenCode tool vector");
    let request = opencode
        .iter()
        .find(|item| item.stage() == ObservationStage::ToolRequested)
        .expect("OpenCode request");
    let result = opencode
        .iter()
        .find(|item| item.stage() == ObservationStage::ToolResultReturned)
        .expect("OpenCode result");
    assert_eq!(request.kind(), ObservationFamily::Tool);
    assert_eq!(result.kind(), ObservationFamily::Tool);
    assert_eq!(
        request.correlation().call_id().unwrap().value(),
        "call-conformance"
    );
    assert_eq!(
        result.correlation().call_id().unwrap().value(),
        "call-conformance"
    );
    let ObservationBody::Tool(request_body) = request.body() else {
        panic!("expected request body")
    };
    assert_eq!(
        request_body.arguments(),
        Some(
            &JsonValue::object([("file_path".to_owned(), JsonValue::string("synthetic.txt"))])
                .unwrap()
        )
    );
    let ObservationBody::Tool(result_body) = result.body() else {
        panic!("expected result body")
    };
    assert_eq!(
        result_body.result(),
        Some(&JsonValue::object([("status".to_owned(), JsonValue::string("ok"))]).unwrap())
    );
    assert_eq!(
        request.facets()["resource.path"].value(),
        &JsonValue::string("synthetic.txt")
    );
    assert!(opencode.iter().all(|item| !matches!(
        item.kind(),
        ObservationFamily::File | ObservationFamily::Process | ObservationFamily::Network
    )));
}

#[test]
fn opencode_sqlite_missing_call_id_is_absent_and_not_derived() {
    let (_directory, opencode) = project_opencode(
        &[(
            "tool-context",
            "opencode-missing-call",
            serde_json::json!({"role":"assistant"}),
        )],
        &[(
            "part-no-call",
            "tool-context",
            1,
            serde_json::json!({
                "type":"tool","tool":"shell",
                "state":{"status":"pending","input":{"command":"printf synthetic"}}
            }),
        )],
    );
    let opencode = opencode.expect("OpenCode missing-call vector");
    let tool = opencode
        .iter()
        .find(|item| item.kind() == ObservationFamily::Tool)
        .expect("OpenCode tool");
    assert_eq!(tool.correlation().call_id(), None);
    assert_eq!(tool.source().native_id(), Some("part-no-call"));
}

#[test]
fn opencode_sqlite_direct_lifecycle_is_supported_without_inferred_success() {
    let (_directory, opencode) = project_opencode(
        &[(
            "tool-context",
            "opencode-lifecycle",
            serde_json::json!({"role":"assistant"}),
        )],
        &[
            (
                "part-running",
                "tool-context",
                1,
                serde_json::json!({
                    "type":"tool","tool":"shell","callID":"call-running",
                    "state":{"status":"running","input":{"command":"printf synthetic"}}
                }),
            ),
            (
                "part-completed",
                "tool-context",
                2,
                serde_json::json!({
                    "type":"tool","tool":"shell","callID":"call-completed",
                    "state":{"status":"completed","output":"Synthetic output"}
                }),
            ),
        ],
    );
    let opencode = opencode.expect("OpenCode lifecycle vector");
    let running = opencode
        .iter()
        .find(|item| item.source().native_id() == Some("part-running"))
        .expect("running observation");
    assert_eq!(running.stage(), ObservationStage::ToolExecutionStarted);
    let completed = opencode
        .iter()
        .find(|item| {
            item.source().native_id() == Some("part-completed")
                && item.stage() == ObservationStage::ToolExecutionCompleted
        })
        .expect("completed observation");
    assert_eq!(completed.stage(), ObservationStage::ToolExecutionCompleted);
    let ObservationBody::Tool(body) = completed.body() else {
        panic!("expected completed tool")
    };
    assert_eq!(body.reported_status(), None);
    assert_eq!(body.is_error(), None);
    assert!(opencode.iter().all(|item| {
        item.capability_context()
            .expect("capabilities")
            .resolve(CapabilityId::ToolExecution)
            == CapabilityAvailability::Supported
    }));
    assert!(
        opencode
            .iter()
            .all(|item| item.stage() != ObservationStage::ToolRequested)
    );
    assert!(
        opencode
            .iter()
            .all(|item| item.stage() != ObservationStage::ToolProposed)
    );
    assert!(
        opencode
            .iter()
            .all(|item| item.body().kind() == ObservationFamily::Tool)
    );
    assert_eq!(body.reported_status(), None::<ToolStatus>);
}
