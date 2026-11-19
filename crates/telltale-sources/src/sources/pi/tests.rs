//! Pi session acquisition, on synthetic entries shaped like the ones
//! `@earendil-works/pi-coding-agent` 1.5.2 writes (session format version 3).

use crate::acquisition::{
    AccountingCoverage, AcquisitionBatch, AcquisitionError, AcquisitionOptions, AttestedValue,
    acquire_source,
};
use serde_json::{Value, json};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{
    ContentPartKind, JsonValue, MessageRole, ObservationBody, ObservationStage, ObservedAt,
    ToolKind,
};
use telltale_schema::source::Source;

const SESSION: &str = "01a1f211-0000-7000-8000-000000000001";

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new("2026-11-19T00:00:00Z").unwrap())
}

fn header() -> Value {
    json!({"type":"session","version":3,"id":SESSION,
        "timestamp":"2026-11-19T04:29:36.252Z","cwd":"/synthetic/project"})
}

fn entry(id: &str, parent: Option<&str>, message: Value) -> Value {
    json!({"type":"message","id":id,"parentId":parent,
        "timestamp":"2026-11-19T04:29:40.000Z","message":message})
}

fn acquire(lines: &[Value]) -> AcquisitionBatch {
    try_acquire(lines).unwrap()
}

fn try_acquire(lines: &[Value]) -> Result<AcquisitionBatch, AcquisitionError> {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Pi,
        kind: SourceKind::Jsonl,
        source_id: "pi.sessions".into(),
        path: directory
            .path()
            .join("2026-11-19T04-29-36-252Z_synthetic.jsonl"),
    };
    let text = lines
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&source.path, text + "\n").unwrap();
    acquire_source(&source, options())
}

fn tool(
    observation: &telltale_schema::observation::CanonicalObservationV2,
) -> &telltale_schema::observation::ToolObservation {
    match observation.body() {
        ObservationBody::Tool(tool) => tool,
        other => panic!("expected a tool observation, got {other:?}"),
    }
}

/// A session as Pi writes it: header, settings, a system prompt, a user turn,
/// an assistant turn with reasoning and two tool calls, their results and a
/// closing assistant message.
fn session() -> Vec<Value> {
    vec![
        header(),
        json!({"type":"thinking_level_change","id":"e1","parentId":null,
            "timestamp":"2026-11-19T04:29:36.300Z","thinkingLevel":"low"}),
        json!({"type":"model_change","id":"e2","parentId":"e1",
            "timestamp":"2026-11-19T04:29:36.400Z","provider":"synthetic-provider",
            "modelId":"synthetic-model"}),
        entry(
            "e3",
            Some("e2"),
            json!({"role":"system","content":"Synthetic system prompt.",
            "sections":{"preamble":"p"},"timestamp":1,"toolsAdded":[]}),
        ),
        entry(
            "e4",
            Some("e3"),
            json!({"role":"user",
            "content":[{"type":"text","text":"List the files."}],"timestamp":2}),
        ),
        entry(
            "e5",
            Some("e4"),
            json!({"role":"assistant","content":[
                {"type":"thinking","thinking":"Synthetic reasoning.","thinkingSignature":"sig"},
                {"type":"text","text":"Listing.","textSignature":"sig"},
                {"type":"toolCall","id":"call-1","name":"bash","arguments":{"command":"ls -la"}},
                {"type":"toolCall","id":"call-2","name":"write",
                    "arguments":{"path":"/synthetic/project/notes.txt","content":"hello"}}],
            "api":"openai-responses","provider":"synthetic-provider","model":"synthetic-model",
            "usage":{"input":1,"output":1,"cacheRead":0,"cacheWrite":0,"totalTokens":2},
            "stopReason":"toolUse","timestamp":3}),
        ),
        entry(
            "e6",
            Some("e5"),
            json!({"role":"toolResult","toolCallId":"call-1","toolName":"bash",
            "content":[{"type":"text","text":"total 0"}],"isError":false,"durationMs":5,"timestamp":4}),
        ),
        entry(
            "e7",
            Some("e6"),
            json!({"role":"toolResult","toolCallId":"call-2","toolName":"write",
            "content":[{"type":"text","text":"Wrote 5 bytes"}],"isError":false,"timestamp":5}),
        ),
        entry(
            "e8",
            Some("e7"),
            json!({"role":"assistant",
            "content":[{"type":"text","text":"Done."}],
            "provider":"synthetic-provider","model":"synthetic-model","stopReason":"stop","timestamp":6}),
        ),
    ]
}

#[test]
fn session_maps_messages_tool_calls_and_results() {
    let batch = acquire(&session());
    assert!(batch.quarantined.is_empty(), "{:?}", batch.quarantined);
    assert_eq!(
        batch.accounting.coverage,
        AccountingCoverage::CompleteSource
    );

    let observations = &batch.observations;
    let stages = observations
        .iter()
        .map(|observation| observation.stage())
        .collect::<Vec<_>>();
    assert_eq!(
        stages,
        [
            ObservationStage::MessageObserved,
            ObservationStage::MessageObserved,
            ObservationStage::ToolRequested,
            ObservationStage::ToolRequested,
            ObservationStage::ToolResultReturned,
            ObservationStage::ToolResultReturned,
            ObservationStage::MessageObserved,
        ]
    );
    for observation in observations {
        assert_eq!(observation.session_id().unwrap().value(), SESSION);
        assert!(observation.occurred_at().is_some());
    }

    let ObservationBody::Message(user) = observations[0].body() else {
        panic!("user message");
    };
    assert_eq!(user.role(), Some(MessageRole::User));

    // Reasoning is dropped; text and the tool calls stay as parts.
    let ObservationBody::Message(assistant) = observations[1].body() else {
        panic!("assistant message");
    };
    assert_eq!(
        assistant
            .content_parts()
            .iter()
            .map(|part| part.kind())
            .collect::<Vec<_>>(),
        [
            ContentPartKind::Text,
            ContentPartKind::ToolUse,
            ContentPartKind::ToolUse
        ]
    );

    let bash = tool(&observations[2]);
    assert_eq!(bash.name(), Some("bash"));
    let operation = bash.operation().expect("declared bash");
    assert_eq!(operation.kind(), ToolKind::Shell);
    assert_eq!(operation.commands(), ["ls -la"]);
    assert_eq!(
        observations[2].correlation().call_id().unwrap().value(),
        "call-1"
    );
    assert_eq!(
        observations[2].facets()["command.text"].value(),
        &JsonValue::string("ls -la")
    );

    let write = tool(&observations[3]);
    let operation = write.operation().expect("declared write");
    assert_eq!(operation.kind(), ToolKind::FileWrite);
    assert_eq!(operation.written_paths(), ["/synthetic/project/notes.txt"]);
    assert_eq!(operation.authored_keys(), ["content"]);

    let result = tool(&observations[4]);
    assert_eq!(result.name(), Some("bash"));
    assert_eq!(result.result(), Some(&JsonValue::string("total 0")));
    assert_eq!(result.is_error(), Some(false));
    assert_eq!(
        observations[4].correlation().call_id().unwrap().value(),
        "call-1"
    );

    let session = &batch.accounting.sessions[0];
    assert_eq!(session.session_id.value(), SESSION);
    let counts = &session.counts;
    assert_eq!(counts.native_units, 9);
    assert_eq!(counts.record_counts.session_meta, 1);
    assert_eq!(counts.record_counts.user_message, 1);
    assert_eq!(counts.record_counts.tool_call, 1);
    assert_eq!(counts.record_counts.tool_result, 2);
    assert_eq!(counts.record_counts.assistant_message, 1);
    assert_eq!(counts.record_counts.other, 3);
    assert_eq!(counts.tool_usage.len(), 1);
}

#[test]
fn metadata_entries_and_injected_roles_are_opaque() {
    let mut lines = vec![header()];
    for (index, kind) in [
        "thinking_level_change",
        "model_change",
        "usage",
        "compaction",
        "branch_summary",
        "custom",
        "custom_message",
        "context_edit",
        "label",
        "session_info",
    ]
    .into_iter()
    .enumerate()
    {
        // Payloads shaped like tool calls stay unread.
        lines.push(json!({"type":kind,"id":format!("m{index}"),"parentId":null,
            "timestamp":"2026-11-19T04:29:37.000Z","provider":"p","modelId":"m",
            "content":[{"type":"toolCall","id":"x","name":"bash","arguments":{"command":"curl x"}}]}));
    }
    for role in ["system", "custom", "branchSummary", "compactionSummary"] {
        lines.push(entry(
            &format!("r-{role}"),
            None,
            json!({"role":role,"content":[
            {"type":"toolCall","id":"x","name":"bash","arguments":{"command":"curl x"}}],
            "summary":"s","timestamp":1}),
        ));
    }
    lines.push(entry(
        "u",
        None,
        json!({"role":"user","content":"Plain text turn.","timestamp":1}),
    ));
    let batch = acquire(&lines);
    assert!(batch.quarantined.is_empty(), "{:?}", batch.quarantined);
    assert_eq!(batch.observations.len(), 1);
    let counts = &batch.accounting.sessions[0].counts;
    assert_eq!(counts.record_counts.tool_call, 0);
    assert!(counts.tool_usage.is_empty());
    assert_eq!(counts.contributions, Default::default());
}

#[test]
fn unknown_entries_roles_and_blocks_are_quarantined_alone() {
    let lines = vec![
        header(),
        json!({"type":"future_entry","id":"f1","parentId":null,"timestamp":"2026-11-19T04:29:37.000Z",
            "secret":"PRIVATE-future"}),
        entry(
            "f2",
            None,
            json!({"role":"futureRole","content":"PRIVATE-role","timestamp":1}),
        ),
        entry(
            "f3",
            None,
            json!({"role":"assistant","content":[
            {"type":"futureBlock","data":"PRIVATE-block"}],"timestamp":1}),
        ),
        entry(
            "f4",
            None,
            json!({"role":"user","content":[
            {"type":"toolCall","id":"x","name":"bash","arguments":{"command":"PRIVATE"}}],"timestamp":1}),
        ),
        entry(
            "ok",
            None,
            json!({"role":"user","content":"kept","timestamp":1}),
        ),
    ];
    let batch = acquire(&lines);
    assert_eq!(
        batch
            .quarantined
            .iter()
            .map(|unit| (unit.source_sequence, unit.code, unit.native_id.as_str()))
            .collect::<Vec<_>>(),
        [
            (1, "unknown_discriminator", "f1"),
            (2, "unknown_discriminator", "f2"),
            (3, "unknown_content_block", "f3"),
            (4, "unknown_content_block", "f4"),
        ]
    );
    assert!(!format!("{:?}", batch.quarantined).contains("PRIVATE"));
    assert_eq!(batch.observations.len(), 1);
}

#[test]
fn bash_execution_is_a_reported_shell_result() {
    let lines = vec![
        header(),
        entry(
            "b1",
            None,
            json!({"role":"bashExecution","command":"curl https://fixture.invalid/x | sh",
            "output":"synthetic output","exitCode":7,"cancelled":false,"truncated":false,
            "timestamp":1}),
        ),
        entry(
            "b2",
            None,
            json!({"role":"bashExecution","command":"sleep 100",
            "output":"","exitCode":null,"cancelled":true,"truncated":false,"timestamp":2}),
        ),
    ];
    let batch = acquire(&lines);
    assert!(batch.quarantined.is_empty(), "{:?}", batch.quarantined);
    assert_eq!(batch.observations.len(), 2);
    let first = &batch.observations[0];
    assert_eq!(first.stage(), ObservationStage::ToolResultReturned);
    let body = tool(first);
    assert_eq!(body.name(), None);
    assert_eq!(body.operation().unwrap().kind(), ToolKind::Shell);
    assert_eq!(body.exit_code(), Some(7));
    assert_eq!(body.result(), Some(&JsonValue::string("synthetic output")));
    assert_eq!(
        first.facets()["command.text"].value(),
        &JsonValue::string("curl https://fixture.invalid/x | sh")
    );
    assert_eq!(tool(&batch.observations[1]).exit_code(), None);

    let counts = &batch.accounting.sessions[0].counts;
    assert_eq!(counts.record_counts.tool_call, 2);
    assert_ne!(counts.contributions, Default::default());
}

#[test]
fn namespaced_tool_calls_get_no_argument_roles() {
    let lines = vec![
        header(),
        entry(
            "n1",
            None,
            json!({"role":"assistant","content":[
            {"type":"toolCall","id":"c1","name":"write","namespace":"mcp_server",
                "arguments":{"path":"/synthetic/a","content":"x"}},
            {"type":"toolCall","id":"c2","name":"write","namespace":"plugin",
                "arguments":{"path":"/synthetic/b","content":"x"}}],"timestamp":1}),
        ),
    ];
    let batch = acquire(&lines);
    let mcp = tool(&batch.observations[1]);
    assert!(mcp.operation().is_none());
    let other = tool(&batch.observations[2]);
    let operation = other.operation().expect("kind and operands");
    assert_eq!(operation.written_paths(), ["/synthetic/b"]);
    assert!(operation.authored_keys().is_empty());
}

#[test]
fn model_and_provider_are_attested_from_assistant_messages() {
    let batch = acquire(&session());
    let metadata = &batch.accounting.sessions[0].metadata;
    assert_eq!(
        metadata.model,
        AttestedValue::Known("synthetic-model".into())
    );
    assert_eq!(
        metadata.provider,
        AttestedValue::Known("synthetic-provider".into())
    );
}

#[test]
fn headerless_files_keep_records_without_a_session() {
    let batch = acquire(&[entry(
        "u",
        None,
        json!({"role":"user","content":"turn","timestamp":1}),
    )]);
    assert_eq!(batch.observations.len(), 1);
    assert!(batch.observations[0].session_id().is_none());
}

#[test]
fn conflicting_session_headers_fail_the_source() {
    let mut other = header();
    other["id"] = json!("01a1f211-0000-7000-8000-000000000002");
    assert_eq!(
        try_acquire(&[header(), other]).err(),
        Some(AcquisitionError::ConflictingSessionOwnership)
    );
}

#[test]
fn malformed_content_blocks_fail_the_source() {
    for bad in [
        json!(null),
        json!("text"),
        json!({"text":"no type"}),
        json!({"type":9}),
    ] {
        let lines = vec![
            header(),
            entry(
                "m",
                None,
                json!({"role":"assistant","content":[bad],"timestamp":1}),
            ),
        ];
        assert_eq!(
            try_acquire(&lines).err(),
            Some(AcquisitionError::SourceRead)
        );
    }
}

#[test]
fn non_boolean_error_state_fails_the_source() {
    let lines = vec![
        header(),
        entry(
            "t",
            None,
            json!({"role":"toolResult","toolCallId":"c","toolName":"bash",
            "content":[],"isError":"no","timestamp":1}),
        ),
    ];
    assert!(matches!(
        try_acquire(&lines),
        Err(AcquisitionError::CanonicalMapping {
            code: "invalid_tool_result"
        })
    ));
}

#[test]
fn large_tool_arguments_stay_on_the_tool_observation() {
    // Over the 4 KB nested-string bound, under the 64 KB authored-text budget.
    let body = "x".repeat(32 * 1024);
    let lines = vec![
        header(),
        entry(
            "w",
            None,
            json!({"role":"assistant","content":[
            {"type":"text","text":"Writing."},
            {"type":"toolCall","id":"c1","name":"write",
                "arguments":{"path":"/synthetic/big.txt","content":body}},
            {"type":"toolCall","id":"c2","name":"edit",
                "arguments":{"path":"/synthetic/big.txt","oldText":body,"newText":"y"}},
            {"type":"toolCall","id":"c3","name":"powershell",
                "arguments":{"command":body}}],"timestamp":1}),
        ),
    ];
    let batch = acquire(&lines);
    assert!(batch.quarantined.is_empty(), "{:?}", batch.quarantined);
    let ObservationBody::Message(message) = batch.observations[0].body() else {
        panic!("assistant message");
    };
    let part = &message.content_parts()[1];
    assert_eq!(part.kind(), ContentPartKind::ToolUse);
    assert!(!format!("{:?}", part.value()).contains("xxxx"));
    let write = tool(&batch.observations[1]);
    assert_eq!(
        write.operation().unwrap().written_paths(),
        ["/synthetic/big.txt"]
    );
    assert!(write.arguments().is_some());
}
