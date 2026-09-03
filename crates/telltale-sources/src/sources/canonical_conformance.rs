use std::fs;

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityId, ObservationFamily,
    ObservationStage, ObservedAt,
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
    let claude = claude.expect("Claude message vector");
    let codex = codex.expect("Codex message vector");
    assert_eq!(claude.len(), 2);
    assert_eq!(codex.len(), 2);
    for (left, right) in claude.iter().zip(&codex) {
        assert_semantically_equal(left, right);
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
    let claude = claude.expect("Claude tool vector");
    let codex = codex.expect("Codex tool vector");
    let claude_tools = claude
        .iter()
        .filter(|item| item.kind() == ObservationFamily::Tool);
    let codex_tools = codex
        .iter()
        .filter(|item| item.kind() == ObservationFamily::Tool);
    for (left, right) in claude_tools.zip(codex_tools) {
        assert_semantically_equal(left, right);
    }
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
