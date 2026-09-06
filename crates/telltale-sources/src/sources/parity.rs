use std::path::Path;

use crate::discovery::discover_sources_best_effort;
use crate::parser::{ParseError, parse_source_records};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::source::Source;

fn fixture_source(root: &Path, source_id: &str, file_name: &str) -> Source {
    discover_sources_best_effort(root)
        .into_iter()
        .find(|source| {
            source.source_id == source_id
                && source.path.file_name().and_then(|name| name.to_str()) == Some(file_name)
        })
        .unwrap_or_else(|| panic!("fixture source {source_id} / {file_name} not found"))
}

fn assert_sequence(
    source: &Source,
    expected_client: ClientId,
    expected_kind: SourceKind,
    expected_records: &[(&str, RecordKind)],
) -> Vec<NormalizedRecord> {
    assert_eq!(source.client, expected_client);
    assert_eq!(source.kind, expected_kind);
    let records = parse_source_records(source).expect("fixture records");
    assert_eq!(
        records
            .iter()
            .map(|record| (record.session_id.as_str(), record.kind))
            .collect::<Vec<_>>(),
        expected_records
    );
    assert!(
        records
            .iter()
            .all(|record| record.client == expected_client.as_str())
    );
    records
}

fn non_discovered_source(
    client: ClientId,
    kind: SourceKind,
    source_id: &str,
    file_name: &str,
) -> Source {
    Source {
        client,
        kind,
        source_id: source_id.to_string(),
        path: crate::test_fixture_path(&format!("parser_maturity/non_discovered/{file_name}")),
    }
}

#[test]
fn registered_identities_preserve_normalized_record_shapes_and_order() {
    let session_root = crate::test_fixture_path("session_stores");
    let maturity_root = crate::test_fixture_path("parser_maturity");

    let records = assert_sequence(
        &fixture_source(&session_root, "codex.sessions", "uc001-positive.jsonl"),
        ClientId::Codex,
        SourceKind::Jsonl,
        &[
            ("uc001-positive", RecordKind::SessionMeta),
            ("uc001-positive", RecordKind::UserMessage),
            ("uc001-positive", RecordKind::AssistantMessage),
        ],
    );
    assert_eq!(records[0].agent.as_deref(), Some("fixture-agent"));
    assert_eq!(records[0].model.as_deref(), Some("fixture-model"));
    assert_eq!(records[0].provider.as_deref(), Some("fixture-provider"));
    assert_eq!(
        records[0].timestamp.as_deref(),
        Some("2026-04-03T00:00:00Z")
    );
    assert!(records[2].content.contains("darkroastcyber.io/mcp-lab"));

    let records = assert_sequence(
        &fixture_source(&session_root, "codex.archived_sessions", "session-b.jsonl"),
        ClientId::Codex,
        SourceKind::ArchivedJsonl,
        &[("session-b", RecordKind::SessionMeta)],
    );
    assert_eq!(records[0].agent.as_deref(), Some("fixture-agent"));
    assert_eq!(records[0].provider.as_deref(), Some("fixture"));
    assert_eq!(
        records[0].timestamp.as_deref(),
        Some("2026-04-02T00:00:00Z")
    );

    let records = assert_sequence(
        &fixture_source(&session_root, "codex.headless_sessions", "headless-a.jsonl"),
        ClientId::Codex,
        SourceKind::HeadlessJsonl,
        &[("headless-a", RecordKind::SessionMeta)],
    );
    assert_eq!(records[0].agent.as_deref(), Some("codex-headless"));
    assert_eq!(records[0].provider.as_deref(), Some("openai"));
    assert!(records[0].content.contains("Headless Codex session"));

    let records = assert_sequence(
        &fixture_source(
            &maturity_root,
            "codex.project_sessions",
            "project-session.jsonl",
        ),
        ClientId::Codex,
        SourceKind::Jsonl,
        &[
            ("project-session", RecordKind::SessionMeta),
            ("project-session", RecordKind::AssistantMessage),
        ],
    );
    assert_eq!(records[0].agent.as_deref(), Some("fixture-agent"));
    assert_eq!(records[1].model.as_deref(), Some("fixture-model"));
    assert!(records[1].content.contains("project-local response"));

    let records = assert_sequence(
        &fixture_source(&session_root, "claude.projects", "session-a.jsonl"),
        ClientId::Claude,
        SourceKind::Jsonl,
        &[
            ("session-a", RecordKind::UserMessage),
            ("session-a", RecordKind::AssistantMessage),
        ],
    );
    assert_eq!(records[0].model.as_deref(), Some("claude-fixture-model"));
    assert_eq!(
        records[0].timestamp.as_deref(),
        Some("2026-04-27T12:00:00Z")
    );
    assert!(records[1].content.contains("benign fixture response"));

    let records = assert_sequence(
        &fixture_source(&session_root, "gemini.tmp", "session-a.json"),
        ClientId::Gemini,
        SourceKind::Json,
        &[
            ("gemini-session-a", RecordKind::UserMessage),
            ("gemini-session-a", RecordKind::AssistantMessage),
        ],
    );
    assert_eq!(records[0].agent.as_deref(), Some("gemini"));
    assert_eq!(records[0].model.as_deref(), Some("gemini-fixture-model"));
    assert_eq!(records[0].provider.as_deref(), Some("google"));
    assert_eq!(
        records[1].timestamp.as_deref(),
        Some("2026-04-27T12:25:01Z")
    );

    let records = assert_sequence(
        &fixture_source(&session_root, "openclaw.agents", "session-a.jsonl.deleted"),
        ClientId::OpenClaw,
        SourceKind::Jsonl,
        &[
            ("openclaw-session-a", RecordKind::UserMessage),
            ("openclaw-session-a", RecordKind::AssistantMessage),
        ],
    );
    assert_eq!(records[0].agent.as_deref(), Some("openclaw"));
    assert_eq!(records[0].provider.as_deref(), Some("openclaw"));
    assert_eq!(records[1].model.as_deref(), Some("openclaw-fixture-model"));

    let records = assert_sequence(
        &fixture_source(&session_root, "qwen.projects", "session-a.jsonl"),
        ClientId::Qwen,
        SourceKind::Jsonl,
        &[
            ("qwen-session-a", RecordKind::UserMessage),
            ("qwen-session-a", RecordKind::AssistantMessage),
        ],
    );
    assert_eq!(records[0].agent.as_deref(), Some("qwen"));
    assert_eq!(records[0].provider.as_deref(), Some("qwen"));
    assert_eq!(records[1].model.as_deref(), Some("qwen3-coder-plus"));

    let records = assert_sequence(
        &fixture_source(&session_root, "roocode.tasks", "ui_messages.json"),
        ClientId::RooCode,
        SourceKind::UiMessagesJson,
        &[
            ("roocode-session-a", RecordKind::UserMessage),
            ("roocode-session-a", RecordKind::AssistantMessage),
        ],
    );
    assert!(records.iter().all(|record| {
        record.agent.is_none() && record.provider.is_none() && record.model.is_none()
    }));

    let records = assert_sequence(
        &fixture_source(&session_root, "kilocode.tasks", "ui_messages.json"),
        ClientId::KiloCode,
        SourceKind::UiMessagesJson,
        &[
            ("task-a", RecordKind::UserMessage),
            ("task-a", RecordKind::AssistantMessage),
        ],
    );
    assert!(records.iter().all(|record| {
        record.agent.is_none() && record.provider.is_none() && record.model.is_none()
    }));

    let records = assert_sequence(
        &fixture_source(&session_root, "opencode.sqlite", "opencode.db"),
        ClientId::OpenCode,
        SourceKind::Sqlite,
        &[
            ("opencode-sqlite-benign", RecordKind::AssistantMessage),
            ("opencode-uc001-sqlite-tool-result", RecordKind::ToolResult),
        ],
    );
    assert_eq!(records[1].agent.as_deref(), Some("build"));
    assert_eq!(records[1].model.as_deref(), Some("fixture-model"));
    assert_eq!(records[1].provider.as_deref(), Some("fixture-provider"));
    assert_eq!(records[1].tool_name.as_deref(), Some("repo_status"));
    assert_eq!(
        records[1].arguments.as_deref(),
        Some("{\"format\":\"json\"}")
    );

    let records = assert_sequence(
        &fixture_source(&session_root, "opencode.legacy_json", "message-b.json"),
        ClientId::OpenCode,
        SourceKind::LegacyJson,
        &[("opencode-uc001-legacy-tool-result", RecordKind::ToolResult)],
    );
    assert_eq!(records[0].tool_name.as_deref(), Some("repo_status"));
    assert_eq!(
        records[0].arguments.as_deref(),
        Some("{\"format\":\"json\"}")
    );
    assert!(records[0].content.contains("darkroastcyber.io/mcp-lab"));

    let records = assert_sequence(
        &fixture_source(
            &maturity_root,
            "opencode.project_json",
            "project-message.json",
        ),
        ClientId::OpenCode,
        SourceKind::LegacyJson,
        &[("opencode-project-session", RecordKind::AssistantMessage)],
    );
    assert_eq!(records[0].agent.as_deref(), Some("build"));
    assert_eq!(records[0].model.as_deref(), Some("fixture-model"));
    assert_eq!(records[0].provider.as_deref(), Some("fixture-provider"));
    assert_eq!(
        records[0].timestamp.as_deref(),
        Some("2026-05-02T00:00:02Z")
    );
    assert!(records[0].content.contains("project-local response"));

    let records = assert_sequence(
        &fixture_source(&session_root, "copilot.process_log", "process-uc001.log"),
        ClientId::Copilot,
        SourceKind::CopilotProcessLog,
        &[
            ("copilot-uc001-tool-result", RecordKind::SessionMeta),
            ("copilot-uc001-tool-result", RecordKind::ToolCall),
            ("copilot-uc001-tool-result", RecordKind::ToolCall),
            ("copilot-uc001-tool-result", RecordKind::ToolResult),
        ],
    );
    assert_eq!(records[0].agent.as_deref(), Some("copilot"));
    assert_eq!(records[0].provider.as_deref(), Some("github"));
    assert_eq!(records[1].tool_name.as_deref(), Some("repo_status"));
    assert_eq!(
        records[1].arguments.as_deref(),
        Some("{\"format\":\"json\"}")
    );
    assert!(records[3].content.contains("MCP tool result"));
}

// These characterization tests retain the original fixtures while documenting
// the two intended expectation changes introduced by exact source registration:
// structural Claude drift and invented identities now fail explicitly.

#[test]
fn claude_schema_envelope_drift_is_rejected() {
    let source = non_discovered_source(
        ClientId::Claude,
        SourceKind::Jsonl,
        "claude.projects",
        "schema-drift.jsonl",
    );

    assert!(matches!(
        parse_source_records(&source),
        Err(ParseError::SchemaDrift { .. })
    ));
}

#[test]
fn claude_unknown_discriminator_remains_other() {
    let source = non_discovered_source(
        ClientId::Claude,
        SourceKind::Jsonl,
        "claude.projects",
        "unknown-variant.jsonl",
    );

    let records = parse_source_records(&source).expect("Claude records");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].session_id, "synthetic-unknown-variant");
    assert_eq!(records[0].kind, RecordKind::Other);
}

#[test]
fn malformed_registered_jsonl_remains_json_error() {
    let source = non_discovered_source(
        ClientId::Codex,
        SourceKind::Jsonl,
        "codex.sessions",
        "malformed-known-parser.jsonl",
    );

    assert!(matches!(
        parse_source_records(&source),
        Err(ParseError::Json(_))
    ));
}

#[test]
fn registered_modeled_json_parser_parses() {
    let source = non_discovered_source(
        ClientId::OpenCode,
        SourceKind::LegacyJson,
        "opencode.legacy_json",
        "explicit-generic-fallback.json",
    );

    let records = parse_source_records(&source).expect("registered modeled JSON records");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].session_id, "synthetic-generic-fallback");
    assert_eq!(records[0].kind, RecordKind::AssistantMessage);
    assert!(
        records[0]
            .content
            .contains("Synthetic generic fallback input")
    );
}

#[test]
fn invented_identity_is_rejected_before_fallback() {
    let source = non_discovered_source(
        ClientId::Codex,
        SourceKind::Jsonl,
        "codex.invented",
        "unsupported-identity.jsonl",
    );

    assert!(matches!(
        parse_source_records(&source),
        Err(ParseError::UnsupportedSourceIdentity { .. })
    ));
}
