use std::fs;

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::ObservedAt;
use telltale_schema::source::Source;
use telltale_sources::acquisition::{AcquisitionOptions, SourceAccounting, acquire_source};
use tempfile::tempdir;

use super::{McpServerInventory, discover_mcp_inventory_servers, project_mcp_usage};

const OBSERVED_AT: &str = "2026-09-20T00:00:00Z";

fn source(client: ClientId, source_id: &str, path: impl Into<std::path::PathBuf>) -> Source {
    Source {
        client,
        kind: SourceKind::Jsonl,
        source_id: source_id.to_owned(),
        path: path.into(),
    }
}

fn acquire_accounting(source: &Source) -> SourceAccounting {
    acquire_source(
        source,
        AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).expect("observed_at")),
    )
    .expect("synthetic source acquisition")
    .accounting
}

fn project(
    source: &Source,
    accounting: &SourceAccounting,
    servers: &[McpServerInventory],
) -> Vec<telltale_schema::event::Event> {
    project_mcp_usage(source, accounting, servers).expect("synthetic MCP usage projection")
}

fn summary(event: &telltale_schema::event::Event) -> serde_json::Value {
    let evidence = event
        .evidence
        .iter()
        .find(|evidence| evidence.field == "tool_usage_summary")
        .expect("tool usage summary");
    serde_json::from_str(&evidence.redacted_value).expect("tool usage summary JSON")
}

#[test]
fn projects_claude_and_qwen_native_tool_calls_with_declared_tool_attribution() {
    let temp = tempdir().expect("tempdir");
    fs::create_dir(temp.path().join(".qwen")).expect("qwen directory");
    fs::write(
        temp.path().join(".mcp.json"),
        r#"{"mcpServers":{"claude-server":{"command":"synthetic-claude","tools":["claude_lookup","claude_write"]}}}"#,
    )
    .expect("Claude MCP config");
    fs::write(
        temp.path().join(".qwen/settings.json"),
        r#"{"mcpServers":{"qwen-server":{"command":"synthetic-qwen","tools":["qwen_lookup"]}}}"#,
    )
    .expect("Qwen MCP config");

    let claude_path = temp.path().join("claude.jsonl");
    fs::write(
        &claude_path,
        r#"{"type":"tool_call","role":"assistant","session_id":"claude-session","timestamp":"2026-09-20T01:00:00Z","agent":"claude-agent","model":"claude-model","provider":"anthropic","content":[{"type":"tool_use","id":"call-claude","name":"claude_lookup","input":{}}]}"#,
    )
    .expect("Claude source");
    let qwen_path = temp.path().join("qwen.jsonl");
    fs::write(
        &qwen_path,
        r#"{"type":"tool_call","session_id":"qwen-session","timestamp":"2026-09-20T02:00:00Z","agent":"qwen-agent","model":"qwen-model","provider":"dashscope","tool_name":"qwen_lookup","arguments":{},"call_id":"call-qwen"}"#,
    )
    .expect("Qwen source");

    let servers = discover_mcp_inventory_servers(temp.path());
    let claude_source = source(ClientId::Claude, "claude.projects", &claude_path);
    let claude_accounting = acquire_accounting(&claude_source);
    fs::remove_file(&claude_path).expect("remove acquired Claude source");
    let claude_events = project(&claude_source, &claude_accounting, &servers);
    assert_eq!(claude_events.len(), 1);
    let claude_event = &claude_events[0];
    assert_eq!(claude_event.session_id, "claude-session");
    assert_eq!(claude_event.agent.as_deref(), Some("claude-agent"));
    assert_eq!(claude_event.model.as_deref(), Some("claude-model"));
    assert_eq!(claude_event.provider.as_deref(), Some("anthropic"));
    assert_eq!(
        claude_event.tool_name.as_deref(),
        Some("mcp::claude-server")
    );
    let claude_summary = summary(claude_event);
    assert_eq!(claude_summary["attribution_method"], "declared_tools");
    assert_eq!(
        claude_summary["declared_tools"],
        serde_json::json!(["claude_lookup", "claude_write"])
    );

    let qwen_source = source(ClientId::Qwen, "qwen.projects", &qwen_path);
    let qwen_accounting = acquire_accounting(&qwen_source);
    fs::remove_file(&qwen_path).expect("remove acquired Qwen source");
    let qwen_events = project(&qwen_source, &qwen_accounting, &servers);
    assert_eq!(qwen_events.len(), 1);
    let qwen_event = &qwen_events[0];
    assert_eq!(qwen_event.session_id, "qwen-session");
    assert_eq!(qwen_event.agent.as_deref(), Some("qwen-agent"));
    assert_eq!(qwen_event.model.as_deref(), Some("qwen-model"));
    assert_eq!(qwen_event.provider.as_deref(), Some("dashscope"));
    assert_eq!(qwen_event.tool_name.as_deref(), Some("mcp::qwen-server"));
    assert_eq!(summary(qwen_event)["attribution_method"], "declared_tools");
}

#[test]
fn uses_first_present_source_time_and_stable_session_server_tool_ordering() {
    let temp = tempdir().expect("tempdir");
    fs::write(
        temp.path().join(".mcp.json"),
        r#"{"mcpServers":{"a-server":{"command":"synthetic-a","tools":["a_tool"]},"shared-server":{"command":"synthetic-shared","tools":["z_tool","a_tool"]}}}"#,
    )
    .expect("MCP config");
    let source_path = temp.path().join("ordering.jsonl");
    fs::write(
        &source_path,
        concat!(
            r#"{"type":"tool_call","role":"assistant","session_id":"session-a","agent":"claude","model":"fixture","provider":"fixture","content":[{"type":"tool_use","id":"call-z-1","name":"z_tool","input":{}}]}"#,
            "\n",
            r#"{"type":"tool_call","role":"assistant","session_id":"session-a","timestamp":"2026-09-20T02:00:00Z","content":[{"type":"tool_use","id":"call-z-2","name":"z_tool","input":{}}]}"#,
            "\n",
            r#"{"type":"tool_call","role":"assistant","session_id":"session-a","timestamp":"2026-09-20T01:00:00Z","content":[{"type":"tool_use","id":"call-a","name":"a_tool","input":{}}]}"#,
            "\n",
            r#"{"type":"tool_call","role":"assistant","session_id":"session-b","timestamp":"2026-09-20T03:00:00Z","content":[{"type":"tool_use","id":"call-b","name":"z_tool","input":{}}]}"#,
        ),
    )
    .expect("source");

    let source = source(ClientId::Claude, "claude.projects", &source_path);
    let accounting = acquire_accounting(&source);
    let session = accounting
        .sessions
        .iter()
        .find(|session| session.session_id.value() == "session-a")
        .expect("session-a accounting");
    let z_tool = &session.counts.tool_usage["z_tool"];
    assert_eq!(z_tool.first_order, 1);
    assert_eq!(
        z_tool
            .first_timestamp
            .as_ref()
            .map(|(_, time)| time.as_str()),
        Some("2026-09-20T02:00:00Z")
    );
    assert_eq!(session.counts.tool_usage["a_tool"].first_order, 3);

    let servers = discover_mcp_inventory_servers(temp.path());
    fs::remove_file(&source_path).expect("remove acquired source");
    let events = project(&source, &accounting, &servers);
    assert_eq!(
        events
            .iter()
            .map(|event| (event.session_id.as_str(), event.tool_name.as_deref()))
            .collect::<Vec<_>>(),
        vec![
            ("session-a", Some("mcp::a-server")),
            ("session-a", Some("mcp::shared-server")),
            ("session-b", Some("mcp::shared-server")),
        ]
    );
    let shared = &events[1];
    assert_eq!(
        shared.event_time.as_deref(),
        Some("2026-09-20T02:00:00.000Z")
    );
    assert_eq!(
        summary(shared)["tools_used"],
        serde_json::json!([
            {"tool_name":"a_tool","call_count":1},
            {"tool_name":"z_tool","call_count":2},
        ])
    );
}

#[test]
fn omits_conflicting_metadata_and_does_not_manufacture_missing_session_events() {
    let temp = tempdir().expect("tempdir");
    fs::create_dir(temp.path().join(".qwen")).expect("qwen directory");
    fs::write(
        temp.path().join(".mcp.json"),
        r#"{"mcpServers":{"conflict":{"command":"synthetic","tools":["conflict_tool"]}}}"#,
    )
    .expect("Claude MCP config");
    fs::write(
        temp.path().join(".qwen/settings.json"),
        r#"{"mcpServers":{"missing-session":{"command":"synthetic","tools":["missing_tool"]}}}"#,
    )
    .expect("Qwen MCP config");

    let conflict_path = temp.path().join("conflict.jsonl");
    fs::write(
        &conflict_path,
        concat!(
            r#"{"type":"tool_call","role":"assistant","session_id":"conflict-session","agent":"stable-agent","model":"model-one","provider":"provider-one","content":[{"type":"tool_use","id":"call-one","name":"conflict_tool","input":{}}]}"#,
            "\n",
            r#"{"type":"tool_call","role":"assistant","session_id":"conflict-session","agent":"stable-agent","model":"model-two","provider":"provider-two","content":[{"type":"tool_use","id":"call-two","name":"conflict_tool","input":{}}]}"#,
        ),
    )
    .expect("conflicting source");
    let conflict_source = source(ClientId::Claude, "claude.projects", &conflict_path);
    let conflict_accounting = acquire_accounting(&conflict_source);
    let servers = discover_mcp_inventory_servers(temp.path());
    let conflict_events = project(&conflict_source, &conflict_accounting, &servers);
    assert_eq!(conflict_events.len(), 1);
    assert_eq!(conflict_events[0].agent.as_deref(), Some("stable-agent"));
    assert_eq!(conflict_events[0].model, None);
    assert_eq!(conflict_events[0].provider, None);

    let missing_path = temp.path().join("missing.jsonl");
    fs::write(
        &missing_path,
        r#"{"type":"tool_call","tool_name":"missing_tool","call_id":"missing-call","timestamp":"2026-09-20T04:00:00Z","model":"qwen-model","provider":"qwen-provider","arguments":{}}"#,
    )
    .expect("missing-session source");
    let missing_source = source(ClientId::Qwen, "qwen.projects", &missing_path);
    // This source cannot establish replay/session ownership, so acquisition
    // rejects it instead of manufacturing a filename-based session.
    assert!(
        acquire_source(
            &missing_source,
            AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap())
        )
        .is_err()
    );
}

#[test]
fn ignores_codex_declared_tools_from_config_toml_for_usage_inference() {
    let temp = tempdir().expect("tempdir");
    fs::create_dir(temp.path().join(".codex")).expect("Codex directory");
    fs::write(
        temp.path().join(".codex/config.toml"),
        r#"[mcp_servers.fixture]
command = "synthetic-codex"
tools = ["ignored_tool"]
"#,
    )
    .expect("Codex MCP config");
    let source_path = temp.path().join("codex.jsonl");
    fs::write(
        &source_path,
        r#"{"type":"tool_call","session_id":"codex-session","timestamp":"2026-09-20T05:00:00Z","model":"codex-model","provider":"openai","tool_name":"ignored_tool","arguments":{},"call_id":"call-codex"}"#,
    )
    .expect("Codex source");

    let servers = discover_mcp_inventory_servers(temp.path());
    let codex_server = servers
        .iter()
        .find(|server| server.client == ClientId::Codex)
        .expect("Codex server inventory");
    assert!(codex_server.declared_tools.is_empty());
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_owned(),
        path: source_path,
    };
    let accounting = acquire_accounting(&source);
    assert!(project(&source, &accounting, &servers).is_empty());
}

#[test]
fn acquisition_debug_redacts_native_tool_names_and_timestamps() {
    let temp = tempdir().expect("tempdir");
    let source_path = temp.path().join("privacy.jsonl");
    let tool_name = "unique_synthetic_debug_tool_9f3b";
    let timestamp = "2099-12-31T23:59:59.999Z";
    fs::write(
        &source_path,
        format!(
            r#"{{"type":"tool_call","role":"assistant","session_id":"privacy-session","timestamp":"{timestamp}","content":[{{"type":"tool_use","id":"privacy-call","name":"{tool_name}","input":{{}}}}]}}"#
        ),
    )
    .expect("privacy source");
    let source = source(ClientId::Claude, "claude.projects", source_path);
    let accounting = acquire_accounting(&source);
    let debug = format!("{accounting:?}");
    assert!(!debug.contains(tool_name));
    assert!(!debug.contains(timestamp));
}
