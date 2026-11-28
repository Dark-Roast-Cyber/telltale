use std::fs;

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::ObservedAt;
use telltale_schema::source::Source;
use telltale_sources::acquisition::{AcquisitionOptions, SourceAccounting, acquire_source};
use tempfile::tempdir;

use super::{McpServerInventory, project_mcp_usage};

fn discover_mcp_inventory_servers(root: &std::path::Path) -> Vec<McpServerInventory> {
    telltale_sources::mcp::acquire_mcp_inventory(root)
        .into_iter()
        .flat_map(|config| config.servers.expect("synthetic MCP acquisition"))
        .collect()
}

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
fn builds_mcp_tool_index_from_declared_tools() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join(".mcp.json"),
        r#"{"mcpServers":{
            "github":{"command":"npx","tools":[{"name":"list_issues"},{"name":"create_issue"}]},
            "empty":{"command":"npx"}
        }}"#,
    )
    .unwrap();
    let servers = discover_mcp_inventory_servers(temp.path());
    let index = super::McpToolIndex::from_servers(&servers);
    let matches = index.lookup(ClientId::Claude, "LIST_ISSUES").unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].server_name, "github");
    assert!(index.lookup(ClientId::Claude, "not_declared").is_none());
    assert!(index.lookup(ClientId::Qwen, "list_issues").is_none());
}

#[test]
fn emits_mcp_usage_event_for_attributed_tool_calls() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join(".mcp.json"),
        r#"{"mcpServers":{"github":{
            "type":"streamable-http","url":"https://api.githubcopilot.com/mcp/",
            "tools":[{"name":"list_issues"},{"name":"create_issue"}]
        }}}"#,
    )
    .unwrap();
    let session_path = temp.path().join("session-a.jsonl");
    fs::write(
        &session_path,
        concat!(
            r#"{"type":"assistant","sessionId":"session-a","timestamp":"2026-04-03T06:00:00Z","agent":"claude","model":"fixture-model","provider":"anthropic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu-list","name":"list_issues","input":{}}]}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"session-a","timestamp":"2026-04-03T06:00:01Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu-create","name":"create_issue","input":{}}]}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"session-a","timestamp":"2026-04-03T06:00:02Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu-view","name":"view","input":{}}]}}"#,
            "\n",
        ),
    ).unwrap();
    let source = source(ClientId::Claude, "claude.projects", session_path);
    let accounting = acquire_accounting(&source);
    let servers = discover_mcp_inventory_servers(temp.path());
    let events = project(&source, &accounting, &servers);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.event_type, "activity");
    assert_eq!(event.session_id, "session-a");
    assert_eq!(event.tool_name.as_deref(), Some("mcp::github"));
    assert!(event.tags.iter().any(|tag| tag == "mcp_usage"));
    assert_eq!(event.risk_score, 0);
    let usage = summary(event);
    assert_eq!(
        usage["tools_used"],
        serde_json::json!([
            {"tool_name":"create_issue", "call_count":1},
            {"tool_name":"list_issues", "call_count":1},
        ])
    );
    assert_eq!(usage["configured_host"], "api.githubcopilot.com");
    assert_eq!(usage["unattributed_tool_calls"], 1);
}

#[test]
fn skips_mcp_usage_when_no_declared_tools_match() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join(".mcp.json"),
        r#"{"mcpServers":{"github":{"command":"npx","tools":[{"name":"list_issues"}]}}}"#,
    )
    .unwrap();
    let servers = discover_mcp_inventory_servers(temp.path());
    let (source, accounting) = lookup_accounting(temp.path());
    assert!(project(&source, &accounting, &servers).is_empty());
}

fn lookup_accounting(root: &std::path::Path) -> (Source, SourceAccounting) {
    let path = root.join("session.jsonl");
    fs::write(
        &path,
        r#"{"type":"tool_call","role":"assistant","session_id":"lookup-session","timestamp":"2026-09-20T01:00:00Z","content":[{"type":"tool_use","id":"lookup-call","name":"lookup","input":{}}]}"#,
    )
    .unwrap();
    let source = source(ClientId::Claude, "claude.projects", path);
    let accounting = acquire_accounting(&source);
    fs::remove_file(&source.path).unwrap();
    (source, accounting)
}

#[test]
fn mcp_usage_separates_same_named_config_servers() {
    for directories in [["", "workspace"], ["workspace-a", "workspace-b"]] {
        let temp = tempdir().unwrap();
        let mut expected = std::collections::BTreeMap::new();
        for (index, directory) in directories.iter().enumerate() {
            let parent = temp.path().join(directory);
            fs::create_dir_all(&parent).unwrap();
            let path = parent.join(".mcp.json");
            let command = format!("synthetic-{index}");
            fs::write(
                &path,
                serde_json::json!({"mcpServers": {
                    "shared": {"command": command, "tools": ["lookup"]}
                }})
                .to_string(),
            )
            .unwrap();
            expected.insert(
                telltale_schema::event::path_hash(&path),
                (
                    command,
                    if directory.is_empty() {
                        "claude.project_mcp_config"
                    } else {
                        "claude.workspace_mcp_config"
                    },
                ),
            );
        }
        let servers = discover_mcp_inventory_servers(temp.path());
        let (source, accounting) = lookup_accounting(temp.path());
        let events = project(&source, &accounting, &servers);
        assert_eq!(
            events.len(),
            2,
            "each configuration retains its attribution"
        );
        for event in &events {
            let config = event
                .evidence
                .iter()
                .find(|e| e.field == "mcp_config_path")
                .unwrap();
            let (command, source_id) = expected.remove(config.hash.as_ref().unwrap()).unwrap();
            let usage = summary(event);
            assert_eq!(usage["tool_call_count"], 1);
            assert_eq!(usage["tools_used"][0]["call_count"], 1);
            assert_eq!(usage["unattributed_tool_calls"], 0);
            assert_eq!(usage["server_command"], command);
            assert_eq!(usage["source_id"], source_id);
            assert_eq!(config.redacted_value, source_id);
            assert_eq!(usage["attribution_method"], "declared_tools");
            assert_eq!(
                event.event_time.as_deref(),
                Some("2026-09-20T01:00:00.000Z")
            );
        }
        assert!(expected.is_empty());
    }
}

#[test]
fn mcp_usage_deduplicates_normalized_declarations() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join(".mcp.json"),
        r#"{"mcpServers":{"actual":{"command":"node","tools":["lookup","LOOKUP"," lookup "]}}}"#,
    )
    .unwrap();
    let servers = discover_mcp_inventory_servers(temp.path());
    let (source, accounting) = lookup_accounting(temp.path());
    let events = project(&source, &accounting, &servers);
    assert_eq!(events.len(), 1);
    let usage = summary(&events[0]);
    assert_eq!(usage["tool_call_count"], 1);
    assert_eq!(usage["tools_used"][0]["call_count"], 1);
    assert_eq!(usage["unattributed_tool_calls"], 0);
    assert_eq!(
        usage["declared_tool_count"], 3,
        "inventory declarations remain unchanged"
    );
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
