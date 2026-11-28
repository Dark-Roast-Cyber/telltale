use super::*;
use telltale_schema::event::{ControlledMarker, check_serialized_event_markers};

#[test]
fn mcp_inventory_summaries_and_errors_cross_the_privacy_boundary() {
    let marker = "TT_PRIVACY_MCP_25";
    let inventory = McpServerInventory {
        client: ClientId::Codex,
        source_id: "codex.mcp_config".to_string(),
        path: PathBuf::from(format!("/home/{marker}/.codex/config.toml")),
        server_name: "fixture".to_string(),
        transport: Some("stdio".to_string()),
        command: Some(format!("node --api-key={marker}")),
        package: Some("mcp-fixture".to_string()),
        url_host: None,
        arg_count: 1,
        env_keys: vec!["API_KEY".to_string()],
        declared_tools: vec!["fixture_tool".to_string()],
        supported: true,
        unsupported_reason: None,
    };
    let events = [
        project_mcp_inventory(&inventory),
        project_mcp_inventory_error(
            ClientId::Codex,
            &format!(
                "config at /home/{marker}/.codex/config.toml failed for https://user:{marker}@example.invalid/?token={marker}"
            ),
        ),
    ];
    let markers = [ControlledMarker {
        id: "mcp-marker",
        value: marker,
    }];

    for event in events {
        let bytes = serde_json::to_vec(&event.emittable()).expect("serialize MCP event");
        assert!(
            check_serialized_event_markers(&bytes, "mcp", &markers).is_ok(),
            "MCP event retained a controlled marker"
        );
    }
}

#[test]
fn a_wrapped_tool_name_belongs_to_the_server_it_spells_out() {
    let server = |name: &str, tools: &[&str]| McpServerInventory {
        client: ClientId::Claude,
        source_id: "claude.mcp_config".to_string(),
        path: PathBuf::from("/synthetic/mcp.json"),
        server_name: name.to_string(),
        transport: Some("stdio".to_string()),
        command: None,
        package: None,
        url_host: None,
        arg_count: 0,
        env_keys: Vec::new(),
        declared_tools: tools.iter().map(|tool| tool.to_string()).collect(),
        supported: true,
        unsupported_reason: None,
    };
    let servers = [
        server("synthetic-docs", &["search_pages"]),
        server("synthetic-wiki", &["search_pages", "edit__page"]),
        server("web", &["search"]),
    ];
    let index = McpToolIndex::from_servers(&servers);
    let names = |tool: &str| {
        index
            .lookup(ClientId::Claude, tool)
            .unwrap_or_default()
            .iter()
            .map(|server| server.server_name.as_str())
            .collect::<Vec<_>>()
    };

    // A bare name belongs to every server that declares it, as before.
    assert_eq!(names("search_pages"), ["synthetic-docs", "synthetic-wiki"]);
    // A wrapped name belongs to its server alone.
    assert_eq!(
        names("mcp__synthetic-docs__search_pages"),
        ["synthetic-docs"]
    );
    assert_eq!(
        names("MCP__Synthetic-Wiki__Search_Pages"),
        ["synthetic-wiki"]
    );
    assert_eq!(names("mcp__synthetic-wiki__edit__page"), ["synthetic-wiki"]);
    // A server that does not declare the tool, or is not configured.
    assert!(names("mcp__web__search_pages").is_empty());
    assert!(names("mcp__absent__search_pages").is_empty());
    // Another client's configuration is not this client's.
    assert!(index.lookup(ClientId::Codex, "mcp__web__search").is_none());
    // A single separator is not read: `web_search` is a built-in's name.
    for unread in ["web_search", "web-search", "web/search", "web:search"] {
        assert!(names(unread).is_empty(), "{unread}");
    }
}

#[test]
fn mcp_inventory_errors_use_the_shared_diagnostic_policy_before_emission() {
    let marker = "TT_PRIVACY_MCP_DIAGNOSTIC_25";
    let event = project_mcp_inventory_error(
        ClientId::Codex,
        &format!("config at /home/{marker}/.codex/config.toml failed with token={marker}"),
    );
    let error = event
        .evidence
        .iter()
        .find(|evidence| evidence.field == "mcp_inventory_error")
        .expect("MCP error evidence");

    assert!(
        !error.redacted_value.contains(marker),
        "MCP diagnostic retained a controlled marker before emission"
    );
    assert!(error.redacted_value.contains("<path>"));
}

#[test]
fn mcp_inventory_summary_hashes_the_established_safe_command_value() {
    let inventory = McpServerInventory {
        client: ClientId::Codex,
        source_id: "codex.mcp_config".to_string(),
        path: PathBuf::from("/synthetic/config.toml"),
        server_name: "fixture".to_string(),
        transport: Some("stdio".to_string()),
        command: Some("node --api-key=synthetic-value".to_string()),
        package: Some("mcp-fixture".to_string()),
        url_host: None,
        arg_count: 1,
        env_keys: Vec::new(),
        declared_tools: Vec::new(),
        supported: true,
        unsupported_reason: None,
    };

    let evidence = inventory_evidence(&inventory);
    let summary = &evidence[0];
    let expected_hash = evidence_hash(&summary.redacted_value);
    assert!(summary.redacted_value.contains("[redacted-command]"));
    assert_eq!(summary.hash.as_deref(), Some(expected_hash.as_str()));
}

#[cfg(test)]
mod canonical;
