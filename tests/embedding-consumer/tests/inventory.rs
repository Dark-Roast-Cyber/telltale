use serde_json::json;
use telltale_core::inventory::*;
use telltale_core::{ClientId, Event3Record, Source, SourceKind};

#[test]
fn launcher_platform_and_session_posture_are_metadata_only_and_private() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("TT_PRIVATE_INSTALL_PATH");
    std::fs::create_dir(&bin).unwrap();
    std::fs::write(bin.join("claude.cmd"), "not an executable; must not run").unwrap();
    let context = InstallInventoryContext {
        home: root.path().into(),
        path_dirs: vec![bin],
        extension_roots: vec![],
        global_storage_roots: vec![],
        node_roots: vec![],
    };
    let unix = collect_install_inventory_for_platform(&context, 1234, InstallPlatform::Unix);
    let windows = collect_install_inventory_for_platform(&context, 1234, InstallPlatform::Windows);
    assert!(
        !unix
            .agents
            .iter()
            .find(|a| a.agent == "claude")
            .unwrap()
            .installed
    );
    assert!(
        windows
            .agents
            .iter()
            .find(|a| a.agent == "claude")
            .unwrap()
            .installed
    );
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path: root.path().join("TT_PRIVATE_SESSION_PATH"),
    };
    let snapshot = collect_install_inventory_with_sources(&context, 1234, &[source]);
    let agent = snapshot.agents.iter().find(|a| a.agent == "codex").unwrap();
    assert!(agent.installed);
    assert_eq!(agent.confidence, InstallConfidence::Partial);
    assert!(
        agent
            .signals
            .iter()
            .any(|s| s.kind == "session_store" && s.present && s.path_hash.is_some())
    );
    let wire = serde_json::to_string(&snapshot_to_event(&snapshot).unwrap()).unwrap();
    Event3Record::from_json_str(&wire).unwrap();
    for output in [
        serde_json::to_string(&windows).unwrap(),
        serde_json::to_string(&snapshot).unwrap(),
        wire,
    ] {
        assert!(!output.contains("TT_PRIVATE"));
        assert!(!output.contains(root.path().to_str().unwrap()));
    }
}

#[test]
fn structured_mcp_metadata_errors_and_fixed_roots_do_not_leak_or_connect() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(
        nested.join(".mcp.json"),
        r#"{"mcpServers":{"nested":{"command":"node"}}}"#,
    )
    .unwrap();
    assert!(collect_mcp_inventory(&McpInventoryInput::FixedRoot(root.path().into())).is_empty());
    let path = root.path().join("TT_PRIVATE_CONFIG_PATH.json");
    std::fs::write(&path, json!({"mcpServers": {
        "local": {"command":"/home/synthetic/TT_PRIVATE_COMMAND/helper", "args":["TT_PRIVATE_ARG"], "env":{"TT_PRIVATE_ENV_KEY":"TT_PRIVATE_ENV_VALUE"}, "tools":["TT_PRIVATE_TOOL"]},
        "remote": {"url":"https://user:TT_PRIVATE_PASSWORD@example.invalid?token=TT_PRIVATE_QUERY#TT_PRIVATE_FRAGMENT"}
    }}).to_string()).unwrap();
    let config = McpConfigInput::new(ClientId::Claude, "claude.project_mcp_config", path.clone());
    let input = McpInventoryInput::Configs(vec![config]);
    let observations = collect_mcp_inventory(&input);
    assert_eq!(observations.len(), 2);
    let local = observations
        .iter()
        .find(|s| s.server_name() == Some("local"))
        .unwrap();
    assert_eq!(local.command(), Some("helper"));
    assert_eq!(
        (
            local.arg_count(),
            local.env_key_count(),
            local.declared_tool_count()
        ),
        (1, 1, 1)
    );
    let remote = observations
        .iter()
        .find(|s| s.server_name() == Some("remote"))
        .unwrap();
    assert_eq!(remote.url_host(), Some("example.invalid"));
    for output in [
        serde_json::to_string(&observations).unwrap(),
        format!("{observations:?}"),
    ] {
        assert!(
            !output.contains("TT_PRIVATE"),
            "MCP DTO retained controlled private material"
        );
        assert!(!output.contains(root.path().to_str().unwrap()));
    }
    std::fs::write(&path, "malformed").unwrap();
    let unsupported = collect_mcp_inventory(&input);
    assert_eq!(unsupported[0].state(), McpInventoryState::Unsupported);
    assert_eq!(unsupported[0].reason(), Some("invalid_json_mcp_config"));
    std::fs::remove_file(&path).unwrap();
    let errors = collect_mcp_inventory(&input);
    assert_eq!(errors[0].state(), McpInventoryState::Error);
    assert!(
        !serde_json::to_string(&errors)
            .unwrap()
            .contains("TT_PRIVATE")
    );
    let wrong_identity =
        collect_mcp_inventory(&McpInventoryInput::Configs(vec![McpConfigInput::new(
            ClientId::Codex,
            "claude.project_mcp_config",
            path,
        )]));
    assert_eq!(
        wrong_identity[0].reason(),
        Some("unsupported_mcp_source_identity")
    );
    std::fs::write(
        root.path().join(".mcp.json"),
        r#"{"mcpServers":{"local":{"command":"node"}}}"#,
    )
    .unwrap();
    let fixed = collect_mcp_inventory(&McpInventoryInput::FixedRoot(root.path().into()));
    assert_eq!(fixed.len(), 1);
    assert_eq!(fixed[0].server_name(), Some("local"));
}
