#[test]
fn scoped_inventory_walks_only_selected_workspaces() {
    let home = tempdir().unwrap();
    fs::create_dir(home.path().join(".codex")).unwrap();
    fs::write(
        home.path().join(".codex/config.toml"),
        "[mcp_servers.fixed]\ncommand = 'synthetic'\n",
    )
    .unwrap();
    for name in ["Music", "Pictures", "Library", "unconfigured-project"] {
        let directory = home.path().join(name);
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join(".mcp.json"),
            r#"{"mcpServers":{"unselected":{"command":"synthetic"}}}"#,
        )
        .unwrap();
    }
    let workspace = home.path().join("selected-project");
    fs::create_dir_all(workspace.join("nested")).unwrap();
    fs::write(
        workspace.join("nested/.mcp.json"),
        r#"{"mcpServers":{"selected":{"command":"synthetic"}}}"#,
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(home.path().join("Music"), workspace.join("media-link")).unwrap();

    let fixed = super::acquire_mcp_inventory_with_workspaces(home.path(), &[]);
    assert_eq!(fixed.len(), 1);
    assert_eq!(fixed[0].servers.as_ref().unwrap()[0].server_name, "fixed");
    let scoped =
        super::acquire_mcp_inventory_with_workspaces(home.path(), &[workspace.clone(), workspace]);
    let mut servers = scoped
        .iter()
        .flat_map(|config| config.servers.as_ref().unwrap())
        .map(|server| server.server_name.as_str())
        .collect::<Vec<_>>();
    servers.sort_unstable();
    assert_eq!(servers, ["fixed", "selected"]);
}

#[cfg(unix)]
#[test]
fn scoped_inventory_does_not_enumerate_unselected_private_directories() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempdir().unwrap();
    fs::write(home.path().join(".mcp.json"), "{}").unwrap();
    let music = home.path().join("Music");
    fs::create_dir(&music).unwrap();
    fs::set_permissions(&music, fs::Permissions::from_mode(0o000)).unwrap();
    let (configs, error) = super::discover_mcp_configs_in_workspaces(home.path(), &[]);
    fs::set_permissions(music, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(configs.len(), 1);
    assert_eq!(error, None);
}

#[test]
fn scoped_inventory_shares_workspace_candidate_limit_and_keeps_fixed_paths() {
    let home = tempdir().unwrap();
    fs::write(
        home.path().join(".mcp.json"),
        r#"{"mcpServers":{"fixed":{"command":"synthetic"}}}"#,
    )
    .unwrap();
    let workspaces = [home.path().join("a"), home.path().join("b")];
    for workspace in &workspaces {
        for index in 0..32 {
            let project = workspace.join(format!("project-{index}"));
            fs::create_dir_all(&project).unwrap();
            fs::write(project.join(".mcp.json"), "{}").unwrap();
        }
    }
    let result = super::acquire_mcp_inventory_with_workspaces(home.path(), &workspaces);
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].servers, Err("mcp_inventory_limit_exceeded"));
    assert_eq!(result[1].servers.as_ref().unwrap()[0].server_name, "fixed");
}

#[test]
fn scan_server_limit_rejects_whole_config_without_charging_later_capacity() {
    let root = tempdir().unwrap();
    let servers = (0..255)
        .map(|i| {
            (
                format!("server-{i}"),
                serde_json::json!({"command": "node"}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    fs::write(
        root.path().join(".claude.json"),
        serde_json::json!({"mcpServers": servers}).to_string(),
    )
    .unwrap();
    fs::write(
        root.path().join(".mcp.json"),
        r#"{"mcpServers":{"overflow-a":{"command":"node"},"overflow-b":{"command":"node"}}}"#,
    )
    .unwrap();
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(
        workspace.join(".mcp.json"),
        r#"{"mcpServers":{"kept":{"command":"node"}}}"#,
    )
    .unwrap();

    let configs = super::acquire_mcp_inventory(root.path());
    assert_eq!(configs.len(), 3);
    assert_eq!(configs[0].servers.as_ref().unwrap().len(), 255);
    assert_eq!(configs[1].servers, Err("mcp_inventory_limit_exceeded"));
    let last = configs[2].servers.as_ref().unwrap();
    assert_eq!(last.len(), 1);
    assert_eq!(last[0].server_name, "kept");
    assert_eq!(last[0].source_id, "claude.workspace_mcp_config");
}

#[test]
fn mcp_nested_servers_object_is_parsed() {
    let temp = tempdir().unwrap();
    let path = temp.path().join(".mcp.json");
    fs::write(
        &path,
        r#"{"mcp":{"servers":{"actual":{"command":"node","tools":["lookup"]}}}}"#,
    )
    .unwrap();
    let configs = super::acquire_mcp_inventory(temp.path());
    assert_eq!(configs.len(), 1);
    let servers = configs[0].servers.as_ref().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].server_name, "actual");
    assert!(servers[0].supported);
    assert_eq!(servers[0].command.as_deref(), Some("node"));
    assert_eq!(servers[0].declared_tools, ["lookup"]);
    assert_eq!(servers[0].source_id, "claude.project_mcp_config");
    assert_eq!(servers[0].path, path);

    let observations =
        super::collect_mcp_inventory(&super::McpInventoryInput::FixedRoot(temp.path().into()));
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].server_name(), Some("actual"));
    assert_eq!(observations[0].state(), super::McpInventoryState::Supported);
    assert_eq!(observations[0].declared_tool_count(), 1);
}

#[test]
fn json_mcp_shapes_preserve_explicit_top_level_precedence() {
    let server = serde_json::json!({"actual": {"command": "node"}});
    for value in [
        serde_json::json!({"mcpServers": server}),
        serde_json::json!({"mcp_servers": server}),
        serde_json::json!({"mcp": server}),
        serde_json::json!({"mcp": {"servers": server}}),
        serde_json::json!({"mcpServers": server, "mcp_servers": {}, "mcp": {"servers": {}}}),
        serde_json::json!({"mcp_servers": server, "mcp": {"servers": {}}}),
    ] {
        assert_eq!(super::find_mcp_servers_object(&value), server.as_object());
    }
    // Preserve the existing nested fallback for malformed explicit keys.
    for value in [
        serde_json::json!({"mcpServers": null, "mcp_servers": server, "mcp": {"servers": server}}),
        serde_json::json!({"mcp_servers": null, "mcp": {"servers": server}}),
    ] {
        assert_eq!(super::find_mcp_servers_object(&value), server.as_object());
    }
    let malformed = serde_json::json!({"mcpServers": null, "mcp_servers": server});
    assert!(super::find_mcp_servers_object(&malformed).is_none());
}

#[test]
fn direct_server_named_servers_is_not_a_nested_container() {
    let root = tempdir().unwrap();
    let path = root.path().join(".mcp.json");
    for definition in [
        serde_json::json!({"command": "node", "tools": ["lookup"]}),
        serde_json::json!({"url": "https://example.invalid/mcp", "tools": ["lookup"]}),
    ] {
        fs::write(
            &path,
            serde_json::json!({"mcp": {
                "servers": definition,
                "actual": {"command": "node", "tools": ["other"]}
            }})
            .to_string(),
        )
        .unwrap();
        let acquired = super::acquire_mcp_inventory(root.path());
        let servers = acquired[0].servers.as_ref().unwrap();
        assert_eq!(
            servers
                .iter()
                .map(|s| s.server_name.as_str())
                .collect::<Vec<_>>(),
            ["actual", "servers"]
        );
        assert!(servers.iter().all(|s| s.supported));
        assert_eq!(servers[1].declared_tools, ["lookup"]);
        let observations =
            super::collect_mcp_inventory(&super::McpInventoryInput::FixedRoot(root.path().into()));
        assert_eq!(observations.len(), 2);
        assert!(
            observations
                .iter()
                .all(|s| s.state() == super::McpInventoryState::Supported)
        );
    }
}

#[cfg(unix)]
#[test]
fn inventory_config_fifo_returns_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let root = tempdir().unwrap();
    let path = root.path().join("fifo");
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // Synthetic FIFO, with no writer: blocking open would hang this regression.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    let observations = super::collect_mcp_inventory(&super::McpInventoryInput::Configs(vec![
        super::McpConfigInput::new(ClientId::Claude, "claude.project_mcp_config", path),
    ]));
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].reason(), Some("non_regular_source"));
}

#[test]
fn workspace_candidate_limit_preserves_fixed_inventory_and_reports_gap() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".mcp.json"),
        r#"{"mcpServers":{"fixed":{"command":"synthetic"}}}"#,
    )
    .unwrap();
    for index in 0..63 {
        let workspace = dir.path().join(format!("workspace-{index}"));
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join(".mcp.json"), "{}").unwrap();
    }
    let (_, error) = super::discover_mcp_configs(dir.path());
    assert_eq!(error, None);
    let workspace = dir.path().join("workspace-overflow");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(workspace.join(".mcp.json"), "{}").unwrap();
    let result = super::acquire_mcp_inventory(dir.path());
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].servers, Err("mcp_inventory_limit_exceeded"));
    let servers = result[1].servers.as_ref().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].server_name, "fixed");
}

#[test]
fn failed_workspace_reads_do_not_starve_fixed_mcp_configs() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".codex")).unwrap();
    std::fs::write(
        dir.path().join(".codex/config.toml"),
        "[mcp_servers.fixed]\ncommand = 'synthetic'\n",
    )
    .unwrap();
    for index in 0..4 {
        let workspace = dir.path().join(format!("workspace-{index}"));
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(workspace.join(".mcp.json")).unwrap();
    }
    let result = super::acquire_mcp_inventory(dir.path());
    assert!(
        result
            .iter()
            .filter_map(|config| config.servers.as_ref().ok())
            .flatten()
            .any(|server| { server.server_name == "fixed" && server.client == ClientId::Codex })
    );
    let error_reasons: Vec<_> = result
        .iter()
        .filter_map(|config| config.servers.as_ref().err().copied())
        .collect();
    assert_eq!(error_reasons.len(), 4);
    assert!(error_reasons.iter().all(|reason| {
        *reason == "non_regular_source" || *reason == "source_permission_denied"
    }));
    assert!(!error_reasons.contains(&"mcp_inventory_limit_exceeded"));
}

#[test]
fn workspace_entry_limit_keeps_fixed_paths_and_counts_irrelevant_entries() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".mcp.json"), "{}").unwrap();
    for index in 0..10_000 {
        std::fs::File::create(dir.path().join(format!("irrelevant-{index}"))).unwrap();
    }
    let (configs, error) = super::discover_mcp_configs(dir.path());
    assert_eq!(configs.len(), 1);
    assert_eq!(error, Some("mcp_traversal_limit_exceeded"));
}

#[cfg(unix)]
#[test]
fn unreadable_workspace_does_not_discard_fixed_paths() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".mcp.json"), "{}").unwrap();
    let private = dir.path().join("unreadable");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o000)).unwrap();
    let permissions_enforced = std::fs::read_dir(&private).is_err();
    let (configs, error) = super::discover_mcp_configs(dir.path());
    std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(configs.len(), 1);
    if permissions_enforced {
        assert_eq!(error, Some("mcp_discovery_unreadable"));
    }
}
#[test]
fn production_inventory_rejects_oversized_padding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".mcp.json");
    let raw = r#"{"mcpServers":{"synthetic":{"command":"synthetic"}}}"#;
    std::fs::write(
        &path,
        format!("{raw}{}", " ".repeat(1024 * 1024 - raw.len())),
    )
    .unwrap();
    let result = super::acquire_mcp_inventory(dir.path());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].servers.as_ref().unwrap().len(), 1);
    std::fs::write(
        &path,
        format!("{raw}{}", " ".repeat(1024 * 1024 + 1 - raw.len())),
    )
    .unwrap();
    let result = super::acquire_mcp_inventory(dir.path());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].servers, Err("source_limit_exceeded"));
}
use std::fs;
use std::path::PathBuf;

use tempfile::tempdir;

use super::{ConfigFormat, DiscoveredMcpConfig, parse_toml_mcp_config};
use telltale_schema::clients::ClientId;

#[test]
fn toml_env_values_never_become_inventory_fields() {
    let temp = tempdir().unwrap();
    let config = DiscoveredMcpConfig {
        client: ClientId::Codex,
        id: "codex.mcp_config",
        path: temp.path().join("config.toml"),
        format: ConfigFormat::Toml,
    };
    fs::write(&config.path, "[mcp_servers.s]\ncommand = 'node'\nargs = []\n[mcp_servers.s.env]\ncommand = 'TT_ENV_COMMAND_VALUE'\nurl = 'TT_ENV_URL_VALUE'\n").unwrap();
    let servers = super::read_mcp_config(&config, &mut (4 * 1024 * 1024), 256).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].server_name, "s");
    assert_eq!(servers[0].command.as_deref(), Some("node"));
    assert_eq!(servers[0].arg_count, 0);
    assert_eq!(servers[0].env_keys.len(), 2);
    assert!(
        !format!("{servers:?}").contains("TT_ENV_"),
        "environment value escaped parser ownership"
    );
}

#[test]
fn parses_codex_toml_mcp_servers_without_toml_dependency() {
    let temp = tempdir().expect("tempdir");
    let config = DiscoveredMcpConfig {
        client: ClientId::Codex,
        id: "codex.mcp_config",
        path: temp.path().join("config.toml"),
        format: ConfigFormat::Toml,
    };
    let inventory = parse_toml_mcp_config(
        &config,
        r#"
            [mcp_servers.filesystem]
            command = "npx"
            args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/project"]

            [mcp_servers.remote]
            type = "http"
            url = "https://mcp.example.invalid/mcp"
            "#,
    );

    assert_eq!(inventory.len(), 2);
    assert_eq!(inventory[0].server_name, "filesystem");
    assert_eq!(inventory[0].transport.as_deref(), Some("stdio"));
    assert_eq!(
        inventory[1].url_host.as_deref(),
        Some("mcp.example.invalid")
    );
}

#[test]
fn static_inventory_unsupported_identities_do_not_charge_read_budget() {
    let configs = (0..65)
        .map(|_| {
            super::McpConfigInput::new(
                ClientId::Claude,
                "unsupported",
                PathBuf::from("synthetic-missing.json"),
            )
        })
        .collect();
    let observations = super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
    assert_eq!(observations.len(), 65);
    assert!(
        observations[..64]
            .iter()
            .all(|item| { item.reason() == Some("unsupported_mcp_source_identity") })
    );
    assert_eq!(
        observations[64].reason(),
        Some("mcp_inventory_limit_exceeded")
    );
}

#[test]
fn static_inventory_failed_reads_do_not_consume_the_byte_budget() {
    let temp = tempdir().unwrap();
    let directory_reason = crate::source_read::bounded_file_bytes(temp.path(), 1024 * 1024)
        .expect_err("a directory must fail at the source read boundary")
        .code();
    assert!(matches!(
        directory_reason,
        "non_regular_source" | "source_permission_denied"
    ));
    if cfg!(windows) {
        // Windows rejects directory opens before regular-file metadata validation.
        assert_eq!(directory_reason, "source_permission_denied");
    }
    let valid = temp.path().join("valid.json");
    fs::write(&valid, r#"{"mcpServers":{"kept":{"command":"node"}}}"#).unwrap();
    for (path, reason) in [
        (temp.path().join("missing.json"), "source_missing"),
        (temp.path().to_path_buf(), directory_reason),
    ] {
        let configs = (0..8)
            .map(|_| {
                super::McpConfigInput::new(
                    ClientId::Claude,
                    "claude.project_mcp_config",
                    path.clone(),
                )
            })
            .chain(std::iter::once(super::McpConfigInput::new(
                ClientId::Claude,
                "claude.project_mcp_config",
                valid.clone(),
            )))
            .collect();
        let observations =
            super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
        assert_eq!(observations.len(), 9);
        assert!(observations[..8].iter().all(|item| {
            item.reason() == Some(reason) && item.state() == super::McpInventoryState::Error
        }));
        assert_eq!(observations[8].state(), super::McpInventoryState::Supported);
        assert_eq!(observations[8].server_name(), Some("kept"));
    }
}

#[test]
fn static_inventory_accepts_exactly_one_mib_and_refunds_unused_read_allowance() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("config.json");
    let mut raw = r#"{"mcpServers":{"fixture":{"command":"node"}}}"#.to_owned();
    raw.push_str(&" ".repeat(1024 * 1024 - raw.len()));
    fs::write(&path, &raw).unwrap();
    let tail = temp.path().join("tail.json");
    fs::write(&tail, &raw[..raw.len() - 1]).unwrap();
    let configs = (0..3)
        .map(|_| {
            super::McpConfigInput::new(ClientId::Claude, "claude.project_mcp_config", path.clone())
        })
        .chain(std::iter::once(super::McpConfigInput::new(
            ClientId::Claude,
            "claude.project_mcp_config",
            tail,
        )))
        .collect();
    let observations = super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
    assert_eq!(observations.len(), 4);
    assert!(
        observations
            .iter()
            .all(|item| item.state() == super::McpInventoryState::Supported)
    );
}

#[test]
fn static_inventory_charges_only_accepted_bytes_at_aggregate_boundary() {
    let temp = tempdir().unwrap();
    let exact = temp.path().join("exact.json");
    let mut raw = r#"{"mcpServers":{"fixture":{"command":"node"}}}"#.to_owned();
    raw.push_str(&" ".repeat(1024 * 1024 - raw.len()));
    fs::write(&exact, &raw).unwrap();
    let oversized = temp.path().join("oversized.json");
    fs::write(&oversized, format!("{raw} ")).unwrap();
    let tiny = temp.path().join("tiny.json");
    fs::write(&tiny, r#"{"mcpServers":{"kept":{"command":"node"}}}"#).unwrap();
    // Three exact-MiB reads leave 1 MiB. The oversized file does not fit in
    // that remainder including its probe, fails closed, and restores the
    // reservation so the tiny file is still accepted.
    let configs = [exact.clone(), exact.clone(), exact.clone(), oversized, tiny]
        .into_iter()
        .map(|path| super::McpConfigInput::new(ClientId::Claude, "claude.project_mcp_config", path))
        .collect();
    let observations = super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
    assert_eq!(observations.len(), 5);
    assert!(
        observations[..3]
            .iter()
            .all(|item| item.state() == super::McpInventoryState::Supported)
    );
    assert_eq!(observations[3].reason(), Some("source_limit_exceeded"));
    assert_eq!(observations[4].state(), super::McpInventoryState::Supported);
    assert_eq!(observations[4].server_name(), Some("kept"));

    // An exact-MiB file does not fit in a 1 MiB remainder once the probe is
    // reserved. That rejection must not consume the remainder.
    let after = temp.path().join("after.json");
    fs::write(&after, r#"{"mcpServers":{"after":{"command":"node"}}}"#).unwrap();
    let configs = [exact.clone(), exact.clone(), exact.clone(), exact, after]
        .into_iter()
        .map(|path| super::McpConfigInput::new(ClientId::Claude, "claude.project_mcp_config", path))
        .collect();
    let observations = super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
    assert_eq!(observations.len(), 5);
    assert!(
        observations[..3]
            .iter()
            .all(|item| item.state() == super::McpInventoryState::Supported)
    );
    assert_eq!(observations[3].reason(), Some("source_limit_exceeded"));
    assert_eq!(observations[4].server_name(), Some("after"));
}

#[test]
fn safe_command_and_package_identities_redact_url_credentials_before_splitting() {
    assert_eq!(
        super::safe_command_identity("https://alice:pass@example.invalid"),
        "[redacted-url]"
    );
    assert_eq!(
        super::safe_command_identity("\"https://alice:pass@example.invalid\""),
        "[redacted-url]"
    );
    assert_eq!(
        super::safe_command_identity("https://alice:pass@example.invalid/bin/server"),
        "[redacted-url]"
    );
    assert_eq!(
        super::safe_package_identity("https://alice:pass@example.invalid"),
        "[redacted-url]"
    );
    assert_eq!(
        super::safe_package_identity("mcp-server-https://alice:pass@example.invalid"),
        "[redacted-url]"
    );
    assert_eq!(
        super::safe_package_identity("@scope/https://alice:pass@example.invalid"),
        "[redacted-url]"
    );
}

#[test]
fn static_inventory_url_commands_are_safe_in_accessors_debug_and_serialization() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("config.json");
    for command in [
        "https://TT_MCP_USER:TT_MCP_PASSWORD@example.invalid",
        "//TT_MCP_USER:TT_MCP_PASSWORD@example.invalid/mcp-server",
        "\"https://TT_MCP_USER:TT_MCP_PASSWORD@example.invalid/bin/server\"",
    ] {
        fs::write(
            &path,
            serde_json::json!({"mcpServers": {"fixture": {"command": command}}}).to_string(),
        )
        .unwrap();
        let observations = super::collect_mcp_inventory(&super::McpInventoryInput::Configs(vec![
            super::McpConfigInput::new(ClientId::Claude, "claude.project_mcp_config", path.clone()),
        ]));
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].command(), Some("[redacted-url]"));
        for output in [
            observations[0].command().unwrap().to_owned(),
            observations[0].package().unwrap_or_default().to_owned(),
            format!("{observations:?}"),
            serde_json::to_string(&observations).unwrap(),
        ] {
            assert!(
                !output.contains("TT_MCP_"),
                "inventory retained URL credential marker"
            );
        }
    }
}

#[test]
fn codex_toml_unrelated_multiline_with_fake_mcp_preserves_declared_tools() {
    let temp = tempdir().expect("tempdir");
    let config = DiscoveredMcpConfig {
        client: ClientId::Codex,
        id: "codex.mcp_config",
        path: temp.path().join("config.toml"),
        format: ConfigFormat::Toml,
    };
    let raw = r#"
instructions = """
[mcp_servers.fake_server]
command = "fake_cmd"
tools = ["fake_tool"]
"""
[mcp_servers.actual]
command = "node"
tools = ["lookup"]
[unrelated]
notes = '''
[mcp_servers.second_fake]
command = "second_fake_cmd"
tools = ["second_tool"]
'''
"#;
    let servers = parse_toml_mcp_config(&config, raw);
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].server_name, "actual");
    assert_eq!(servers[0].declared_tools, vec!["lookup".to_string()]);
    assert!(servers[0].supported);
}
