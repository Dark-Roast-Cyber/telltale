//! Opt-in local install and static MCP configuration inventory.
//!
//! These APIs reuse the existing collectors without compiling rules, connecting
//! to MCP servers, or starting a watcher. Pipeline scans do not call them, and
//! this facade does not change CLI scan/watch activation.
//!
//! Prefer [`collect_install_inventory_with_context`] with an explicit,
//! host-owned [`InstallInventoryContext`]. [`InstallInventoryContext::current`]
//! and [`collect_install_inventory`] read the process environment (home, PATH,
//! and extension overrides), which may not describe the intended host roots.
//! Snapshots contain signal presence and path hashes, not raw paths. The
//! context itself contains paths; it is caller configuration, not safe telemetry.

use std::path::Path;

use crate::{Event, Source};

pub use telltale_sources::install_inventory::{
    AgentInstallObservation, InstallConfidence, InstallInventoryContext, InstallInventorySnapshot,
    InstallPlatform, InstallSignal, collect_install_inventory,
    collect_install_inventory_for_platform, collect_install_inventory_with_context,
    collect_install_inventory_with_sources, install_inventory_due, snapshot_to_event,
};

pub use telltale_detect::mcp::{
    McpConfigInput, McpInventoryInput, McpInventoryObservation, McpInventoryState,
    collect_mcp_inventory,
};

/// Read supported static MCP configurations under `root` and return the existing
/// privacy-projected Event 3 inventory activity (or inventory error activity).
/// No server connection, command execution, or rule compilation occurs.
/// `Source.path` retains the local config path for caller correlation; only the
/// returned `Event` is the telemetry projection. No raw MCP inventory is exposed.
pub fn discover_mcp_inventory(root: &Path) -> Vec<(Source, Event)> {
    telltale_detect::mcp::discover_mcp_inventory(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pipeline;

    #[test]
    fn structured_mcp_rejects_credential_urls_before_identity_projection() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        std::fs::write(&path, serde_json::json!({"mcpServers": {
            "command": {"command": "https://TT_URL_USER:TT_URL_PASSWORD@example.invalid"},
            "package": {"command": "node", "args": ["mcp-server-https://TT_PACKAGE_USER:TT_PACKAGE_PASSWORD@example.invalid"]},
            "quoted": {"command": "\"https://TT_QUOTED_USER:TT_QUOTED_PASSWORD@example.invalid\""}
        }}).to_string()).unwrap();
        let inventory =
            collect_mcp_inventory(&McpInventoryInput::Configs(vec![McpConfigInput::new(
                crate::ClientId::Claude,
                "claude.project_mcp_config",
                path,
            )]));
        assert_eq!(
            inventory
                .iter()
                .find(|s| s.server_name() == Some("command"))
                .unwrap()
                .command(),
            Some("[redacted-url]")
        );
        assert_eq!(
            inventory
                .iter()
                .find(|s| s.server_name() == Some("package"))
                .unwrap()
                .package(),
            Some("[redacted-url]")
        );
        for output in [
            format!("{inventory:?}"),
            serde_json::to_string(&inventory).unwrap(),
            format!(
                "{:?}",
                inventory
                    .iter()
                    .map(|s| (s.command(), s.package()))
                    .collect::<Vec<_>>()
            ),
        ] {
            assert!(
                !output.contains("TT_"),
                "URL credentials escaped identity projection"
            );
        }
    }

    #[test]
    fn structured_codex_skips_unrelated_multiline_strings() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
instructions = """
[mcp_servers.TT_UNRELATED_FAKE_SERVER]
command = "TT_UNRELATED_FAKE_COMMAND"
"""
[mcp_servers.actual]
command = "node"
tools = ["lookup"]
[unrelated]
notes = '''
[mcp_servers.TT_SECOND_FAKE_SERVER]
command = "TT_SECOND_FAKE_COMMAND"
'''
"#,
        )
        .unwrap();
        let inventory =
            collect_mcp_inventory(&McpInventoryInput::Configs(vec![McpConfigInput::new(
                crate::ClientId::Codex,
                "codex.mcp_config",
                path,
            )]));
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].server_name(), Some("actual"));
        assert_eq!(inventory[0].state(), McpInventoryState::Supported);
        assert_eq!(inventory[0].declared_tool_count(), 1);
        for output in [
            format!("{inventory:?}"),
            serde_json::to_string(&inventory).unwrap(),
        ] {
            assert!(
                !output.contains("TT_"),
                "unrelated multiline contents became MCP metadata"
            );
        }
    }

    #[test]
    fn failed_inventory_reads_consume_the_attempt_budget() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("oversize.json");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(1024 * 1024 + 1)
            .unwrap();
        let config =
            McpConfigInput::new(crate::ClientId::Claude, "claude.project_mcp_config", path);
        let inventory = collect_mcp_inventory(&McpInventoryInput::Configs(vec![config; 5]));
        assert_eq!(inventory.len(), 5);
        assert!(
            inventory
                .iter()
                .all(|s| s.state() == McpInventoryState::Error)
        );
        assert!(inventory.iter().all(|s| s.server_name().is_none()));
        assert!(
            inventory[..4]
                .iter()
                .all(|s| s.reason() == Some("source_limit_exceeded"))
        );
        assert_eq!(inventory[4].reason(), Some("mcp_inventory_limit_exceeded"));
    }

    #[test]
    fn structured_mcp_bounds_files_and_aggregate_outputs() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("TT_LIMIT_PATH_MARKER");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(1024 * 1024 + 1).unwrap();
        let config = McpConfigInput::new(
            crate::ClientId::Claude,
            "claude.project_mcp_config",
            path.clone(),
        );
        let inventory = collect_mcp_inventory(&McpInventoryInput::Configs(vec![config.clone()]));
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].state(), McpInventoryState::Error);
        assert_eq!(inventory[0].reason(), Some("source_limit_exceeded"));
        let servers = (0..257)
            .map(|i| (format!("server-{i}"), serde_json::json!({"command":"node"})))
            .collect::<serde_json::Map<_, _>>();
        std::fs::write(&path, serde_json::json!({"mcpServers":servers}).to_string()).unwrap();
        let inventory = collect_mcp_inventory(&McpInventoryInput::Configs(vec![config.clone()]));
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].state(), McpInventoryState::Error);
        assert_eq!(inventory[0].reason(), Some("mcp_inventory_limit_exceeded"));
        std::fs::remove_file(&path).unwrap();
        let inventory =
            collect_mcp_inventory(&McpInventoryInput::Configs(vec![config.clone(); 65]));
        // Failed attempts retain their full allowance, including the probe;
        // the fourth attempt uses the remainder and the fifth reports exhaustion.
        assert_eq!(inventory.len(), 5);
        assert!(
            inventory
                .iter()
                .all(|s| s.state() == McpInventoryState::Error)
        );
        assert!(
            inventory[..4]
                .iter()
                .all(|s| s.reason() == Some("source_missing"))
        );
        assert_eq!(
            inventory.last().unwrap().reason(),
            Some("mcp_inventory_limit_exceeded")
        );
        // Unsupported identities perform no reads, independently exercising
        // the 64-candidate cap without consuming the read budget.
        let unsupported = McpConfigInput::new(crate::ClientId::Claude, "unsupported", path.clone());
        let inventory = collect_mcp_inventory(&McpInventoryInput::Configs(vec![unsupported; 65]));
        assert_eq!(inventory.len(), 65);
        assert!(
            inventory
                .iter()
                .all(|s| s.state() == McpInventoryState::Error)
        );
        assert!(
            inventory[..64]
                .iter()
                .all(|s| s.reason() == Some("unsupported_mcp_source_identity"))
        );
        assert_eq!(inventory[64].reason(), Some("mcp_inventory_limit_exceeded"));
        let mut raw = "{\"mcpServers\":{}}".to_string();
        raw.extend(std::iter::repeat_n(' ', 1024 * 1024 - raw.len()));
        std::fs::write(&path, raw).unwrap();
        let inventory = collect_mcp_inventory(&McpInventoryInput::Configs(vec![config; 5]));
        // The first three successful exact-MiB reads refund their unused probes.
        // The fourth has only 1 MiB left including its probe, so cannot accept
        // another exact-MiB file. Empty server maps produce no observations.
        assert_eq!(inventory.len(), 2);
        assert!(
            inventory
                .iter()
                .all(|s| s.state() == McpInventoryState::Error)
        );
        assert!(inventory.iter().all(|s| s.server_name().is_none()));
        assert_eq!(inventory[0].reason(), Some("source_limit_exceeded"));
        assert_eq!(inventory[1].reason(), Some("mcp_inventory_limit_exceeded"));
        for output in [
            format!("{inventory:?}"),
            serde_json::to_string(&inventory).unwrap(),
        ] {
            assert!(!output.contains("TT_LIMIT_PATH_MARKER"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn structured_mcp_rejects_special_files() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("socket");
        let _socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let inventory =
            collect_mcp_inventory(&McpInventoryInput::Configs(vec![McpConfigInput::new(
                crate::ClientId::Claude,
                "claude.project_mcp_config",
                path,
            )]));
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].state(), McpInventoryState::Error);
    }

    #[test]
    fn structured_codex_env_tables_are_not_servers_or_commands() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[mcp_servers.s]
command = "local/mcp-helper"
args = []
[mcp_servers.s.env]
command = "TT_PRIVATE_ENV_VALUE"
TOKEN = "TT_OTHER_ENV_VALUE"
[mcp_servers."quoted.server"]
command = 'private\directory\mcp-helper.exe'
args = ["comma,inside", 'second']
"#,
        )
        .unwrap();
        let inventory =
            collect_mcp_inventory(&McpInventoryInput::Configs(vec![McpConfigInput::new(
                crate::ClientId::Codex,
                "codex.mcp_config",
                path,
            )]));
        assert_eq!(inventory.len(), 2);
        let server = inventory
            .iter()
            .find(|s| s.server_name() == Some("s"))
            .unwrap();
        assert_eq!(server.command(), Some("mcp-helper"));
        assert_eq!(server.package(), Some("mcp-helper"));
        assert_eq!((server.arg_count(), server.env_key_count()), (0, 2));
        let quoted = inventory
            .iter()
            .find(|s| s.server_name() == Some("quoted.server"))
            .unwrap();
        assert_eq!(quoted.command(), Some("mcp-helper.exe"));
        assert_eq!(quoted.arg_count(), 2);
        for output in [
            format!("{inventory:?}"),
            serde_json::to_string(&inventory).unwrap(),
        ] {
            for marker in [
                "TT_PRIVATE_ENV_VALUE",
                "TT_OTHER_ENV_VALUE",
                "local/",
                "private",
                "directory",
            ] {
                assert!(
                    !output.contains(marker),
                    "MCP projection retained private material"
                );
            }
        }
    }

    #[test]
    fn structured_mcp_rejects_unrepresented_toml_counts() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.toml");
        std::fs::write(
            &path,
            "[mcp_servers.s]\ncommand = 'node'\nargs = [\n 'a',\n]\n",
        )
        .unwrap();
        let inventory =
            collect_mcp_inventory(&McpInventoryInput::Configs(vec![McpConfigInput::new(
                crate::ClientId::Codex,
                "codex.mcp_config",
                path,
            )]));
        assert_eq!(inventory[0].state(), McpInventoryState::Unsupported);
        assert_eq!(inventory[0].reason(), Some("unsupported_toml_mcp_syntax"));
    }

    #[test]
    fn structured_mcp_does_not_reinterpret_multiline_env_values() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.toml");
        std::fs::write(&path, "[mcp_servers.s]\ncommand = 'node'\n[mcp_servers.s.env]\nTOKEN = \"\"\"\n[mcp_servers.TT_PRIVATE_SECTION]\ncommand = 'TT_PRIVATE_COMMAND'\n\"\"\"\n").unwrap();
        let inventory =
            collect_mcp_inventory(&McpInventoryInput::Configs(vec![McpConfigInput::new(
                crate::ClientId::Codex,
                "codex.mcp_config",
                path,
            )]));
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].state(), McpInventoryState::Unsupported);
        for output in [
            format!("{inventory:?}"),
            serde_json::to_string(&inventory).unwrap(),
        ] {
            assert!(
                !output.contains("TT_PRIVATE"),
                "multiline environment content escaped"
            );
        }
    }

    #[test]
    fn structured_mcp_command_paths_are_basename_or_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        std::fs::write(&path, serde_json::json!({"mcpServers": {
            "quoted": {"command": "\"TT_PRIVATE_DIRECTORY/mcp-helper\" --flag=TT_ARGUMENT_VALUE"},
            "ambiguous": {"command": "C:\\TT_PRIVATE_DIRECTORY name\\mcp-helper.exe"}
        }}).to_string()).unwrap();
        let inventory =
            collect_mcp_inventory(&McpInventoryInput::Configs(vec![McpConfigInput::new(
                crate::ClientId::Claude,
                "claude.project_mcp_config",
                path,
            )]));
        assert_eq!(
            inventory
                .iter()
                .find(|s| s.server_name() == Some("quoted"))
                .unwrap()
                .command(),
            Some("mcp-helper")
        );
        assert_eq!(
            inventory
                .iter()
                .find(|s| s.server_name() == Some("ambiguous"))
                .unwrap()
                .command(),
            Some("[unrepresented-command]")
        );
        for output in [
            format!("{inventory:?}"),
            serde_json::to_string(&inventory).unwrap(),
        ] {
            assert!(!output.contains("TT_PRIVATE_DIRECTORY"));
            assert!(!output.contains("TT_ARGUMENT_VALUE"));
        }
    }

    #[test]
    fn structured_mcp_is_private_and_fixed_root_does_not_walk() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("workspace");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(
            nested.join(".mcp.json"),
            r#"{"mcpServers":{"nested":{"command":"node"}}}"#,
        )
        .unwrap();
        assert!(
            collect_mcp_inventory(&McpInventoryInput::FixedRoot(root.path().into())).is_empty()
        );
        let path = root.path().join("TT_CONFIG_PATH_MARKER.json");
        std::fs::write(&path, serde_json::json!({"mcpServers": {
            "password=TT_NAME_MARKER": {"command":"node --password=TT_COMMAND_MARKER", "args":["TT_ARG_MARKER"], "env":{"TT_ENV_KEY_MARKER":"TT_ENV_VALUE_MARKER"}, "tools":["TT_TOOL_MARKER"]},
            "remote": {"url":"https://user:TT_USER_MARKER@example.invalid?token=TT_QUERY_MARKER#TT_FRAGMENT_MARKER"}
        }}).to_string()).unwrap();
        let input = McpInventoryInput::Configs(vec![McpConfigInput::new(
            crate::ClientId::Claude,
            "claude.project_mcp_config",
            path.clone(),
        )]);
        let inventory = collect_mcp_inventory(&input);
        assert_eq!(inventory.len(), 2);
        let local = inventory.iter().find(|s| s.url_host().is_none()).unwrap();
        assert_eq!(local.command(), Some("node"));
        assert_eq!(
            (
                local.arg_count(),
                local.env_key_count(),
                local.declared_tool_count()
            ),
            (1, 1, 1)
        );
        assert_eq!(
            inventory
                .iter()
                .find(|s| s.server_name() == Some("remote"))
                .unwrap()
                .url_host(),
            Some("example.invalid")
        );
        let bytes = serde_json::to_string(&inventory).unwrap();
        for marker in [
            "TT_CONFIG_PATH_MARKER",
            "TT_NAME_MARKER",
            "TT_COMMAND_MARKER",
            "TT_ARG_MARKER",
            "TT_ENV_KEY_MARKER",
            "TT_ENV_VALUE_MARKER",
            "TT_TOOL_MARKER",
            "TT_USER_MARKER",
            "TT_QUERY_MARKER",
            "TT_FRAGMENT_MARKER",
        ] {
            assert!(
                !bytes.contains(marker),
                "structured inventory retained a marker"
            );
        }
        std::fs::remove_file(&path).unwrap();
        let errors = collect_mcp_inventory(&input);
        assert_eq!(errors[0].state(), McpInventoryState::Error);
        assert!(
            !serde_json::to_string(&errors)
                .unwrap()
                .contains("TT_CONFIG_PATH_MARKER")
        );
    }

    #[test]
    fn structured_mcp_preserves_unsupported_and_invalid_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(".mcp.json");
        std::fs::write(&path, "invalid json").unwrap();
        let input = McpInventoryInput::Configs(vec![McpConfigInput::new(
            crate::ClientId::Claude,
            "claude.project_mcp_config",
            path.clone(),
        )]);
        let inventory = collect_mcp_inventory(&input);
        assert_eq!(inventory[0].state(), McpInventoryState::Unsupported);
        assert_eq!(inventory[0].reason(), Some("invalid_json_mcp_config"));
        let input = McpInventoryInput::Configs(vec![McpConfigInput::new(
            crate::ClientId::Codex,
            "claude.project_mcp_config",
            path,
        )]);
        let inventory = collect_mcp_inventory(&input);
        assert_eq!(inventory[0].state(), McpInventoryState::Error);
        assert_eq!(
            inventory[0].reason(),
            Some("unsupported_mcp_source_identity")
        );
    }

    #[test]
    fn inventory_explicit_install_context_keeps_paths_out_of_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let executable = bin.join("claude");
        std::fs::write(&executable, b"synthetic executable signal").unwrap();
        let context = InstallInventoryContext {
            home: root.path().to_path_buf(),
            path_dirs: vec![bin],
            extension_roots: vec![root.path().join("extensions")],
            global_storage_roots: vec![root.path().join("storage")],
            node_roots: vec![root.path().join("node_modules")],
        };

        let snapshot = collect_install_inventory_with_context(&context, 1234);
        assert_eq!(snapshot.observed_at_unix_ms, 1234);
        let agent = snapshot
            .agents
            .iter()
            .find(|a| a.agent == "claude")
            .unwrap();
        assert!(agent.installed);
        assert_eq!(agent.confidence, InstallConfidence::Confirmed);
        let signal = agent.signals.iter().find(|s| s.name == "claude").unwrap();
        assert!(signal.present);
        assert_eq!(signal.kind, "executable");
        assert_eq!(
            signal.path_hash.as_deref(),
            Some(telltale_schema::event::evidence_hash(&executable.to_string_lossy()).as_str())
        );
        let signal_json = serde_json::to_value(signal).unwrap();
        assert_eq!(signal_json.as_object().unwrap().len(), 4);
        assert!(signal_json.get("path").is_none());
        for output in [
            format!("{snapshot:?}"),
            serde_json::to_string(&snapshot).unwrap(),
            serde_json::to_string(&snapshot_to_event(&snapshot).unwrap()).unwrap(),
        ] {
            assert!(!output.contains(root.path().to_str().unwrap()));
        }
    }

    #[test]
    fn inventory_mcp_events_are_private_and_separate_from_pipeline_scans() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join(".mcp.json");
        let secret = "synthetic-inventory-secret";
        std::fs::write(
            &config,
            serde_json::json!({
                "mcpServers": {
                    "ordinary-server": {"command": format!("password={secret}")}
                }
            })
            .to_string(),
        )
        .unwrap();

        let inventory = discover_mcp_inventory(root.path());
        assert_eq!(inventory.len(), 1);
        let (source, event) = &inventory[0];
        assert_eq!(source.path, config);
        assert_eq!(source.source_id, "claude.project_mcp_config");
        assert_eq!(event.event_type, "activity");
        assert_eq!(event.session_id, "mcp_inventory");
        let json = serde_json::to_string(event).unwrap();
        assert!(!json.contains(root.path().to_str().unwrap()));
        assert!(!json.contains(secret));
        assert!(json.contains("ordinary-server"));
        let evidence = event
            .evidence
            .iter()
            .find(|item| item.field == "mcp_config_path")
            .unwrap();
        assert_eq!(evidence.redacted_value, source.source_id);
        assert_eq!(
            evidence.hash.as_deref(),
            Some(telltale_schema::event::path_hash(&config).as_str())
        );

        let pipeline = Pipeline::builder().build().unwrap();
        assert!(pipeline.scan_root(root.path()).unwrap().is_empty());
        let sources = inventory
            .into_iter()
            .map(|(source, _)| source)
            .collect::<Vec<_>>();
        let scanned = pipeline.scan_sources(&sources).unwrap();
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].1.event_type, "scanner_error");
        assert_ne!(scanned[0].1.session_id, "mcp_inventory");
    }
}
