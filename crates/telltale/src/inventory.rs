//! Opt-in local install and static MCP configuration inventory.
//!
//! Current development after RC1; not covered by published RC1 qualification.
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
    InstallSignal, collect_install_inventory, collect_install_inventory_with_context,
    install_inventory_due, snapshot_to_event,
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
