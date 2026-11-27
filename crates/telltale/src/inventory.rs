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

use std::path::{Path, PathBuf};

use crate::{Event, Source};

pub use telltale_sources::install_inventory::{
    AgentInstallObservation, InstallConfidence, InstallInventoryContext, InstallInventorySnapshot,
    InstallPlatform, InstallSignal, collect_install_inventory,
    collect_install_inventory_for_platform, collect_install_inventory_with_context,
    collect_install_inventory_with_sources, install_inventory_due, snapshot_to_event,
};

pub use telltale_sources::mcp::{
    McpConfigInput, McpInventoryInput, McpInventoryObservation, McpInventoryState,
    McpServerInventory, collect_mcp_inventory,
};

/// Read supported static MCP configurations under `root` and return the existing
/// privacy-projected Event 3 inventory activity (or inventory error activity).
/// No server connection, command execution, or rule compilation occurs.
/// `Source.path` retains the local config path for caller correlation; only the
/// returned `Event` is the telemetry projection. No raw MCP inventory is exposed.
pub fn discover_mcp_inventory(root: &Path) -> Vec<(Source, Event)> {
    discover_mcp_scan(root).events
}

/// The same bounded static discovery as [`discover_mcp_inventory`], returned as
/// structured servers for a host that builds its own inventory view. `path` is
/// the local config path, host data like `Source.path`: hash it before it
/// leaves the host. No server connection or command execution occurs.
pub fn discover_mcp_inventory_servers(root: &Path) -> Vec<McpServerInventory> {
    discover_mcp_scan(root).servers
}

/// Internal scan composition, not an additional supported embedding interface.
#[doc(hidden)]
#[derive(Default)]
pub struct McpScan {
    pub servers: Vec<McpServerInventory>,
    pub events: Vec<(Source, Event)>,
}

/// One bounded scan-local acquisition supplies inventory and usage inference.
#[doc(hidden)]
pub fn discover_mcp_scan(root: &Path) -> McpScan {
    let workspaces = if root.is_dir() {
        vec![root.to_path_buf()]
    } else {
        Vec::new()
    };
    discover_mcp_scan_with_workspaces(root, &workspaces)
}

/// Scan-local acquisition with workspace traversal explicitly scoped by the
/// caller, independently of the root used to locate user configuration files.
#[doc(hidden)]
pub fn discover_mcp_scan_with_workspaces(root: &Path, workspace_roots: &[PathBuf]) -> McpScan {
    use telltale_detect::mcp::{project_mcp_inventory, project_mcp_inventory_error};

    let mut scan = McpScan::default();
    for config in
        telltale_sources::mcp::acquire_mcp_inventory_with_workspaces(root, workspace_roots)
    {
        match config.servers {
            Ok(servers) => {
                scan.events.extend(
                    servers
                        .iter()
                        .map(|server| (config.source.clone(), project_mcp_inventory(server))),
                );
                scan.servers.extend(servers);
            }
            Err(reason) => {
                let event = project_mcp_inventory_error(config.source.client, reason);
                scan.events.push((config.source, event));
            }
        }
    }
    scan
}

#[cfg(test)]
mod tests;
