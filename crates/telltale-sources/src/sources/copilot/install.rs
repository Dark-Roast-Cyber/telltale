//! GitHub Copilot install inventory evidence definition.

use crate::install_inventory::AgentInstallDef;

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "copilot",
    executables: &[],
    node_packages: &[],
    extension_ids: &["github.copilot", "github.copilot-chat"],
    global_storage_ids: &["github.copilot", "github.copilot-chat"],
};
