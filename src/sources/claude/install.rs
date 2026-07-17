//! Claude Code install inventory evidence definition.

use crate::install_inventory::AgentInstallDef;

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "claude",
    executables: &["claude"],
    node_packages: &["@anthropic-ai/claude-code"],
    extension_ids: &[],
    global_storage_ids: &[],
};
