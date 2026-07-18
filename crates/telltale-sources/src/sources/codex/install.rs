//! Codex install inventory evidence definition.

use crate::install_inventory::AgentInstallDef;

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "codex",
    executables: &["codex"],
    node_packages: &["@openai/codex"],
    extension_ids: &[],
    global_storage_ids: &[],
};
