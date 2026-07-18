//! Gemini CLI install inventory evidence definition.

use crate::install_inventory::AgentInstallDef;

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "gemini",
    executables: &["gemini"],
    node_packages: &["@google/gemini-cli"],
    extension_ids: &[],
    global_storage_ids: &[],
};
