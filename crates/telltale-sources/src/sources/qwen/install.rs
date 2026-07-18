//! Qwen CLI install inventory evidence definition.

use crate::install_inventory::AgentInstallDef;

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "qwen",
    executables: &["qwen"],
    node_packages: &["@qwen-code/qwen-code"],
    extension_ids: &[],
    global_storage_ids: &[],
};
