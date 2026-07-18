//! OpenCode install inventory evidence definition.

use crate::install_inventory::AgentInstallDef;

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "opencode",
    executables: &["opencode"],
    node_packages: &["opencode-ai"],
    extension_ids: &[],
    global_storage_ids: &[],
};
