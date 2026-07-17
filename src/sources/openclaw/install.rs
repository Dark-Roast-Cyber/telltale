//! OpenClaw install inventory evidence definition.

use crate::install_inventory::AgentInstallDef;

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "openclaw",
    executables: &["openclaw"],
    node_packages: &["openclaw"],
    extension_ids: &[],
    global_storage_ids: &[],
};
