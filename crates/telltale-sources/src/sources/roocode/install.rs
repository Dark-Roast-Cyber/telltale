//! RooCode install inventory evidence definition.

use crate::install_inventory::AgentInstallDef;

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "roocode",
    executables: &[],
    node_packages: &[],
    extension_ids: &["rooveterinaryinc.roo-cline"],
    global_storage_ids: &["rooveterinaryinc.roo-cline"],
};
