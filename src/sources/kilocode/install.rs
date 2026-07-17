//! KiloCode install inventory evidence definition.

use crate::install_inventory::AgentInstallDef;

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "kilocode",
    executables: &["kilo", "kilocode"],
    node_packages: &["@kilocode/cli"],
    extension_ids: &["kilocode.kilo-code"],
    global_storage_ids: &["kilocode.kilo-code"],
};
