//! Pi install inventory evidence definition.

use std::path::Path;

use crate::install_inventory::{
    AgentInstallDef, InstallPlatform, InstallSignal, executable_path_signal,
};

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "pi",
    executables: &["pi"],
    node_packages: &["@earendil-works/pi-coding-agent"],
    extension_ids: &[],
    global_storage_ids: &[],
};

/// Pi's managed installer keeps its launcher in `~/.pi/agent/bin`, which it
/// adds to `PATH` itself, with its own Node runtime; a shell that has not
/// picked up that `PATH` change still has the launcher. Probe its metadata
/// only, on every platform.
pub(crate) fn managed_install_signals(
    home: &Path,
    platform: InstallPlatform,
) -> Vec<InstallSignal> {
    let bin = home.join(".pi/agent/bin");
    let candidates = match platform {
        InstallPlatform::Windows => vec![bin.join("pi.cmd"), bin.join("pi.exe")],
        InstallPlatform::Unix => vec![bin.join("pi")],
    };
    vec![executable_path_signal("pi-managed", candidates)]
}
