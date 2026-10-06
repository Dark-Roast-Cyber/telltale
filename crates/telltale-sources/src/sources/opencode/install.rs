//! OpenCode install inventory evidence definition.

use std::path::Path;

use crate::install_inventory::{
    AgentInstallDef, InstallPlatform, InstallSignal, executable_path_signal,
};

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "opencode",
    executables: &["opencode"],
    node_packages: &["opencode-ai"],
    extension_ids: &[],
    global_storage_ids: &[],
};

/// Desktop v2 need not expose a PATH shim or an npm package. Probe only known
/// executable metadata, including one level of versioned CLI directories.
pub(crate) fn desktop_install_signals(
    home: &Path,
    platform: InstallPlatform,
) -> Vec<InstallSignal> {
    if platform != InstallPlatform::Windows {
        return Vec::new();
    }
    let desktop = home.join("AppData/Local/Programs/@opencode-aidesktop/OpenCode.exe");
    let cli_root = home.join("AppData/Roaming/ai.opencode.desktop/cli");
    let mut cli_candidates = std::fs::read_dir(cli_root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path().join("opencode-cli.exe"))
        .collect::<Vec<_>>();
    cli_candidates.sort_unstable();
    vec![
        executable_path_signal("opencode-desktop", [desktop]),
        executable_path_signal("opencode-desktop-cli", cli_candidates),
    ]
}
