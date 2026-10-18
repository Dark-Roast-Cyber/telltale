//! Claude Code install inventory evidence definition.

use std::path::Path;

use crate::install_inventory::{
    AgentInstallDef, InstallPlatform, InstallSignal, executable_path_signal,
};

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "claude",
    executables: &["claude"],
    node_packages: &["@anthropic-ai/claude-code"],
    extension_ids: &[],
    global_storage_ids: &[],
};

/// The Claude desktop app bundles Claude Code and may not expose a PATH shim
/// or an npm package. Probe only the known executable locations, metadata
/// only: versioned directories, one hash directory below each, `claude.exe`.
/// The MSIX-virtualized mirror of `%APPDATA%\Claude` is probed as well.
pub(crate) fn desktop_install_signals(
    home: &Path,
    platform: InstallPlatform,
) -> Vec<InstallSignal> {
    if platform != InstallPlatform::Windows {
        return Vec::new();
    }
    let roaming = home.join("AppData/Roaming/Claude/claude-code");
    let packaged = home
        .join("AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude-code");
    vec![
        executable_path_signal("claude-desktop", bundled_executables(&roaming)),
        executable_path_signal("claude-desktop-packaged", bundled_executables(&packaged)),
    ]
}

/// Lists `<root>/<version>/<hash>/claude.exe` candidates in sorted order so the
/// reported path hash is deterministic. Entries that are not directories are
/// skipped; a directory named `claude.exe` never matches because the probe
/// requires a regular file.
fn bundled_executables(root: &Path) -> Vec<std::path::PathBuf> {
    let mut candidates = Vec::new();
    for version in read_subdirs(root) {
        for hash in read_subdirs(&version) {
            candidates.push(hash.join("claude.exe"));
        }
    }
    candidates.sort_unstable();
    candidates
}

fn read_subdirs(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut dirs = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    dirs.sort_unstable();
    dirs
}
