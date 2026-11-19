//! Codex install inventory evidence definition.

use std::path::{Path, PathBuf};

use crate::install_inventory::{
    AgentInstallDef, InstallPlatform, InstallSignal, executable_path_signal,
};

pub(crate) const INSTALL: AgentInstallDef = AgentInstallDef {
    agent: "codex",
    executables: &["codex"],
    node_packages: &["@openai/codex"],
    extension_ids: &[],
    global_storage_ids: &[],
};

/// The Windows desktop app (the `OpenAI.Codex` package, which also ships the
/// ChatGPT app) unpacks its bundled CLI to
/// `%LOCALAPPDATA%\OpenAI\Codex\bin\<hash>\codex.exe` and need not expose a
/// PATH shim or an npm package. Probe that executable's metadata only, one
/// hash directory deep. The packaged install directory itself is not probed.
pub(crate) fn desktop_install_signals(
    home: &Path,
    platform: InstallPlatform,
) -> Vec<InstallSignal> {
    if platform != InstallPlatform::Windows {
        return Vec::new();
    }
    vec![executable_path_signal(
        "codex-desktop",
        bundled_executables(&home.join("AppData/Local/OpenAI/Codex/bin")),
    )]
}

/// Lists `<root>/<hash>/codex.exe` candidates in sorted order so the reported
/// path hash is deterministic. A directory named `codex.exe` never matches
/// because the probe requires a regular file.
fn bundled_executables(root: &Path) -> Vec<PathBuf> {
    let mut candidates = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path().join("codex.exe"))
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates
}
