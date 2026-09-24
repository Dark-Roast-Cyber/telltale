//! Telltale's filesystem-facing source layer: session-store discovery,
//! per-agent native extraction, canonical acquisition, and installed-agent inventory.
//!
//! Source modules read local agent session stores into source-native facts and
//! Canonical Observation v2. Caller-supplied normalized records are a separate
//! compatibility path and are not produced here. Detection, scoring, and
//! delivery live in the downstream crates.

pub mod acquisition;
pub mod clients;
pub mod discovery;
pub mod install_inventory;
pub mod journal;
pub mod paths;
pub mod projects;
pub mod source_read;
pub mod sources;

#[cfg(test)]
pub(crate) fn test_fixture_path(relative: &str) -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.join("../../tests/fixtures");
    let root = if workspace_root.is_dir() {
        workspace_root
    } else {
        manifest_dir.join("tests/fixtures")
    };
    root.join(relative)
}
