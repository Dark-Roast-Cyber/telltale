//! Telltale's filesystem-facing source layer: session-store discovery,
//! per-agent source modules, record parsers, and installed-agent inventory.
//!
//! Everything here reads local agent session stores and normalizes them into
//! `telltale-schema` records; detection, scoring, and delivery live in the
//! downstream crates.

/// Experimental, non-production Canonical Observation v2 projection facade.
pub mod canonical;
pub mod clients;
pub mod discovery;
pub mod install_inventory;
pub mod parser;
pub mod paths;
pub mod projects;
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
