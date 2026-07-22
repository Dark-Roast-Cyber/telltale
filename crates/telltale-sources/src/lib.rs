//! Telltale's filesystem-facing source layer: session-store discovery,
//! per-agent source adapters, record parsers, and installed-agent inventory.
//!
//! Everything here reads local agent session stores and normalizes them into
//! `telltale-schema` records; detection, scoring, and delivery live in the
//! downstream crates.

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
    let workspace_root_is_dir = workspace_root.is_dir();
    let root = if workspace_root_is_dir {
        workspace_root.clone()
    } else {
        manifest_dir.join("tests/fixtures")
    };
    let result = root.join(relative);
    if !result.exists() && relative.contains("gemini") {
        eprintln!(
            "test_fixture_path MISSING: manifest_dir={:?} result={:?}",
            manifest_dir, result
        );
        let fixture_root = manifest_dir.join("tests/fixtures");
        if let Ok(entries) = std::fs::read_dir(&fixture_root) {
            eprintln!("  fixture_root {:?} entries:", fixture_root);
            for entry in entries.flatten() {
                eprintln!("    {}", entry.path().display());
            }
        }
        let session_stores = fixture_root.join("session_stores");
        if let Ok(entries) = std::fs::read_dir(&session_stores) {
            eprintln!("  session_stores entries:");
            for entry in entries.flatten() {
                eprintln!("    {}", entry.path().display());
            }
        }
        let gemini = session_stores.join("gemini");
        eprintln!("  gemini exists: {}", gemini.exists());
        if let Ok(entries) = std::fs::read_dir(&gemini) {
            eprintln!("  gemini entries:");
            for entry in entries.flatten() {
                eprintln!("    {}", entry.path().display());
            }
        }
        let gemini_tmp = gemini.join("tmp");
        eprintln!("  gemini/tmp exists: {}", gemini_tmp.exists());
        if let Ok(entries) = std::fs::read_dir(&gemini_tmp) {
            eprintln!("  gemini/tmp entries:");
            for entry in entries.flatten() {
                eprintln!("    {}", entry.path().display());
            }
        }
    }
    result
}
