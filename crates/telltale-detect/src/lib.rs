//! Telltale's detection layer: deterministic rule evaluation over parsed
//! session records, session timelines, baseline deviation, cross-session
//! correlation, allowlist suppression, and MCP usage analysis.
//!
//! Records in, events out. Runtime concerns — state persistence, sinks, and
//! the CLI — live in the downstream binary crate.

pub mod allowlist;
pub mod baseline;
pub mod correlation;
pub mod detection;
#[cfg(feature = "source-io")]
pub mod mcp;
pub mod process_chain;
/// Experimental, non-production I/O-free Detection v2 equivalence harness.
pub mod shadow_v2;
pub mod timeline;
/// Experimental, non-production Detection v2 APIs. This module is not
/// scanner-wired and accepts only caller-provided typed observations.
pub mod v2;

#[cfg(all(test, feature = "source-io"))]
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
