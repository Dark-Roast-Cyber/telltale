//! Telltale's detection layer: deterministic evaluation over caller-supplied
//! records or canonical observations, session timelines, baseline state and
//! deviation, correlation, allowlist suppression, and optional MCP analysis.
//!
//! Source discovery and parsing live in `telltale-sources`; source orchestration
//! lives in `telltale-core`. State persistence and sinks live downstream.

pub mod allowlist;
pub mod baseline;
pub mod correlation;
pub mod detection;
#[cfg(feature = "source-io")]
pub mod mcp;
pub mod process_chain;
pub(crate) mod process_chain_session;
pub mod timeline;
/// Detection v2 APIs used by the canonical source runtime. Evaluation remains
/// I/O-free and accepts caller-provided typed observations.
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
