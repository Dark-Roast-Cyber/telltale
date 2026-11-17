//! Telltale's source registry, native extraction, canonical acquisition and
//! legacy installed-agent inventory. Discovery delegates to `telltale-discover`.
//!
//! Source modules read local agent session stores into source-native facts and
//! Canonical Observation v2. There is no normalized-record compatibility path.
//! Detection, scoring, and delivery live in the downstream crates.

pub mod acquisition;
pub mod clients;
pub mod discovery;
pub mod install_inventory;
pub mod journal;
pub mod mcp;
pub mod paths;
pub mod projects;
pub(crate) mod source_read;
pub mod sources;
pub(crate) mod tool_operation;

/// Every built-in tool each source declares, as `(client, tool name, kind)`.
/// For tests that check the tables against the name lists detection keeps as
/// its fallback.
#[doc(hidden)]
pub fn declared_tool_kinds() -> Vec<(
    telltale_schema::clients::ClientId,
    &'static str,
    telltale_schema::observation::ToolKind,
)> {
    use sources::{claude, codex, copilot, openclaw, opencode, qwen};
    use telltale_schema::clients::ClientId;
    [
        (ClientId::Claude, claude::tools::TOOLS),
        (ClientId::Codex, codex::tools::TOOLS),
        (ClientId::Copilot, copilot::tools::TOOLS),
        (ClientId::OpenClaw, openclaw::tools::TOOLS),
        (ClientId::OpenCode, opencode::tools::TOOLS),
        (ClientId::Qwen, qwen::tools::TOOLS),
    ]
    .into_iter()
    .flat_map(|(client, table)| {
        table
            .iter()
            .map(move |spec| (client, spec.name(), spec.kind()))
    })
    .collect()
}

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
