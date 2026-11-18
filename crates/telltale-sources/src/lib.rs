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

/// One built-in tool a source's table declares, for tests that check the
/// tables against recorded upstream tool lists and against the name lists
/// detection keeps as its fallback.
#[doc(hidden)]
pub struct DeclaredTool {
    pub client: telltale_schema::clients::ClientId,
    pub name: &'static str,
    pub kind: telltale_schema::observation::ToolKind,
    /// Argument keys the row reads, by category: `command`, `written`, `read`,
    /// `url` and `patch`.
    pub operand_keys: Vec<(&'static str, &'static [&'static str])>,
}

/// Every built-in tool each source declares.
#[doc(hidden)]
pub fn declared_tools() -> Vec<DeclaredTool> {
    use telltale_schema::clients::ClientId;
    [
        ClientId::Claude,
        ClientId::Codex,
        ClientId::Copilot,
        ClientId::OpenClaw,
        ClientId::OpenCode,
        ClientId::Qwen,
    ]
    .into_iter()
    .flat_map(|client| {
        tool_operation::table(client)
            .unwrap_or_default()
            .iter()
            .map(move |spec| DeclaredTool {
                client,
                name: spec.name(),
                kind: spec.kind(),
                operand_keys: spec.operand_keys().into_iter().collect(),
            })
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
