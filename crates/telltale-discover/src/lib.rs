//! Local discovery independent of detection and session acquisition.
//!
//! Supported-source callers supply their own descriptors. Broad tool inventory
//! has a separate catalog: an inventory entry is not a supported detection source.
//! This crate never schedules scans, parses session content, or delivers events.

mod anchored;
pub mod catalog;
pub mod clients;
pub mod discovery;
pub mod inventory;
pub mod projects;
pub mod record;

/// Embedded upstream notice, also available in standalone CLI distributions.
pub const TOKSCALE_LICENSE: &str = include_str!("../data/TOKSCALE-LICENSE-MIT");

#[cfg(test)]
mod test_registry;

#[cfg(test)]
pub(crate) fn test_fixture_path(relative: &str) -> std::path::PathBuf {
    use std::sync::OnceLock;
    static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();
    let root = ROOT.get_or_init(|| {
        let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .expect("synthetic discovery fixtures");
        for path in [
            "codex/sessions/2026/04/session-a.jsonl",
            "codex/archived_sessions/session-b.jsonl",
            "codex/headless/headless-a.jsonl",
            "claude/projects/project-a/session-a.jsonl",
            "openclaw/agents/project-a/session-a.jsonl.deleted",
            "qwen/projects/project-a/chats/session-a.jsonl",
            "opencode/opencode.db",
            "copilot/process-fixture.log",
        ] {
            let path = root.path().join("tests/fixtures/session_stores").join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"synthetic metadata only\n").unwrap();
        }
        root
    });
    root.path().join("tests/fixtures").join(relative)
}
