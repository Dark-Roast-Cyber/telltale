//! Codex source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourceKind, SourcePattern};

mod install;

pub(crate) use install::INSTALL;

pub(crate) const SOURCES: &[ClientSourceDef] = &[
    ClientSourceDef {
        id: "codex.sessions",
        kind: SourceKind::Jsonl,
        root: PathRoot::CodexHome,
        relative_path: "sessions",
        fixture_relative_path: "codex/sessions",
        pattern: SourcePattern::Extension("jsonl"),
        recursive: true,
        project_relative_path: None,
    },
    ClientSourceDef {
        id: "codex.archived_sessions",
        kind: SourceKind::ArchivedJsonl,
        root: PathRoot::CodexHome,
        relative_path: "archived_sessions",
        fixture_relative_path: "codex/archived_sessions",
        pattern: SourcePattern::Extension("jsonl"),
        recursive: true,
        project_relative_path: None,
    },
    ClientSourceDef {
        id: "codex.headless_sessions",
        kind: SourceKind::HeadlessJsonl,
        root: PathRoot::CodexHome,
        relative_path: "headless",
        fixture_relative_path: "codex/headless",
        pattern: SourcePattern::Extension("jsonl"),
        recursive: true,
        project_relative_path: None,
    },
    ClientSourceDef {
        id: "codex.project_sessions",
        kind: SourceKind::Jsonl,
        root: PathRoot::ProjectLocal,
        relative_path: ".codex-worktree",
        fixture_relative_path: "codex/project_sessions",
        pattern: SourcePattern::Extension("jsonl"),
        recursive: true,
        project_relative_path: Some(".codex-worktree"),
    },
];

#[cfg(test)]
mod tests;
