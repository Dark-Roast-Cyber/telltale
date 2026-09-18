//! Codex source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

pub(crate) mod canonical;
mod install;
pub(crate) mod native;
pub(crate) mod parser;

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
];

#[cfg(test)]
mod tests;
