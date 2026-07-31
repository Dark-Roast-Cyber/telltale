//! Claude Code source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

mod install;
pub(crate) mod parser;

pub(crate) use install::INSTALL;

pub(crate) const SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "claude.projects",
    kind: SourceKind::Jsonl,
    root: PathRoot::Home,
    relative_path: ".claude/projects",
    fixture_relative_path: "claude/projects",
    pattern: SourcePattern::Extension("jsonl"),
    recursive: true,
    project_relative_path: None,
}];

#[cfg(test)]
mod tests;
