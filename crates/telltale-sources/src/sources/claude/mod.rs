//! Claude Code source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

pub(crate) mod canonical;
mod install;
pub(crate) mod native;
pub(crate) mod parser;

#[allow(unused_imports)]
pub(crate) use canonical::{
    ClaudeCanonicalError, ClaudeCanonicalOptions, project_claude_canonical_observations,
};
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
