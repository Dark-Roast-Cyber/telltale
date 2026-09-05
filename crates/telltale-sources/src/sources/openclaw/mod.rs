//! OpenClaw source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

pub(crate) mod canonical;
mod install;
pub(crate) mod native;
pub(crate) mod parser;

pub(crate) use install::INSTALL;

pub(crate) const SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "openclaw.agents",
    kind: SourceKind::Jsonl,
    root: PathRoot::Home,
    relative_path: ".openclaw/agents",
    fixture_relative_path: "openclaw/agents",
    pattern: SourcePattern::FileNameContains(".jsonl"),
    recursive: true,
    project_relative_path: None,
}];

#[cfg(test)]
mod tests;
