//! Qwen CLI source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

pub(crate) mod canonical;
mod install;
pub(crate) mod native;
pub(crate) mod parser;

pub(crate) use install::INSTALL;

pub(crate) const SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "qwen.projects",
    kind: SourceKind::Jsonl,
    root: PathRoot::Home,
    relative_path: ".qwen/projects",
    fixture_relative_path: "qwen/projects",
    pattern: SourcePattern::Extension("jsonl"),
    recursive: true,
    project_relative_path: None,
}];

#[cfg(test)]
mod tests;
