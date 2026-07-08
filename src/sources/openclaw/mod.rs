//! OpenClaw source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourceKind, SourcePattern};

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
