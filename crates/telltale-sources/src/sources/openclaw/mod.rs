//! OpenClaw source adapter: its source definitions and install signals.
//!
//! Native parsing lives in `native` and Canonical Observation v2 mapping in
//! `canonical`; both are crate-private and reached only through the
//! acquisition router. Shared reading belongs in `source_read`, not here.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

pub(crate) mod canonical;
mod install;
pub(crate) mod native;

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
