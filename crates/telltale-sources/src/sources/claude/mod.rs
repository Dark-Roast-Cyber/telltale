//! Claude Code source adapter: its source definitions and install signals.
//!
//! Native parsing lives in `native` and Canonical Observation v2 mapping in
//! `canonical`; both are crate-private and reached only through the
//! acquisition router. Shared reading belongs in `source_read`, not here.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

pub(crate) mod canonical;
mod install;
pub(crate) mod native;
pub(crate) mod tools;

pub(crate) use install::{INSTALL, desktop_install_signals};

/// The hook-journal identity of this client: not a registered source, only
/// known to acquisition.
pub(crate) const HOOK_JOURNAL: super::HookJournal = super::HookJournal {
    client: telltale_schema::clients::ClientId::Claude,
    source_id: "claude.hooks",
    adapter_type: "claude_code",
};

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
