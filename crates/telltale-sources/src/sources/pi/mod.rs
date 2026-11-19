//! Pi coding agent source adapter: its source definitions and install signals.
//!
//! Pi (`earendil-works/pi`) writes one append-only JSONL file per session
//! under `~/.pi/agent/sessions/<cwd slug>/<timestamp>_<session id>.jsonl`: a
//! `session` header, then entries that form a tree through `id`/`parentId`.
//! Native parsing lives in `native` and Canonical Observation v2 mapping in
//! `canonical`; both are crate-private and reached only through the
//! acquisition router. Shared reading belongs in `source_read`, not here.
//!
//! `PI_CODING_AGENT_DIR` and `PI_CODING_AGENT_SESSION_DIR` relocate the store;
//! relocated stores are not discovered.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

pub(crate) mod canonical;
mod install;
pub(crate) mod native;
pub(crate) mod tools;

pub(crate) use install::{INSTALL, managed_install_signals};

pub(crate) const SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "pi.sessions",
    kind: SourceKind::Jsonl,
    root: PathRoot::Home,
    relative_path: ".pi/agent/sessions",
    fixture_relative_path: "pi/sessions",
    pattern: SourcePattern::Extension("jsonl"),
    recursive: true,
    project_relative_path: None,
}];

#[cfg(test)]
mod tests;
