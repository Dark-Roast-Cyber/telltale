//! GitHub Copilot source adapter: its source definitions and install signals.
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
    id: "copilot.process_log",
    kind: SourceKind::CopilotProcessLog,
    root: PathRoot::ProjectLocal,
    relative_path: "logs/copilot",
    fixture_relative_path: "copilot",
    pattern: SourcePattern::Extension("log"),
    recursive: false,
    project_relative_path: Some("logs/copilot"),
}];
