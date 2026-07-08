//! GitHub Copilot source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourceKind, SourcePattern};

pub(crate) mod parser;

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
