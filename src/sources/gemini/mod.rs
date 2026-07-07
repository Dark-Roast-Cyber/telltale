//! Gemini CLI source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourceKind, SourcePattern};

pub(crate) mod parser;

pub(crate) const SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "gemini.tmp",
    kind: SourceKind::Json,
    root: PathRoot::Home,
    relative_path: ".gemini/tmp",
    fixture_relative_path: "gemini/tmp",
    pattern: SourcePattern::Extension("json"),
    recursive: true,
    project_relative_path: None,
}];
