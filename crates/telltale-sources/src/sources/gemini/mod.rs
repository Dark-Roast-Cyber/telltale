//! Gemini CLI source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

mod install;
pub(crate) mod parser;

pub(crate) use install::INSTALL;

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
