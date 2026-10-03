//! OpenCode source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

#[cfg(feature = "opencode-sqlite")]
pub(crate) mod canonical;
mod install;
#[cfg(feature = "opencode-sqlite")]
pub(crate) mod native;

#[cfg(all(test, feature = "opencode-sqlite"))]
mod tests;

pub(crate) use install::INSTALL;

pub(crate) const SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "opencode.sqlite",
    kind: SourceKind::Sqlite,
    root: PathRoot::DataHome,
    relative_path: "opencode/opencode.db",
    fixture_relative_path: "opencode/opencode.db",
    pattern: SourcePattern::ExactFile("opencode.db"),
    recursive: false,
    project_relative_path: None,
}];
