//! OpenCode source adapter: its source definitions and install signals.
//!
//! Native parsing lives in `native` and Canonical Observation v2 mapping in
//! `canonical`; both are crate-private and reached only through the
//! acquisition router. Shared reading belongs in `source_read`, not here.

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::SourceKind;

#[cfg(feature = "opencode-sqlite")]
pub(crate) mod canonical;
mod install;
#[cfg(feature = "opencode-sqlite")]
pub(crate) mod native;
#[cfg(feature = "opencode-sqlite")]
pub(crate) mod session_message;
#[cfg(feature = "opencode-sqlite")]
pub(crate) mod session_message_canonical;

#[cfg(all(test, feature = "opencode-sqlite"))]
mod tests;
#[cfg(all(test, feature = "opencode-sqlite"))]
mod v2_tests;

pub(crate) use install::INSTALL;
pub(crate) use install::desktop_install_signals;

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
