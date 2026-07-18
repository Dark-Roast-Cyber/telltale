//! KiloCode source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourceKind, SourcePattern};

mod install;

pub(crate) use install::INSTALL;

pub(crate) const SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "kilocode.tasks",
    kind: SourceKind::UiMessagesJson,
    root: PathRoot::ConfigHome,
    relative_path: "Code/User/globalStorage/kilocode.kilo-code/tasks",
    fixture_relative_path: "kilocode/tasks",
    pattern: SourcePattern::ExactFile("ui_messages.json"),
    recursive: true,
    project_relative_path: None,
}];

#[cfg(test)]
mod tests;
