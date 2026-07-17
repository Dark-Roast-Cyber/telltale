//! OpenCode source adapter.

use crate::clients::{ClientSourceDef, PathRoot, SourceKind, SourcePattern};

mod install;
pub(crate) mod parser;

#[cfg(test)]
mod tests;

pub(crate) use install::INSTALL;

pub(crate) const SOURCES: &[ClientSourceDef] = &[
    ClientSourceDef {
        id: "opencode.sqlite",
        kind: SourceKind::Sqlite,
        root: PathRoot::DataHome,
        relative_path: "opencode/opencode.db",
        fixture_relative_path: "opencode/opencode.db",
        pattern: SourcePattern::ExactFile("opencode.db"),
        recursive: false,
        project_relative_path: None,
    },
    ClientSourceDef {
        id: "opencode.legacy_json",
        kind: SourceKind::LegacyJson,
        root: PathRoot::DataHome,
        relative_path: "opencode/storage/message",
        fixture_relative_path: "opencode/storage/message",
        pattern: SourcePattern::Extension("json"),
        recursive: true,
        project_relative_path: None,
    },
    ClientSourceDef {
        id: "opencode.project_json",
        kind: SourceKind::LegacyJson,
        root: PathRoot::ProjectLocal,
        relative_path: ".opencode",
        fixture_relative_path: "opencode/project",
        pattern: SourcePattern::Extension("json"),
        recursive: true,
        project_relative_path: Some(".opencode"),
    },
];
