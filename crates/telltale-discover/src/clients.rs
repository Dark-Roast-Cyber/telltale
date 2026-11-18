//! Source-discovery descriptors. The caller owns the registry and its order;
//! these types describe locations, never parser selection or broad inventory.

use std::path::{Path, PathBuf};

use telltale_schema::clients::{ClientId, SourceKind};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum PathRoot {
    CodexHome,
    Home,
    DataHome,
    ProjectLocal,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourcePattern {
    Extension(&'static str),
    ExactFile(&'static str),
    FileNameContains(&'static str),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ClientSourceDef {
    pub id: &'static str,
    pub kind: SourceKind,
    pub root: PathRoot,
    pub relative_path: &'static str,
    pub fixture_relative_path: &'static str,
    pub pattern: SourcePattern,
    pub recursive: bool,
    pub project_relative_path: Option<&'static str>,
}

impl ClientSourceDef {
    pub fn fixture_path(self, fixture_root: &Path) -> PathBuf {
        fixture_root.join(self.fixture_relative_path)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ClientDef {
    pub id: ClientId,
    pub display_name: &'static str,
    pub sources: &'static [ClientSourceDef],
}
