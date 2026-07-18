use std::path::PathBuf;

use crate::clients::{ClientId, SourceKind};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Source {
    pub client: ClientId,
    pub kind: SourceKind,
    pub source_id: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SourceInventoryChangeSummary {
    pub baseline: bool,
    pub added: u32,
    pub removed: u32,
    pub unchanged: u32,
    pub hash: String,
}
