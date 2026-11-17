//! Compatibility entry points using the supported acquisition registry.
//!
//! Filesystem discovery is implemented once in `telltale-discover`. Broad tool
//! inventory is intentionally never passed as a supported-source registry.

use crate::clients::{ClientSourceDef, supported_clients};
use crate::projects::ProjectDef;
use std::path::{Path, PathBuf};
use telltale_discover::discovery as shared;
use telltale_schema::{clients::ClientId, source::Source};

pub use shared::{BoundedDiscoveryError, DiscoveryError};

#[cfg(test)]
#[path = "discovery_contract_tests.rs"]
mod tests;

pub fn discover_sources(root: &Path) -> Result<Vec<Source>, DiscoveryError> {
    shared::discover_sources(root, supported_clients())
}

pub fn discover_sources_bounded(
    root: &Path,
    client: ClientId,
    max_entries: usize,
) -> Result<Vec<Source>, BoundedDiscoveryError> {
    shared::discover_sources_bounded(root, client, max_entries, supported_clients())
}

pub fn discover_sources_best_effort(root: &Path) -> Vec<Source> {
    shared::discover_sources_best_effort(root, supported_clients())
}

pub fn discover_sources_with_projects(
    root: &Path,
    projects: &[ProjectDef],
) -> Result<Vec<Source>, DiscoveryError> {
    shared::discover_sources_with_projects(root, projects, supported_clients())
}

pub fn discover_sources_with_projects_best_effort(
    root: &Path,
    projects: &[ProjectDef],
) -> Vec<Source> {
    shared::discover_sources_with_projects_best_effort(root, projects, supported_clients())
}

pub fn discover_watch_roots(root: &Path) -> Vec<PathBuf> {
    shared::discover_watch_roots(root, supported_clients())
}

pub fn discover_watch_roots_for_clients(root: &Path, clients: &[ClientId]) -> Vec<PathBuf> {
    shared::discover_watch_roots_for_clients(root, clients, supported_clients())
}

pub fn discover_watch_roots_with_projects(
    root: &Path,
    clients: &[ClientId],
    projects: &[ProjectDef],
) -> Vec<PathBuf> {
    shared::discover_watch_roots_with_projects(root, clients, projects, supported_clients())
}

pub fn source_search_root(root: &Path, source_def: ClientSourceDef) -> PathBuf {
    shared::source_search_root(root, source_def, supported_clients())
}

pub fn is_fixture_root(root: &Path) -> bool {
    shared::is_fixture_root(root, supported_clients())
}

pub fn opencode_data_directories(root: &Path) -> Vec<PathBuf> {
    shared::opencode_data_directories(root, supported_clients())
}

pub fn opencode_database_override(root: &Path) -> Result<Option<PathBuf>, BoundedDiscoveryError> {
    shared::opencode_database_override(root, supported_clients())
}
