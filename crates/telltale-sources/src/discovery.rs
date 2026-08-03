use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::clients::{ClientSourceDef, PathRoot, SourcePattern, supported_clients};
use telltale_schema::clients::ClientId;
use telltale_schema::source::Source;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiscoveryError {
    InvalidRoot { root: PathBuf },
    Traversal { root: PathBuf, source_id: String },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot { root } => {
                write!(
                    formatter,
                    "discovery root is not a readable directory: {}",
                    root.display()
                )
            }
            Self::Traversal { root, source_id } => write!(
                formatter,
                "could not traverse discovery root {} for source {source_id}",
                root.display()
            ),
        }
    }
}

impl std::error::Error for DiscoveryError {}

struct DiscoveryContext<'a> {
    root: &'a Path,
    source_id: &'static str,
}

#[derive(Clone, Copy)]
enum DiscoveryMode {
    Checked,
    BestEffort,
}

impl DiscoveryMode {
    fn is_checked(self) -> bool {
        matches!(self, Self::Checked)
    }
}

impl DiscoveryContext<'_> {
    fn traversal_error(&self) -> DiscoveryError {
        DiscoveryError::Traversal {
            root: self.root.to_path_buf(),
            source_id: self.source_id.to_string(),
        }
    }
}

fn new_source(client: ClientId, source_def: ClientSourceDef, path: PathBuf) -> Source {
    Source {
        client,
        kind: source_def.kind,
        source_id: source_def.id.to_string(),
        path,
    }
}

pub fn discover_sources(root: &Path) -> Result<Vec<Source>, DiscoveryError> {
    discover_sources_with_projects(root, &[])
}

pub fn discover_sources_best_effort(root: &Path) -> Vec<Source> {
    discover_sources_with_projects_best_effort(root, &[])
}

pub fn discover_sources_with_projects(
    root: &Path,
    projects: &[crate::projects::ProjectDef],
) -> Result<Vec<Source>, DiscoveryError> {
    discover_sources_with_projects_impl(root, projects, DiscoveryMode::Checked)
}

pub fn discover_sources_with_projects_best_effort(
    root: &Path,
    projects: &[crate::projects::ProjectDef],
) -> Vec<Source> {
    discover_sources_with_projects_impl(root, projects, DiscoveryMode::BestEffort)
        .unwrap_or_default()
}

fn discover_sources_with_projects_impl(
    root: &Path,
    projects: &[crate::projects::ProjectDef],
    mode: DiscoveryMode,
) -> Result<Vec<Source>, DiscoveryError> {
    if mode.is_checked() {
        validate_root(root)?;
        for project in projects {
            validate_root(&project.path)?;
        }
    }

    let mut sources = Vec::new();
    let fixture_root = is_fixture_root(root);

    for client in supported_clients() {
        for source_def in client.sources {
            if source_def.root != PathRoot::ProjectLocal || fixture_root {
                let context = DiscoveryContext {
                    root,
                    source_id: source_def.id,
                };
                match discover_source(root, client.id, *source_def, &context, mode) {
                    Ok(found) => sources.extend(found),
                    Err(error) if mode.is_checked() => return Err(error),
                    Err(_) => {}
                }
            }
        }
    }

    for project in projects {
        for client in supported_clients() {
            for source_def in client.sources {
                if source_def.root == PathRoot::ProjectLocal {
                    let context = DiscoveryContext {
                        root: &project.path,
                        source_id: source_def.id,
                    };
                    match discover_source(&project.path, client.id, *source_def, &context, mode) {
                        Ok(found) => sources.extend(found),
                        Err(error) if mode.is_checked() => return Err(error),
                        Err(_) => {}
                    }
                }
            }
        }
    }

    sources.sort_by(|left, right| {
        (
            left.client.as_str(),
            left.kind.as_str(),
            left.source_id.as_str(),
            left.path.to_string_lossy(),
        )
            .cmp(&(
                right.client.as_str(),
                right.kind.as_str(),
                right.source_id.as_str(),
                right.path.to_string_lossy(),
            ))
    });
    Ok(sources)
}

fn validate_root(root: &Path) -> Result<(), DiscoveryError> {
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        _ => Err(DiscoveryError::InvalidRoot {
            root: root.to_path_buf(),
        }),
    }
}

pub fn discover_watch_roots(root: &Path) -> Vec<PathBuf> {
    discover_watch_roots_for_clients(root, &[])
}

pub fn discover_watch_roots_for_clients(root: &Path, clients: &[ClientId]) -> Vec<PathBuf> {
    discover_watch_roots_with_projects(root, clients, &[])
}

pub fn discover_watch_roots_with_projects(
    root: &Path,
    clients: &[ClientId],
    projects: &[crate::projects::ProjectDef],
) -> Vec<PathBuf> {
    let mut roots = supported_clients()
        .iter()
        .filter(|client| clients.is_empty() || clients.contains(&client.id))
        .flat_map(|client| client.sources.iter())
        .filter(|source_def| source_def.root != PathRoot::ProjectLocal)
        .flat_map(|source_def| source_watch_roots(root, *source_def))
        .collect::<Vec<_>>();

    for project in projects {
        for client in supported_clients() {
            if !clients.is_empty() && !clients.contains(&client.id) {
                continue;
            }
            for source_def in client.sources {
                if source_def.root == PathRoot::ProjectLocal {
                    roots.extend(source_watch_roots(&project.path, *source_def));
                }
            }
        }
    }

    roots.sort_unstable();
    roots.dedup();
    roots
}

fn source_watch_roots(root: &Path, source_def: ClientSourceDef) -> Vec<PathBuf> {
    if source_def.root == PathRoot::ProjectLocal && !is_fixture_root(root) {
        let subpath = source_def
            .project_relative_path
            .unwrap_or(source_def.relative_path);
        let context = DiscoveryContext {
            root,
            source_id: source_def.id,
        };
        return discover_project_local_search_roots(
            root,
            subpath,
            &context,
            DiscoveryMode::BestEffort,
        )
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| {
            if p.is_dir() {
                Some(p)
            } else {
                p.parent()
                    .filter(|parent| parent.is_dir())
                    .map(Path::to_path_buf)
            }
        })
        .collect();
    }

    let search_root = source_search_root(root, source_def);
    if search_root.is_dir() {
        return vec![search_root];
    }
    if search_root.is_file() || matches!(source_def.pattern, SourcePattern::ExactFile(_)) {
        return search_root
            .parent()
            .filter(|parent| parent.is_dir())
            .map(Path::to_path_buf)
            .into_iter()
            .collect();
    }
    Vec::new()
}

fn discover_source(
    root: &Path,
    client: ClientId,
    source_def: ClientSourceDef,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<Vec<Source>, DiscoveryError> {
    let search_root = source_search_root(root, source_def);

    // For project-local sources, recursively search for the subpath under the project root
    if source_def.root == PathRoot::ProjectLocal && !is_fixture_root(root) {
        let subpath = source_def
            .project_relative_path
            .unwrap_or(source_def.relative_path);
        return discover_project_local_paths(
            root,
            subpath,
            source_def.pattern,
            source_def.recursive,
            context,
            mode,
        )
        .map(|paths| {
            paths
                .into_iter()
                .map(|path| new_source(client, source_def, path))
                .collect()
        });
    }

    discover_matching_paths(
        &search_root,
        source_def.pattern,
        source_def.recursive,
        context,
        mode,
    )
    .map(|paths| {
        paths
            .into_iter()
            .map(|path| new_source(client, source_def, path))
            .collect()
    })
}

/// Search for project-local subdirectories under a project or workspace root.
/// For example, if root is ~/github and subpath is "logs/copilot", this checks
/// both ~/github/logs/copilot and common nested checkout layouts such as
/// ~/github/<repo>/logs/copilot and ~/github/<org>/<repo>/logs/copilot.
fn discover_project_local_paths(
    root: &Path,
    subpath: &str,
    pattern: SourcePattern,
    recursive: bool,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    const MAX_WORKSPACE_DEPTH: usize = 2;

    discover_project_local_paths_with_depth(
        root,
        subpath,
        pattern,
        recursive,
        MAX_WORKSPACE_DEPTH,
        context,
        mode,
    )
}

fn discover_project_local_paths_with_depth(
    root: &Path,
    subpath: &str,
    pattern: SourcePattern,
    recursive: bool,
    remaining_depth: usize,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    let search_roots = discover_project_local_search_roots_with_depth(
        root,
        subpath,
        remaining_depth,
        context,
        mode,
    )?;
    let mut paths = Vec::new();
    for search_root in search_roots {
        match discover_matching_paths(&search_root, pattern, recursive, context, mode) {
            Ok(found) => paths.extend(found),
            Err(error) if mode.is_checked() => return Err(error),
            Err(_) => {}
        }
    }
    Ok(paths)
}

fn discover_project_local_search_roots(
    root: &Path,
    subpath: &str,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    const MAX_WORKSPACE_DEPTH: usize = 2;

    discover_project_local_search_roots_with_depth(
        root,
        subpath,
        MAX_WORKSPACE_DEPTH,
        context,
        mode,
    )
}

fn discover_project_local_search_roots_with_depth(
    root: &Path,
    subpath: &str,
    remaining_depth: usize,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    let mut results = Vec::new();

    // First, check if the subpath exists directly under the root.
    let direct_path = root.join(subpath);
    if path_exists(&direct_path, context, mode)? {
        results.push(direct_path);
    }

    if remaining_depth == 0 {
        return Ok(results);
    }

    // Then search bounded nested workspace directories without following symlinked dirs.
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(results),
        Err(_) if mode.is_checked() => return Err(context.traversal_error()),
        Err(_) => return Ok(results),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) if mode.is_checked() => return Err(context.traversal_error()),
            Err(_) => continue,
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) if mode.is_checked() => return Err(context.traversal_error()),
            Err(_) => continue,
        };
        if file_type.is_dir() && !is_hidden_path(&path) {
            match discover_project_local_search_roots_with_depth(
                &path,
                subpath,
                remaining_depth - 1,
                context,
                mode,
            ) {
                Ok(found) => results.extend(found),
                Err(error) if mode.is_checked() => return Err(error),
                Err(_) => {}
            }
        }
    }

    Ok(results)
}

fn is_hidden_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}

fn source_search_root(root: &Path, source_def: ClientSourceDef) -> PathBuf {
    if is_fixture_root(root) {
        return source_def.fixture_path(root);
    }

    match source_def.root {
        PathRoot::ProjectLocal => root.join(
            source_def
                .project_relative_path
                .unwrap_or(source_def.relative_path),
        ),
        _ => resolve_path_root(root, source_def.root).join(source_def.relative_path),
    }
}

pub fn is_fixture_root(root: &Path) -> bool {
    supported_clients()
        .iter()
        .flat_map(|client| client.sources.iter())
        .any(|source_def| source_def.fixture_path(root).exists())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HostPlatform {
    Linux,
    MacOs,
    Windows,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RootResolutionContext {
    home: PathBuf,
    codex_home: Option<PathBuf>,
    config_home: Option<PathBuf>,
    data_home: Option<PathBuf>,
}

fn resolve_path_root(root: &Path, path_root: PathRoot) -> PathBuf {
    let use_environment_roots = root == Path::new(".");
    let platform = current_host_platform();
    let context = if use_environment_roots {
        environment_root_context(platform, root)
    } else {
        rooted_path_context(platform, root)
    };

    resolve_path_root_from_context(&context, path_root)
}

#[cfg(test)]
fn source_search_root_from_context(
    context: &RootResolutionContext,
    source_def: ClientSourceDef,
) -> PathBuf {
    resolve_path_root_from_context(context, source_def.root).join(source_def.relative_path)
}

#[cfg(test)]
fn discover_source_from_context(
    context: &RootResolutionContext,
    client: ClientId,
    source_def: ClientSourceDef,
) -> Vec<Source> {
    let search_root = source_search_root_from_context(context, source_def);
    let discovery_context = DiscoveryContext {
        root: &search_root,
        source_id: source_def.id,
    };

    discover_matching_paths(
        &search_root,
        source_def.pattern,
        source_def.recursive,
        &discovery_context,
        DiscoveryMode::Checked,
    )
    .expect("discover source paths")
    .into_iter()
    .map(|path| new_source(client, source_def, path))
    .collect()
}

fn discover_matching_paths(
    root: &Path,
    pattern: SourcePattern,
    recursive: bool,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    match pattern {
        SourcePattern::Extension(extension) => {
            files_with_extension(root, extension, recursive, context, mode)
        }
        SourcePattern::ExactFile(file_name) => {
            files_named(root, file_name, recursive, context, mode)
        }
        SourcePattern::FileNameContains(needle) => {
            files_with_name_containing(root, needle, recursive, context, mode)
        }
    }
}

fn resolve_path_root_from_context(context: &RootResolutionContext, path_root: PathRoot) -> PathBuf {
    match path_root {
        PathRoot::Home => context.home.clone(),
        PathRoot::CodexHome => context
            .codex_home
            .clone()
            .unwrap_or_else(|| context.home.join(".codex")),
        PathRoot::ConfigHome => context
            .config_home
            .clone()
            .unwrap_or_else(|| default_config_home(current_host_platform(), &context.home)),
        PathRoot::DataHome => context
            .data_home
            .clone()
            .unwrap_or_else(|| default_data_home(current_host_platform(), &context.home)),
        PathRoot::ProjectLocal => context.home.clone(),
    }
}

fn current_host_platform() -> HostPlatform {
    if cfg!(target_os = "windows") {
        HostPlatform::Windows
    } else if cfg!(target_os = "macos") {
        HostPlatform::MacOs
    } else {
        HostPlatform::Linux
    }
}

fn environment_root_context(platform: HostPlatform, fallback_root: &Path) -> RootResolutionContext {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| fallback_root.to_path_buf());

    RootResolutionContext {
        home: home.clone(),
        codex_home: env::var_os("CODEX_HOME").map(PathBuf::from),
        config_home: env_config_home(platform, &home),
        data_home: env_data_home(platform, &home),
    }
}

fn rooted_path_context(platform: HostPlatform, root: &Path) -> RootResolutionContext {
    let home = root.to_path_buf();
    RootResolutionContext {
        home: home.clone(),
        codex_home: Some(home.join(".codex")),
        config_home: Some(default_config_home(platform, &home)),
        data_home: Some(default_data_home(platform, &home)),
    }
}

fn env_config_home(platform: HostPlatform, home: &Path) -> Option<PathBuf> {
    match platform {
        HostPlatform::Linux => env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| Some(default_config_home(platform, home))),
        HostPlatform::MacOs => Some(default_config_home(platform, home)),
        HostPlatform::Windows => env::var_os("APPDATA")
            .map(PathBuf::from)
            .or_else(|| Some(default_config_home(platform, home))),
    }
}

fn env_data_home(platform: HostPlatform, home: &Path) -> Option<PathBuf> {
    match platform {
        HostPlatform::Linux => env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| Some(default_data_home(platform, home))),
        HostPlatform::MacOs => Some(default_data_home(platform, home)),
        HostPlatform::Windows => env::var_os("LOCALAPPDATA")
            .or_else(|| env::var_os("APPDATA"))
            .map(PathBuf::from)
            .or_else(|| Some(default_data_home(platform, home))),
    }
}

fn default_config_home(platform: HostPlatform, home: &Path) -> PathBuf {
    match platform {
        HostPlatform::Linux => home.join(".config"),
        HostPlatform::MacOs => home.join("Library/Application Support"),
        HostPlatform::Windows => home.join("AppData/Roaming"),
    }
}

fn default_data_home(platform: HostPlatform, home: &Path) -> PathBuf {
    match platform {
        HostPlatform::Linux => home.join(".local/share"),
        HostPlatform::MacOs => home.join("Library/Application Support"),
        HostPlatform::Windows => home.join("AppData/Local"),
    }
}

fn files_with_extension(
    root: &Path,
    extension: &str,
    recursive: bool,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    let mut paths: Vec<PathBuf> = walk_files(root, recursive, context, mode)?
        .into_iter()
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .filter(|path| path.extension().is_some_and(|value| value == extension))
        .collect();
    paths.sort_unstable();
    Ok(paths)
}

fn files_named(
    root: &Path,
    file_name: &str,
    recursive: bool,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_file() => {
            return Ok(root
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| *name == file_name)
                .map(|_| vec![root.to_path_buf()])
                .unwrap_or_default());
        }
        Ok(metadata) if !metadata.is_dir() => return Ok(Vec::new()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) if mode.is_checked() => return Err(context.traversal_error()),
        Err(_) => return Ok(Vec::new()),
    }

    let mut paths: Vec<PathBuf> = walk_files(root, recursive, context, mode)?
        .into_iter()
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some(file_name))
        .collect();
    paths.sort_unstable();
    Ok(paths)
}

fn files_with_name_containing(
    root: &Path,
    needle: &str,
    recursive: bool,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<Vec<PathBuf>, DiscoveryError> {
    let mut paths: Vec<PathBuf> = walk_files(root, recursive, context, mode)?
        .into_iter()
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains(needle))
        })
        .collect();
    paths.sort_unstable();
    Ok(paths)
}

fn walk_files(
    root: &Path,
    recursive: bool,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<Vec<walkdir::DirEntry>, DiscoveryError> {
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Ok(Vec::new()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) if mode.is_checked() => return Err(context.traversal_error()),
        Err(_) => return Ok(Vec::new()),
    }

    let walker = if recursive {
        WalkDir::new(root)
    } else {
        WalkDir::new(root).max_depth(1)
    };
    collect_walk_entries(walker, mode, || context.traversal_error())
}

fn path_exists(
    path: &Path,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
) -> Result<bool, DiscoveryError> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) if mode.is_checked() => Err(context.traversal_error()),
        Err(_) => Ok(false),
    }
}

fn collect_walk_entries<I, T, E, F>(
    entries: I,
    mode: DiscoveryMode,
    error: F,
) -> Result<Vec<T>, DiscoveryError>
where
    I: IntoIterator<Item = Result<T, E>>,
    F: Fn() -> DiscoveryError,
{
    let mut found = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => found.push(entry),
            Err(_) if mode.is_checked() => return Err(error()),
            Err(_) => {}
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    use telltale_schema::clients::{ClientId, SourceKind};
    use tempfile::tempdir;

    use crate::clients::{ClientSourceDef, PathRoot};

    use super::{
        DiscoveryError, DiscoveryMode, HostPlatform, RootResolutionContext, collect_walk_entries,
        current_host_platform, default_config_home, default_data_home,
        discover_source_from_context, discover_sources, discover_sources_best_effort,
        discover_sources_with_projects, discover_watch_roots, discover_watch_roots_for_clients,
        discover_watch_roots_with_projects, resolve_path_root_from_context,
        source_search_root_from_context,
    };
    use crate::clients::supported_clients;

    fn lookup_source(id: &str) -> (ClientId, ClientSourceDef) {
        supported_clients()
            .iter()
            .flat_map(|client| {
                client
                    .sources
                    .iter()
                    .map(move |source| (client.id, *source))
            })
            .find(|(_, source)| source.id == id)
            .expect("source definition")
    }

    #[test]
    fn discovers_codex_and_opencode_fixture_sources() {
        let sources =
            discover_sources(&crate::test_fixture_path("session_stores")).expect("discovery");

        let keys: HashSet<_> = sources
            .iter()
            .map(|source| {
                (
                    source.client,
                    source.kind,
                    source.path.file_name().and_then(|name| name.to_str()),
                )
            })
            .collect();

        assert!(keys.contains(&(ClientId::Codex, SourceKind::Jsonl, Some("session-a.jsonl"))));
        assert!(keys.contains(&(ClientId::Claude, SourceKind::Jsonl, Some("session-a.jsonl"))));
        assert!(keys.contains(&(ClientId::Gemini, SourceKind::Json, Some("session-a.json"))));
        assert!(keys.contains(&(
            ClientId::OpenClaw,
            SourceKind::Jsonl,
            Some("session-a.jsonl.deleted")
        )));
        assert!(keys.contains(&(ClientId::Qwen, SourceKind::Jsonl, Some("session-a.jsonl"))));
        assert!(keys.contains(&(
            ClientId::RooCode,
            SourceKind::UiMessagesJson,
            Some("ui_messages.json")
        )));
        assert!(keys.contains(&(
            ClientId::KiloCode,
            SourceKind::UiMessagesJson,
            Some("ui_messages.json")
        )));
        assert!(keys.contains(&(
            ClientId::Codex,
            SourceKind::ArchivedJsonl,
            Some("session-b.jsonl")
        )));
        assert!(keys.contains(&(
            ClientId::Codex,
            SourceKind::HeadlessJsonl,
            Some("headless-a.jsonl")
        )));
        assert!(keys.contains(&(
            ClientId::OpenCode,
            SourceKind::LegacyJson,
            Some("message-a.json")
        )));
        assert!(keys.contains(&(ClientId::OpenCode, SourceKind::Sqlite, Some("opencode.db"))));
    }

    #[test]
    fn checked_discovery_reports_invalid_roots_and_best_effort_preserves_empty_behavior() {
        let temp = tempdir().expect("tempdir");
        let missing = temp.path().join("missing");

        let error = discover_sources(&missing).expect_err("missing root should fail");
        assert_eq!(
            error,
            DiscoveryError::InvalidRoot {
                root: missing.clone()
            }
        );
        assert!(discover_sources_best_effort(&missing).is_empty());
        assert!(
            error
                .to_string()
                .contains(missing.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn best_effort_walk_retains_valid_entries_around_failure() {
        let traversal_error = DiscoveryError::Traversal {
            root: PathBuf::from("synthetic-root"),
            source_id: "synthetic.source".to_string(),
        };
        let entries = [Ok("direct"), Err("failed"), Ok("sibling")];

        let retained = collect_walk_entries(entries, DiscoveryMode::BestEffort, || {
            traversal_error.clone()
        })
        .expect("best effort keeps valid entries");
        assert_eq!(retained, ["direct", "sibling"]);

        let entries = [Ok("direct"), Err("failed"), Ok("sibling")];
        let error =
            collect_walk_entries(entries, DiscoveryMode::Checked, || traversal_error.clone())
                .expect_err("checked discovery reports the first failure");
        assert_eq!(error, traversal_error);
    }

    #[test]
    fn best_effort_discovery_matches_checked_success_ordering() {
        let fixture_root = crate::test_fixture_path("session_stores");
        let checked = discover_sources(&fixture_root).expect("checked discovery");
        let best_effort = discover_sources_best_effort(&fixture_root);

        assert_eq!(checked, best_effort);
    }

    #[cfg(unix)]
    #[test]
    fn checked_discovery_reports_unreadable_source_traversal() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().expect("tempdir");
        let restricted = temp.path().join(".codex/sessions");
        fs::create_dir_all(&restricted).expect("sessions directory");
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o000))
            .expect("restrict sessions directory");
        let result = discover_sources(temp.path());
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o755))
            .expect("restore sessions directory");

        let Err(error) = result else {
            return;
        };
        assert!(matches!(
            error,
            DiscoveryError::Traversal { ref source_id, .. } if source_id == "codex.sessions"
        ));
    }

    #[test]
    fn discovers_project_local_sources_from_tempdir() {
        let temp = tempdir().expect("tempdir");
        let project = temp.path().join("myproject");
        let copilot_dir = project.join("logs/copilot");
        fs::create_dir_all(&copilot_dir).expect("copilot dir");
        fs::write(
            copilot_dir.join("process.log"),
            b"2026-01-01T00:00:00Z init\n",
        )
        .expect("copilot log");

        let opencode_dir = project.join(".opencode");
        fs::create_dir_all(&opencode_dir).expect("opencode dir");
        fs::write(opencode_dir.join("message.json"), b"{}").expect("opencode json");

        let codex_dir = project.join(".codex-worktree");
        fs::create_dir_all(&codex_dir).expect("codex dir");
        fs::write(codex_dir.join("session.jsonl"), b"{}\n").expect("codex jsonl");

        let projects = vec![crate::projects::ProjectDef {
            name: "myproject".to_string(),
            path: project,
        }];
        let sources = discover_sources_with_projects(std::path::Path::new("."), &projects)
            .expect("discovery");
        let keys: HashSet<_> = sources
            .iter()
            .map(|source| {
                (
                    source.client,
                    source.kind,
                    source.path.file_name().and_then(|name| name.to_str()),
                )
            })
            .collect();

        assert!(keys.contains(&(
            ClientId::Copilot,
            SourceKind::CopilotProcessLog,
            Some("process.log")
        )));
        assert!(keys.contains(&(
            ClientId::OpenCode,
            SourceKind::LegacyJson,
            Some("message.json")
        )));
        assert!(keys.contains(&(ClientId::Codex, SourceKind::Jsonl, Some("session.jsonl"))));
    }

    #[test]
    fn discovers_and_parses_codex_and_opencode_project_identities_portably() {
        let temp = tempdir().expect("tempdir");
        let discovery_root = temp.path().join("discovery-root");
        let project = temp.path().join("project-root");
        fs::create_dir_all(&discovery_root).expect("discovery root");

        let codex_path = project
            .join(".codex-worktree")
            .join("project-session.jsonl");
        fs::create_dir_all(codex_path.parent().expect("codex parent")).expect("codex dir");
        fs::write(
            &codex_path,
            b"{\"type\":\"session_meta\",\"payload\":{\"agent_nickname\":\"fixture-agent\"}}\n{\"type\":\"event_msg\",\"payload\":{\"type\":\"assistant_message\",\"message\":\"project response\"}}\n",
        )
        .expect("codex project fixture");

        let opencode_path = project.join(".opencode").join("project-message.json");
        fs::create_dir_all(opencode_path.parent().expect("opencode parent")).expect("opencode dir");
        fs::write(
            &opencode_path,
            b"{\"sessionID\":\"opencode-project\",\"role\":\"assistant\",\"agent\":\"build\",\"content\":\"project response\"}",
        )
        .expect("opencode project fixture");

        let projects = vec![crate::projects::ProjectDef {
            name: "project-root".to_string(),
            path: project,
        }];
        let sources =
            discover_sources_with_projects(&discovery_root, &projects).expect("discovery");

        let codex = sources
            .iter()
            .find(|source| source.source_id == "codex.project_sessions")
            .expect("codex project source");
        assert_eq!(codex.client, ClientId::Codex);
        assert_eq!(codex.kind, SourceKind::Jsonl);
        assert_eq!(
            codex.path.file_name().and_then(|name| name.to_str()),
            Some("project-session.jsonl")
        );
        assert!(
            codex
                .path
                .ends_with(PathBuf::from(".codex-worktree").join("project-session.jsonl"))
        );
        assert!(
            codex
                .path
                .components()
                .any(|component| component.as_os_str() == "project-root")
        );
        let codex_records = crate::parser::parse_source_records(codex).expect("codex records");
        assert_eq!(codex_records.len(), 2);
        assert_eq!(
            codex_records[0].kind,
            telltale_schema::record::RecordKind::SessionMeta
        );
        assert_eq!(
            codex_records[1].kind,
            telltale_schema::record::RecordKind::AssistantMessage
        );
        assert_eq!(codex_records[0].agent.as_deref(), Some("fixture-agent"));

        let opencode = sources
            .iter()
            .find(|source| source.source_id == "opencode.project_json")
            .expect("opencode project source");
        assert_eq!(opencode.client, ClientId::OpenCode);
        assert_eq!(opencode.kind, SourceKind::LegacyJson);
        assert_eq!(
            opencode.path.file_name().and_then(|name| name.to_str()),
            Some("project-message.json")
        );
        assert!(
            opencode
                .path
                .ends_with(PathBuf::from(".opencode").join("project-message.json"))
        );
        assert!(
            opencode
                .path
                .components()
                .any(|component| component.as_os_str() == "project-root")
        );
        let opencode_records =
            crate::parser::parse_source_records(opencode).expect("opencode records");
        assert_eq!(opencode_records.len(), 1);
        assert_eq!(
            opencode_records[0].kind,
            telltale_schema::record::RecordKind::AssistantMessage
        );
        assert_eq!(opencode_records[0].session_id, "opencode-project");
        assert_eq!(opencode_records[0].agent.as_deref(), Some("build"));
    }

    #[test]
    fn discovers_all_nested_project_local_watch_roots() {
        let temp = tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let first = workspace.join("org-a/repo-a/logs/copilot");
        let second = workspace.join("org-b/repo-b/logs/copilot");
        fs::create_dir_all(&first).expect("first copilot dir");
        fs::create_dir_all(&second).expect("second copilot dir");

        let projects = vec![crate::projects::ProjectDef {
            name: "workspace".to_string(),
            path: workspace,
        }];
        let roots = discover_watch_roots_with_projects(
            std::path::Path::new("."),
            &[ClientId::Copilot],
            &projects,
        );

        assert!(roots.contains(&first));
        assert!(roots.contains(&second));
    }

    #[test]
    fn discovers_host_style_opencode_sources_from_home_root() {
        let temp = tempdir().expect("tempdir");
        let home = temp.path();
        let data_home = default_data_home(current_host_platform(), home).join("opencode");
        let data_home_relative = data_home
            .strip_prefix(home)
            .expect("data home relative path")
            .to_path_buf();
        let legacy_dir = data_home.join("storage/message/session-a");

        fs::create_dir_all(&legacy_dir).expect("legacy dir");
        fs::write(data_home.join("opencode.db"), b"sqlite fixture").expect("sqlite fixture");
        fs::write(legacy_dir.join("message-a.json"), b"{}").expect("legacy fixture");

        let sources = discover_sources(home).expect("discovery");
        let keys: HashSet<_> = sources
            .iter()
            .map(|source| {
                (
                    source.client,
                    source.kind,
                    source
                        .path
                        .strip_prefix(home)
                        .expect("relative path")
                        .to_path_buf(),
                )
            })
            .collect();

        assert!(keys.contains(&(
            ClientId::OpenCode,
            SourceKind::Sqlite,
            data_home_relative.join("opencode.db")
        )));
        assert!(keys.contains(&(
            ClientId::OpenCode,
            SourceKind::LegacyJson,
            data_home_relative.join("storage/message/session-a/message-a.json")
        )));
    }

    #[test]
    fn discovers_existing_fixture_watch_roots() {
        let roots = discover_watch_roots(&crate::test_fixture_path("session_stores"));
        let fixture_root = Path::new("tests").join("fixtures").join("session_stores");

        assert!(
            roots
                .iter()
                .any(|path| path.ends_with(fixture_root.join("codex").join("sessions")))
        );
        assert!(
            roots
                .iter()
                .any(|path| path.ends_with(fixture_root.join("opencode")))
        );
    }

    #[test]
    fn filters_fixture_watch_roots_by_client() {
        let roots = discover_watch_roots_for_clients(
            &crate::test_fixture_path("session_stores"),
            &[ClientId::Gemini],
        );
        let fixture_root = Path::new("tests").join("fixtures").join("session_stores");

        assert!(!roots.is_empty());
        assert!(
            roots
                .iter()
                .all(|path| path.ends_with(fixture_root.join("gemini").join("tmp")))
        );
    }

    #[test]
    fn resolves_linux_roots_from_context() {
        let context = RootResolutionContext {
            home: PathBuf::from("/home/tester"),
            codex_home: Some(PathBuf::from("/srv/codex")),
            config_home: Some(PathBuf::from("/xdg/config")),
            data_home: Some(PathBuf::from("/xdg/data")),
        };

        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::Home),
            PathBuf::from("/home/tester")
        );
        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::CodexHome),
            PathBuf::from("/srv/codex")
        );
        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::ConfigHome),
            PathBuf::from("/xdg/config")
        );
        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::DataHome),
            PathBuf::from("/xdg/data")
        );
    }

    #[test]
    fn resolves_macos_default_roots_from_context() {
        let home = PathBuf::from("/Users/tester");
        let context = RootResolutionContext {
            home: home.clone(),
            codex_home: None,
            config_home: Some(default_config_home(HostPlatform::MacOs, &home)),
            data_home: Some(default_data_home(HostPlatform::MacOs, &home)),
        };

        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::CodexHome),
            PathBuf::from("/Users/tester/.codex")
        );
        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::ConfigHome),
            PathBuf::from("/Users/tester/Library/Application Support")
        );
        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::DataHome),
            PathBuf::from("/Users/tester/Library/Application Support")
        );
    }

    #[test]
    fn resolves_windows_default_roots_from_context() {
        let home = PathBuf::from(r#"C:\Users\tester"#);
        let context = RootResolutionContext {
            home: home.clone(),
            codex_home: None,
            config_home: Some(default_config_home(HostPlatform::Windows, &home)),
            data_home: Some(default_data_home(HostPlatform::Windows, &home)),
        };

        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::CodexHome),
            PathBuf::from(r#"C:\Users\tester/.codex"#)
        );
        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::ConfigHome),
            PathBuf::from(r#"C:\Users\tester/AppData/Roaming"#)
        );
        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::DataHome),
            PathBuf::from(r#"C:\Users\tester/AppData/Local"#)
        );
    }

    #[test]
    fn discovers_experimental_windows_confirmed_source_candidates() {
        let temp = tempdir().expect("tempdir");
        let home = temp.path().join("Users/tester");
        let codex_home = home.join(".codex");
        let config_home = home.join("AppData/Roaming");
        let context = RootResolutionContext {
            home: home.clone(),
            codex_home: None,
            config_home: Some(config_home.clone()),
            data_home: Some(home.join("AppData/Local")),
        };

        fs::create_dir_all(codex_home.join("sessions/2026/05")).expect("codex sessions dir");
        fs::create_dir_all(codex_home.join("archived_sessions")).expect("codex archived dir");
        fs::create_dir_all(codex_home.join("headless")).expect("codex headless dir");
        fs::write(codex_home.join("sessions/2026/05/session-a.jsonl"), b"{}\n")
            .expect("codex session fixture");
        fs::write(
            codex_home.join("archived_sessions/session-b.jsonl"),
            b"{}\n",
        )
        .expect("codex archived fixture");
        fs::write(codex_home.join("headless/headless-a.jsonl"), b"{}\n")
            .expect("codex headless fixture");

        let roocode_task =
            config_home.join("Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/task-a");
        let kilocode_task =
            config_home.join("Code/User/globalStorage/kilocode.kilo-code/tasks/task-a");
        fs::create_dir_all(&roocode_task).expect("roocode task dir");
        fs::create_dir_all(&kilocode_task).expect("kilocode task dir");
        fs::write(roocode_task.join("ui_messages.json"), b"[]").expect("roocode fixture");
        fs::write(kilocode_task.join("ui_messages.json"), b"[]").expect("kilocode fixture");

        let source_ids = [
            "codex.sessions",
            "codex.archived_sessions",
            "codex.headless_sessions",
            "roocode.tasks",
            "kilocode.tasks",
        ];
        let sources = source_ids
            .into_iter()
            .flat_map(|source_id| {
                let (client, source_def) = lookup_source(source_id);
                discover_source_from_context(&context, client, source_def)
            })
            .collect::<Vec<_>>();
        let keys: HashSet<_> = sources
            .iter()
            .map(|source| {
                (
                    source.client,
                    source.kind,
                    source
                        .path
                        .strip_prefix(&home)
                        .expect("relative path")
                        .to_path_buf(),
                )
            })
            .collect();

        assert!(keys.contains(&(
            ClientId::Codex,
            SourceKind::Jsonl,
            PathBuf::from(".codex/sessions/2026/05/session-a.jsonl")
        )));
        assert!(keys.contains(&(
            ClientId::Codex,
            SourceKind::ArchivedJsonl,
            PathBuf::from(".codex/archived_sessions/session-b.jsonl")
        )));
        assert!(keys.contains(&(
            ClientId::Codex,
            SourceKind::HeadlessJsonl,
            PathBuf::from(".codex/headless/headless-a.jsonl")
        )));
        assert!(keys.contains(&(
            ClientId::RooCode,
            SourceKind::UiMessagesJson,
            PathBuf::from(
                "AppData/Roaming/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/task-a/ui_messages.json"
            )
        )));
        assert!(keys.contains(&(
            ClientId::KiloCode,
            SourceKind::UiMessagesJson,
            PathBuf::from(
                "AppData/Roaming/Code/User/globalStorage/kilocode.kilo-code/tasks/task-a/ui_messages.json"
            )
        )));
    }

    #[test]
    fn resolves_confirmed_macos_source_candidates() {
        let home = PathBuf::from("/Users/tester");
        let context = RootResolutionContext {
            home: home.clone(),
            codex_home: None,
            config_home: Some(default_config_home(HostPlatform::MacOs, &home)),
            data_home: Some(default_data_home(HostPlatform::MacOs, &home)),
        };

        let lookup = |id: &str| lookup_source(id).1;

        assert_eq!(
            source_search_root_from_context(&context, lookup("codex.sessions")),
            PathBuf::from("/Users/tester/.codex/sessions")
        );
        assert_eq!(
            source_search_root_from_context(&context, lookup("claude.projects")),
            PathBuf::from("/Users/tester/.claude/projects")
        );
        assert_eq!(
            source_search_root_from_context(&context, lookup("gemini.tmp")),
            PathBuf::from("/Users/tester/.gemini/tmp")
        );
        assert_eq!(
            source_search_root_from_context(&context, lookup("qwen.projects")),
            PathBuf::from("/Users/tester/.qwen/projects")
        );
        assert_eq!(
            source_search_root_from_context(&context, lookup("openclaw.agents")),
            PathBuf::from("/Users/tester/.openclaw/agents")
        );
        assert_eq!(
            source_search_root_from_context(&context, lookup("roocode.tasks")),
            PathBuf::from(
                "/Users/tester/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks"
            )
        );
        assert_eq!(
            source_search_root_from_context(&context, lookup("kilocode.tasks")),
            PathBuf::from(
                "/Users/tester/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/tasks"
            )
        );
        assert_eq!(
            source_search_root_from_context(&context, lookup("opencode.sqlite")),
            PathBuf::from("/Users/tester/Library/Application Support/opencode/opencode.db")
        );
        assert_eq!(
            source_search_root_from_context(&context, lookup("opencode.legacy_json")),
            PathBuf::from("/Users/tester/Library/Application Support/opencode/storage/message")
        );
    }
}
