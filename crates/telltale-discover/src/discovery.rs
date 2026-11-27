//! Session-store discovery: walks OS-aware roots and project-local paths for
//! the registered source definitions and returns sorted, deduplicated `Source`
//! values and watch roots. The caller supplies its supported-source registry;
//! no broad inventory entry can become a source implicitly. No files are parsed.

use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::clients::{ClientDef, ClientSourceDef, PathRoot, SourcePattern};
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

pub fn discover_sources(
    root: &Path,
    registry: &[ClientDef],
) -> Result<Vec<Source>, DiscoveryError> {
    discover_sources_with_projects(root, &[], registry)
}

/// Payload-free failure for finite on-demand discovery. An incomplete traversal
/// cannot prove unique ownership and never returns a successful partial listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedDiscoveryError {
    InvalidLimit,
    LimitExceeded,
    SymlinkRoot,
    PermissionDenied,
    Traversal,
}

impl BoundedDiscoveryError {
    pub(crate) fn from_io(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Traversal,
        }
    }
}

/// Discover one client's home/data sources using the existing registry and root
/// resolution. Project-local process logs are outside session investigation.
/// Limits count all visited entries, not merely matched files. The approved
/// starting directory is resolved once (see `trust_anchors`); no link below it
/// is followed. Unix leaf files are not opened; Windows uses
/// attribute-only handles. No session or database contents are read. Root
/// establishment is separately limited to 256 components per candidate.
pub fn discover_sources_bounded(
    root: &Path,
    client: ClientId,
    max_entries: usize,
    registry: &[ClientDef],
) -> Result<Vec<Source>, BoundedDiscoveryError> {
    const MAX_DEPTH: usize = 32;
    if max_entries == 0 || max_entries > 16384 {
        return Err(BoundedDiscoveryError::InvalidLimit);
    }
    let anchors = trust_anchors(root);
    let mut remaining = max_entries;
    let mut sources = Vec::new();
    for def in registry.iter().filter(|def| def.id == client) {
        for source_def in def
            .sources
            .iter()
            .filter(|def| def.root != PathRoot::ProjectLocal)
        {
            if environment_opencode(root, *source_def, registry) {
                bounded_opencode_paths(
                    root,
                    client,
                    *source_def,
                    &mut remaining,
                    &mut sources,
                    registry,
                )?;
                continue;
            }
            for search in source_search_roots(root, *source_def, registry) {
                bounded_paths(
                    &search,
                    &anchors,
                    client,
                    *source_def,
                    &mut remaining,
                    MAX_DEPTH,
                    false,
                    &mut sources,
                )?;
            }
        }
    }
    sources.sort_by(|a, b| (&a.source_id, &a.path).cmp(&(&b.source_id, &b.path)));
    sources.dedup();
    Ok(sources)
}

#[allow(clippy::too_many_arguments)]
fn bounded_paths(
    path: &Path,
    anchors: &[PathBuf],
    client: ClientId,
    def: ClientSourceDef,
    remaining: &mut usize,
    depth: usize,
    opencode_channels: bool,
    sources: &mut Vec<Source>,
) -> Result<(), BoundedDiscoveryError> {
    let Some(node) = crate::anchored::Node::open(path, anchors)? else {
        return Ok(());
    };
    bounded_node(
        &node,
        path,
        client,
        def,
        remaining,
        depth,
        opencode_channels,
        sources,
    )
}

#[allow(clippy::too_many_arguments)]
fn bounded_node(
    node: &crate::anchored::Node,
    path: &Path,
    client: ClientId,
    def: ClientSourceDef,
    remaining: &mut usize,
    depth: usize,
    opencode_channels: bool,
    sources: &mut Vec<Source>,
) -> Result<(), BoundedDiscoveryError> {
    use crate::anchored::Kind;
    if *remaining == 0 {
        return Err(BoundedDiscoveryError::LimitExceeded);
    }
    *remaining -= 1;
    if node.kind == Kind::Link {
        if opencode_channels && path.file_name().is_some_and(|name| name == "opencode.db") {
            return Err(BoundedDiscoveryError::SymlinkRoot);
        }
        return Ok(());
    }
    if node.kind == Kind::File {
        let matched = if opencode_channels {
            path.file_name().is_some_and(|name| name != "opencode.db")
                && opencode_database_name(path)
        } else {
            match def.pattern {
                SourcePattern::Extension(ext) => path.extension().is_some_and(|v| v == ext),
                SourcePattern::ExactFile(name) => path.file_name().is_some_and(|v| v == name),
                SourcePattern::FileNameContains(needle) => path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .is_some_and(|v| v.contains(needle)),
            }
        };
        if matched {
            sources.push(new_source(client, def, path.to_path_buf()));
        }
    } else if node.kind == Kind::Directory {
        if depth == 0 {
            return Err(BoundedDiscoveryError::LimitExceeded);
        }
        // Enumeration and every child lookup remain relative to the opened
        // parent, even if its original pathname is replaced during the walk.
        for name in node.entries()? {
            let name = name?;
            if *remaining == 0 {
                return Err(BoundedDiscoveryError::LimitExceeded);
            }
            let child = node
                .child_for_walk(&name, def.recursive)?
                .ok_or(BoundedDiscoveryError::Traversal)?;
            if !def.recursive && child.kind == Kind::Directory {
                *remaining -= 1;
                continue;
            }
            bounded_node(
                &child,
                &path.join(name),
                client,
                def,
                remaining,
                depth - 1,
                opencode_channels,
                sources,
            )?;
        }
    }
    Ok(())
}

pub fn discover_sources_best_effort(root: &Path, registry: &[ClientDef]) -> Vec<Source> {
    discover_sources_with_projects_best_effort(root, &[], registry)
}

pub fn discover_sources_with_projects(
    root: &Path,
    projects: &[crate::projects::ProjectDef],
    registry: &[ClientDef],
) -> Result<Vec<Source>, DiscoveryError> {
    discover_sources_with_projects_impl(root, projects, DiscoveryMode::Checked, registry)
}

pub fn discover_sources_with_projects_best_effort(
    root: &Path,
    projects: &[crate::projects::ProjectDef],
    registry: &[ClientDef],
) -> Vec<Source> {
    discover_sources_with_projects_impl(root, projects, DiscoveryMode::BestEffort, registry)
        .unwrap_or_default()
}

fn discover_sources_with_projects_impl(
    root: &Path,
    projects: &[crate::projects::ProjectDef],
    mode: DiscoveryMode,
    registry: &[ClientDef],
) -> Result<Vec<Source>, DiscoveryError> {
    if mode.is_checked() {
        validate_root(root)?;
        for project in projects {
            validate_root(&project.path)?;
        }
    }

    let mut sources = Vec::new();
    let fixture_root = is_fixture_root(root, registry);

    for client in registry {
        for source_def in client.sources {
            if source_def.root != PathRoot::ProjectLocal || fixture_root {
                let context = DiscoveryContext {
                    root,
                    source_id: source_def.id,
                };
                match discover_source(root, client.id, *source_def, &context, mode, registry) {
                    Ok(found) => sources.extend(found),
                    Err(error) if mode.is_checked() => return Err(error),
                    Err(_) => {}
                }
            }
        }
    }

    for project in projects {
        for client in registry {
            for source_def in client.sources {
                if source_def.root == PathRoot::ProjectLocal {
                    let context = DiscoveryContext {
                        root: &project.path,
                        source_id: source_def.id,
                    };
                    match discover_source(
                        &project.path,
                        client.id,
                        *source_def,
                        &context,
                        mode,
                        registry,
                    ) {
                        Ok(found) => sources.extend(found),
                        Err(error) if mode.is_checked() => return Err(error),
                        Err(_) => {}
                    }
                }
            }
        }
    }

    sort_and_dedup_sources(&mut sources);
    Ok(sources)
}

fn sort_and_dedup_sources(sources: &mut Vec<Source>) {
    sources.sort_by(|left, right| {
        (
            left.client.as_str(),
            left.kind.as_str(),
            left.source_id.as_str(),
            left.path.to_string_lossy(),
            left.path.as_os_str().as_encoded_bytes(),
        )
            .cmp(&(
                right.client.as_str(),
                right.kind.as_str(),
                right.source_id.as_str(),
                right.path.to_string_lossy(),
                right.path.as_os_str().as_encoded_bytes(),
            ))
    });
    sources.dedup();
}

fn validate_root(root: &Path) -> Result<(), DiscoveryError> {
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        _ => Err(DiscoveryError::InvalidRoot {
            root: root.to_path_buf(),
        }),
    }
}

pub fn discover_watch_roots(root: &Path, registry: &[ClientDef]) -> Vec<PathBuf> {
    discover_watch_roots_for_clients(root, &[], registry)
}

pub fn discover_watch_roots_for_clients(
    root: &Path,
    clients: &[ClientId],
    registry: &[ClientDef],
) -> Vec<PathBuf> {
    discover_watch_roots_with_projects(root, clients, &[], registry)
}

pub fn discover_watch_roots_with_projects(
    root: &Path,
    clients: &[ClientId],
    projects: &[crate::projects::ProjectDef],
    registry: &[ClientDef],
) -> Vec<PathBuf> {
    let mut roots = registry
        .iter()
        .filter(|client| clients.is_empty() || clients.contains(&client.id))
        .flat_map(|client| client.sources.iter())
        .filter(|source_def| source_def.root != PathRoot::ProjectLocal)
        .flat_map(|source_def| source_watch_roots(root, *source_def, registry))
        .collect::<Vec<_>>();

    for project in projects {
        for client in registry {
            if !clients.is_empty() && !clients.contains(&client.id) {
                continue;
            }
            for source_def in client.sources {
                if source_def.root == PathRoot::ProjectLocal {
                    roots.extend(source_watch_roots(&project.path, *source_def, registry));
                }
            }
        }
    }

    roots.sort_unstable();
    roots.dedup();
    roots
}

fn source_watch_roots(
    root: &Path,
    source_def: ClientSourceDef,
    registry: &[ClientDef],
) -> Vec<PathBuf> {
    if source_def.root == PathRoot::ProjectLocal && !is_fixture_root(root, registry) {
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

    if environment_opencode(root, source_def, registry) {
        let mut directories = opencode_data_directories_for_source(root, source_def, registry);
        if let Ok(Some(path)) = opencode_database_override(root, registry)
            && let Some(parent) = path.parent()
        {
            directories.push(parent.to_path_buf());
        }
        let anchors = trust_anchors(root);
        return directories
            .into_iter()
            .filter(|directory| {
                let mut remaining = usize::MAX;
                inspect_opencode_path(directory, &anchors, &mut remaining, true) == Ok(true)
            })
            .collect();
    }
    source_search_roots(root, source_def, registry)
        .into_iter()
        .filter_map(|search_root| {
            if search_root.is_dir() {
                Some(search_root)
            } else if search_root.is_file()
                || matches!(source_def.pattern, SourcePattern::ExactFile(_))
            {
                search_root
                    .parent()
                    .filter(|parent| parent.is_dir())
                    .map(Path::to_path_buf)
            } else {
                None
            }
        })
        .collect()
}

fn discover_source(
    root: &Path,
    client: ClientId,
    source_def: ClientSourceDef,
    context: &DiscoveryContext<'_>,
    mode: DiscoveryMode,
    registry: &[ClientDef],
) -> Result<Vec<Source>, DiscoveryError> {
    if environment_opencode(root, source_def, registry) {
        let mut sources = Vec::new();
        let anchors = trust_anchors(root);
        for directory in opencode_data_directories_for_source(root, source_def, registry) {
            let mut remaining = usize::MAX;
            match inspect_opencode_path(&directory, &anchors, &mut remaining, true) {
                Ok(true) => {}
                Err(_) if mode.is_checked() => return Err(context.traversal_error()),
                _ => continue,
            }
            // Preserve the default's source coordinate without following a linked target.
            let default = directory.join("opencode.db");
            match fs::symlink_metadata(&default) {
                Ok(metadata) if metadata.is_file() => {
                    sources.push(new_source(client, source_def, default))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ if mode.is_checked() => return Err(context.traversal_error()),
                _ => {}
            }
            sources.extend(
                walk_files(&directory, false, context, mode)?
                    .into_iter()
                    .filter(|entry| entry.file_type().is_file())
                    .map(|entry| entry.into_path())
                    .filter(|path| {
                        path.file_name().is_some_and(|name| name != "opencode.db")
                            && opencode_database_name(path)
                    })
                    .map(|path| new_source(client, source_def, path)),
            );
        }
        match opencode_database_override(root, registry) {
            Ok(Some(path)) if path.is_file() => {
                add_opencode_override(&mut sources, client, source_def, path)
            }
            Err(_) if mode.is_checked() => return Err(context.traversal_error()),
            _ => {}
        }
        return Ok(sources);
    }
    // For project-local sources, recursively search for the subpath under the project root
    if source_def.root == PathRoot::ProjectLocal && !is_fixture_root(root, registry) {
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

    let mut sources = Vec::new();
    for search_root in source_search_roots(root, source_def, registry) {
        let paths = discover_matching_paths(
            &search_root,
            source_def.pattern,
            source_def.recursive,
            context,
            mode,
        )?;
        sources.extend(
            paths
                .into_iter()
                .map(|path| new_source(client, source_def, path)),
        );
    }
    Ok(sources)
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

/// Resolves a registry source definition using the same roots as source discovery.
pub fn source_search_root(
    root: &Path,
    source_def: ClientSourceDef,
    registry: &[ClientDef],
) -> PathBuf {
    if is_fixture_root(root, registry) {
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

pub fn is_fixture_root(root: &Path, registry: &[ClientDef]) -> bool {
    // OpenCode's fixture layout is also its real data-home layout. It cannot
    // identify synthetic data by itself; single-client fixtures can opt in with
    // an explicit marker. Other flattened fixture paths differ from host paths.
    root.join(".telltale-fixtures").is_file()
        || registry
            .iter()
            .flat_map(|client| client.sources.iter())
            .filter(|source_def| source_def.id != "opencode.sqlite")
            .any(|source_def| source_def.fixture_path(root).exists())
}

fn source_search_roots(
    root: &Path,
    source_def: ClientSourceDef,
    registry: &[ClientDef],
) -> Vec<PathBuf> {
    if source_def.id == "claude.projects"
        && root == Path::new(".")
        && !is_fixture_root(root, registry)
    {
        return claude_projects_search_roots(
            source_search_root(root, source_def, registry),
            env::var_os("CLAUDE_CONFIG_DIR"),
        );
    }
    if is_fixture_root(root, registry) || source_def.id != "opencode.sqlite" {
        return vec![source_search_root(root, source_def, registry)];
    }
    let platform = current_host_platform();
    let mut context = if root == Path::new(".") {
        environment_root_context(platform, root)
    } else {
        rooted_path_context(platform, root)
    };
    let xdg_data_home = if root == Path::new(".") {
        env::var_os("XDG_DATA_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    } else {
        None
    };
    if root == Path::new(".") && platform == HostPlatform::Linux {
        context.data_home = Some(
            xdg_data_home
                .clone()
                .unwrap_or_else(|| context.home.join(".local/share")),
        );
    }
    let mut roots = opencode_search_roots(&context, platform, source_def, xdg_data_home.as_deref());
    if root == Path::new(".") {
        roots.push(
            opencode_data_directory(&context.home, xdg_data_home.as_deref()).join("opencode.db"),
        );
    }
    // Also accept an explicit data-home root without classifying it as fixtures.
    if root != Path::new(".") {
        roots.push(root.join(source_def.relative_path));
    }
    roots.sort_unstable();
    roots.dedup();
    roots
}

fn environment_opencode(root: &Path, source_def: ClientSourceDef, registry: &[ClientDef]) -> bool {
    root == Path::new(".") && source_def.id == "opencode.sqlite" && !is_fixture_root(root, registry)
}

fn opencode_data_directory(home: &Path, xdg: Option<&Path>) -> PathBuf {
    xdg.filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(".local/share"))
        .join("opencode")
}

fn opencode_data_directories_for_source(
    root: &Path,
    def: ClientSourceDef,
    registry: &[ClientDef],
) -> Vec<PathBuf> {
    let mut directories = source_search_roots(root, def, registry)
        .into_iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect::<Vec<_>>();
    directories.sort_unstable();
    directories.dedup();
    directories
}

/// Fixed OpenCode directory candidates, excluding the arbitrary override's parent.
/// This namespace list does not enumerate directories or read source bytes. It
/// distinguishes channel directories from an arbitrary configured file's parent.
pub fn opencode_data_directories(root: &Path, registry: &[ClientDef]) -> Vec<PathBuf> {
    registry
        .iter()
        .filter(|client| client.id == ClientId::OpenCode)
        .flat_map(|client| client.sources)
        .flat_map(|def| opencode_data_directories_for_source(root, *def, registry))
        .collect()
}

fn opencode_database_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == "opencode.db"
        || name
            .strip_prefix("opencode-")
            .and_then(|name| name.strip_suffix(".db"))
            .is_some_and(|channel| {
                !channel.is_empty()
                    && channel
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            })
}

fn resolved_opencode_override(
    root: &Path,
    registry: &[ClientDef],
) -> Result<Option<PathBuf>, BoundedDiscoveryError> {
    if root != Path::new(".") || is_fixture_root(root, registry) {
        return Ok(None);
    }
    let Some(value) =
        env::var_os("OPENCODE_DB").filter(|value| !value.is_empty() && value != ":memory:")
    else {
        return Ok(None);
    };
    let context = environment_root_context(current_host_platform(), root);
    let xdg = env::var_os("XDG_DATA_HOME").map(PathBuf::from);
    let path = opencode_data_directory(&context.home, xdg.as_deref()).join(value);
    normalized_opencode_path(&path).map(Some)
}

fn normalized_opencode_path(path: &Path) -> Result<PathBuf, BoundedDiscoveryError> {
    let absolute = std::path::absolute(path).map_err(BoundedDiscoveryError::from_io)?;
    // Node path.resolve normalizes '..' lexically, without following links or expanding '~'.
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                resolved.pop();
            }
            component => resolved.push(component.as_os_str()),
        }
    }
    Ok(resolved)
}

fn add_opencode_override(
    sources: &mut Vec<Source>,
    client: ClientId,
    def: ClientSourceDef,
    path: PathBuf,
) {
    // Retain the old default/channel coordinate when the override is its lexical alias.
    if !sources
        .iter()
        .any(|source| normalized_opencode_path(&source.path).is_ok_and(|existing| existing == path))
    {
        sources.push(new_source(client, def, path));
    }
}

fn inspect_opencode_path(
    path: &Path,
    anchors: &[PathBuf],
    remaining: &mut usize,
    directory: bool,
) -> Result<bool, BoundedDiscoveryError> {
    for component in path.components() {
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        if *remaining == 0 {
            return Err(BoundedDiscoveryError::LimitExceeded);
        }
        *remaining -= 1;
    }
    let Some(node) = crate::anchored::Node::open(path, anchors)? else {
        return Ok(false);
    };
    if (directory && node.kind == crate::anchored::Kind::Directory)
        || (!directory && node.kind == crate::anchored::Kind::File)
    {
        Ok(true)
    } else {
        Err(BoundedDiscoveryError::Traversal)
    }
}

/// The exact environment-configured OpenCode file, including a not-yet-created file.
/// Explicit/fixture roots ignore it. No directory contents or source bytes are read;
/// existing components must not be symlinks and the target must not be a directory.
/// The override has no trust anchor of its own: only an alias of the home
/// directory that contains it is resolved. Watch uses this same coordinate to
/// distinguish arbitrary names from their sidecars.
pub fn opencode_database_override(
    root: &Path,
    registry: &[ClientDef],
) -> Result<Option<PathBuf>, BoundedDiscoveryError> {
    let path = resolved_opencode_override(root, registry)?;
    if let Some(path) = &path {
        let mut remaining = usize::MAX;
        inspect_opencode_path(path, &trust_anchors(root), &mut remaining, false)?;
    }
    Ok(path)
}

/// Check an SQLite store and its journal sidecars (`-wal`, `-shm`,
/// `-journal`) under the trust anchors bounded discovery of `root` uses: the
/// store must be a regular file and each present sidecar too, every one
/// reached without following a link (a link is `SymlinkRoot`, another kind of
/// node `Traversal`). `false` when the store is absent. SQLite opens these
/// files by name afterwards, so a replacement made between this check and
/// that open is not refused.
#[doc(hidden)]
pub fn check_sqlite_store(root: &Path, path: &Path) -> Result<bool, BoundedDiscoveryError> {
    let anchors = trust_anchors(root);
    let mut remaining = usize::MAX;
    if !inspect_opencode_path(path, &anchors, &mut remaining, false)? {
        return Ok(false);
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        let mut remaining = usize::MAX;
        inspect_opencode_path(Path::new(&sidecar), &anchors, &mut remaining, false)?;
    }
    Ok(true)
}

/// Caller-approved starting directory for no-follow traversal: an explicit
/// root, or in environment mode the home directory. It is resolved to its real
/// location once, so administrator aliases at or above it (a linked `/home`,
/// macOS `/var`, a linked profile) are accepted; nothing below it is followed.
/// Relocation variables (`CODEX_HOME`, `XDG_DATA_HOME`, ...) are not anchors: a
/// link at or above a relocated store stays refused, inside home or outside it.
fn trust_anchors(root: &Path) -> Vec<PathBuf> {
    if root != Path::new(".") {
        return vec![root.to_path_buf()];
    }
    ["HOME", "USERPROFILE"]
        .into_iter()
        .filter_map(|name| env::var_os(name).filter(|value| !value.is_empty()))
        .map(PathBuf::from)
        .take(1)
        .collect()
}

/// Open a source coordinate for reading under the trust anchors that bounded
/// discovery of `root` uses: the anchor is resolved once (aliases at or above
/// it are accepted), and no link below it (or anywhere, for a path under no
/// anchor) is followed, including the file itself. The open walks directory handles, so replacing an ancestor
/// pathname with a link while it runs cannot redirect it. `path` keeps the
/// caller's spelling and may be any coordinate, discovered or caller-supplied.
/// Returns `None` when a component is absent. The caller checks that the
/// opened object is a regular file; a FIFO opens without blocking.
pub fn open_source_file(
    root: &Path,
    path: &Path,
) -> Result<Option<fs::File>, BoundedDiscoveryError> {
    crate::anchored::open_file(path, &trust_anchors(root))
}

/// Open an already-resolved file (a canonical path, as from
/// `std::fs::canonicalize`) for reading. The path is walked strictly from the
/// filesystem root through directory handles, so a link or replacement made
/// after the path was resolved is refused rather than followed, even while the
/// open runs. The leaf opens without blocking; the caller checks that it is a
/// regular file. `None` when a component is absent.
pub fn open_resolved_file(path: &Path) -> Result<Option<fs::File>, BoundedDiscoveryError> {
    crate::anchored::open_file(path, &[])
}

fn bounded_opencode_paths(
    root: &Path,
    client: ClientId,
    def: ClientSourceDef,
    remaining: &mut usize,
    sources: &mut Vec<Source>,
    registry: &[ClientDef],
) -> Result<(), BoundedDiscoveryError> {
    let anchors = trust_anchors(root);
    for directory in opencode_data_directories_for_source(root, def, registry) {
        let Some(node) = crate::anchored::Node::open(&directory, &anchors)? else {
            continue;
        };
        if node.kind != crate::anchored::Kind::Directory {
            return Err(BoundedDiscoveryError::Traversal);
        }
        // Preserve the default's exact spelling, including native Windows case aliases.
        let default = directory.join("opencode.db");
        if let Some(default_node) = node.child(std::ffi::OsStr::new("opencode.db"))? {
            if default_node.kind == crate::anchored::Kind::Link {
                return Err(BoundedDiscoveryError::SymlinkRoot);
            }
            if default_node.kind != crate::anchored::Kind::File {
                return Err(BoundedDiscoveryError::Traversal);
            }
            bounded_node(
                &default_node,
                &default,
                client,
                def,
                remaining,
                0,
                false,
                sources,
            )?;
        }
        bounded_node(&node, &directory, client, def, remaining, 1, true, sources)?;
    }
    if let Some(path) = resolved_opencode_override(root, registry)?
        && let Some(node) = crate::anchored::Node::open(&path, &anchors)?
    {
        if node.kind != crate::anchored::Kind::File {
            return Err(BoundedDiscoveryError::Traversal);
        }
        if *remaining == 0 {
            return Err(BoundedDiscoveryError::LimitExceeded);
        }
        *remaining -= 1;
        add_opencode_override(sources, client, def, path);
    }
    Ok(())
}

/// Claude Code keeps `projects/` under `CLAUDE_CONFIG_DIR` when that is set.
/// The default `~/.claude/projects` stays a root as well: a scanner service
/// may not share the user's environment, and sessions written before the
/// relocation remain there. Only environment-resolved discovery reads the
/// variable; an explicit root is a home directory with the default layout.
/// A relocation that names the default directory yields one root.
fn claude_projects_search_roots(
    default: PathBuf,
    config_dir: Option<std::ffi::OsString>,
) -> Vec<PathBuf> {
    let mut roots = vec![default];
    if let Some(config_dir) = config_dir.filter(|value| !value.is_empty()) {
        let relocated = PathBuf::from(config_dir).join("projects");
        let same = |left: &Path, right: &Path| {
            left == right
                || matches!(
                    (fs::canonicalize(left), fs::canonicalize(right)),
                    (Ok(left), Ok(right)) if left == right
                )
        };
        if !same(&roots[0], &relocated) {
            roots.push(relocated);
        }
    }
    roots
}

fn opencode_search_roots(
    context: &RootResolutionContext,
    platform: HostPlatform,
    source_def: ClientSourceDef,
    xdg_data_home: Option<&Path>,
) -> Vec<PathBuf> {
    let mut roots = vec![
        resolve_path_root_from_context(context, source_def.root).join(source_def.relative_path),
    ];
    if platform == HostPlatform::Windows {
        if let Some(data_home) = xdg_data_home {
            roots.push(data_home.join(source_def.relative_path));
        }
        roots.push(
            context
                .home
                .join(".local/share")
                .join(source_def.relative_path),
        );
    }
    roots.sort_unstable();
    roots.dedup();
    roots
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
        data_home: env_data_home(platform, &home),
    }
}

fn rooted_path_context(platform: HostPlatform, root: &Path) -> RootResolutionContext {
    let home = root.to_path_buf();
    RootResolutionContext {
        home: home.clone(),
        codex_home: Some(home.join(".codex")),
        data_home: Some(default_data_home(platform, &home)),
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
mod tests;
