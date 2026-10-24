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
    fn from_io(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Traversal,
        }
    }
}

/// Discover one client's home/data sources using the existing registry and root
/// resolution. Project-local process logs are outside session investigation.
/// Limits count all visited entries, not merely matched files. Symlink roots and
/// descendants are not followed. No session files or databases are opened.
pub fn discover_sources_bounded(
    root: &Path,
    client: ClientId,
    max_entries: usize,
) -> Result<Vec<Source>, BoundedDiscoveryError> {
    const MAX_DEPTH: usize = 32;
    if max_entries == 0 || max_entries > 16384 {
        return Err(BoundedDiscoveryError::InvalidLimit);
    }
    let mut remaining = max_entries;
    let mut sources = Vec::new();
    for def in supported_clients().iter().filter(|def| def.id == client) {
        for source_def in def
            .sources
            .iter()
            .filter(|def| def.root != PathRoot::ProjectLocal)
        {
            if environment_opencode(root, *source_def) {
                bounded_opencode_paths(root, client, *source_def, &mut remaining, &mut sources)?;
                continue;
            }
            for search in source_search_roots(root, *source_def) {
                match fs::symlink_metadata(&search) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(BoundedDiscoveryError::from_io(error)),
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(BoundedDiscoveryError::SymlinkRoot);
                    }
                    _ => {}
                }
                bounded_paths(
                    &search,
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

fn bounded_paths(
    path: &Path,
    client: ClientId,
    def: ClientSourceDef,
    remaining: &mut usize,
    depth: usize,
    opencode_channels: bool,
    sources: &mut Vec<Source>,
) -> Result<(), BoundedDiscoveryError> {
    if *remaining == 0 {
        return Err(BoundedDiscoveryError::LimitExceeded);
    }
    *remaining -= 1;
    let metadata = fs::symlink_metadata(path).map_err(BoundedDiscoveryError::from_io)?;
    if metadata.file_type().is_symlink() {
        if opencode_channels && path.file_name().is_some_and(|name| name == "opencode.db") {
            return Err(BoundedDiscoveryError::SymlinkRoot);
        }
        return Ok(());
    }
    if metadata.is_file() {
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
    } else if metadata.is_dir() {
        if depth == 0 {
            return Err(BoundedDiscoveryError::LimitExceeded);
        }
        // Do not let a walker collect a directory before the budget sees its
        // entries. ReadDir streams one entry at a time; recursion holds at most
        // MAX_DEPTH directory handles and a bounded path stack.
        for entry in fs::read_dir(path).map_err(BoundedDiscoveryError::from_io)? {
            let entry = entry.map_err(BoundedDiscoveryError::from_io)?;
            if !def.recursive
                && entry
                    .file_type()
                    .map_err(BoundedDiscoveryError::from_io)?
                    .is_dir()
            {
                if *remaining == 0 {
                    return Err(BoundedDiscoveryError::LimitExceeded);
                }
                *remaining -= 1;
                continue;
            }
            bounded_paths(
                &entry.path(),
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

    if environment_opencode(root, source_def) {
        let mut directories = opencode_data_directories_for_source(root, source_def);
        if let Ok(Some(path)) = opencode_database_override(root)
            && let Some(parent) = path.parent()
        {
            directories.push(parent.to_path_buf());
        }
        return directories
            .into_iter()
            .filter(|directory| {
                let mut remaining = usize::MAX;
                inspect_opencode_path(directory, &mut remaining, true) == Ok(true)
            })
            .collect();
    }
    source_search_roots(root, source_def)
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
) -> Result<Vec<Source>, DiscoveryError> {
    if environment_opencode(root, source_def) {
        let mut sources = Vec::new();
        for directory in opencode_data_directories_for_source(root, source_def) {
            let mut remaining = usize::MAX;
            match inspect_opencode_path(&directory, &mut remaining, true) {
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
        match opencode_database_override(root) {
            Ok(Some(path)) if path.is_file() => {
                add_opencode_override(&mut sources, client, source_def, path)
            }
            Err(_) if mode.is_checked() => return Err(context.traversal_error()),
            _ => {}
        }
        return Ok(sources);
    }
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

    let mut sources = Vec::new();
    for search_root in source_search_roots(root, source_def) {
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
pub fn source_search_root(root: &Path, source_def: ClientSourceDef) -> PathBuf {
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
    // OpenCode's fixture layout is also its real data-home layout. It cannot
    // identify synthetic data by itself; single-client fixtures can opt in with
    // an explicit marker. Other flattened fixture paths differ from host paths.
    root.join(".telltale-fixtures").is_file()
        || supported_clients()
            .iter()
            .flat_map(|client| client.sources.iter())
            .filter(|source_def| source_def.id != "opencode.sqlite")
            .any(|source_def| source_def.fixture_path(root).exists())
}

fn source_search_roots(root: &Path, source_def: ClientSourceDef) -> Vec<PathBuf> {
    if source_def.id == "claude.projects" && root == Path::new(".") && !is_fixture_root(root) {
        return claude_projects_search_roots(
            source_search_root(root, source_def),
            env::var_os("CLAUDE_CONFIG_DIR"),
        );
    }
    if is_fixture_root(root) || source_def.id != "opencode.sqlite" {
        return vec![source_search_root(root, source_def)];
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

fn environment_opencode(root: &Path, source_def: ClientSourceDef) -> bool {
    root == Path::new(".") && source_def.id == "opencode.sqlite" && !is_fixture_root(root)
}

fn opencode_data_directory(home: &Path, xdg: Option<&Path>) -> PathBuf {
    xdg.filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(".local/share"))
        .join("opencode")
}

fn opencode_data_directories_for_source(root: &Path, def: ClientSourceDef) -> Vec<PathBuf> {
    let mut directories = source_search_roots(root, def)
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
pub fn opencode_data_directories(root: &Path) -> Vec<PathBuf> {
    supported_clients()
        .iter()
        .filter(|client| client.id == ClientId::OpenCode)
        .flat_map(|client| client.sources)
        .flat_map(|def| opencode_data_directories_for_source(root, *def))
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

fn resolved_opencode_override(root: &Path) -> Result<Option<PathBuf>, BoundedDiscoveryError> {
    if root != Path::new(".") || is_fixture_root(root) {
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
    remaining: &mut usize,
    directory: bool,
) -> Result<bool, BoundedDiscoveryError> {
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        if matches!(component, std::path::Component::Prefix(_)) {
            ancestor.push(component.as_os_str());
            continue;
        }
        if *remaining == 0 {
            return Err(BoundedDiscoveryError::LimitExceeded);
        }
        *remaining -= 1;
        ancestor.push(component.as_os_str());
        match fs::symlink_metadata(&ancestor) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(BoundedDiscoveryError::from_io(error)),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(BoundedDiscoveryError::SymlinkRoot);
            }
            Ok(metadata) if ancestor == path => {
                return if (directory && metadata.is_dir()) || (!directory && metadata.is_file()) {
                    Ok(true)
                } else {
                    Err(BoundedDiscoveryError::Traversal)
                };
            }
            Ok(metadata) if !metadata.is_dir() => return Err(BoundedDiscoveryError::Traversal),
            _ => {}
        }
    }
    Ok(false)
}

/// The exact environment-configured OpenCode file, including a not-yet-created file.
/// Explicit/fixture roots ignore it. No directory contents or source bytes are read;
/// existing components must not be symlinks and the target must not be a directory.
/// Watch uses this same coordinate to distinguish arbitrary names from their sidecars.
pub fn opencode_database_override(root: &Path) -> Result<Option<PathBuf>, BoundedDiscoveryError> {
    let path = resolved_opencode_override(root)?;
    if let Some(path) = &path {
        let mut remaining = usize::MAX;
        inspect_opencode_path(path, &mut remaining, false)?;
    }
    Ok(path)
}

fn bounded_opencode_paths(
    root: &Path,
    client: ClientId,
    def: ClientSourceDef,
    remaining: &mut usize,
    sources: &mut Vec<Source>,
) -> Result<(), BoundedDiscoveryError> {
    for directory in opencode_data_directories_for_source(root, def) {
        if !inspect_opencode_path(&directory, remaining, true)? {
            continue;
        }
        // Preserve the default's exact spelling, including native Windows case aliases.
        let default = directory.join("opencode.db");
        let default_present = match fs::symlink_metadata(&default) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(BoundedDiscoveryError::from_io(error)),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(BoundedDiscoveryError::SymlinkRoot);
            }
            Ok(metadata) if !metadata.is_file() => return Err(BoundedDiscoveryError::Traversal),
            _ => true,
        };
        if default_present {
            bounded_paths(&default, client, def, remaining, 0, false, sources)?;
        }
        bounded_paths(&directory, client, def, remaining, 1, true, sources)?;
    }
    if let Some(path) = resolved_opencode_override(root)?
        && inspect_opencode_path(&path, remaining, false)?
    {
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
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    use telltale_schema::clients::{ClientId, SourceKind};
    use tempfile::tempdir;

    use crate::clients::{ClientSourceDef, PathRoot};

    use super::{
        DiscoveryError, DiscoveryMode, HostPlatform, RootResolutionContext, collect_walk_entries,
        current_host_platform, default_data_home, discover_source_from_context, discover_sources,
        discover_sources_best_effort, discover_sources_with_projects, discover_watch_roots,
        discover_watch_roots_for_clients, discover_watch_roots_with_projects,
        resolve_path_root_from_context, source_search_root_from_context,
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
    fn bounded_discovery_classifies_only_observed_permission() {
        for (kind, expected) in [
            (
                std::io::ErrorKind::PermissionDenied,
                super::BoundedDiscoveryError::PermissionDenied,
            ),
            (
                std::io::ErrorKind::NotFound,
                super::BoundedDiscoveryError::Traversal,
            ),
            (
                std::io::ErrorKind::WouldBlock,
                super::BoundedDiscoveryError::Traversal,
            ),
        ] {
            let error = super::BoundedDiscoveryError::from_io(std::io::Error::new(
                kind,
                "/synthetic/private/DIAGNOSTIC_CANARY",
            ));
            assert_eq!(error, expected);
            assert!(!format!("{error:?}").contains("CANARY"));
        }
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
        assert!(keys.contains(&(
            ClientId::OpenClaw,
            SourceKind::Jsonl,
            Some("session-a.jsonl.deleted")
        )));
        assert!(keys.contains(&(ClientId::Qwen, SourceKind::Jsonl, Some("session-a.jsonl"))));
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
    fn repeated_and_overlapping_projects_return_exact_sources_once() {
        let temp = tempdir().expect("tempdir");
        let home = temp.path().join("home");
        let workspace = temp.path().join("workspace");
        let project = workspace.join("repo");
        fs::create_dir_all(&home).expect("home");
        fs::create_dir_all(project.join("logs/copilot")).expect("logs");
        let path = project.join("logs/copilot/process.log");
        fs::write(&path, b"synthetic log\n").expect("log");
        let projects =
            [workspace, project.clone(), project].map(|path| crate::projects::ProjectDef {
                name: "synthetic".to_string(),
                path,
            });
        let expected = vec![telltale_schema::source::Source {
            client: ClientId::Copilot,
            kind: SourceKind::CopilotProcessLog,
            source_id: "copilot.process_log".to_string(),
            path,
        }];
        assert_eq!(
            discover_sources_with_projects(&home, &projects).expect("checked"),
            expected
        );
        assert_eq!(
            super::discover_sources_with_projects_best_effort(&home, &projects),
            expected
        );
        let roots = discover_watch_roots_with_projects(&home, &[ClientId::Copilot], &projects);
        assert_eq!(
            roots,
            vec![expected[0].path.parent().expect("parent").to_path_buf()]
        );
    }

    #[test]
    fn overlapping_fixture_and_project_discovery_preserves_source_ownership() {
        let root = crate::test_fixture_path("session_stores");
        let expected = discover_sources(&root).expect("fixture sources");
        let projects = [crate::projects::ProjectDef {
            name: "fixture".to_string(),
            path: root.clone(),
        }];
        assert_eq!(
            discover_sources_with_projects(&root, &projects).expect("overlap"),
            expected
        );
        assert_eq!(
            super::discover_sources_with_projects_best_effort(&root, &projects),
            expected
        );
        for id in [
            "codex.sessions",
            "codex.archived_sessions",
            "codex.headless_sessions",
        ] {
            assert!(
                expected
                    .iter()
                    .any(|source| source.client == ClientId::Codex && source.source_id == id)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn exact_dedup_preserves_paths_with_identical_lossy_display() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        // APFS rejects these filenames; exact path identity needs no filesystem.
        let paths = [0xfe, 0xff].map(|byte| {
            let mut name = b"process-".to_vec();
            name.push(byte);
            name.extend_from_slice(b".log");
            std::path::PathBuf::from(OsString::from_vec(name))
        });
        assert_ne!(paths[0], paths[1]);
        assert_eq!(paths[0].to_string_lossy(), paths[1].to_string_lossy());
        let expected = paths.map(|path| telltale_schema::source::Source {
            client: ClientId::Copilot,
            kind: SourceKind::CopilotProcessLog,
            source_id: "copilot.process_log".to_string(),
            path,
        });
        let mut sources = vec![
            expected[1].clone(),
            expected[0].clone(),
            expected[1].clone(),
            expected[0].clone(),
        ];
        super::sort_and_dedup_sources(&mut sources);
        assert_eq!(sources, expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn discovery_preserves_paths_with_identical_lossy_display() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let temp = tempdir().expect("tempdir");
        let logs = temp.path().join("logs/copilot");
        fs::create_dir_all(&logs).expect("logs");
        for byte in [0xfe, 0xff] {
            let mut name = b"process-".to_vec();
            name.push(byte);
            name.extend_from_slice(b".log");
            fs::write(logs.join(OsString::from_vec(name)), b"synthetic log\n").expect("log");
        }
        let project = crate::projects::ProjectDef {
            name: "synthetic".to_string(),
            path: temp.path().to_path_buf(),
        };
        let sources = discover_sources_with_projects(temp.path(), &[project.clone(), project])
            .expect("discovery");
        assert_eq!(sources.len(), 2);
        assert_ne!(sources[0].path, sources[1].path);
        assert_eq!(
            sources[0].path.to_string_lossy(),
            sources[1].path.to_string_lossy()
        );
        assert!(
            sources[0].path.as_os_str().as_encoded_bytes()
                < sources[1].path.as_os_str().as_encoded_bytes()
        );
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
        fs::create_dir_all(&data_home).expect("data home");
        fs::write(data_home.join("opencode.db"), b"sqlite fixture").expect("sqlite fixture");

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
    fn opencode_data_home_is_not_a_fixture_and_supports_bounded_discovery_and_watch() {
        let temp = tempdir().unwrap();
        let data_home = temp.path().join(".local/share");
        let db = data_home.join("opencode/opencode.db");
        fs::create_dir_all(db.parent().unwrap()).unwrap();
        fs::write(&db, b"synthetic metadata only").unwrap();
        assert!(!super::is_fixture_root(&data_home));
        let sources = discover_sources(&data_home).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].path, db);
        assert_eq!(
            super::discover_sources_bounded(&data_home, ClientId::OpenCode, 1).unwrap(),
            sources
        );
        assert_eq!(
            discover_watch_roots_for_clients(&data_home, &[ClientId::OpenCode]),
            vec![db.parent().unwrap().to_path_buf()]
        );
        fs::write(data_home.join(".telltale-fixtures"), b"").unwrap();
        assert!(super::is_fixture_root(&data_home));
        assert_eq!(discover_sources(&data_home).unwrap(), sources);
        assert!(super::is_fixture_root(&crate::test_fixture_path(
            "session_stores"
        )));
    }

    #[test]
    fn windows_opencode_candidates_include_appdata_xdg_and_home_fallback() {
        let temp = tempdir().unwrap();
        let context = RootResolutionContext {
            home: temp.path().join("home"),
            codex_home: None,
            data_home: Some(temp.path().join("local-app-data")),
        };
        let xdg = temp.path().join("xdg-data");
        let source_def = lookup_source("opencode.sqlite").1;
        let roots =
            super::opencode_search_roots(&context, HostPlatform::Windows, source_def, Some(&xdg));
        assert_eq!(roots.len(), 3);
        for data_home in [
            context.data_home.clone().unwrap(),
            xdg,
            context.home.join(".local/share"),
        ] {
            assert!(roots.contains(&data_home.join("opencode/opencode.db")));
        }
        let roots = super::opencode_search_roots(
            &context,
            HostPlatform::Windows,
            source_def,
            context.data_home.as_deref(),
        );
        assert_eq!(
            roots.len(),
            2,
            "duplicate candidates must not consume bounded discovery budget"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_opencode_home_discovery_keeps_both_stores_and_watch_roots() {
        let temp = tempdir().unwrap();
        let stores = ["AppData/Local/opencode", ".local/share/opencode"]
            .map(|subpath| temp.path().join(subpath));
        for store in &stores {
            fs::create_dir_all(store).unwrap();
            fs::write(store.join("opencode.db"), b"synthetic metadata only").unwrap();
        }
        let sources = discover_sources(temp.path()).unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(
            super::discover_sources_bounded(temp.path(), ClientId::OpenCode, 2).unwrap(),
            sources
        );
        assert_eq!(
            super::discover_sources_bounded(temp.path(), ClientId::OpenCode, 1),
            Err(super::BoundedDiscoveryError::LimitExceeded)
        );
        let mut expected = stores.to_vec();
        expected.sort_unstable();
        assert_eq!(
            discover_watch_roots_for_clients(temp.path(), &[ClientId::OpenCode]),
            expected
        );
    }

    #[test]
    fn filters_fixture_watch_roots_by_client() {
        let roots = discover_watch_roots_for_clients(
            &crate::test_fixture_path("session_stores"),
            &[ClientId::Claude],
        );
        let fixture_root = Path::new("tests").join("fixtures").join("session_stores");

        assert!(!roots.is_empty());
        assert!(
            roots
                .iter()
                .all(|path| path.ends_with(fixture_root.join("claude").join("projects")))
        );
    }

    #[test]
    fn resolves_linux_roots_from_context() {
        let context = RootResolutionContext {
            home: PathBuf::from("/home/tester"),
            codex_home: Some(PathBuf::from("/srv/codex")),
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
            data_home: Some(default_data_home(HostPlatform::MacOs, &home)),
        };

        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::CodexHome),
            PathBuf::from("/Users/tester/.codex")
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
            data_home: Some(default_data_home(HostPlatform::Windows, &home)),
        };

        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::CodexHome),
            PathBuf::from(r#"C:\Users\tester/.codex"#)
        );
        assert_eq!(
            resolve_path_root_from_context(&context, PathRoot::DataHome),
            PathBuf::from(r#"C:\Users\tester/AppData/Local"#)
        );
    }

    #[test]
    fn discovers_windows_codex_source_candidates() {
        let temp = tempdir().expect("tempdir");
        let home = temp.path().join("Users/tester");
        let codex_home = home.join(".codex");
        let context = RootResolutionContext {
            home: home.clone(),
            codex_home: None,
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

        let source_ids = [
            "codex.sessions",
            "codex.archived_sessions",
            "codex.headless_sessions",
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
    }

    #[test]
    fn resolves_confirmed_macos_source_candidates() {
        let home = PathBuf::from("/Users/tester");
        let context = RootResolutionContext {
            home: home.clone(),
            codex_home: None,
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
            source_search_root_from_context(&context, lookup("qwen.projects")),
            PathBuf::from("/Users/tester/.qwen/projects")
        );
        assert_eq!(
            source_search_root_from_context(&context, lookup("openclaw.agents")),
            PathBuf::from("/Users/tester/.openclaw/agents")
        );
        assert_eq!(
            source_search_root_from_context(&context, lookup("opencode.sqlite")),
            PathBuf::from("/Users/tester/Library/Application Support/opencode/opencode.db")
        );
    }

    #[test]
    fn claude_config_dir_adds_a_relocated_projects_root() {
        use super::claude_projects_search_roots;
        let temp = tempdir().unwrap();
        let default = temp.path().join("home/.claude/projects");
        let relocated = temp.path().join("relocated");

        assert_eq!(
            claude_projects_search_roots(default.clone(), None),
            vec![default.clone()]
        );
        assert_eq!(
            claude_projects_search_roots(default.clone(), Some("".into())),
            vec![default.clone()]
        );
        assert_eq!(
            claude_projects_search_roots(default.clone(), Some(relocated.clone().into())),
            vec![default.clone(), relocated.join("projects")]
        );
        // A relocation naming the default directory, spelled differently, is one root.
        fs::create_dir_all(&default).unwrap();
        let alias = temp.path().join("home/.claude/../.claude");
        assert_eq!(
            claude_projects_search_roots(default.clone(), Some(alias.into())),
            vec![default]
        );
    }

    #[test]
    fn explicit_root_ignores_claude_config_dir() {
        let (_, def) = lookup_source("claude.projects");
        let temp = tempdir().unwrap();
        // Environment-independent: an explicit root never consults the variable.
        assert_eq!(
            super::source_search_roots(temp.path(), def),
            vec![temp.path().join(".claude/projects")]
        );
    }

    #[test]
    fn opencode_channel_names_and_xdg_controls_are_exact() {
        for name in [
            "opencode.db",
            "opencode-stable.db",
            "opencode-Latest.db",
            "opencode-test_branch.1.db",
        ] {
            assert!(super::opencode_database_name(Path::new(name)), "{name}");
        }
        for name in [
            "Opencode.db",
            "Opencode-stable.db",
            "opencode-.db",
            "opencode-a b.db",
            "opencode-stable.db-wal",
            "opencode-stable.db-shm",
            "opencode-stable.db.bak",
            "unrelated.db",
        ] {
            assert!(!super::opencode_database_name(Path::new(name)), "{name}");
        }
        let home = Path::new("/synthetic/home");
        assert_eq!(
            super::opencode_data_directory(home, None),
            home.join(".local/share/opencode")
        );
        assert_eq!(
            super::opencode_data_directory(home, Some(Path::new(""))),
            home.join(".local/share/opencode")
        );
        assert_eq!(
            super::opencode_data_directory(home, Some(Path::new("/synthetic/xdg"))),
            Path::new("/synthetic/xdg/opencode")
        );
    }

    #[test]
    fn opencode_channel_budget_counts_unmatched_directory_entries() {
        let temp = tempdir().unwrap();
        for index in 0..20 {
            fs::write(
                temp.path().join(format!("unrelated-{index}")),
                b"synthetic metadata only",
            )
            .unwrap();
        }
        let mut remaining = 10;
        assert_eq!(
            super::bounded_paths(
                temp.path(),
                ClientId::OpenCode,
                lookup_source("opencode.sqlite").1,
                &mut remaining,
                1,
                true,
                &mut Vec::new()
            ),
            Err(super::BoundedDiscoveryError::LimitExceeded)
        );
        assert_eq!(remaining, 0);
    }

    #[test]
    fn opencode_bounded_environment_discovery_preserves_scope_and_failures() {
        const CHILD: &str = "TELLTALE_RELOCATION_DISCOVERY_CHILD";
        if let Some(mode) = std::env::var_os(CHILD) {
            let bounded =
                super::discover_sources_bounded(Path::new("."), ClientId::OpenCode, 16384);
            if mode == "symlink" || mode == "directory" {
                let expected = if mode == "symlink" {
                    super::BoundedDiscoveryError::SymlinkRoot
                } else {
                    super::BoundedDiscoveryError::Traversal
                };
                assert_eq!(bounded, Err(expected));
                assert_eq!(
                    super::opencode_database_override(Path::new(".")),
                    Err(expected)
                );
                assert!(discover_sources(Path::new(".")).is_err());
                assert_eq!(discover_sources_best_effort(Path::new(".")).len(), 2);
            } else {
                let checked = discover_sources(Path::new(".")).unwrap();
                assert_eq!(checked.len(), if mode == "duplicate" { 2 } else { 3 });
                assert_eq!(bounded.unwrap(), checked);
                assert_eq!(discover_sources_best_effort(Path::new(".")), checked);
                assert!(
                    checked
                        .iter()
                        .all(|source| source.client == ClientId::OpenCode
                            && source.source_id == "opencode.sqlite")
                );
                assert_eq!(
                    super::discover_sources_bounded(Path::new("."), ClientId::OpenCode, 1),
                    Err(super::BoundedDiscoveryError::LimitExceeded)
                );
                let override_path = super::opencode_database_override(Path::new("."))
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    super::inspect_opencode_path(&override_path, &mut 1, false),
                    Err(super::BoundedDiscoveryError::LimitExceeded)
                );
                assert!(
                    super::discover_sources_bounded(Path::new("."), ClientId::Qwen, 16384)
                        .unwrap()
                        .is_empty()
                );
            }
            return;
        }
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let home = root.join("home");
        let work = root.join("work");
        let data = home.join("data/opencode");
        let outside = root.join("PRIVATE-OVERRIDE");
        fs::create_dir_all(data.join("nested")).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&outside).unwrap();
        for name in [
            "opencode.db",
            "opencode-stable.db",
            "unrelated.db",
            "opencode-stable.db-wal",
            "nested/opencode-other.db",
        ] {
            fs::write(data.join(name), b"synthetic metadata only").unwrap();
        }
        let database = outside.join("custom.sqlite");
        fs::write(&database, b"synthetic metadata only").unwrap();
        fs::write(
            outside.join("opencode-neighbor.db"),
            b"synthetic metadata only",
        )
        .unwrap();
        let run = |mode: &str, path: &Path| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.env_clear().current_dir(&work)
                .env("HOME", &home).env("USERPROFILE", &home).env("XDG_DATA_HOME", home.join("data"))
                .env("OPENCODE_DB", path).env(CHILD, mode)
                .args(["--exact", "discovery::tests::opencode_bounded_environment_discovery_preserves_scope_and_failures", "--nocapture"]);
            if mode == "duplicate" {
                command.env("XDG_DATA_HOME", home.join("data/../data"));
            }
            for key in ["PATH", "SystemRoot", "windir"] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "{output:?}");
        };
        run("normal", &database);
        run(
            "normal",
            Path::new("../../../PRIVATE-OVERRIDE/custom.sqlite"),
        );
        run("duplicate", Path::new("opencode.db"));
        fs::create_dir_all(data.join("~")).unwrap();
        fs::write(data.join("~/custom.sqlite"), b"synthetic metadata only").unwrap();
        run("normal", Path::new("~/custom.sqlite"));
        #[cfg(windows)]
        {
            fs::rename(data.join("opencode.db"), data.join("Opencode.db")).unwrap();
            run("normal", &database);
        }
        run("directory", &outside);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&database, outside.join("leaf-link")).unwrap();
            run("symlink", &outside.join("leaf-link"));
            std::os::unix::fs::symlink(&outside, root.join("directory-link")).unwrap();
            run("symlink", &root.join("directory-link/custom.sqlite"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn opencode_explicit_root_retains_legacy_default_link_coordinates() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        let data = home.join("opencode");
        fs::create_dir_all(&data).unwrap();
        let target = temp.path().join("synthetic.sqlite");
        fs::write(&target, b"synthetic metadata only").unwrap();
        let path = data.join("opencode.db");
        std::os::unix::fs::symlink(target, &path).unwrap();
        let sources = discover_sources(&home).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].path, path);
        assert_eq!(discover_sources_best_effort(&home), sources);
        assert_eq!(
            discover_watch_roots_for_clients(&home, &[ClientId::OpenCode]),
            vec![data]
        );
        assert_eq!(
            super::discover_sources_bounded(&home, ClientId::OpenCode, 16384),
            Err(super::BoundedDiscoveryError::SymlinkRoot)
        );
    }

    #[cfg(unix)]
    #[test]
    fn opencode_environment_default_links_preserve_discovery_boundaries() {
        const CHILD: &str = "TELLTALE_OPENCODE_DEFAULT_LINK_CHILD";
        if let Some(mode) = std::env::var_os(CHILD) {
            let home = PathBuf::from(std::env::var_os("HOME").unwrap());
            let root = home.parent().unwrap();
            let data = home.join("data/opencode");
            let bounded =
                super::discover_sources_bounded(Path::new("."), ClientId::OpenCode, 16384);
            let checked = discover_sources(Path::new("."));
            assert_eq!(bounded, Err(super::BoundedDiscoveryError::SymlinkRoot));
            assert!(
                matches!(&checked, Err(DiscoveryError::Traversal { source_id, .. }) if source_id == "opencode.sqlite"),
                "bounded={bounded:?}; checked={checked:?}"
            );
            let mut expected = vec![root.join("allowed.sqlite")];
            let mut expected_roots = vec![root.to_path_buf()];
            if mode != "directory" && mode != "ancestor" && mode != "home" {
                expected.push(data.join("opencode-preview.db"));
                expected_roots.push(data);
            }
            expected.sort();
            expected_roots.sort();
            let sources = discover_sources_best_effort(Path::new("."));
            let mut actual = sources
                .iter()
                .map(|source| source.path.clone())
                .collect::<Vec<_>>();
            actual.sort();
            assert_eq!(actual, expected);
            assert_eq!(
                discover_watch_roots_for_clients(Path::new("."), &[ClientId::OpenCode]),
                expected_roots
            );
            return;
        }
        let mut failures = Vec::new();
        for mode in [
            "file",
            "dangling",
            "leaf-directory",
            "directory",
            "ancestor",
            "home",
        ] {
            let temp = tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let home = root.join("home");
            let work = root.join("work");
            let outside = root.join("PRIVATE-DEFAULT/opencode");
            if mode == "home" {
                let real_home = root.join("real-home");
                fs::create_dir_all(&real_home).unwrap();
                std::os::unix::fs::symlink(real_home, &home).unwrap();
            } else {
                fs::create_dir_all(&home).unwrap();
            }
            fs::create_dir_all(&work).unwrap();
            fs::create_dir_all(&outside).unwrap();
            fs::write(root.join("allowed.sqlite"), b"synthetic metadata only").unwrap();
            fs::write(outside.join("opencode.db"), b"synthetic metadata only").unwrap();
            let data = home.join("data/opencode");
            match mode {
                "ancestor" => {
                    std::os::unix::fs::symlink(outside.parent().unwrap(), home.join("data"))
                        .unwrap()
                }
                "directory" => {
                    fs::create_dir_all(home.join("data")).unwrap();
                    std::os::unix::fs::symlink(&outside, &data).unwrap();
                }
                _ => {
                    fs::create_dir_all(&data).unwrap();
                    fs::write(data.join("opencode-preview.db"), b"synthetic metadata only")
                        .unwrap();
                    let target = match mode {
                        "dangling" => outside.join("missing.sqlite"),
                        "leaf-directory" => outside.clone(),
                        _ => outside.join("opencode.db"),
                    };
                    std::os::unix::fs::symlink(target, data.join("opencode.db")).unwrap();
                }
            }
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.env_clear().current_dir(&work)
                .env("HOME", &home).env("USERPROFILE", &home)
                .env("XDG_DATA_HOME", home.join("data"))
                .env("OPENCODE_DB", root.join("allowed.sqlite")).env(CHILD, mode)
                .args(["--exact", "discovery::tests::opencode_environment_default_links_preserve_discovery_boundaries", "--nocapture"]);
            for key in ["PATH", "SystemRoot", "windir"] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
            let output = command.output().unwrap();
            if !output.status.success() {
                failures.push(format!("{mode}: {output:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
