use std::env;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::clients::{
    ClientId, ClientSourceDef, PathRoot, SourceKind, SourcePattern, supported_clients,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Source {
    pub client: ClientId,
    pub kind: SourceKind,
    pub source_id: String,
    pub path: PathBuf,
}

impl Source {
    fn new(client: ClientId, source_def: ClientSourceDef, path: PathBuf) -> Self {
        Self {
            client,
            kind: source_def.kind,
            source_id: source_def.id.to_string(),
            path,
        }
    }
}

pub fn discover_sources(root: &Path) -> Vec<Source> {
    let mut sources = Vec::new();

    for client in supported_clients() {
        for source_def in client.sources {
            sources.extend(discover_source(root, client.id, *source_def));
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
    sources
}

pub fn discover_watch_roots(root: &Path) -> Vec<PathBuf> {
    let mut roots = supported_clients()
        .iter()
        .flat_map(|client| client.sources.iter())
        .filter_map(|source_def| source_watch_root(root, *source_def))
        .collect::<Vec<_>>();
    roots.sort_unstable();
    roots.dedup();
    roots
}

fn source_watch_root(root: &Path, source_def: ClientSourceDef) -> Option<PathBuf> {
    let search_root = source_search_root(root, source_def);
    if search_root.is_dir() {
        return Some(search_root);
    }
    if search_root.is_file() || matches!(source_def.pattern, SourcePattern::ExactFile(_)) {
        return search_root
            .parent()
            .filter(|parent| parent.is_dir())
            .map(Path::to_path_buf);
    }
    None
}

fn discover_source(root: &Path, client: ClientId, source_def: ClientSourceDef) -> Vec<Source> {
    let search_root = source_search_root(root, source_def);

    discover_matching_paths(&search_root, source_def.pattern, source_def.recursive)
        .into_iter()
        .map(|path| Source::new(client, source_def, path))
        .collect()
}

fn source_search_root(root: &Path, source_def: ClientSourceDef) -> PathBuf {
    if is_fixture_root(root) {
        return source_def.fixture_path(root);
    }

    resolve_path_root(root, source_def.root).join(source_def.relative_path)
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

    discover_matching_paths(&search_root, source_def.pattern, source_def.recursive)
        .into_iter()
        .map(|path| Source::new(client, source_def, path))
        .collect()
}

fn discover_matching_paths(root: &Path, pattern: SourcePattern, recursive: bool) -> Vec<PathBuf> {
    match pattern {
        SourcePattern::Extension(extension) => files_with_extension(root, extension, recursive),
        SourcePattern::ExactFile(file_name) => files_named(root, file_name, recursive),
        SourcePattern::FileNameContains(needle) => {
            files_with_name_containing(root, needle, recursive)
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

fn files_with_extension(root: &Path, extension: &str, recursive: bool) -> Vec<PathBuf> {
    if !root.is_dir() {
        return Vec::new();
    }

    let walker = if recursive {
        WalkDir::new(root)
    } else {
        WalkDir::new(root).max_depth(1)
    };

    let mut paths: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| path.extension().is_some_and(|value| value == extension))
        .collect();
    paths.sort_unstable();
    paths
}

fn files_named(root: &Path, file_name: &str, recursive: bool) -> Vec<PathBuf> {
    if root.is_file() {
        return root
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| *name == file_name)
            .map(|_| vec![root.to_path_buf()])
            .unwrap_or_default();
    }
    if !root.is_dir() {
        return Vec::new();
    }

    let walker = if recursive {
        WalkDir::new(root)
    } else {
        WalkDir::new(root).max_depth(1)
    };

    let mut paths: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some(file_name))
        .collect();
    paths.sort_unstable();
    paths
}

fn files_with_name_containing(root: &Path, needle: &str, recursive: bool) -> Vec<PathBuf> {
    if !root.is_dir() {
        return Vec::new();
    }

    let walker = if recursive {
        WalkDir::new(root)
    } else {
        WalkDir::new(root).max_depth(1)
    };

    let mut paths: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains(needle))
        })
        .collect();
    paths.sort_unstable();
    paths
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    use crate::clients::{ClientId, ClientSourceDef, PathRoot, SourceKind};
    use tempfile::tempdir;

    use super::{
        HostPlatform, RootResolutionContext, current_host_platform, default_config_home,
        default_data_home, discover_source_from_context, discover_sources, discover_watch_roots,
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
    fn discovers_codex_and_opencode_fixture_sources() {
        let sources = discover_sources(std::path::Path::new("tests/fixtures/session_stores"));

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

        let sources = discover_sources(home);
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
        let roots = discover_watch_roots(std::path::Path::new("tests/fixtures/session_stores"));
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
