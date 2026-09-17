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

pub fn supported_clients() -> &'static [ClientDef] {
    crate::sources::registry::builtin_client_defs()
}

#[cfg(test)]
mod tests {
    use super::{ClientId, SourceKind, supported_clients};

    fn resolved_path(root: &std::path::Path, relative_path: &str) -> std::path::PathBuf {
        root.join(relative_path)
    }

    #[test]
    fn registry_covers_first_supported_sources() {
        let mut source_keys = supported_clients()
            .iter()
            .flat_map(|client| {
                client
                    .sources
                    .iter()
                    .map(move |source| (client.id, source.kind, source.fixture_relative_path))
            })
            .collect::<Vec<_>>();
        source_keys.sort_unstable();

        assert!(source_keys.contains(&(ClientId::Codex, SourceKind::Jsonl, "codex/sessions")));
        assert!(source_keys.contains(&(ClientId::Claude, SourceKind::Jsonl, "claude/projects")));
        assert!(source_keys.contains(&(ClientId::OpenClaw, SourceKind::Jsonl, "openclaw/agents")));
        assert!(source_keys.contains(&(ClientId::Qwen, SourceKind::Jsonl, "qwen/projects")));
        assert!(source_keys.contains(&(
            ClientId::Codex,
            SourceKind::ArchivedJsonl,
            "codex/archived_sessions"
        )));
        assert!(source_keys.contains(&(
            ClientId::Codex,
            SourceKind::HeadlessJsonl,
            "codex/headless"
        )));
        assert!(source_keys.contains(&(
            ClientId::OpenCode,
            SourceKind::Sqlite,
            "opencode/opencode.db"
        )));
    }

    #[test]
    fn source_definitions_map_to_expected_relative_paths() {
        let codex = supported_clients()
            .iter()
            .find(|client| client.id == ClientId::Codex)
            .expect("codex client");
        let claude = supported_clients()
            .iter()
            .find(|client| client.id == ClientId::Claude)
            .expect("claude client");
        let opencode = supported_clients()
            .iter()
            .find(|client| client.id == ClientId::OpenCode)
            .expect("opencode client");
        let openclaw = supported_clients()
            .iter()
            .find(|client| client.id == ClientId::OpenClaw)
            .expect("openclaw client");
        let qwen = supported_clients()
            .iter()
            .find(|client| client.id == ClientId::Qwen)
            .expect("qwen client");

        let codex_home = std::path::Path::new("/tmp/.codex");
        assert_eq!(
            resolved_path(codex_home, codex.sources[0].relative_path),
            codex_home.join("sessions")
        );
        assert_eq!(
            resolved_path(codex_home, codex.sources[1].relative_path),
            codex_home.join("archived_sessions")
        );
        assert_eq!(
            resolved_path(codex_home, codex.sources[2].relative_path),
            codex_home.join("headless")
        );

        let home = std::path::Path::new("/tmp/home");
        assert_eq!(
            resolved_path(home, claude.sources[0].relative_path),
            home.join(".claude/projects")
        );
        assert_eq!(
            resolved_path(home, openclaw.sources[0].relative_path),
            home.join(".openclaw/agents")
        );
        assert_eq!(
            resolved_path(home, qwen.sources[0].relative_path),
            home.join(".qwen/projects")
        );

        let data_home = std::path::Path::new("/tmp/.local/share");
        assert_eq!(
            resolved_path(data_home, opencode.sources[0].relative_path),
            data_home.join("opencode/opencode.db")
        );
    }
}
