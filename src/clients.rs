use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum ClientId {
    Codex,
    Claude,
    Gemini,
    OpenClaw,
    Qwen,
    RooCode,
    KiloCode,
    OpenCode,
    Copilot,
}

impl ClientId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Gemini => "gemini",
            Self::OpenClaw => "openclaw",
            Self::Qwen => "qwen",
            Self::RooCode => "roocode",
            Self::KiloCode => "kilocode",
            Self::OpenCode => "opencode",
            Self::Copilot => "copilot",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PathRoot {
    CodexHome,
    Home,
    ConfigHome,
    DataHome,
    ProjectLocal,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum SourceKind {
    Json,
    Jsonl,
    ArchivedJsonl,
    HeadlessJsonl,
    Sqlite,
    LegacyJson,
    UiMessagesJson,
    CopilotProcessLog,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::ArchivedJsonl => "archived_jsonl",
            Self::HeadlessJsonl => "headless_jsonl",
            Self::Sqlite => "sqlite",
            Self::LegacyJson => "legacy_json",
            Self::UiMessagesJson => "ui_messages_json",
            Self::CopilotProcessLog => "copilot_process_log",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

const CODEX_SOURCES: &[ClientSourceDef] = &[
    ClientSourceDef {
        id: "codex.sessions",
        kind: SourceKind::Jsonl,
        root: PathRoot::CodexHome,
        relative_path: "sessions",
        fixture_relative_path: "codex/sessions",
        pattern: SourcePattern::Extension("jsonl"),
        recursive: true,
        project_relative_path: None,
    },
    ClientSourceDef {
        id: "codex.archived_sessions",
        kind: SourceKind::ArchivedJsonl,
        root: PathRoot::CodexHome,
        relative_path: "archived_sessions",
        fixture_relative_path: "codex/archived_sessions",
        pattern: SourcePattern::Extension("jsonl"),
        recursive: true,
        project_relative_path: None,
    },
    ClientSourceDef {
        id: "codex.headless_sessions",
        kind: SourceKind::HeadlessJsonl,
        root: PathRoot::CodexHome,
        relative_path: "headless",
        fixture_relative_path: "codex/headless",
        pattern: SourcePattern::Extension("jsonl"),
        recursive: true,
        project_relative_path: None,
    },
    ClientSourceDef {
        id: "codex.project_sessions",
        kind: SourceKind::Jsonl,
        root: PathRoot::ProjectLocal,
        relative_path: ".codex-worktree",
        fixture_relative_path: "codex/project_sessions",
        pattern: SourcePattern::Extension("jsonl"),
        recursive: true,
        project_relative_path: Some(".codex-worktree"),
    },
];

const CLAUDE_SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "claude.projects",
    kind: SourceKind::Jsonl,
    root: PathRoot::Home,
    relative_path: ".claude/projects",
    fixture_relative_path: "claude/projects",
    pattern: SourcePattern::Extension("jsonl"),
    recursive: true,
    project_relative_path: None,
}];

const GEMINI_SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "gemini.tmp",
    kind: SourceKind::Json,
    root: PathRoot::Home,
    relative_path: ".gemini/tmp",
    fixture_relative_path: "gemini/tmp",
    pattern: SourcePattern::Extension("json"),
    recursive: true,
    project_relative_path: None,
}];

const OPENCLAW_SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "openclaw.agents",
    kind: SourceKind::Jsonl,
    root: PathRoot::Home,
    relative_path: ".openclaw/agents",
    fixture_relative_path: "openclaw/agents",
    pattern: SourcePattern::FileNameContains(".jsonl"),
    recursive: true,
    project_relative_path: None,
}];

const QWEN_SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "qwen.projects",
    kind: SourceKind::Jsonl,
    root: PathRoot::Home,
    relative_path: ".qwen/projects",
    fixture_relative_path: "qwen/projects",
    pattern: SourcePattern::Extension("jsonl"),
    recursive: true,
    project_relative_path: None,
}];

const ROOCODE_SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "roocode.tasks",
    kind: SourceKind::UiMessagesJson,
    root: PathRoot::ConfigHome,
    relative_path: "Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks",
    fixture_relative_path: "roocode/tasks",
    pattern: SourcePattern::ExactFile("ui_messages.json"),
    recursive: true,
    project_relative_path: None,
}];

const KILOCODE_SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "kilocode.tasks",
    kind: SourceKind::UiMessagesJson,
    root: PathRoot::ConfigHome,
    relative_path: "Code/User/globalStorage/kilocode.kilo-code/tasks",
    fixture_relative_path: "kilocode/tasks",
    pattern: SourcePattern::ExactFile("ui_messages.json"),
    recursive: true,
    project_relative_path: None,
}];

const OPENCODE_SOURCES: &[ClientSourceDef] = &[
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

const COPILOT_SOURCES: &[ClientSourceDef] = &[ClientSourceDef {
    id: "copilot.process_log",
    kind: SourceKind::CopilotProcessLog,
    root: PathRoot::ProjectLocal,
    relative_path: "logs/copilot",
    fixture_relative_path: "copilot",
    pattern: SourcePattern::Extension("log"),
    recursive: false,
    project_relative_path: Some("logs/copilot"),
}];

const CLIENTS: &[ClientDef] = &[
    ClientDef {
        id: ClientId::Codex,
        display_name: "Codex",
        sources: CODEX_SOURCES,
    },
    ClientDef {
        id: ClientId::Claude,
        display_name: "Claude Code",
        sources: CLAUDE_SOURCES,
    },
    ClientDef {
        id: ClientId::Gemini,
        display_name: "Gemini CLI",
        sources: GEMINI_SOURCES,
    },
    ClientDef {
        id: ClientId::OpenClaw,
        display_name: "OpenClaw",
        sources: OPENCLAW_SOURCES,
    },
    ClientDef {
        id: ClientId::Qwen,
        display_name: "Qwen CLI",
        sources: QWEN_SOURCES,
    },
    ClientDef {
        id: ClientId::RooCode,
        display_name: "RooCode",
        sources: ROOCODE_SOURCES,
    },
    ClientDef {
        id: ClientId::KiloCode,
        display_name: "KiloCode",
        sources: KILOCODE_SOURCES,
    },
    ClientDef {
        id: ClientId::OpenCode,
        display_name: "OpenCode",
        sources: OPENCODE_SOURCES,
    },
    ClientDef {
        id: ClientId::Copilot,
        display_name: "GitHub Copilot",
        sources: COPILOT_SOURCES,
    },
];

pub fn supported_clients() -> &'static [ClientDef] {
    CLIENTS
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
        assert!(source_keys.contains(&(ClientId::Gemini, SourceKind::Json, "gemini/tmp")));
        assert!(source_keys.contains(&(ClientId::OpenClaw, SourceKind::Jsonl, "openclaw/agents")));
        assert!(source_keys.contains(&(ClientId::Qwen, SourceKind::Jsonl, "qwen/projects")));
        assert!(source_keys.contains(&(
            ClientId::RooCode,
            SourceKind::UiMessagesJson,
            "roocode/tasks"
        )));
        assert!(source_keys.contains(&(
            ClientId::KiloCode,
            SourceKind::UiMessagesJson,
            "kilocode/tasks"
        )));
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
        assert!(source_keys.contains(&(
            ClientId::OpenCode,
            SourceKind::LegacyJson,
            "opencode/storage/message"
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
        let gemini = supported_clients()
            .iter()
            .find(|client| client.id == ClientId::Gemini)
            .expect("gemini client");
        let openclaw = supported_clients()
            .iter()
            .find(|client| client.id == ClientId::OpenClaw)
            .expect("openclaw client");
        let qwen = supported_clients()
            .iter()
            .find(|client| client.id == ClientId::Qwen)
            .expect("qwen client");
        let roocode = supported_clients()
            .iter()
            .find(|client| client.id == ClientId::RooCode)
            .expect("roocode client");
        let kilocode = supported_clients()
            .iter()
            .find(|client| client.id == ClientId::KiloCode)
            .expect("kilocode client");

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
        let config_home = std::path::Path::new("/tmp/home/.config");
        assert_eq!(
            resolved_path(home, claude.sources[0].relative_path),
            home.join(".claude/projects")
        );
        assert_eq!(
            resolved_path(home, gemini.sources[0].relative_path),
            home.join(".gemini/tmp")
        );
        assert_eq!(
            resolved_path(home, openclaw.sources[0].relative_path),
            home.join(".openclaw/agents")
        );
        assert_eq!(
            resolved_path(home, qwen.sources[0].relative_path),
            home.join(".qwen/projects")
        );
        assert_eq!(
            resolved_path(config_home, roocode.sources[0].relative_path),
            config_home.join("Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks")
        );
        assert_eq!(
            resolved_path(config_home, kilocode.sources[0].relative_path),
            config_home.join("Code/User/globalStorage/kilocode.kilo-code/tasks")
        );

        let data_home = std::path::Path::new("/tmp/.local/share");
        assert_eq!(
            resolved_path(data_home, opencode.sources[0].relative_path),
            data_home.join("opencode/opencode.db")
        );
        assert_eq!(
            resolved_path(data_home, opencode.sources[1].relative_path),
            data_home.join("opencode/storage/message")
        );
    }
}
