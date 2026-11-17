//! Synthetic descriptor fixture for the extracted discovery behavior tests.
//! Production registries belong to callers, not this crate.

use crate::clients::{ClientDef, ClientSourceDef, PathRoot, SourcePattern};
use telltale_schema::clients::{ClientId, SourceKind};

pub(crate) fn supported_clients() -> &'static [ClientDef] {
    const CLIENTS: &[ClientDef] = &[
        ClientDef {
            id: ClientId::Codex,
            display_name: "Codex",
            sources: &[
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
            ],
        },
        ClientDef {
            id: ClientId::Claude,
            display_name: "Claude Code",
            sources: &[ClientSourceDef {
                id: "claude.projects",
                kind: SourceKind::Jsonl,
                root: PathRoot::Home,
                relative_path: ".claude/projects",
                fixture_relative_path: "claude/projects",
                pattern: SourcePattern::Extension("jsonl"),
                recursive: true,
                project_relative_path: None,
            }],
        },
        ClientDef {
            id: ClientId::OpenClaw,
            display_name: "OpenClaw",
            sources: &[ClientSourceDef {
                id: "openclaw.agents",
                kind: SourceKind::Jsonl,
                root: PathRoot::Home,
                relative_path: ".openclaw/agents",
                fixture_relative_path: "openclaw/agents",
                pattern: SourcePattern::FileNameContains(".jsonl"),
                recursive: true,
                project_relative_path: None,
            }],
        },
        ClientDef {
            id: ClientId::Qwen,
            display_name: "Qwen CLI",
            sources: &[ClientSourceDef {
                id: "qwen.projects",
                kind: SourceKind::Jsonl,
                root: PathRoot::Home,
                relative_path: ".qwen/projects",
                fixture_relative_path: "qwen/projects",
                pattern: SourcePattern::Extension("jsonl"),
                recursive: true,
                project_relative_path: None,
            }],
        },
        ClientDef {
            id: ClientId::OpenCode,
            display_name: "OpenCode",
            sources: &[ClientSourceDef {
                id: "opencode.sqlite",
                kind: SourceKind::Sqlite,
                root: PathRoot::DataHome,
                relative_path: "opencode/opencode.db",
                fixture_relative_path: "opencode/opencode.db",
                pattern: SourcePattern::ExactFile("opencode.db"),
                recursive: false,
                project_relative_path: None,
            }],
        },
        ClientDef {
            id: ClientId::Copilot,
            display_name: "GitHub Copilot",
            sources: &[ClientSourceDef {
                id: "copilot.process_log",
                kind: SourceKind::CopilotProcessLog,
                root: PathRoot::ProjectLocal,
                relative_path: "logs/copilot",
                fixture_relative_path: "copilot",
                pattern: SourcePattern::Extension("log"),
                recursive: false,
                project_relative_path: Some("logs/copilot"),
            }],
        },
    ];
    CLIENTS
}
