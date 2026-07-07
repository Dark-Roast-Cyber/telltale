//! Built-in client source registry.
//!
//! Phase 1 moves the static `CLIENTS` assembly from `crate::clients` into this
//! module. The per-client source arrays and the final `ClientDef` slice live
//! here; the types themselves remain in `crate::clients` to preserve the public
//! API during migration.

use crate::clients::{ClientDef, ClientId, ClientSourceDef, PathRoot, SourceKind, SourcePattern};

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

pub(crate) fn builtin_client_defs() -> &'static [ClientDef] {
    CLIENTS
}

#[cfg(test)]
mod tests {
    use crate::clients::{ClientId, PathRoot, SourceKind, SourcePattern};
    use crate::sources::registry::builtin_client_defs;

    /// Exhaustive regression snapshot of the built-in source registry. This test
    /// must fail if any client id, display name, source count, or source metadata
    /// changes during the Phase 1 delegation.
    #[test]
    fn registry_matches_expected_phase1_snapshot() {
        let clients = builtin_client_defs();
        assert_eq!(clients.len(), 9, "expected nine built-in clients");

        assert_client(clients, 0, ClientId::Codex, "Codex", 4);
        assert_source(
            clients[0].sources[0],
            "codex.sessions",
            SourceKind::Jsonl,
            PathRoot::CodexHome,
            "sessions",
            "codex/sessions",
            SourcePattern::Extension("jsonl"),
            true,
            None,
        );
        assert_source(
            clients[0].sources[1],
            "codex.archived_sessions",
            SourceKind::ArchivedJsonl,
            PathRoot::CodexHome,
            "archived_sessions",
            "codex/archived_sessions",
            SourcePattern::Extension("jsonl"),
            true,
            None,
        );
        assert_source(
            clients[0].sources[2],
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
            PathRoot::CodexHome,
            "headless",
            "codex/headless",
            SourcePattern::Extension("jsonl"),
            true,
            None,
        );
        assert_source(
            clients[0].sources[3],
            "codex.project_sessions",
            SourceKind::Jsonl,
            PathRoot::ProjectLocal,
            ".codex-worktree",
            "codex/project_sessions",
            SourcePattern::Extension("jsonl"),
            true,
            Some(".codex-worktree"),
        );

        assert_client(clients, 1, ClientId::Claude, "Claude Code", 1);
        assert_source(
            clients[1].sources[0],
            "claude.projects",
            SourceKind::Jsonl,
            PathRoot::Home,
            ".claude/projects",
            "claude/projects",
            SourcePattern::Extension("jsonl"),
            true,
            None,
        );

        assert_client(clients, 2, ClientId::Gemini, "Gemini CLI", 1);
        assert_source(
            clients[2].sources[0],
            "gemini.tmp",
            SourceKind::Json,
            PathRoot::Home,
            ".gemini/tmp",
            "gemini/tmp",
            SourcePattern::Extension("json"),
            true,
            None,
        );

        assert_client(clients, 3, ClientId::OpenClaw, "OpenClaw", 1);
        assert_source(
            clients[3].sources[0],
            "openclaw.agents",
            SourceKind::Jsonl,
            PathRoot::Home,
            ".openclaw/agents",
            "openclaw/agents",
            SourcePattern::FileNameContains(".jsonl"),
            true,
            None,
        );

        assert_client(clients, 4, ClientId::Qwen, "Qwen CLI", 1);
        assert_source(
            clients[4].sources[0],
            "qwen.projects",
            SourceKind::Jsonl,
            PathRoot::Home,
            ".qwen/projects",
            "qwen/projects",
            SourcePattern::Extension("jsonl"),
            true,
            None,
        );

        assert_client(clients, 5, ClientId::RooCode, "RooCode", 1);
        assert_source(
            clients[5].sources[0],
            "roocode.tasks",
            SourceKind::UiMessagesJson,
            PathRoot::ConfigHome,
            "Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks",
            "roocode/tasks",
            SourcePattern::ExactFile("ui_messages.json"),
            true,
            None,
        );

        assert_client(clients, 6, ClientId::KiloCode, "KiloCode", 1);
        assert_source(
            clients[6].sources[0],
            "kilocode.tasks",
            SourceKind::UiMessagesJson,
            PathRoot::ConfigHome,
            "Code/User/globalStorage/kilocode.kilo-code/tasks",
            "kilocode/tasks",
            SourcePattern::ExactFile("ui_messages.json"),
            true,
            None,
        );

        assert_client(clients, 7, ClientId::OpenCode, "OpenCode", 3);
        assert_source(
            clients[7].sources[0],
            "opencode.sqlite",
            SourceKind::Sqlite,
            PathRoot::DataHome,
            "opencode/opencode.db",
            "opencode/opencode.db",
            SourcePattern::ExactFile("opencode.db"),
            false,
            None,
        );
        assert_source(
            clients[7].sources[1],
            "opencode.legacy_json",
            SourceKind::LegacyJson,
            PathRoot::DataHome,
            "opencode/storage/message",
            "opencode/storage/message",
            SourcePattern::Extension("json"),
            true,
            None,
        );
        assert_source(
            clients[7].sources[2],
            "opencode.project_json",
            SourceKind::LegacyJson,
            PathRoot::ProjectLocal,
            ".opencode",
            "opencode/project",
            SourcePattern::Extension("json"),
            true,
            Some(".opencode"),
        );

        assert_client(clients, 8, ClientId::Copilot, "GitHub Copilot", 1);
        assert_source(
            clients[8].sources[0],
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            PathRoot::ProjectLocal,
            "logs/copilot",
            "copilot",
            SourcePattern::Extension("log"),
            false,
            Some("logs/copilot"),
        );
    }

    fn assert_client(
        clients: &[crate::clients::ClientDef],
        index: usize,
        expected_id: ClientId,
        expected_display_name: &str,
        expected_source_count: usize,
    ) {
        let client = &clients[index];
        assert_eq!(
            client.id, expected_id,
            "client at index {index} has unexpected id"
        );
        assert_eq!(
            client.display_name, expected_display_name,
            "client at index {index} has unexpected display_name"
        );
        assert_eq!(
            client.sources.len(),
            expected_source_count,
            "client {expected_id:?} has unexpected source count"
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_source(
        source: crate::clients::ClientSourceDef,
        expected_id: &str,
        expected_kind: SourceKind,
        expected_root: PathRoot,
        expected_relative_path: &str,
        expected_fixture_relative_path: &str,
        expected_pattern: SourcePattern,
        expected_recursive: bool,
        expected_project_relative_path: Option<&str>,
    ) {
        assert_eq!(source.id, expected_id, "unexpected source id");
        assert_eq!(
            source.kind, expected_kind,
            "source {expected_id} has unexpected kind"
        );
        assert_eq!(
            source.root, expected_root,
            "source {expected_id} has unexpected root"
        );
        assert_eq!(
            source.relative_path, expected_relative_path,
            "source {expected_id} has unexpected relative_path"
        );
        assert_eq!(
            source.fixture_relative_path, expected_fixture_relative_path,
            "source {expected_id} has unexpected fixture_relative_path"
        );
        assert_eq!(
            source.pattern, expected_pattern,
            "source {expected_id} has unexpected pattern"
        );
        assert_eq!(
            source.recursive, expected_recursive,
            "source {expected_id} has unexpected recursive flag"
        );
        assert_eq!(
            source.project_relative_path, expected_project_relative_path,
            "source {expected_id} has unexpected project_relative_path"
        );
    }
}
