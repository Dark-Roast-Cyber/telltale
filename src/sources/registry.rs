//! Built-in client source registry.
//!
//! Phase 1 moves the static `CLIENTS` assembly from `crate::clients` into this
//! module. The per-client source arrays and the final `ClientDef` slice live
//! here; the types themselves remain in `crate::clients` to preserve the public
//! API during migration.

use crate::clients::{ClientDef, ClientId};
use crate::install_inventory::AgentInstallDef;
use crate::sources::{claude, codex, copilot, gemini, kilocode, openclaw, opencode, qwen, roocode};

const CLIENTS: &[ClientDef] = &[
    ClientDef {
        id: ClientId::Codex,
        display_name: "Codex",
        sources: codex::SOURCES,
    },
    ClientDef {
        id: ClientId::Claude,
        display_name: "Claude Code",
        sources: claude::SOURCES,
    },
    ClientDef {
        id: ClientId::Gemini,
        display_name: "Gemini CLI",
        sources: gemini::SOURCES,
    },
    ClientDef {
        id: ClientId::OpenClaw,
        display_name: "OpenClaw",
        sources: openclaw::SOURCES,
    },
    ClientDef {
        id: ClientId::Qwen,
        display_name: "Qwen CLI",
        sources: qwen::SOURCES,
    },
    ClientDef {
        id: ClientId::RooCode,
        display_name: "RooCode",
        sources: roocode::SOURCES,
    },
    ClientDef {
        id: ClientId::KiloCode,
        display_name: "KiloCode",
        sources: kilocode::SOURCES,
    },
    ClientDef {
        id: ClientId::OpenCode,
        display_name: "OpenCode",
        sources: opencode::SOURCES,
    },
    ClientDef {
        id: ClientId::Copilot,
        display_name: "GitHub Copilot",
        sources: copilot::SOURCES,
    },
];

pub(crate) fn builtin_client_defs() -> &'static [ClientDef] {
    CLIENTS
}

/// Install inventory evidence definitions, in the same order as `CLIENTS`.
/// The order must stay aligned with the client registry so install inventory
/// snapshot hashes remain stable across the adapter migration.
const INSTALL_DEFS: &[AgentInstallDef] = &[
    codex::INSTALL,
    claude::INSTALL,
    gemini::INSTALL,
    openclaw::INSTALL,
    qwen::INSTALL,
    roocode::INSTALL,
    kilocode::INSTALL,
    opencode::INSTALL,
    copilot::INSTALL,
];

pub(crate) fn builtin_install_defs() -> &'static [AgentInstallDef] {
    INSTALL_DEFS
}

#[cfg(test)]
mod tests {
    use crate::clients::{ClientId, PathRoot, SourceKind, SourcePattern};
    use crate::install_inventory::AgentInstallDef;
    use crate::sources::registry::{builtin_client_defs, builtin_install_defs};

    /// Exhaustive regression snapshot of the per-agent install evidence
    /// definitions collected through the registry. This test must fail if any
    /// agent id, signal list, or ordering changes during the Phase 5 migration:
    /// ordering feeds the install inventory snapshot hash, so a reorder would
    /// re-emit inventory events on hosts with unchanged installs.
    #[test]
    fn install_defs_match_expected_phase5_snapshot() {
        let expected: &[AgentInstallDef] = &[
            AgentInstallDef {
                agent: "codex",
                executables: &["codex"],
                node_packages: &["@openai/codex"],
                extension_ids: &[],
                global_storage_ids: &[],
            },
            AgentInstallDef {
                agent: "claude",
                executables: &["claude"],
                node_packages: &["@anthropic-ai/claude-code"],
                extension_ids: &[],
                global_storage_ids: &[],
            },
            AgentInstallDef {
                agent: "gemini",
                executables: &["gemini"],
                node_packages: &["@google/gemini-cli"],
                extension_ids: &[],
                global_storage_ids: &[],
            },
            AgentInstallDef {
                agent: "openclaw",
                executables: &["openclaw"],
                node_packages: &["openclaw"],
                extension_ids: &[],
                global_storage_ids: &[],
            },
            AgentInstallDef {
                agent: "qwen",
                executables: &["qwen"],
                node_packages: &["@qwen-code/qwen-code"],
                extension_ids: &[],
                global_storage_ids: &[],
            },
            AgentInstallDef {
                agent: "roocode",
                executables: &[],
                node_packages: &[],
                extension_ids: &["rooveterinaryinc.roo-cline"],
                global_storage_ids: &["rooveterinaryinc.roo-cline"],
            },
            AgentInstallDef {
                agent: "kilocode",
                executables: &["kilo", "kilocode"],
                node_packages: &["@kilocode/cli"],
                extension_ids: &["kilocode.kilo-code"],
                global_storage_ids: &["kilocode.kilo-code"],
            },
            AgentInstallDef {
                agent: "opencode",
                executables: &["opencode"],
                node_packages: &["opencode-ai"],
                extension_ids: &[],
                global_storage_ids: &[],
            },
            AgentInstallDef {
                agent: "copilot",
                executables: &[],
                node_packages: &[],
                extension_ids: &["github.copilot", "github.copilot-chat"],
                global_storage_ids: &["github.copilot", "github.copilot-chat"],
            },
        ];

        assert_eq!(builtin_install_defs(), expected);
    }

    /// Install definitions must stay aligned with the client registry order so
    /// the inventory snapshot hash is stable across the adapter migration.
    #[test]
    fn install_defs_follow_client_registry_order() {
        let clients = builtin_client_defs();
        let installs = builtin_install_defs();
        assert_eq!(clients.len(), installs.len());
        for (client, install) in clients.iter().zip(installs) {
            assert_eq!(
                client.id.as_str(),
                install.agent,
                "install def order diverges from client registry order"
            );
        }
    }

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
