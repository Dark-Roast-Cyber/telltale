//! Built-in client source registry.
//!
//! Per-client source arrays live in their source modules. This module collects
//! them into the deterministic built-in client and install registries.

use crate::clients::ClientDef;
use crate::install_inventory::AgentInstallDef;
use crate::sources::{claude, codex, copilot, openclaw, opencode, pi, qwen};
use telltale_schema::clients::ClientId;

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
        id: ClientId::OpenCode,
        display_name: "OpenCode",
        sources: opencode::SOURCES,
    },
    ClientDef {
        id: ClientId::Copilot,
        display_name: "GitHub Copilot",
        sources: copilot::SOURCES,
    },
    ClientDef {
        id: ClientId::Pi,
        display_name: "Pi",
        sources: pi::SOURCES,
    },
];

pub(crate) fn builtin_client_defs() -> &'static [ClientDef] {
    CLIENTS
}

/// Install inventory evidence definitions, in the same order as `CLIENTS`.
/// The order must stay aligned with the client registry so install inventory
/// snapshot hashes are deterministic.
const INSTALL_DEFS: &[AgentInstallDef] = &[
    codex::INSTALL,
    claude::INSTALL,
    openclaw::INSTALL,
    qwen::INSTALL,
    opencode::INSTALL,
    copilot::INSTALL,
    pi::INSTALL,
];

pub(crate) fn builtin_install_defs() -> &'static [AgentInstallDef] {
    INSTALL_DEFS
}

#[cfg(test)]
mod tests;
