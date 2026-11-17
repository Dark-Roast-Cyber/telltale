//! Per-agent source modules and the static source registry.
//!
//! Each agent module owns its static source definitions, native extraction, and
//! install-inventory evidence. `registry` collects them into the fixed table that
//! `crate::clients::supported_clients()` wraps; there is no trait-based adapter
//! contract and no runtime registration. Acquisition dispatches the same eight
//! identities explicitly. `SourceKind` is container/reporting metadata, not a
//! second routing key.
//!
//! Acquisition also knows one hook-journal identity per client that has a hooks
//! adapter ([`HOOK_JOURNALS`]) and reads it only with the `hook-journal`
//! feature; without it the identity is an uncompiled capability. They are
//! host-fed: not in the registry, so never discovered, listed or catalogued, and
//! not session sources.

pub(crate) mod claude;
pub(crate) mod codex;
pub(crate) mod copilot;
pub(crate) mod openclaw;
pub(crate) mod opencode;
pub(crate) mod qwen;
pub mod registry;

/// A hook-journal identity: the client whose hooks write the journal, the
/// source ID its window is scanned under and the adapter type stamped on its
/// observations. The journal is read with the Claude Code reader and tool
/// table, whichever client the identity names.
pub(crate) struct HookJournal {
    pub(crate) client: telltale_schema::clients::ClientId,
    pub(crate) source_id: &'static str,
    pub(crate) adapter_type: &'static str,
}

/// Every hook-journal identity, each exported by its client's module.
pub(crate) const HOOK_JOURNALS: &[HookJournal] = &[
    claude::HOOK_JOURNAL,
    codex::HOOK_JOURNAL,
    copilot::HOOK_JOURNAL,
];

#[cfg(test)]
mod canonical_conformance;
