//! Per-agent source modules and the static source registry.
//!
//! Each agent module owns its static source definitions, native extraction, and
//! install-inventory evidence. `registry` collects them into the fixed table that
//! `crate::clients::supported_clients()` wraps; there is no trait-based adapter
//! contract and no runtime registration. Acquisition dispatches the same eight
//! identities explicitly. `SourceKind` is container/reporting metadata, not a
//! second routing key.

pub(crate) mod claude;
pub(crate) mod codex;
pub(crate) mod copilot;
pub(crate) mod openclaw;
pub(crate) mod opencode;
pub(crate) mod qwen;
pub mod registry;

#[cfg(test)]
mod canonical_conformance;
