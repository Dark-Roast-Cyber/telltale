//! Per-agent source modules and the static source registry.
//!
//! Each agent module owns its static source definitions and install-inventory
//! evidence. `registry` collects them into the fixed table that
//! `crate::clients::supported_clients()` wraps; there is no trait-based adapter
//! contract and no runtime registration. The private exact `(ClientId,
//! source_id)` parser table is maintained in `crate::parser`; `SourceKind` is
//! container/reporting metadata, not semantic parser selection. Modeled parser
//! code and focused tests live in the agent modules where practical.

pub(crate) mod claude;
pub(crate) mod codex;
pub(crate) mod copilot;
pub(crate) mod gemini;
pub(crate) mod kilocode;
pub(crate) mod openclaw;
pub(crate) mod opencode;
pub(crate) mod qwen;
pub mod registry;
pub(crate) mod roocode;

#[cfg(test)]
mod parity;
