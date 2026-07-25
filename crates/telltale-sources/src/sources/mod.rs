//! Per-agent source modules and the static source registry.
//!
//! Each agent module owns its static source definitions and install-inventory
//! evidence. `registry` collects them into the fixed table that
//! `crate::clients::supported_clients()` wraps; there is no trait-based adapter
//! contract and no runtime registration. Parser dispatch remains centralized,
//! with selected source-specific helpers living in the agent modules.

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

pub use crate::clients::{
    ClientDef, ClientId, ClientSourceDef, PathRoot, SourceKind, SourcePattern, supported_clients,
};
