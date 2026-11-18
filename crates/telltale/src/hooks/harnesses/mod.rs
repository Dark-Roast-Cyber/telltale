//! Harness adapters: everything Telltale Hooks knows about one harness's hook
//! protocol, one module per harness.
//!
//! Each adapter exports one [`Adapter`](crate::hooks::harness::Adapter)
//! descriptor, registered in `harness.rs`. Nothing outside this directory
//! names a harness, its payload keys, its environment variables or its files:
//! the runtime, normalization, generated rules and the CLI read the
//! descriptor. An adapter may call another only where the harnesses share a
//! protocol (Copilot CLI payloads arrive at the Claude Code entry point), and
//! what several adapters need lives in [`payload`].

use crate::hooks::harness::{Harness, Normalization};

pub mod claude_code;
pub mod codex_cli;
pub mod copilot_cli;
pub mod opencode;
pub mod payload;

/// The normalization for a `Context::harness` name: the registered adapter's
/// choice. Any other name is the identity.
pub fn normalization(name: &str) -> Normalization {
    match Harness::from_name(name) {
        Some(harness) => harness.adapter().normalization,
        None => Normalization::Identity,
    }
}
