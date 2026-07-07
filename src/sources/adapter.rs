//! Placeholder adapter trait for future per-agent source adapters.
//!
//! Phase 1 does not implement or wire this trait into runtime. It exists only to
//! establish the intended contract while the registry delegation is validated.

use crate::clients::ClientDef;
use crate::discovery::Source;
use crate::parser::{ParseError, ParseOptions, ParsedSourceRecords};

/// Per-agent source adapter contract.
///
/// Reserved for future phases. No built-in adapter implements this trait yet.
/// The `install_def` method is intentionally omitted because the current
/// `AgentInstallDef` is crate-private; it will be surfaced once install inventory
/// moves behind adapters in a later phase.
#[allow(dead_code)]
pub trait SourceAdapter {
    fn client(&self) -> ClientDef;
    fn parse(
        &self,
        source: &Source,
        options: ParseOptions,
    ) -> Result<ParsedSourceRecords, ParseError>;
}
