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
/// Install inventory evidence is collected as per-agent constants through
/// `crate::sources::registry::builtin_install_defs()` rather than a trait
/// method, matching how source definitions are collected.
#[allow(dead_code)]
pub trait SourceAdapter {
    fn client(&self) -> ClientDef;
    fn parse(
        &self,
        source: &Source,
        options: ParseOptions,
    ) -> Result<ParsedSourceRecords, ParseError>;
}
