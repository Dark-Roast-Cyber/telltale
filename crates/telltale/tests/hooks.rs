//! Library-level tests of `telltale_core::hooks`: adapter contracts replayed
//! from synthetic captures, runtime decisions, journal and state safety, and
//! the published telemetry schema. Binary-level tests are in the CLI's
//! `tests/cli/hooks_*.rs`.
#![cfg(feature = "hooks")]

#[path = "hooks/claude_code_contract.rs"]
mod claude_code_contract;
#[path = "hooks/codex_journal_encoding.rs"]
mod codex_journal_encoding;
#[path = "hooks/common.rs"]
mod common;
#[path = "hooks/deny_reason.rs"]
mod deny_reason;
#[path = "hooks/harness_contract.rs"]
mod harness_contract;
#[path = "hooks/harness_identity.rs"]
mod harness_identity;
#[path = "hooks/host_rule_integrity.rs"]
mod host_rule_integrity;
#[path = "hooks/journal_id_safety.rs"]
mod journal_id_safety;
#[path = "hooks/native_parity.rs"]
mod native_parity;
#[path = "hooks/projection_padding.rs"]
mod projection_padding;
#[path = "hooks/scenarios.rs"]
mod scenarios;
#[path = "hooks/self_protection_corpus.rs"]
mod self_protection_corpus;
#[path = "hooks/source_failure_recovery.rs"]
mod source_failure_recovery;
#[path = "hooks/state_tampering.rs"]
mod state_tampering;
#[path = "hooks/telemetry_schema.rs"]
mod telemetry_schema;
#[path = "hooks/test_signatures.rs"]
mod test_signatures;
