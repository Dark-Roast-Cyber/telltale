//! Telltale's detection layer: deterministic rule evaluation over parsed
//! session records, session timelines, baseline deviation, cross-session
//! correlation, allowlist suppression, and MCP usage analysis.
//!
//! Records in, events out. Runtime concerns — state persistence, sinks,
//! triage, and the CLI — live in the downstream binary crate.

pub mod allowlist;
pub mod baseline;
pub mod correlation;
pub mod detection;
pub mod mcp;
pub mod timeline;
