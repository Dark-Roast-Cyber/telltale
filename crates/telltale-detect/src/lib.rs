//! Telltale's detection layer: deterministic evaluation over caller-supplied
//! records or canonical observations, session timelines, baseline state and
//! deviation, correlation, allowlist suppression, and optional MCP analysis.
//!
//! Source discovery and canonical acquisition live in `telltale-sources`; source orchestration
//! lives in `telltale-core`. State persistence and sinks live downstream.
//! Process-chain evaluation consumes canonical Tool evidence through `v2`;
//! `process_chain` exposes its configuration, not a direct-record detector.

pub mod allowlist;
pub mod baseline;
pub mod correlation;
pub mod detection;
#[cfg(feature = "source-io")]
pub mod mcp;
pub mod process_chain;
pub(crate) mod process_chain_session;
pub mod timeline;
/// Detection v2 APIs used by the canonical source runtime. Evaluation remains
/// I/O-free and accepts caller-provided typed observations.
pub mod v2;
