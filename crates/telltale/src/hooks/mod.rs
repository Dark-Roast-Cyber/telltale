//! Telltale Hooks: pre-execution monitoring and enforcement for AI agent
//! harnesses, reusing Telltale's detection through this crate's embedding
//! facade (the `hooks` feature, on by default; `telltale hooks` in the CLI).
//!
//! Layout: harness adapters (`claude_code`, `codex_cli`, `copilot_cli`), selected through the `harness`
//! registry, translate native hook payloads into harness-neutral `runtime`
//! events; `normalize` reshapes non-Claude tool inputs for the evaluation
//! encoding (ADR 0002). The runtime journals what the
//! harness reported (`journal`, `state`), evaluates it with Telltale
//! (`engine`), applies host promotion policy (`policy`) and writes
//! telemetry envelopes around Telltale's own records (`telemetry`).
//! `identity` names the running build for telemetry and for evaluator
//! compatibility; `evaluator` is the long-lived local evaluator.
//!
//! The runtime reaches Telltale only through the crate's public facade
//! (`Pipeline`, `ActionRecordV1`, `ObservationStage`), the same surface an
//! external embedder has.

pub mod claude_code;
pub mod codex_cli;
pub mod config;
pub mod copilot_cli;
pub mod engine;
pub mod evaluator;
pub mod harness;
pub mod identity;
pub mod journal;
pub mod normalize;
pub mod policy;
pub mod projection;
pub mod runtime;
pub mod state;
pub mod telemetry;
