//! Telltale Hooks: pre-execution monitoring and enforcement for AI agent
//! harnesses, reusing Telltale's detection through this crate's embedding
//! facade (the `hooks` feature, on by default; `telltale hooks` in the CLI).
//!
//! Layout: harness adapters (`harnesses/`, one module and one descriptor per
//! harness), selected through the `harness` registry, translate native hook
//! payloads into harness-neutral `runtime` events. Harness knowledge stays in
//! the adapters: everything else reads the descriptor. The runtime journals what the
//! harness reported (`journal`, `state`), evaluates it with Telltale
//! (`engine`), applies host promotion policy (`policy`) and writes
//! telemetry envelopes around Telltale's own records (`telemetry`).
//! `identity` names the running build for telemetry and for evaluator
//! compatibility; `evaluator` is the long-lived local evaluator. `gate` is the
//! one place an answer is released to the harness: detect-only by default,
//! enforcing only when the configuration says so.
//!
//! The runtime reaches Telltale only through the crate's public facade
//! (`Pipeline`, `ActionRecordV1`, `ObservationStage`), the same surface an
//! external embedder has.

pub mod config;
pub mod engine;
pub mod evaluator;
pub mod gate;
pub mod harness;
pub mod harnesses;
pub mod identity;
pub mod journal;
pub mod policy;
pub mod projection;
pub mod runtime;
pub mod state;
pub mod telemetry;
