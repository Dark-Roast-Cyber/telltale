//! Telltale's canonical data layer: client identifiers, normalized records,
//! the emitted SIEM event model, redaction, and risk scoring thresholds.
//!
//! This crate performs no I/O beyond serde serialization; filesystem
//! discovery, parsing, and delivery live in the downstream crates.

pub mod canonical;
pub mod clients;
pub mod event;
pub mod record;
pub mod scoring;
pub mod source;
