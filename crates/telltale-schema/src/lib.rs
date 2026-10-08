//! Telltale's canonical data layer: client identifiers, Canonical Observation v2,
//! the emitted SIEM event model, redaction, and risk scoring thresholds.
//!
//! This crate performs no I/O beyond serde serialization; filesystem
//! discovery, parsing, and delivery live in the downstream crates.

pub mod activity_facts;
pub mod clients;
pub mod event;
pub mod event4;
pub mod observation;
pub mod provenance;
pub mod record;
pub mod scoring;
pub mod source;
