//! Telltale's canonical data layer: client identifiers, Canonical Observation v2,
//! the emitted SIEM event model, redaction, and risk scoring thresholds.
//!
//! This crate performs no I/O beyond serde serialization; filesystem
//! discovery, parsing, and delivery live in the downstream crates.

pub mod action_record;
pub mod action_record_v2;
pub mod activity_facts;
pub mod clients;
pub mod destination_facts;
pub mod effective_configuration;
pub mod event;
pub mod event4;
pub mod observation;
pub mod provenance;
pub mod record;
pub mod rule_catalog;
pub mod scoring;
pub mod source;
