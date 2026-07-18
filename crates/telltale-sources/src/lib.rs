//! Telltale's filesystem-facing source layer: session-store discovery,
//! per-agent source adapters, record parsers, and installed-agent inventory.
//!
//! Everything here reads local agent session stores and normalizes them into
//! `telltale-schema` records; detection, scoring, and delivery live in the
//! downstream crates.

pub mod clients;
pub mod discovery;
pub mod install_inventory;
pub mod parser;
pub mod paths;
pub mod projects;
pub mod sources;
