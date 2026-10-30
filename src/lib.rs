//! The `telltale` command-line application: scan and watch orchestration,
//! settings, scanner state, and delivery to JSONL and SIEM sinks.
//!
//! This crate owns process lifecycle, files, locks and delivery. Shared
//! semantics belong in the library crates it calls: discovery and acquisition in
//! `telltale-sources`, detection in `telltale-detect`, rules in `telltale-rules`,
//! event types and privacy in `telltale-schema`, and source processing in
//! `telltale-core`. Do not add a CLI-only copy of library behavior.

mod cli;
mod config;
mod event;
mod file_lock;
mod rules;
mod settings;
mod sink;
mod state;

use telltale_detect::{allowlist, baseline, correlation, process_chain};
use telltale_schema::scoring;
use telltale_sources::{discovery, install_inventory, paths, projects};

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    cli::run()
}
