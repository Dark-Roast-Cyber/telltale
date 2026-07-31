mod cli;
mod config;
mod event;
mod rules;
mod schema;
mod sink;
mod state;
mod triage;

use telltale_detect::{allowlist, baseline, correlation, detection, mcp, timeline};
use telltale_schema::scoring;
use telltale_sources::{discovery, install_inventory, parser, paths, projects};

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    cli::run()
}
