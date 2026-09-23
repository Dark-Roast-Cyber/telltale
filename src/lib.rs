mod cli;
mod config;
mod event;
mod file_lock;
mod rules;
mod schema;
mod sink;
mod state;

use telltale_detect::{allowlist, baseline, correlation, mcp, process_chain};
use telltale_schema::scoring;
use telltale_sources::{discovery, install_inventory, parser, paths, projects};

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    cli::run()
}
