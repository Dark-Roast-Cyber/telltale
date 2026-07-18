pub mod cli;
pub mod config;
pub mod event;
pub mod rules;
pub mod schema;
pub mod sink;
pub mod state;
pub mod triage;

pub use telltale_detect::{allowlist, baseline, correlation, detection, mcp, timeline};
pub use telltale_schema::scoring;
pub use telltale_sources::{
    clients, discovery, install_inventory, parser, paths, projects, sources,
};
