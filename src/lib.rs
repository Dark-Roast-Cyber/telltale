pub mod allowlist;
pub mod baseline;
pub mod cli;
pub mod config;
pub mod correlation;
pub mod detection;
pub mod event;
pub mod mcp;
pub mod rules;
pub mod schema;
pub mod sink;
pub mod state;
pub mod timeline;
pub mod triage;

pub use telltale_schema::scoring;
pub use telltale_sources::{
    clients, discovery, install_inventory, parser, paths, projects, sources,
};
