//! Re-exports the canonical event model from `telltale-schema` and adds the
//! filesystem-facing JSONL append helper, which stays out of the I/O-free
//! schema crate.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub use telltale_schema::event::*;

pub fn append_jsonl_events(
    path: &Path,
    events: &[Event],
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    for event in events {
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}
