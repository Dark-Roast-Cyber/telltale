//! Minimal embedding example: point Telltale at a directory of agent session
//! stores and receive detection events as values — no CLI, no JSONL, no SIEM.
//!
//! Run with: `cargo run -p telltale --example embed_scan`

use std::path::Path;

use telltale::Pipeline;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pipeline = Pipeline::builder().build()?;
    println!("compiled {} rules", pipeline.rule_count());

    // A host application would pass a real root (e.g. the user's home
    // directory); this example scans the repository's synthetic fixtures.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/session_stores");

    for (source, event) in pipeline.scan_root(&root)? {
        println!(
            "{} [{}] {} rules={:?} score={}",
            source.source_id, event.severity, event.event_type, event.rule_ids, event.risk_score
        );
    }
    Ok(())
}
