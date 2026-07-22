//! Minimal embedding example: point Telltale at a directory of agent session
//! stores and receive detection events as values — no CLI, no JSONL, no SIEM.
//!
//! Run with: `cargo run -p telltale-core --example embed_scan -- <session-root>`

use std::path::PathBuf;

use telltale_core::Pipeline;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pipeline = Pipeline::builder().build()?;
    println!("compiled {} rules", pipeline.rule_count());

    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: embed_scan <session-root>")?;

    for (source, event) in pipeline.scan_root(&root)? {
        println!(
            "{} [{}] {} rules={:?} score={}",
            source.source_id, event.severity, event.event_type, event.rule_ids, event.risk_score
        );
    }
    Ok(())
}
