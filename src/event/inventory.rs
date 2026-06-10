use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::Evidence;
use crate::discovery::Source;
use crate::state::SourceInventoryChangeSummary;

pub(crate) fn source_counts(sources: &[Source]) -> BTreeMap<String, u32> {
    let mut counts = BTreeMap::new();
    for source in sources {
        let key = format!("{}.{}", source.client.as_str(), source.kind.as_str());
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

pub(crate) fn source_inventory_evidence(sources: &[Source]) -> Evidence {
    let counts = source_counts(sources);
    let mut inventory = sources
        .iter()
        .map(|source| {
            format!(
                "{}:{}:{}",
                source.client.as_str(),
                source.kind.as_str(),
                path_hash(&source.path)
            )
        })
        .collect::<Vec<_>>();
    inventory.sort();

    let mut hasher = Sha256::new();
    for item in &inventory {
        hasher.update(item.as_bytes());
        hasher.update(b"\n");
    }

    Evidence {
        field: "source_inventory".to_string(),
        redacted_value: format!(
            "sources={}; client_source_kinds={}",
            sources.len(),
            counts.len()
        ),
        hash: Some(format!("{:x}", hasher.finalize())),
        rule_id: None,
    }
}

pub(crate) fn source_inventory_change_evidence(change: &SourceInventoryChangeSummary) -> Evidence {
    Evidence {
        field: "source_inventory_change".to_string(),
        redacted_value: format!(
            "baseline={}; added={}; removed={}; unchanged={}",
            change.baseline, change.added, change.removed, change.unchanged
        ),
        hash: Some(change.hash.clone()),
        rule_id: None,
    }
}

pub(crate) fn display_name(source: &Source) -> String {
    source
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

pub fn append_jsonl_events(
    path: &Path,
    events: &[super::Event],
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

pub fn path_hash(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn evidence_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}
