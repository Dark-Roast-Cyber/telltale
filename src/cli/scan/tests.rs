use crate::event::scanner_error_event;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use telltale_sources::acquisition::{
    AcquisitionError, AcquisitionProgress, RecordCounts, SessionAccounting, SourceAccounting,
};

use super::discovery::ProjectConfigurationAccounting;
use super::*;
use crate::install_inventory::InstallInventorySnapshot;
use crate::sink::{DeliveryError, DeliveryErrorClass, EventSink, LocalJsonlSink, RotationConfig};

fn opencode_test_source() -> Source {
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: PathBuf::from("/synthetic/opencode.db"),
    }
}

struct CountingSink {
    calls: Arc<AtomicUsize>,
}

impl EventSink for CountingSink {
    fn name(&self) -> &str {
        "synthetic"
    }

    fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn emit_canonical_once(&self, _payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn test_source(path: &str) -> Source {
    Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from(path),
    }
}

fn test_discovery_accounting() -> SourceDiscoveryAccounting {
    SourceDiscoveryAccounting {
        checked_status: "succeeded",
        first_error_category: None,
        best_effort_fallback_used: false,
        returned_source_count: 0,
        operational_source_count: 0,
        project_configuration: ProjectConfigurationAccounting::none(),
    }
}

/// A bounded unit as an adapter reports it (the type is not
/// constructible outside its crate), moved to the given coordinates.
fn bounded_entry(
    native_id: &str,
    source_sequence: u64,
    target: telltale_schema::observation::BoundedTarget,
) -> (String, telltale_sources::acquisition::BoundedUnit) {
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::ObservedAt;
    use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};

    let temp = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path: temp.path().join("synthetic-bounded.jsonl"),
    };
    let record = serde_json::json!({"type": "tool_result", "session_id": "synthetic",
            "name": "exec", "output": ["x".repeat(4_097)]});
    std::fs::write(&source.path, format!("{record}\n")).unwrap();
    let options = AcquisitionOptions::new(ObservedAt::new("2026-09-18T12:00:00Z").unwrap());
    let batch = acquire_source(&source, options).unwrap();
    let [unit] = batch.bounded.as_slice() else {
        panic!("expected one bounded unit: {:?}", batch.bounded)
    };
    let mut unit = unit.clone();
    unit.native_id = native_id.to_string();
    unit.source_sequence = source_sequence;
    unit.target = target;
    ("synthetic-source".to_string(), unit)
}

fn warning_codes(warnings: &[serde_json::Value]) -> Vec<&str> {
    warnings
        .iter()
        .map(|warning| warning["code"].as_str().expect("warning code"))
        .collect()
}

#[cfg(test)]
mod activation;

mod durable_state;
mod event_selection;
mod operational_health;
mod processing_accounting;
mod session_summary;
mod source_options;
