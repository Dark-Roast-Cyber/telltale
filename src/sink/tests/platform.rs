use tempfile::tempdir;

use super::super::outbox::{CapacityLimits, WINDOWS_DURABLE_STORAGE_UNSUPPORTED};
use super::super::{
    DeliveryError, DeliveryErrorClass, EventSink, LocalJsonlSink, RotationConfig, SinkSet,
    durable_health_json_from_path_for_platform,
};
use crate::event::{HealthEventInput, health_event_with_metadata};

fn health_event() -> crate::event::Event {
    health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 1,
        rule_count: 1,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    })
}

fn assert_windows_storage_error(error: Box<dyn std::error::Error>) {
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("Windows durable policy must return a structured delivery error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(
        error
            .to_string()
            .contains(WINDOWS_DURABLE_STORAGE_UNSUPPORTED)
    );
}

#[test]
fn simulated_windows_durable_admission_rejects_before_jsonl_append_or_outbox_creation() {
    let temp = tempdir().expect("temporary directory");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
    );
    sinks.add_best_effort("synthetic", Box::new(NoopSink));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["synthetic".to_string()],
        CapacityLimits::default(),
    );

    let error = sinks
        .persist_for_durable_replay_with_failures_for_platform(&[health_event()], true)
        .expect_err("Windows durable admission must be rejected");
    assert_windows_storage_error(error);
    assert!(!log_path.exists());
    assert!(!outbox_path.parent().expect("outbox parent").exists());
    assert!(!outbox_path.exists());
}

#[test]
fn simulated_windows_durable_health_reports_rejection_without_opening_storage() {
    let temp = tempdir().expect("temporary directory");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");

    let health = durable_health_json_from_path_for_platform(&outbox_path, &[], true);
    assert_eq!(health["mode"], "unavailable");
    assert_eq!(health["error"]["class"], "durable_storage");
    assert_eq!(
        health["error"]["message"],
        super::super::outbox::WINDOWS_DURABLE_STORAGE_UNSUPPORTED
    );
    assert_eq!(
        DeliveryError::new(
            DeliveryErrorClass::DurableStorage,
            0,
            super::super::outbox::WINDOWS_DURABLE_STORAGE_UNSUPPORTED,
        )
        .to_string(),
        format!(
            "{} (after 0 attempts)",
            super::super::outbox::WINDOWS_DURABLE_STORAGE_UNSUPPORTED
        )
    );
    assert!(!outbox_path.parent().expect("outbox parent").exists());
    assert!(!outbox_path.exists());
}

struct NoopSink;

impl EventSink for NoopSink {
    fn name(&self) -> &str {
        "synthetic"
    }

    fn emit(&self, _events: &[crate::event::Event]) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
