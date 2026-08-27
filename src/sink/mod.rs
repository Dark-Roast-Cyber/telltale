pub mod config;
mod elastic;
pub mod http;
mod jsonl;
mod splunk_hec;

pub(crate) use elastic::{DEFAULT_ELASTIC_INDEX, ElasticBulkSink, elastic_bulk_action_json};
pub(crate) use jsonl::{LocalJsonlSink, RotationConfig};
pub(crate) use splunk_hec::{SplunkHecConfig, SplunkHecHttpSink};

use crate::event::{Event, PrivacySanitizer, SanitizationContext};
use crate::file_lock::RotationNamespace;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DeliveryPosture {
    DurableFirstWrite,
    BestEffortNoReplay,
    NoEnabledSinks,
}

impl DeliveryPosture {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DurableFirstWrite => "durable_first_write",
            Self::BestEffortNoReplay => "best_effort_no_replay",
            Self::NoEnabledSinks => "no_enabled_sinks",
        }
    }

    pub(crate) fn has_durable_first_write(self) -> bool {
        matches!(self, Self::DurableFirstWrite)
    }
}

pub(crate) trait EventSink {
    /// Operator-facing sink name, used in delivery-failure alerts and logs.
    fn name(&self) -> &str;
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>>;
}

#[cfg(test)]
fn emit_events(sink: &dyn EventSink, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
    sink.emit(events)
}

/// A delivery failure on a non-durable sink, reported back to the caller so it
/// can emit an operational alert and continue.
#[derive(Debug, Clone)]
pub(crate) struct SinkFailure {
    pub name: String,
    pub kind: String,
    pub attempts: u32,
    pub error: String,
}

/// Error type network sinks return from `emit` so the delivery loop can
/// report how many attempts the transport made.
#[derive(Debug)]
pub(crate) struct SinkDeliveryError {
    pub attempts: u32,
    pub message: String,
}

impl std::fmt::Display for SinkDeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (after {} attempts)", self.message, self.attempts)
    }
}

impl std::error::Error for SinkDeliveryError {}

struct SinkEntry {
    sink: Box<dyn EventSink + Send + Sync>,
    kind: &'static str,
    persistence_path: Option<std::path::PathBuf>,
    rotation_namespace: Option<RotationNamespace>,
    /// Durable sinks (the local JSONL file) are the durable first-write and
    /// bounded handoff: a write failure there aborts the scan. Non-durable
    /// (remote) sink failures are collected and reported instead.
    durable: bool,
}

/// The ordered set of sinks a scan delivers events to.
#[derive(Default)]
pub(crate) struct SinkSet {
    entries: Vec<SinkEntry>,
}

impl SinkSet {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub(crate) fn add_durable(
        &mut self,
        kind: &'static str,
        sink: Box<dyn EventSink + Send + Sync>,
    ) {
        self.entries.push(SinkEntry {
            sink,
            kind,
            persistence_path: None,
            rotation_namespace: None,
            durable: true,
        });
    }

    pub(crate) fn add_durable_path_with_rotation(
        &mut self,
        kind: &'static str,
        sink: Box<dyn EventSink + Send + Sync>,
        path: impl Into<std::path::PathBuf>,
        rotation_namespace: Option<RotationNamespace>,
    ) {
        self.entries.push(SinkEntry {
            sink,
            kind,
            persistence_path: Some(path.into()),
            rotation_namespace,
            durable: true,
        });
    }

    pub(crate) fn add_remote(
        &mut self,
        kind: &'static str,
        sink: Box<dyn EventSink + Send + Sync>,
    ) {
        self.entries.push(SinkEntry {
            sink,
            kind,
            persistence_path: None,
            rotation_namespace: None,
            durable: false,
        });
    }

    pub(crate) fn local_persistence_paths(&self) -> Vec<std::path::PathBuf> {
        self.entries
            .iter()
            .filter_map(|entry| entry.persistence_path.clone())
            .collect()
    }

    pub(crate) fn local_rotation_namespaces(&self) -> Vec<RotationNamespace> {
        self.entries
            .iter()
            .filter_map(|entry| entry.rotation_namespace.clone())
            .collect()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn has_durable(&self) -> bool {
        self.entries.iter().any(|entry| entry.durable)
    }

    pub(crate) fn delivery_posture(&self) -> DeliveryPosture {
        if self.entries.is_empty() {
            DeliveryPosture::NoEnabledSinks
        } else if self.has_durable() {
            DeliveryPosture::DurableFirstWrite
        } else {
            DeliveryPosture::BestEffortNoReplay
        }
    }

    /// Deliver a batch to every sink. Durable sinks are always attempted first,
    /// preserving order within each class. A durable sink failure is fatal
    /// (`Err`); remote failures are collected and returned while delivery to
    /// the remaining remote sinks continues.
    pub(crate) fn deliver(
        &self,
        events: &[Event],
    ) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        let mut failures = Vec::new();
        for entry in self.entries.iter().filter(|entry| entry.durable) {
            entry.sink.emit(events)?;
        }
        for entry in self.entries.iter().filter(|entry| !entry.durable) {
            match entry.sink.emit(events) {
                Ok(()) => {}
                Err(err) => {
                    let attempts = err
                        .downcast_ref::<SinkDeliveryError>()
                        .map(|delivery| delivery.attempts)
                        .unwrap_or(1);
                    failures.push(SinkFailure {
                        name: entry.sink.name().to_string(),
                        kind: entry.kind.to_string(),
                        attempts,
                        error: err.to_string(),
                    });
                }
            }
        }
        Ok(failures)
    }

    /// Deliver follow-up delivery-failure alert events, skipping the named
    /// (just-failed) sinks. Errors here are logged to stderr and never
    /// generate further events, so a failing sink cannot alert about itself
    /// recursively. Durable sinks are attempted before remotes, preserving
    /// order within each class; a durable alert failure stops alert delivery.
    pub(crate) fn deliver_alerts(&self, events: &[Event], skip: &[&str]) {
        for entry in self.entries.iter().filter(|entry| entry.durable) {
            if skip.contains(&entry.sink.name()) {
                continue;
            }
            if let Err(err) = entry.sink.emit(events) {
                let rendered = format!(
                    "warning: could not deliver sink-failure alert to sink {}: {err}",
                    entry.sink.name()
                );
                eprintln!(
                    "{}",
                    PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered)
                );
                return;
            }
        }
        for entry in self.entries.iter().filter(|entry| !entry.durable) {
            if skip.contains(&entry.sink.name()) {
                continue;
            }
            if let Err(err) = entry.sink.emit(events) {
                let rendered = format!(
                    "warning: could not deliver sink-failure alert to sink {}: {err}",
                    entry.sink.name()
                );
                eprintln!(
                    "{}",
                    PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered)
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{EventSink, SinkSet};
    use crate::event::{
        ControlledMarker, Event, OperationalAlertInput, check_serialized_event_markers,
        health_event_with_metadata, operational_alert_event,
    };

    fn make_health_event() -> Event {
        health_event_with_metadata(crate::event::HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        })
    }

    struct RecordingSink {
        name: String,
        batches: Arc<Mutex<Vec<usize>>>,
    }

    struct OrderedSink {
        name: String,
        order: Arc<Mutex<Vec<String>>>,
    }

    impl OrderedSink {
        fn new(name: &str, order: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                name: name.to_string(),
                order,
            }
        }
    }

    impl EventSink for OrderedSink {
        fn name(&self) -> &str {
            &self.name
        }

        fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
            self.order.lock().expect("lock").push(self.name.clone());
            Ok(())
        }
    }

    impl RecordingSink {
        fn new(name: &str) -> (Self, Arc<Mutex<Vec<usize>>>) {
            let batches = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    name: name.to_string(),
                    batches: Arc::clone(&batches),
                },
                batches,
            )
        }
    }

    impl EventSink for RecordingSink {
        fn name(&self) -> &str {
            &self.name
        }

        fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
            self.batches.lock().expect("lock").push(events.len());
            Ok(())
        }
    }

    struct FailingSink {
        name: String,
        emit_calls: Arc<Mutex<u32>>,
    }

    impl FailingSink {
        fn new(name: &str) -> (Self, Arc<Mutex<u32>>) {
            let emit_calls = Arc::new(Mutex::new(0));
            (
                Self {
                    name: name.to_string(),
                    emit_calls: Arc::clone(&emit_calls),
                },
                emit_calls,
            )
        }
    }

    impl EventSink for FailingSink {
        fn name(&self) -> &str {
            &self.name
        }

        fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
            *self.emit_calls.lock().expect("lock") += 1;
            Err("connection refused".into())
        }
    }

    #[test]
    fn deliver_collects_remote_failures_and_continues_to_other_sinks() {
        let (failing, _) = FailingSink::new("corp-splunk");
        let (recorder, batches) = RecordingSink::new("second-remote");
        let mut sinks = SinkSet::new();
        sinks.add_remote("splunk_hec", Box::new(failing));
        sinks.add_remote("splunk_hec", Box::new(recorder));

        let failures = sinks
            .deliver(&[make_health_event()])
            .expect("remote failure is not fatal");

        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "corp-splunk");
        assert_eq!(failures[0].kind, "splunk_hec");
        assert!(failures[0].error.contains("connection refused"));
        // The later sink still received the batch.
        assert_eq!(*batches.lock().expect("lock"), vec![1]);
    }

    #[test]
    fn delivery_failures_redact_unsafe_urls_before_alert_serialization() {
        struct UnsafeFailingSink;

        impl EventSink for UnsafeFailingSink {
            fn name(&self) -> &str {
                "remote"
            }

            fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
                Err("request to https://user:TT_PRIVACY_DELIVERY_25@example.invalid/?token=TT_PRIVACY_DELIVERY_25 failed at /home/TT_PRIVACY_DELIVERY_25/.config/state.db".into())
            }
        }

        let mut sinks = SinkSet::new();
        sinks.add_remote("splunk_hec", Box::new(UnsafeFailingSink));
        let failures = sinks
            .deliver(&[make_health_event()])
            .expect("remote failure is collected");
        assert_eq!(failures.len(), 1);
        assert!(failures[0].error.contains("TT_PRIVACY_DELIVERY_25"));

        let alert = operational_alert_event(OperationalAlertInput {
            alert_type: "sink_delivery_failure".to_string(),
            threshold: "attempts_made=1".to_string(),
            actual_value: format!(
                "sink={} type={} error={}",
                failures[0].name, failures[0].kind, failures[0].error
            ),
            scan_duration_ms: None,
            scanner_error_count: None,
        });
        let bytes = serde_json::to_vec(&alert.emittable()).expect("serialize delivery alert");
        assert!(
            check_serialized_event_markers(
                &bytes,
                "delivery-alert",
                &[ControlledMarker {
                    id: "delivery-marker",
                    value: "TT_PRIVACY_DELIVERY_25",
                }],
            )
            .is_ok()
        );
    }

    #[test]
    fn deliver_fails_fast_when_durable_sink_fails() {
        let (failing, _) = FailingSink::new("local");
        let mut sinks = SinkSet::new();
        sinks.add_durable("jsonl", Box::new(failing));

        let result = sinks.deliver(&[make_health_event()]);

        assert!(result.is_err(), "durable sink failure must be fatal");
    }

    #[test]
    fn durable_failure_prevents_remote_delivery_even_when_remote_was_added_first() {
        let (remote, batches) = RecordingSink::new("remote");
        let (durable, _) = FailingSink::new("local");
        let mut sinks = SinkSet::new();
        sinks.add_remote("splunk_hec", Box::new(remote));
        sinks.add_durable("jsonl", Box::new(durable));

        assert!(sinks.deliver(&[make_health_event()]).is_err());
        assert!(
            batches.lock().expect("lock").is_empty(),
            "remote delivery must wait for durable sinks"
        );
    }

    #[test]
    fn deliver_alerts_skips_failed_sinks_and_never_recurses() {
        let (failing, emit_calls) = FailingSink::new("corp-splunk");
        let (recorder, batches) = RecordingSink::new("local");

        let mut sinks = SinkSet::new();
        sinks.add_durable("jsonl", Box::new(recorder));
        sinks.add_remote("splunk_hec", Box::new(failing));

        let events = [make_health_event()];
        let failures = sinks.deliver(&events).expect("deliver");
        assert_eq!(failures.len(), 1);

        let failed_names: Vec<&str> = failures.iter().map(|f| f.name.as_str()).collect();
        sinks.deliver_alerts(&events, &failed_names);

        // The failed sink was skipped: exactly one emit call (the original delivery).
        assert_eq!(*emit_calls.lock().expect("lock"), 1);
        // The healthy durable sink received both the batch and the alert.
        assert_eq!(*batches.lock().expect("lock"), vec![1, 1]);
    }

    #[test]
    fn deliver_alerts_swallows_errors_from_remaining_sinks() {
        let (failing, _) = FailingSink::new("corp-splunk");
        let mut sinks = SinkSet::new();
        sinks.add_remote("splunk_hec", Box::new(failing));

        // No skip: the failing sink receives the alert, fails, and the error
        // is swallowed (stderr only) instead of propagating or recursing.
        sinks.deliver_alerts(&[make_health_event()], &[]);
    }

    #[test]
    fn deliver_alerts_runs_durable_sinks_before_remotes_in_class_order() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut sinks = SinkSet::new();
        sinks.add_remote(
            "splunk_hec",
            Box::new(OrderedSink::new("remote-1", Arc::clone(&order))),
        );
        sinks.add_durable(
            "jsonl",
            Box::new(OrderedSink::new("local-1", Arc::clone(&order))),
        );
        sinks.add_remote(
            "elastic_bulk",
            Box::new(OrderedSink::new("remote-2", Arc::clone(&order))),
        );
        sinks.add_durable(
            "jsonl",
            Box::new(OrderedSink::new("local-2", Arc::clone(&order))),
        );

        sinks.deliver_alerts(&[make_health_event()], &[]);

        assert_eq!(
            *order.lock().expect("lock"),
            vec!["local-1", "local-2", "remote-1", "remote-2"]
        );
    }

    #[test]
    fn durable_alert_failure_stops_before_remote_alert_even_when_remote_was_added_first() {
        let (remote, batches) = RecordingSink::new("remote");
        let (durable, _) = FailingSink::new("local");
        let mut sinks = SinkSet::new();
        sinks.add_remote("splunk_hec", Box::new(remote));
        sinks.add_durable("jsonl", Box::new(durable));

        sinks.deliver_alerts(&[make_health_event()], &[]);

        assert!(
            batches.lock().expect("lock").is_empty(),
            "remote alert must wait for durable alert delivery"
        );
    }

    #[test]
    fn has_durable_reflects_entries() {
        let mut sinks = SinkSet::new();
        assert!(!sinks.has_durable());
        assert!(sinks.is_empty());
        let (remote, _) = RecordingSink::new("remote");
        sinks.add_remote("splunk_hec", Box::new(remote));
        assert!(!sinks.has_durable());
        let (local, _) = RecordingSink::new("local");
        sinks.add_durable("jsonl", Box::new(local));
        assert!(sinks.has_durable());
        assert!(!sinks.is_empty());
    }
}
