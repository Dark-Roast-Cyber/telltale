pub mod config;
mod elastic;
pub mod http;
mod jsonl;
mod splunk_hec;

pub use elastic::{DEFAULT_ELASTIC_INDEX, ElasticBulkSink, elastic_bulk_action_json};
pub use jsonl::{LocalJsonlSink, RotationConfig};
pub use splunk_hec::{SplunkHecConfig, SplunkHecEnvelope, SplunkHecHttpSink, splunk_hec_envelopes};

use crate::event::Event;

pub trait EventSink {
    /// Operator-facing sink name, used in delivery-failure alerts and logs.
    fn name(&self) -> &str;
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>>;
}

pub fn emit_events(
    sink: &dyn EventSink,
    events: &[Event],
) -> Result<(), Box<dyn std::error::Error>> {
    sink.emit(events)
}

/// A delivery failure on a non-durable sink, reported back to the caller so it
/// can emit an operational alert and continue.
#[derive(Debug, Clone)]
pub struct SinkFailure {
    pub name: String,
    pub kind: String,
    pub attempts: u32,
    pub error: String,
}

/// Error type network sinks return from `emit` so the delivery loop can
/// report how many attempts the transport made.
#[derive(Debug)]
pub struct SinkDeliveryError {
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
    /// Durable sinks (the local JSONL file) are the system of record: a write
    /// failure there aborts the scan. Non-durable (remote) sink failures are
    /// collected and reported instead.
    durable: bool,
}

/// The ordered set of sinks a scan delivers events to.
#[derive(Default)]
pub struct SinkSet {
    entries: Vec<SinkEntry>,
}

impl SinkSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_durable(&mut self, kind: &'static str, sink: Box<dyn EventSink + Send + Sync>) {
        self.entries.push(SinkEntry {
            sink,
            kind,
            durable: true,
        });
    }

    pub fn add_remote(&mut self, kind: &'static str, sink: Box<dyn EventSink + Send + Sync>) {
        self.entries.push(SinkEntry {
            sink,
            kind,
            durable: false,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn has_durable(&self) -> bool {
        self.entries.iter().any(|entry| entry.durable)
    }

    /// Deliver a batch to every sink. A durable sink failure is fatal (`Err`);
    /// remote failures are collected and returned while delivery to the
    /// remaining sinks continues.
    pub fn deliver(&self, events: &[Event]) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        let mut failures = Vec::new();
        for entry in &self.entries {
            match entry.sink.emit(events) {
                Ok(()) => {}
                Err(err) if entry.durable => return Err(err),
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
    /// recursively.
    pub fn deliver_alerts(&self, events: &[Event], skip: &[&str]) {
        for entry in &self.entries {
            if skip.contains(&entry.sink.name()) {
                continue;
            }
            if let Err(err) = entry.sink.emit(events) {
                eprintln!(
                    "warning: could not deliver sink-failure alert to sink {}: {err}",
                    entry.sink.name()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{EventSink, SinkSet};
    use crate::event::{Event, health_event_with_metadata};

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
    fn deliver_fails_fast_when_durable_sink_fails() {
        let (failing, _) = FailingSink::new("local");
        let mut sinks = SinkSet::new();
        sinks.add_durable("jsonl", Box::new(failing));

        let result = sinks.deliver(&[make_health_event()]);

        assert!(result.is_err(), "durable sink failure must be fatal");
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
