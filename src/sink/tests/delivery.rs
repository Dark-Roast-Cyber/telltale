use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use tempfile::tempdir;

use super::super::outbox::{CapacityLimits, DeliveryClock, DeliveryState, DeliveryUpdate, Outbox};
use super::super::test_support::{make_health_event, read_mock_request};
use super::super::{
    DeliveryError, DeliveryErrorClass, DeliveryPolicy, EventSink, LocalJsonlSink, PersistenceRole,
    RetryConfig, RotationConfig, SinkSet,
};
use crate::event::{
    ActivityEventInput, ControlledMarker, Event, Evidence, OperationalAlertInput,
    check_serialized_event_markers, operational_alert_event,
};
use telltale_schema::clients::ClientId;

fn marked_event(marker: &str) -> Event {
    crate::event::activity_event(ActivityEventInput {
        client: ClientId::Codex,
        agent: None,
        model: None,
        provider: None,
        session_id: "synthetic-sink-session".to_string(),
        source_path_hash: "synthetic-sink-source".to_string(),
        tool_name: Some("shell".to_string()),
        tags: vec![format!("synthetic:{marker}")],
        evidence: vec![Evidence {
            field: "tool_result".to_string(),
            redacted_value: format!("token={marker}"),
            hash: None,
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("synthetic activity event")
}

fn capacity_limits(max_pending_events: u64, max_pending_bytes: u64) -> CapacityLimits {
    CapacityLimits {
        max_pending_events,
        max_pending_bytes,
    }
}

type RecordedPayloads = Arc<Mutex<Vec<Vec<u8>>>>;
type AlertCallCount = Arc<Mutex<usize>>;

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

#[derive(Clone, Copy)]
enum ScriptedOutcome {
    Success,
    Failure(DeliveryErrorClass),
}

struct ScriptedDurableSink {
    name: String,
    outcomes: Mutex<VecDeque<ScriptedOutcome>>,
    calls: Arc<Mutex<Vec<Vec<u8>>>>,
    alert_calls: Option<Arc<Mutex<usize>>>,
}

impl ScriptedDurableSink {
    fn new(
        name: &str,
        outcomes: impl IntoIterator<Item = ScriptedOutcome>,
    ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                name: name.to_string(),
                outcomes: Mutex::new(outcomes.into_iter().collect()),
                calls: Arc::clone(&calls),
                alert_calls: None,
            },
            calls,
        )
    }

    fn new_with_alerts(
        name: &str,
        outcomes: impl IntoIterator<Item = ScriptedOutcome>,
    ) -> (Self, RecordedPayloads, AlertCallCount) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let alert_calls = Arc::new(Mutex::new(0));
        (
            Self {
                name: name.to_string(),
                outcomes: Mutex::new(outcomes.into_iter().collect()),
                calls: Arc::clone(&calls),
                alert_calls: Some(Arc::clone(&alert_calls)),
            },
            calls,
            alert_calls,
        )
    }
}

impl EventSink for ScriptedDurableSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(alert_calls) = &self.alert_calls {
            *alert_calls.lock().expect("alert calls lock") += 1;
        }
        Ok(())
    }

    fn emit_canonical_once(&self, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.calls
            .lock()
            .expect("calls lock")
            .push(payload.to_vec());
        let outcome = self
            .outcomes
            .lock()
            .expect("outcomes lock")
            .pop_front()
            .unwrap_or(ScriptedOutcome::Success);
        match outcome {
            ScriptedOutcome::Success => Ok(()),
            ScriptedOutcome::Failure(class) => {
                Err(DeliveryError::new(class, 1, "synthetic durable delivery failure").into())
            }
        }
    }
}

struct FakeClock {
    now: AtomicI64,
    monotonic: Mutex<std::time::Instant>,
    dispatch_step: std::time::Duration,
}

impl FakeClock {
    fn new(now: i64) -> Self {
        Self {
            now: AtomicI64::new(now),
            monotonic: Mutex::new(std::time::Instant::now()),
            dispatch_step: std::time::Duration::ZERO,
        }
    }

    fn with_dispatch_step(now: i64, step_millis: u64) -> Self {
        Self {
            dispatch_step: std::time::Duration::from_millis(step_millis),
            ..Self::new(now)
        }
    }

    fn advance(&self, millis: i64) {
        self.now.fetch_add(millis, Ordering::SeqCst);
    }
}

impl DeliveryClock for FakeClock {
    fn now_millis(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }

    fn monotonic_now(&self) -> std::time::Instant {
        let mut now = self.monotonic.lock().expect("monotonic clock lock");
        let instant = *now;
        *now += self.dispatch_step;
        instant
    }
}

fn retry_config(max_attempts: u32, base_delay_ms: u64) -> RetryConfig {
    RetryConfig {
        max_attempts,
        base_delay_ms,
    }
}

fn seed_pending(
    outbox_path: &Path,
    events: &[&Event],
    sink_ids: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut outbox = Outbox::open(outbox_path)?;
    for event in events {
        outbox.insert_event(event, sink_ids)?;
    }
    Ok(())
}

fn durable_sink_set(outbox_path: &Path, sink: ScriptedDurableSink, retry: RetryConfig) -> SinkSet {
    let sink_id = sink.name.clone();
    let mut sinks = SinkSet::new();
    sinks.add_best_effort_with_retry("synthetic", Box::new(sink), retry);
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.to_path_buf(),
        vec![sink_id],
        super::super::outbox::CapacityLimits::default(),
    );
    sinks
}

fn classify_admission(
    result: Result<(), Box<dyn std::error::Error>>,
) -> (bool, Option<DeliveryErrorClass>, String) {
    match result {
        Ok(()) => (true, None, String::new()),
        Err(error) => {
            let class = error
                .downcast_ref::<DeliveryError>()
                .map(|error| error.class);
            (false, class, error.to_string())
        }
    }
}

// Channels order transport completion, not timing. Dropping the release
// guard also unblocks scoped workers if the coordinator assertion panics.
struct ReleaseSend(Option<std::sync::mpsc::Sender<()>>);

impl ReleaseSend {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for ReleaseSend {
    fn drop(&mut self) {
        self.release();
    }
}

struct ControlledDurableSink {
    entered: std::sync::mpsc::Sender<bool>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    calls: Arc<AtomicI64>,
    fails: bool,
}

impl EventSink for ControlledDurableSink {
    fn name(&self) -> &str {
        "remote"
    }

    fn emit(&self, _: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        unreachable!("only canonical attempts are expected")
    }

    fn emit_canonical_once(&self, _: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.send(true)?;
        self.release
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))?;
        if self.fails {
            Err(DeliveryError::new(
                DeliveryErrorClass::SinkApplicationRejected,
                1,
                "synthetic rejection",
            )
            .into())
        } else {
            Ok(())
        }
    }
}

fn paired_sink_set(log: &Path, outbox: &Path, remote: Box<dyn EventSink + Send + Sync>) -> SinkSet {
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            log,
            RotationConfig::disabled(),
        )),
        log.to_path_buf(),
        None,
    );
    sinks.add_best_effort("synthetic", remote);
    sinks.enable_persistent_replay_with_capacity(
        outbox.to_path_buf(),
        vec!["remote".into()],
        CapacityLimits::default(),
    );
    sinks
}

fn assert_dispatch_ownership(first_admits: bool, second_admits: bool) {
    use std::sync::mpsc::channel;
    let directory = tempdir().unwrap();
    let log = directory.path().join("events.jsonl");
    let path = directory.path().join("private/outbox.sqlite");
    let event = make_health_event();
    let prospective = make_health_event();
    LocalJsonlSink::with_rotation(&log, RotationConfig::disabled())
        .emit(std::slice::from_ref(&event))
        .unwrap();
    let mut outbox = Outbox::open(&path).unwrap();
    outbox.reconcile_jsonl(&log, &["remote"]).unwrap();
    let cursor_before = outbox.ingest_cursor().unwrap();
    drop(outbox);
    let journal_before = fs::read(&log).unwrap();
    let _state_a =
        crate::state::StateLock::acquire(&directory.path().join("a-state.json")).unwrap();
    let _state_b =
        crate::state::StateLock::acquire(&directory.path().join("b-state.json")).unwrap();
    let (a_tx, a_rx) = channel();
    let (b_tx, b_rx) = channel();
    let (release_a, wait_a) = channel();
    let (release_b, wait_b) = channel();
    let a_calls = Arc::new(AtomicI64::new(0));
    let b_calls = Arc::new(AtomicI64::new(0));
    let a = paired_sink_set(
        &log,
        &path,
        Box::new(ControlledDurableSink {
            entered: a_tx,
            release: Mutex::new(wait_a),
            calls: a_calls.clone(),
            fails: false,
        }),
    );
    let b = paired_sink_set(
        &log,
        &path,
        Box::new(ControlledDurableSink {
            entered: b_tx.clone(),
            release: Mutex::new(wait_b),
            calls: b_calls.clone(),
            fails: true,
        }),
    );
    let (entered, result_b, ack_before_late_failure) = std::thread::scope(|scope| {
        let mut release_a = ReleaseSend(Some(release_a));
        let mut release_b = ReleaseSend(Some(release_b));
        let first = scope.spawn(|| {
            let result = if first_admits {
                a.persist_for_durable_replay_with_failures(&[])
            } else {
                a.dispatch_durable_with_clock(&FakeClock::new(1_000))
            };
            result
                .map(|failures| failures.len())
                .map_err(|e| e.to_string())
        });
        assert!(
            a_rx.recv_timeout(std::time::Duration::from_secs(10))
                .unwrap()
        );
        let second = scope.spawn(|| {
            let result = if second_admits {
                b.persist_for_durable_replay_with_failures(std::slice::from_ref(&prospective))
            } else {
                b.dispatch_durable_with_clock(&FakeClock::new(1_000))
            };
            let result = result.map(|failures| failures.len()).map_err(|e| {
                let delivery = e
                    .downcast_ref::<DeliveryError>()
                    .expect("structured failure");
                (delivery.class, delivery.attempts)
            });
            let _ = b_tx.send(false);
            result
        });
        let entered = b_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        release_a.release();
        assert_eq!(first.join().unwrap(), Ok(0));
        let row = Outbox::open(&path)
            .unwrap()
            .get_delivery(&event.event_id, "remote")
            .unwrap()
            .unwrap();
        release_b.release();
        (entered, second.join().unwrap(), row.state)
    });
    let outbox = Outbox::open(&path).unwrap();
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .unwrap()
        .unwrap();
    assert_eq!(ack_before_late_failure, DeliveryState::Acked);
    if entered {
        assert_eq!(
            row.state,
            DeliveryState::Dead,
            "old-code late failure overwrites committed ACK"
        );
    }
    assert!(
        !entered,
        "second dispatcher entered send; committed ACK regressed to {:?}",
        row.state
    );
    assert_eq!(result_b, Err((DeliveryErrorClass::DurableStorage, 0)));
    assert_eq!(row.state, DeliveryState::Acked);
    assert_eq!(row.attempts, 1);
    assert_eq!(row.last_error_class, None);
    assert_eq!(outbox.ingest_cursor().unwrap(), cursor_before);
    assert_eq!(fs::read(&log).unwrap(), journal_before);
    assert!(
        outbox
            .get_delivery(&prospective.event_id, "remote")
            .unwrap()
            .is_none()
    );
    drop(outbox);
    assert!(
        b.dispatch_durable_with_clock(&FakeClock::new(2_000))
            .unwrap()
            .is_empty()
    );
    assert_eq!(a_calls.load(Ordering::SeqCst), 1);
    assert_eq!(b_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn dispatch_owner_serializes_standalone_ack_and_late_failure() {
    assert_dispatch_ownership(false, false);
}

#[test]
fn dispatch_owner_serializes_admission_before_standalone() {
    assert_dispatch_ownership(true, false);
}

#[test]
fn dispatch_owner_serializes_standalone_before_admission() {
    assert_dispatch_ownership(false, true);
}

#[test]
fn dispatch_owner_failure_preserves_rows_cursor_and_eligible_rotation() {
    let directory = tempdir().unwrap();
    let log = directory.path().join("events.jsonl");
    let path = directory.path().join("private/outbox.sqlite");
    let local = LocalJsonlSink::with_rotation(
        &log,
        RotationConfig {
            max_size_bytes: 1,
            keep: 0,
        },
    )
    .with_durable_rotation();
    let namespace = local.rotation_namespace().unwrap();
    let first = make_health_event();
    local.emit(std::slice::from_ref(&first)).unwrap();
    local.emit(&[make_health_event()]).unwrap();
    let mut outbox = Outbox::open(&path).unwrap();
    outbox.reconcile_jsonl(&log, &["remote"]).unwrap();
    let cursor = outbox.ingest_cursor().unwrap();
    let row = outbox.get_delivery(&first.event_id, "remote").unwrap();
    drop(outbox);
    let generations = super::super::jsonl::discover_jsonl_generations(&log).unwrap();
    assert_eq!(generations.len(), 2);
    let journal = fs::read(&log).unwrap();
    let (remote, calls) = ScriptedDurableSink::new("remote", []);
    let mut sinks = durable_sink_set(&path, remote, retry_config(3, 1));
    sinks.add_canonical_first_write_path_with_rotation_and_keep(
        "jsonl",
        Box::new(local),
        log.clone(),
        namespace,
        Some(0),
    );
    let lock = super::super::outbox::acquire_admission_lock(&path).unwrap();
    let result = sinks.deliver_durable_with_clock(&FakeClock::new(1_000));
    drop(lock);
    let error = result.expect_err("busy owner must reject before send or pruning");
    let error = error.downcast_ref::<DeliveryError>().unwrap();
    assert_eq!(
        (error.class, error.attempts),
        (DeliveryErrorClass::DurableStorage, 0)
    );
    assert!(calls.lock().unwrap().is_empty());
    let outbox = Outbox::open(&path).unwrap();
    assert_eq!(outbox.get_delivery(&first.event_id, "remote").unwrap(), row);
    assert_eq!(outbox.ingest_cursor().unwrap(), cursor);
    drop(outbox);
    assert_eq!(fs::read(&log).unwrap(), journal);
    assert_eq!(
        super::super::jsonl::discover_jsonl_generations(&log)
            .unwrap()
            .len(),
        2
    );
    assert!(
        sinks
            .deliver_durable_with_clock(&FakeClock::new(1_000))
            .unwrap()
            .is_empty()
    );
    assert_eq!(calls.lock().unwrap().len(), 2);
    assert_eq!(
        super::super::jsonl::discover_jsonl_generations(&log)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn dispatch_owner_unsafe_sidecar_rejects_before_send_or_update() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("private/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&path, &[&event], &["remote"]).unwrap();
    let before = Outbox::open(&path)
        .unwrap()
        .get_delivery(&event.event_id, "remote")
        .unwrap();
    fs::create_dir(path.with_extension("sqlite.lock")).unwrap();
    let (remote, calls) = ScriptedDurableSink::new("remote", []);
    let sinks = durable_sink_set(&path, remote, retry_config(3, 1));
    let error = sinks
        .deliver_durable_with_clock(&FakeClock::new(1_000))
        .unwrap_err();
    let error = error.downcast_ref::<DeliveryError>().unwrap();
    assert_eq!(
        (error.class, error.attempts),
        (DeliveryErrorClass::DurableStorage, 0)
    );
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(
        Outbox::open(&path)
            .unwrap()
            .get_delivery(&event.event_id, "remote")
            .unwrap(),
        before
    );
}

#[test]
fn deliver_collects_remote_failures_and_continues_to_other_sinks() {
    let (failing, _) = FailingSink::new("corp-splunk");
    let (recorder, batches) = RecordingSink::new("second-remote");
    let mut sinks = SinkSet::new();
    sinks.add_best_effort("splunk_hec", Box::new(failing));
    sinks.add_best_effort("splunk_hec", Box::new(recorder));

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
    sinks.add_best_effort("splunk_hec", Box::new(UnsafeFailingSink));
    let failures = sinks
        .deliver(&[make_health_event()])
        .expect("remote failure is collected");
    assert_eq!(failures.len(), 1);
    assert!(!failures[0].error.contains("TT_PRIVACY_DELIVERY_25"));

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
    sinks.add_canonical_first_write("jsonl", Box::new(failing));

    let result = sinks.deliver(&[make_health_event()]);

    assert!(result.is_err(), "durable sink failure must be fatal");
}

#[test]
fn durable_failure_prevents_remote_delivery_even_when_remote_was_added_first() {
    let (remote, batches) = RecordingSink::new("remote");
    let (durable, _) = FailingSink::new("local");
    let mut sinks = SinkSet::new();
    sinks.add_best_effort("splunk_hec", Box::new(remote));
    sinks.add_canonical_first_write("jsonl", Box::new(durable));

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
    sinks.add_canonical_first_write("jsonl", Box::new(recorder));
    sinks.add_best_effort("splunk_hec", Box::new(failing));

    let events = [make_health_event()];
    let failures = sinks.deliver(&events).expect("deliver");
    assert_eq!(failures.len(), 1);

    let failed_names: Vec<&str> = failures.iter().map(|f| f.name.as_str()).collect();
    assert!(sinks.deliver_alerts(&events, &failed_names).unwrap());

    // The failed sink was skipped: exactly one emit call (the original delivery).
    assert_eq!(*emit_calls.lock().expect("lock"), 1);
    // The healthy durable sink received both the batch and the alert.
    assert_eq!(*batches.lock().expect("lock"), vec![1, 1]);
}

#[test]
fn deliver_alerts_swallows_errors_from_remaining_sinks() {
    let (failing, _) = FailingSink::new("corp-splunk");
    let mut sinks = SinkSet::new();
    sinks.add_best_effort("splunk_hec", Box::new(failing));

    // No skip: the failing sink receives the alert, fails, and the error
    // is swallowed (stderr only) instead of propagating or recursing.
    assert!(!sinks.deliver_alerts(&[make_health_event()], &[]).unwrap());
}

#[test]
fn deliver_alerts_runs_durable_sinks_before_remotes_in_class_order() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut sinks = SinkSet::new();
    sinks.add_best_effort(
        "splunk_hec",
        Box::new(OrderedSink::new("remote-1", Arc::clone(&order))),
    );
    sinks.add_canonical_first_write(
        "jsonl",
        Box::new(OrderedSink::new("local-1", Arc::clone(&order))),
    );
    sinks.add_best_effort(
        "elastic_bulk",
        Box::new(OrderedSink::new("remote-2", Arc::clone(&order))),
    );
    sinks.add_canonical_first_write(
        "jsonl",
        Box::new(OrderedSink::new("local-2", Arc::clone(&order))),
    );

    assert!(sinks.deliver_alerts(&[make_health_event()], &[]).unwrap());

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
    sinks.add_best_effort("splunk_hec", Box::new(remote));
    sinks.add_canonical_first_write("jsonl", Box::new(durable));

    assert!(sinks.deliver_alerts(&[make_health_event()], &[]).is_err());

    assert!(
        batches.lock().expect("lock").is_empty(),
        "remote alert must wait for durable alert delivery"
    );
}

#[test]
fn has_durable_reflects_entries() {
    let mut sinks = SinkSet::new();
    assert!(!sinks.has_canonical_first_write());
    assert!(sinks.is_empty());
    let (remote, _) = RecordingSink::new("remote");
    sinks.add_best_effort("splunk_hec", Box::new(remote));
    assert!(!sinks.has_canonical_first_write());
    let (local, _) = RecordingSink::new("local");
    sinks.add_canonical_first_write("jsonl", Box::new(local));
    assert!(sinks.has_canonical_first_write());
    assert!(!sinks.is_empty());
}

#[test]
fn transport_policy_and_persistence_role_are_independent() {
    let (local, _) = RecordingSink::new("local-collector");
    let (remote, _) = RecordingSink::new("remote");
    let mut sinks = SinkSet::new();
    sinks.add_best_effort("local_collector", Box::new(local));
    sinks.add_with_roles(
        "http",
        Box::new(remote),
        DeliveryPolicy::Durable,
        PersistenceRole::DeliveryState,
    );

    assert_eq!(sinks.entries[0].delivery_policy, DeliveryPolicy::BestEffort);
    assert_eq!(sinks.entries[0].persistence_role, PersistenceRole::None);
    assert_eq!(sinks.entries[1].delivery_policy, DeliveryPolicy::Durable);
    assert_eq!(
        sinks.entries[1].persistence_role,
        PersistenceRole::DeliveryState
    );
    assert_eq!(sinks.entries[0].transport, "local_collector");
    assert_eq!(sinks.entries[1].transport, "http");
    assert_eq!(
        sinks.delivery_posture(),
        super::super::DeliveryPosture::BestEffortNoReplay
    );
}

#[test]
fn delivery_error_class_retryability_does_not_depend_on_message() {
    assert!(DeliveryErrorClass::TransportNoResponse.is_retryable());
    assert!(DeliveryErrorClass::Timeout.is_retryable());
    assert!(DeliveryErrorClass::HttpStatus { status: 429 }.is_retryable());
    assert!(DeliveryErrorClass::HttpStatus { status: 503 }.is_retryable());
    assert!(!DeliveryErrorClass::AuthenticationBlocked { status: 403 }.is_retryable());
    assert!(!DeliveryErrorClass::SinkApplicationRejected.is_retryable());
    assert!(!DeliveryErrorClass::PayloadCollision.is_retryable());
    assert!(!DeliveryErrorClass::DurableStorage.is_retryable());
    assert_eq!(
        DeliveryErrorClass::HttpStatus { status: 503 }.as_str(),
        "http_status"
    );
    let error = DeliveryError::new(
        DeliveryErrorClass::TransportNoResponse,
        2,
        "connection refused https://user:TT_PRIVACY_DELIVERY_26@example.invalid/path",
    );
    assert_eq!(error.class, DeliveryErrorClass::TransportNoResponse);
    assert!(!error.to_string().contains("TT_PRIVACY_DELIVERY_26"));
}

#[test]
fn persistent_replay_prunes_ingested_rotation_before_unavailable_delivery() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = marked_event("TT_SINK_ROTATION_FIRST_26");
    let second = marked_event("TT_SINK_ROTATION_SECOND_26");
    let sink = LocalJsonlSink::with_rotation(
        &log_path,
        RotationConfig {
            max_size_bytes: 1,
            keep: 0,
        },
    )
    .with_durable_rotation();
    let namespace = sink.rotation_namespace().expect("rotation namespace");
    let (remote, _) = ScriptedDurableSink::new(
        "remote",
        [ScriptedOutcome::Failure(
            DeliveryErrorClass::TransportNoResponse,
        )],
    );
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation_and_keep(
        "jsonl",
        Box::new(sink),
        log_path.clone(),
        namespace,
        Some(0),
    );
    sinks.add_best_effort("http", Box::new(remote));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path,
        vec!["remote".to_string()],
        CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("persist first event");
    let pre_admission_failures = sinks
        .persist_for_durable_replay_with_failures(std::slice::from_ref(&second))
        .expect("persist and prune rotated event");
    assert_eq!(pre_admission_failures.len(), 1);
    let generations = crate::sink::jsonl::discover_jsonl_generations(&log_path)
        .expect("discover post-prune generations");
    assert!(generations.iter().any(|generation| generation.is_active));
    assert!(generations.iter().all(|generation| generation.is_active));

    let failures = sinks.deliver_durable().expect("post-admission dispatch");
    assert!(failures.is_empty());
}

#[test]
fn persistent_replay_persists_canonical_jsonl_and_outbox_before_delivery() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    let sink = LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled());
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(sink),
        log_path.clone(),
        None,
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path,
        vec!["remote".to_string()],
        super::super::outbox::CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("persistent handoff");

    let output = std::fs::read_to_string(log_path).expect("canonical JSONL");
    assert_eq!(output.lines().count(), 1);
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let outbox = Outbox::open(outbox_path).expect("open outbox");
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("outbox event")
            .is_some()
    );
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "remote")
            .expect("outbox delivery")
            .expect("pending delivery")
            .state,
        DeliveryState::Pending
    );
}

#[cfg(unix)]
#[test]
fn persistent_replay_classifies_unresolvable_rollback_journal_without_mutation() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("TT_OUTBOX_PATH_PRIVATE_175.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = make_health_event();
    let second = make_health_event();
    let (remote, calls) = ScriptedDurableSink::new("remote", [ScriptedOutcome::Success]);
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort_with_retry("synthetic", Box::new(remote), retry_config(3, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        CapacityLimits::default(),
    );
    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("admit first event");
    let outbox = Outbox::open_read_only(&outbox_path).expect("read admitted outbox");
    let cursor_before = outbox.ingest_cursor().expect("admitted cursor");
    assert!(cursor_before.is_some());
    let delivery_before = outbox
        .get_delivery(&first.event_id, "remote")
        .expect("admitted delivery")
        .expect("pending delivery");
    assert_eq!(delivery_before.state, DeliveryState::Pending);
    drop(outbox);
    let snapshots = [
        log_path.clone(),
        outbox_path.clone(),
        log_path.with_file_name("TT_OUTBOX_PATH_PRIVATE_175.jsonl.lock"),
        outbox_path.with_file_name("outbox.sqlite.lock"),
    ]
    .map(|path| {
        let bytes = fs::read(&path).expect("persistence snapshot");
        (path, bytes)
    });

    // A dangling journal reaches canonicalization's ENOENT deterministically
    // after symlink_metadata finds it, without racing a SQLite transaction.
    let journal_path = outbox_path.with_file_name("outbox.sqlite-journal");
    let missing_target = directory.path().join("TT_OUTBOX_PATH_PRIVATE_175-missing");
    symlink(&missing_target, &journal_path).expect("dangling rollback journal");
    assert!(
        fs::symlink_metadata(&journal_path)
            .expect("journal symlink exists")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::canonicalize(&journal_path)
            .expect_err("journal target is missing")
            .kind(),
        std::io::ErrorKind::NotFound
    );

    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect_err("unresolvable rollback journal must fail closed");
    assert!(calls.lock().expect("calls lock").is_empty());
    for (path, before) in snapshots {
        assert_eq!(fs::read(path).expect("unchanged persistence bytes"), before);
    }
    assert_eq!(
        fs::read_link(&journal_path).expect("unchanged rollback journal symlink"),
        missing_target
    );
    assert!(!missing_target.exists());
    fs::remove_file(&journal_path).expect("remove synthetic dangling journal");
    let outbox = Outbox::open_read_only(&outbox_path).expect("read unchanged outbox");
    assert_eq!(
        outbox.ingest_cursor().expect("unchanged cursor"),
        cursor_before
    );
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "remote")
            .expect("unchanged delivery"),
        Some(delivery_before)
    );
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("rejected event lookup")
            .is_none()
    );

    let delivery = error
        .downcast_ref::<DeliveryError>()
        .unwrap_or_else(|| panic!("expected structured path-validation error, got {error:?}"));
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert_eq!(delivery.attempts, 0);
    assert!(
        delivery
            .message
            .starts_with("outbox validate JSONL/outbox paths:")
    );
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_OUTBOX_PATH_PRIVATE_175"));
    assert!(
        !delivery
            .message
            .contains(directory.path().to_str().expect("temp path"))
    );
    assert!(!delivery.message.chars().any(char::is_control));
}

#[test]
fn persistent_replay_rejects_before_append_when_pending_capacity_is_full() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = marked_event("TT_CAPACITY_SINK_FIRST_26");
    let second = marked_event("TT_CAPACITY_SINK_SECOND_26");
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("first event persists");
    let before = fs::read(&log_path).expect("canonical JSONL");
    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect_err("second event exceeds pending capacity");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured capacity error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(delivery.message.contains("limit_kind=pending_events"));
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_CAPACITY_SINK"));
    assert_eq!(
        fs::read(&log_path).expect("canonical JSONL unchanged"),
        before
    );
    sinks.durable_capacity_limits = capacity_limits(0, 0);
    sinks
        .persist_for_durable_replay(&[])
        .expect("recovery-only admission must not reject already accepted work");
    assert_eq!(fs::read(&log_path).expect("no empty append"), before);
    assert_eq!(
        fs::read_to_string(&log_path)
            .expect("canonical JSONL")
            .lines()
            .count(),
        1
    );

    let outbox = Outbox::open(outbox_path).expect("reopen outbox");
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("second event lookup")
            .is_none()
    );
    assert!(
        outbox
            .get_event(&first.event_id)
            .expect("first event lookup")
            .is_some()
    );
}

#[test]
fn slow_http_backlog_does_not_delay_fresh_first_write_by_backlog_length() {
    use std::io::Write;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};
    let directory = tempdir().unwrap();
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let backlog = (0..100).map(|_| make_health_event()).collect::<Vec<_>>();
    LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled())
        .emit(&backlog)
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/ingest", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = std::thread::spawn(move || {
        let mut requests = 0;
        while !server_stop.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            read_mock_request(&mut stream);
            std::thread::sleep(Duration::from_millis(50));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{\"code\":0}").unwrap();
            requests += 1;
        }
        requests
    });
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort(
        "splunk_hec",
        Box::new(
            super::super::SplunkHecHttpSink::new(
                endpoint,
                "synthetic".into(),
                super::super::SplunkHecConfig::default(),
            )
            .with_name("remote"),
        ),
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".into()],
        capacity_limits(1000, u64::MAX),
    );
    let fresh = make_health_event();
    let started = Instant::now();
    let admitted = sinks.persist_for_durable_replay(std::slice::from_ref(&fresh));
    let latency = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    let requests = server.join().unwrap();
    admitted.unwrap();
    assert!((1..=16).contains(&requests));
    assert!(
        latency < Duration::from_secs(2),
        "first-write latency: {latency:?}"
    );
    assert!(
        fs::read_to_string(&log_path)
            .unwrap()
            .contains(&fresh.event_id)
    );
    let outbox = Outbox::open(&outbox_path).unwrap();
    assert_eq!(
        outbox
            .get_delivery(&fresh.event_id, "remote")
            .unwrap()
            .unwrap()
            .state,
        DeliveryState::Pending
    );
    assert!(backlog.iter().any(|event| {
        outbox
            .get_delivery(&event.event_id, "remote")
            .unwrap()
            .unwrap()
            .state
            == DeliveryState::Pending
    }));
    eprintln!(
        "synthetic backlog=100 delay=50ms requests={requests} first_write_ms={}",
        latency.as_millis()
    );
}

#[test]
fn durable_dispatch_bounds_each_sink_and_leaves_replayable_work() {
    let directory = tempdir().unwrap();
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    let (first, first_calls) =
        ScriptedDurableSink::new("first", (0..40).map(|_| ScriptedOutcome::Success));
    let (second, second_calls) =
        ScriptedDurableSink::new("second", (0..40).map(|_| ScriptedOutcome::Success));
    sinks.add_best_effort_with_retry("synthetic", Box::new(first), retry_config(3, 1));
    sinks.add_best_effort_with_retry("synthetic", Box::new(second), retry_config(3, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["first".into(), "second".into()],
        capacity_limits(100, u64::MAX),
    );
    let events = (0..40).map(|_| make_health_event()).collect::<Vec<_>>();
    sinks.persist_for_durable_replay(&events).unwrap();
    let clock = FakeClock::new(1_000);
    sinks.deliver_durable_with_clock(&clock).unwrap();
    for calls in [&first_calls, &second_calls] {
        assert_eq!(calls.lock().unwrap().len(), 16);
    }
    let outbox = Outbox::open(&outbox_path).unwrap();
    assert!(events.iter().any(|event| {
        outbox
            .get_delivery(&event.event_id, "first")
            .unwrap()
            .unwrap()
            .state
            == DeliveryState::Pending
    }));
    drop(outbox);
    for _ in 0..2 {
        sinks.deliver_durable_with_clock(&clock).unwrap();
    }
    assert_eq!(first_calls.lock().unwrap().len(), 40);
    assert_eq!(second_calls.lock().unwrap().len(), 40);
}

#[test]
fn full_pending_queue_drains_before_new_admission() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = make_health_event();
    let second = make_health_event();
    let (remote, calls) = ScriptedDurableSink::new(
        "remote",
        [ScriptedOutcome::Success, ScriptedOutcome::Success],
    );
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort_with_retry("synthetic", Box::new(remote), retry_config(3, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("admit first event");
    let failures = sinks
        .persist_for_durable_replay_with_failures(std::slice::from_ref(&second))
        .expect("drain first event before admitting second");
    assert!(failures.is_empty());
    assert_eq!(calls.lock().expect("calls lock").len(), 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "remote")
            .expect("first delivery")
            .expect("first row")
            .state,
        DeliveryState::Acked
    );
    assert_eq!(
        outbox
            .get_delivery(&second.event_id, "remote")
            .expect("second delivery")
            .expect("second row")
            .state,
        DeliveryState::Pending
    );
    drop(outbox);

    sinks.deliver_durable().expect("drain newly admitted event");
    assert_eq!(calls.lock().expect("calls lock").len(), 2);
}

#[test]
fn blocked_delivery_stays_blocked_until_release_then_drains_before_admission() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = make_health_event();
    let second = make_health_event();
    let (remote, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
            ScriptedOutcome::Success,
            ScriptedOutcome::Success,
        ],
    );
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort_with_retry("synthetic", Box::new(remote), retry_config(3, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("admit first event");
    let before = fs::read(&log_path).expect("canonical JSONL before blocked admission");
    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect_err("blocked work must keep the queue full");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured capacity error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert_eq!(
        fs::read(&log_path).expect("canonical JSONL after blocked rejection"),
        before
    );
    assert_eq!(calls.lock().expect("calls lock").len(), 1);
    {
        let outbox = Outbox::open(&outbox_path).expect("reopen blocked outbox");
        assert_eq!(
            outbox
                .get_delivery(&first.event_id, "remote")
                .expect("blocked delivery")
                .expect("blocked row")
                .state,
            DeliveryState::Blocked
        );
        assert!(
            outbox
                .get_delivery(&second.event_id, "remote")
                .expect("rejected delivery")
                .is_none()
        );
    }

    let mut outbox = Outbox::open(&outbox_path).expect("open blocked outbox for release");
    assert_eq!(
        outbox
            .release_blocked_for_sink("remote", super::super::outbox::unix_millis())
            .expect("release blocked sink"),
        1
    );
    drop(outbox);

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect("release drains before admitting second event");
    assert_eq!(calls.lock().expect("calls lock").len(), 2);
    let outbox = Outbox::open(&outbox_path).expect("reopen released outbox");
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "remote")
            .expect("released first delivery")
            .expect("released first row")
            .state,
        DeliveryState::Acked
    );
    assert_eq!(
        outbox
            .get_delivery(&second.event_id, "remote")
            .expect("second delivery")
            .expect("second row")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn concurrent_same_pair_admission_is_capacity_bounded_and_cursor_consistent() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    drop(Outbox::open(&outbox_path).expect("initialize shared outbox before concurrent admission"));
    let first = make_health_event();
    let second = make_health_event();
    let first_id = first.event_id.clone();
    let second_id = second.event_id.clone();

    // Persistence-only admission cannot free capacity through predrain,
    // even when the threads acquire ownership sequentially.
    let mut first_sinks = SinkSet::new();
    first_sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    first_sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    let mut second_sinks = SinkSet::new();
    second_sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    second_sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first_handle = std::thread::spawn(move || {
        first_barrier.wait();
        classify_admission(first_sinks.persist_for_durable_replay(&[first]))
    });
    let second_barrier = Arc::clone(&barrier);
    let second_handle = std::thread::spawn(move || {
        second_barrier.wait();
        classify_admission(second_sinks.persist_for_durable_replay(&[second]))
    });
    barrier.wait();
    let results = [
        first_handle.join().expect("first admission thread"),
        second_handle.join().expect("second admission thread"),
    ];

    assert_eq!(
        results.iter().filter(|result| result.0).count(),
        1,
        "admission results: {results:?}"
    );
    let loser = results
        .iter()
        .find(|result| !result.0)
        .expect("one admission must lose");
    assert_eq!(
        loser.1,
        Some(DeliveryErrorClass::DurableStorage),
        "admission results: {results:?}"
    );
    assert!(!loser.2.is_empty(), "admission results: {results:?}");

    let bytes = fs::read(&log_path).expect("canonical JSONL after contention");
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
    let admitted_id = serde_json::from_slice::<serde_json::Value>(
        bytes.strip_suffix(b"\n").expect("newline-terminated event"),
    )
    .expect("admitted event JSON")
    .get("event_id")
    .and_then(serde_json::Value::as_str)
    .expect("admitted event ID")
    .to_string();
    assert!(admitted_id == first_id || admitted_id == second_id);

    let outbox = Outbox::open(&outbox_path).expect("reopen contended outbox");
    assert!(
        outbox
            .get_event(&admitted_id)
            .expect("admitted event lookup")
            .is_some()
    );
    let rejected_id = if admitted_id == first_id {
        second_id
    } else {
        first_id
    };
    assert!(
        outbox
            .get_event(&rejected_id)
            .expect("rejected event lookup")
            .is_none()
    );
    assert_eq!(
        outbox
            .ingest_cursor()
            .expect("contention cursor lookup")
            .expect("contention cursor")
            .byte_offset,
        bytes.len() as u64
    );
}

#[test]
fn persistent_replay_rejects_committed_unread_jsonl_before_append() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = marked_event("TT_CAPACITY_SINK_UNREAD_FIRST_26");
    let second = marked_event("TT_CAPACITY_SINK_UNREAD_SECOND_26");
    LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled())
        .emit(std::slice::from_ref(&first))
        .expect("committed canonical JSONL");
    let outbox = Outbox::open(&outbox_path).expect("create empty outbox");
    drop(outbox);
    let before = fs::read(&log_path).expect("canonical JSONL");

    let attempt = || {
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["remote".to_string()],
            capacity_limits(1, u64::MAX),
        );
        sinks.persist_for_durable_replay(std::slice::from_ref(&second))
    };

    for error in [
        attempt().expect_err("unread event consumes the one-event capacity"),
        attempt().expect_err("the same result survives outbox reopen"),
    ] {
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured capacity error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(delivery.message.contains("limit_kind=pending_events"));
        assert!(delivery.message.len() <= 200);
        assert!(!delivery.message.contains("TT_CAPACITY_SINK"));
    }
    assert_eq!(
        fs::read(&log_path).expect("canonical JSONL unchanged"),
        before
    );
    let outbox = Outbox::open(outbox_path).expect("reopen empty outbox");
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("second event lookup")
            .is_none()
    );
    assert!(
        outbox
            .get_event(&first.event_id)
            .expect("first recovered event lookup")
            .is_some(),
        "the already committed event must be reconciled before the new-event gate"
    );
    let cursor = outbox
        .ingest_cursor()
        .expect("recovered cursor lookup")
        .expect("recovered cursor");
    assert_eq!(cursor.byte_offset, before.len() as u64);
}

#[test]
fn persistent_replay_recovers_before_capacity_scan_when_unread_bytes_exceed_limit() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = marked_event("TT_CAPACITY_SINK_BOUNDED_RECOVERY_FIRST_26");
    let second = marked_event("TT_CAPACITY_SINK_BOUNDED_RECOVERY_SECOND_26");
    LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled())
        .emit(std::slice::from_ref(&first))
        .expect("committed canonical JSONL");
    let before = fs::read(&log_path).expect("canonical JSONL");
    assert!(before.len() > 1, "synthetic record must exceed scan limit");

    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );
    // The production bound remains 64 MiB. This injected test limit makes
    // the already-committed record exceed the unread scan bound without
    // allocating a 64 MiB fixture. Recovery must advance the cursor first.
    sinks.set_durable_capacity_scan_limit((before.len() as u64) - 1);

    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect_err("new event must be rejected after recovery fills capacity");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured capacity error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(delivery.message.contains("limit_kind=pending_events"));
    assert!(
        !delivery
            .message
            .contains("capacity scan exceeds the bounded inspection range")
    );
    assert_eq!(
        fs::read(&log_path).expect("canonical JSONL unchanged"),
        before
    );

    let outbox = Outbox::open(outbox_path).expect("reopen recovered outbox");
    assert!(
        outbox
            .get_event(&first.event_id)
            .expect("first recovered event lookup")
            .is_some()
    );
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("prospective event lookup")
            .is_none()
    );
    assert_eq!(
        outbox
            .ingest_cursor()
            .expect("cursor lookup")
            .expect("recovered cursor")
            .byte_offset,
        before.len() as u64
    );
}

#[test]
fn persistent_delivery_alert_is_admitted_once_to_jsonl_and_outbox() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    let alert = operational_alert_event(OperationalAlertInput {
        alert_type: "sink_delivery_failure".to_string(),
        threshold: "attempts_made=1".to_string(),
        actual_value: "sink=synthetic-remote type=synthetic class=transport_no_response"
            .to_string(),
        scan_duration_ms: None,
        scanner_error_count: None,
    });
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["synthetic-remote".to_string()],
        CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("persist original event");
    sinks
        .persist_for_durable_replay(std::slice::from_ref(&alert))
        .expect("persist delivery alert");

    let lines = fs::read_to_string(&log_path)
        .expect("canonical JSONL")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSONL event"))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line["event_id"] == event.event_id)
            .count(),
        1
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line["event_id"] == alert.event_id)
            .count(),
        1
    );

    let outbox = Outbox::open(outbox_path).expect("reopen outbox");
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("original event")
            .is_some()
    );
    assert!(
        outbox
            .get_event(&alert.event_id)
            .expect("alert event")
            .is_some()
    );
    assert!(
        outbox
            .get_delivery(&alert.event_id, "synthetic-remote")
            .expect("alert delivery lookup")
            .is_none(),
        "sink-delivery alerts must not become durable replay work"
    );
}

#[test]
fn full_capacity_rejects_delivery_alert_before_append_without_recursion() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    let alert = operational_alert_event(OperationalAlertInput {
        alert_type: "sink_delivery_failure".to_string(),
        threshold: "attempts_made=1".to_string(),
        actual_value: "sink=failed-remote type=synthetic class=transport_no_response".to_string(),
        scan_duration_ms: None,
        scanner_error_count: None,
    });
    let (failed, failed_calls) = ScriptedDurableSink::new(
        "failed-remote",
        [ScriptedOutcome::Failure(
            DeliveryErrorClass::AuthenticationBlocked { status: 403 },
        )],
    );
    let (healthy, healthy_calls, healthy_alert_calls) =
        ScriptedDurableSink::new_with_alerts("healthy-remote", [ScriptedOutcome::Success]);
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort_with_retry("synthetic", Box::new(healthy), retry_config(1, 1));
    sinks.add_best_effort_with_retry("synthetic", Box::new(failed), retry_config(1, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["failed-remote".to_string(), "healthy-remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("persist original event");
    let failures = sinks
        .dispatch_durable_with_clock(&FakeClock::new(7_000))
        .expect("record failed delivery");
    assert_eq!(failures.len(), 1);
    let before = fs::read(&log_path).expect("canonical JSONL before alert");

    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&alert))
        .expect_err("full capacity must reject alert before append");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured capacity error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert_eq!(
        fs::read(&log_path).expect("unchanged canonical JSONL"),
        before
    );

    let failed_names = failures
        .iter()
        .map(|failure| failure.name.as_str())
        .collect::<Vec<_>>();
    assert!(
        !sinks
            .deliver_alerts(std::slice::from_ref(&alert), &failed_names)
            .unwrap()
    );
    assert_eq!(failed_calls.lock().expect("failed calls").len(), 1);
    assert_eq!(healthy_calls.lock().expect("healthy calls").len(), 1);
    assert_eq!(*healthy_alert_calls.lock().expect("healthy alert calls"), 0);

    let outbox = Outbox::open(outbox_path).expect("reopen outbox");
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("original event")
            .is_some()
    );
    assert!(
        outbox
            .get_event(&alert.event_id)
            .expect("alert event")
            .is_none()
    );
}

#[test]
fn durable_delivery_failure_alert_is_one_time_and_reaches_healthy_sinks() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    let (failed, failed_calls) = ScriptedDurableSink::new(
        "failed-remote",
        [ScriptedOutcome::Failure(
            DeliveryErrorClass::TransportNoResponse,
        )],
    );
    let (healthy, healthy_calls, healthy_alert_calls) =
        ScriptedDurableSink::new_with_alerts("healthy-remote", [ScriptedOutcome::Success]);
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort_with_retry("synthetic", Box::new(failed), retry_config(1, 1));
    sinks.add_best_effort_with_retry("synthetic", Box::new(healthy), retry_config(1, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["failed-remote".to_string(), "healthy-remote".to_string()],
        CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("admit source event");
    let failures = sinks
        .dispatch_durable_with_clock(&FakeClock::new(8_000))
        .expect("record one failed sink and one healthy sink");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].name, "failed-remote");
    assert_eq!(failed_calls.lock().expect("failed calls").len(), 1);
    assert_eq!(healthy_calls.lock().expect("healthy calls").len(), 1);

    let alert = operational_alert_event(OperationalAlertInput {
        alert_type: "sink_delivery_failure".to_string(),
        threshold: format!("attempts_made={}", failures[0].attempts),
        actual_value: format!(
            "sink={} type={} class={}",
            failures[0].name,
            failures[0].kind,
            failures[0].class.as_str()
        ),
        scan_duration_ms: None,
        scanner_error_count: None,
    });
    assert_eq!(alert.check_name.as_deref(), Some("sink_delivery"));
    sinks
        .persist_for_durable_replay(std::slice::from_ref(&alert))
        .expect("admit operational alert once");
    assert!(
        sinks
            .deliver_alerts(std::slice::from_ref(&alert), &[failures[0].name.as_str()])
            .unwrap()
    );
    assert_eq!(
        *healthy_alert_calls.lock().expect("healthy alert calls"),
        1,
        "healthy durable sink receives the one-time operational signal"
    );
    assert_eq!(failed_calls.lock().expect("failed calls").len(), 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen alert outbox");
    assert!(
        outbox
            .get_delivery(&alert.event_id, "failed-remote")
            .expect("failed alert delivery lookup")
            .is_none()
    );
    assert!(
        outbox
            .get_delivery(&alert.event_id, "healthy-remote")
            .expect("healthy alert delivery lookup")
            .is_none()
    );
    drop(outbox);

    for _ in 0..3 {
        assert!(
            sinks
                .dispatch_durable_with_clock(&FakeClock::new(8_000))
                .expect("later durable cycle")
                .is_empty(),
            "delivery-failure alerts must not recurse into later cycles"
        );
    }
    assert_eq!(*healthy_alert_calls.lock().expect("healthy alert calls"), 1);
}

#[test]
fn persistent_replay_rejects_uncertain_capacity_before_append() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = marked_event("TT_CAPACITY_SINK_UNCERTAIN_FIRST_26");
    let second = marked_event("TT_CAPACITY_SINK_UNCERTAIN_SECOND_26");
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(10, u64::MAX),
    );
    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("initialize durable journal metadata");

    fs::OpenOptions::new()
        .write(true)
        .open(&log_path)
        .expect("open journal for deterministic truncation")
        .set_len(0)
        .expect("truncate journal");
    let after_truncation = fs::read(&log_path).expect("truncated JSONL");
    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect_err("uncertain journal capacity must fail closed");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured durable storage error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(delivery.message.len() <= 200);
    assert!(!delivery.message.contains("TT_CAPACITY_SINK"));
    assert_eq!(
        fs::read(&log_path).expect("journal unchanged"),
        after_truncation
    );

    let outbox = Outbox::open(outbox_path).expect("reopen outbox");
    assert!(
        outbox
            .get_event(&second.event_id)
            .expect("second event lookup")
            .is_none()
    );
}

#[test]
fn persistent_replay_delivers_canonical_jsonl_only_once() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    let sink = LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled());
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(sink),
        log_path.clone(),
        None,
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path,
        vec!["remote".to_string()],
        super::super::outbox::CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("persistent handoff");
    sinks
        .deliver_best_effort(std::slice::from_ref(&event))
        .expect("best-effort delivery");

    let output = std::fs::read_to_string(log_path).expect("canonical JSONL");
    assert_eq!(output.lines().count(), 1);
}

#[test]
fn persistent_replay_survives_best_effort_failure_after_state_handoff() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let state_path = directory.path().join("state.json");
    let event = make_health_event();
    let canonical = LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled());
    let (remote, _) = FailingSink::new("best-effort-remote");
    let (durable, _) = RecordingSink::new("durable-remote");
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(canonical),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort("synthetic", Box::new(remote));
    sinks.add_best_effort("synthetic", Box::new(durable));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["durable-remote".to_string()],
        super::super::outbox::CapacityLimits::default(),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&event))
        .expect("durable persistence");
    crate::state::ScanState::default()
        .prepare_atomic_save(&state_path)
        .expect("prepare scanner state")
        .install_replace(&state_path)
        .expect("install scanner state");
    let failures = sinks
        .deliver_best_effort(std::slice::from_ref(&event))
        .expect("best-effort failure is reported");
    assert_eq!(failures.len(), 1);

    assert_eq!(
        std::fs::read_to_string(log_path)
            .expect("JSONL")
            .lines()
            .count(),
        1
    );
    let outbox = Outbox::open(outbox_path).expect("reopen outbox");
    assert!(
        outbox
            .get_event(&event.event_id)
            .expect("outbox event")
            .is_some()
    );
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "durable-remote")
            .expect("outbox delivery")
            .expect("pending delivery")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn durable_retryable_failure_waits_for_the_fake_clock_before_ack() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::TransportNoResponse),
            ScriptedOutcome::Success,
        ],
    );
    let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 100));
    let clock = FakeClock::new(1_000);

    let failures = sinks
        .dispatch_durable_with_clock(&clock)
        .expect("schedule retry");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].class, DeliveryErrorClass::TransportNoResponse);
    assert_eq!(calls.lock().expect("calls lock").len(), 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("pending row");
    assert_eq!(row.state, DeliveryState::Pending);
    assert_eq!(row.next_attempt_at, Some(1_100));
    assert_eq!(
        row.last_error_class,
        Some(DeliveryErrorClass::TransportNoResponse)
    );
    assert!(
        outbox
            .next_ready_delivery("remote", clock.now_millis())
            .expect("ready lookup")
            .is_none()
    );
    drop(outbox);

    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("not due dispatch");
    assert_eq!(calls.lock().expect("calls lock").len(), 1);

    clock.advance(100);
    let failures = sinks
        .dispatch_durable_with_clock(&clock)
        .expect("retry succeeds");
    assert!(failures.is_empty());
    assert_eq!(calls.lock().expect("calls lock").len(), 2);
    let outbox = Outbox::open(&outbox_path).expect("reopen acked outbox");
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("acked row");
    assert_eq!(row.state, DeliveryState::Acked);
    assert_eq!(row.next_attempt_at, None);
}

#[test]
fn pending_retry_time_survives_outbox_and_sink_set_restart() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");
    let clock = FakeClock::new(2_000);

    let (first_sink, first_calls) = ScriptedDurableSink::new(
        "remote",
        [ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus {
            status: 503,
        })],
    );
    {
        let sinks = durable_sink_set(&outbox_path, first_sink, retry_config(3, 250));
        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("schedule retry before restart");
    }
    assert_eq!(first_calls.lock().expect("calls lock").len(), 1);

    let reopened = Outbox::open(&outbox_path).expect("reopen outbox");
    let row = reopened
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("pending row");
    assert_eq!(row.state, DeliveryState::Pending);
    assert_eq!(row.next_attempt_at, Some(2_250));
    drop(reopened);

    let (second_sink, second_calls) =
        ScriptedDurableSink::new("remote", [ScriptedOutcome::Success]);
    let restarted_sinks = durable_sink_set(&outbox_path, second_sink, retry_config(3, 250));
    restarted_sinks
        .dispatch_durable_with_clock(&clock)
        .expect("restart does not send early");
    assert!(second_calls.lock().expect("calls lock").is_empty());

    clock.advance(250);
    restarted_sinks
        .dispatch_durable_with_clock(&clock)
        .expect("restart replays when due");
    assert_eq!(second_calls.lock().expect("calls lock").len(), 1);
    let reopened = Outbox::open(&outbox_path).expect("reopen acked outbox");
    assert_eq!(
        reopened
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("acked row")
            .state,
        DeliveryState::Acked
    );
}

#[test]
fn http_429_and_5xx_are_pending_until_a_later_success() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 429 }),
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 503 }),
            ScriptedOutcome::Success,
        ],
    );
    let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
    let clock = FakeClock::new(3_000);

    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("schedule 429 retry");
    let outbox = Outbox::open(&outbox_path).expect("reopen after 429");
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("pending row");
    assert_eq!(row.state, DeliveryState::Pending);
    assert_eq!(row.next_attempt_at, Some(3_010));
    assert_eq!(
        row.last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 429 })
    );
    drop(outbox);

    clock.advance(10);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("schedule 5xx retry");
    let outbox = Outbox::open(&outbox_path).expect("reopen after 5xx");
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("pending row");
    assert_eq!(row.state, DeliveryState::Pending);
    assert_eq!(row.next_attempt_at, Some(3_030));
    assert_eq!(
        row.last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 503 })
    );
    drop(outbox);

    clock.advance(20);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("5xx retry succeeds");
    assert_eq!(calls.lock().expect("calls lock").len(), 3);
    let outbox = Outbox::open(&outbox_path).expect("reopen successful outbox");
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("acked row")
            .state,
        DeliveryState::Acked
    );
}

#[test]
fn authentication_failures_block_until_each_row_is_explicitly_released() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = make_health_event();
    let second = make_health_event();
    seed_pending(&outbox_path, &[&first, &second], &["remote"]).expect("seed pending events");
    {
        let mut outbox = Outbox::open(&outbox_path).expect("open seeded outbox");
        outbox
            .record_delivery_at(
                &first.event_id,
                "remote",
                DeliveryUpdate {
                    state: DeliveryState::Pending,
                    attempts: 0,
                    next_attempt_at: None,
                    last_error_class: None,
                    updated_at: 1,
                },
            )
            .expect("order first authentication failure");
        outbox
            .record_delivery_at(
                &second.event_id,
                "remote",
                DeliveryUpdate {
                    state: DeliveryState::Pending,
                    attempts: 0,
                    next_attempt_at: None,
                    last_error_class: None,
                    updated_at: 2,
                },
            )
            .expect("order second authentication failure");
    }

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 401 }),
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 403 }),
            ScriptedOutcome::Success,
            ScriptedOutcome::Success,
        ],
    );
    let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
    let clock = FakeClock::new(4_000);

    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("block authentication failures");
    let outbox = Outbox::open(&outbox_path).expect("reopen blocked outbox");
    for (event, status) in [(&first, 401), (&second, 403)] {
        let row = outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("blocked row");
        assert_eq!(row.state, DeliveryState::Blocked);
        assert_eq!(row.next_attempt_at, None);
        assert_eq!(
            row.last_error_class,
            Some(DeliveryErrorClass::AuthenticationBlocked { status })
        );
    }
    assert!(
        outbox
            .next_ready_delivery("remote", clock.now_millis())
            .expect("blocked ready lookup")
            .is_none()
    );
    drop(outbox);
    assert_eq!(calls.lock().expect("calls lock").len(), 2);

    let mut outbox = Outbox::open(&outbox_path).expect("open for first release");
    outbox
        .release_blocked_delivery(&first.event_id, "remote", clock.now_millis())
        .expect("release first blocked row");
    drop(outbox);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("deliver released first row");
    assert_eq!(calls.lock().expect("calls lock").len(), 3);

    let mut outbox = Outbox::open(&outbox_path).expect("open for second release");
    outbox
        .release_blocked_delivery(&second.event_id, "remote", clock.now_millis())
        .expect("release second blocked row");
    drop(outbox);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("deliver released second row");
    assert_eq!(calls.lock().expect("calls lock").len(), 4);

    let outbox = Outbox::open(&outbox_path).expect("reopen released outbox");
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "remote")
            .expect("first delivery")
            .expect("first row")
            .state,
        DeliveryState::Acked
    );
    assert_eq!(
        outbox
            .get_delivery(&second.event_id, "remote")
            .expect("second delivery")
            .expect("second row")
            .state,
        DeliveryState::Acked
    );
}

#[test]
fn poison_delivery_is_dead_but_does_not_wedge_a_later_valid_event() {
    assert_poison_delivery_progress(0, false);
}

#[test]
fn poison_delivery_preserves_valid_work_at_the_dispatch_time_boundary() {
    for (step_millis, deferred) in [(99, false), (100, true), (101, true)] {
        assert_poison_delivery_progress(step_millis, deferred);
    }
}

fn assert_poison_delivery_progress(dispatch_step_millis: u64, deferred: bool) {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let poison = make_health_event();
    let valid = make_health_event();
    seed_pending(&outbox_path, &[&poison, &valid], &["remote"]).expect("seed pending events");
    let valid_before = {
        let mut outbox = Outbox::open(&outbox_path).expect("open seeded outbox");
        outbox
            .record_delivery_at(
                &poison.event_id,
                "remote",
                DeliveryUpdate {
                    state: DeliveryState::Pending,
                    attempts: 0,
                    next_attempt_at: None,
                    last_error_class: None,
                    updated_at: 1,
                },
            )
            .expect("order poison first");
        outbox
            .record_delivery_at(
                &valid.event_id,
                "remote",
                DeliveryUpdate {
                    state: DeliveryState::Pending,
                    attempts: 0,
                    next_attempt_at: None,
                    last_error_class: None,
                    updated_at: 2,
                },
            )
            .expect("order valid second");
        outbox
            .get_delivery(&valid.event_id, "remote")
            .expect("original valid delivery")
            .expect("original valid row")
    };

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::SinkApplicationRejected),
            ScriptedOutcome::Success,
        ],
    );
    let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
    let clock = FakeClock::with_dispatch_step(5_000, dispatch_step_millis);
    let failures = sinks
        .dispatch_durable_with_clock(&clock)
        .expect("quarantine poison within the dispatch budget");
    assert_eq!(failures.len(), 1);
    assert_eq!(
        failures[0].class,
        DeliveryErrorClass::SinkApplicationRejected
    );
    assert_eq!(failures[0].attempts, 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen poison outbox");
    let poison_row = outbox
        .get_delivery(&poison.event_id, "remote")
        .expect("poison delivery")
        .expect("poison row");
    assert_eq!(poison_row.state, DeliveryState::Dead);
    assert_eq!(poison_row.attempts, 1);
    assert_eq!(poison_row.next_attempt_at, None);
    assert_eq!(
        poison_row.last_error_class,
        Some(DeliveryErrorClass::SinkApplicationRejected)
    );
    if deferred {
        assert_eq!(calls.lock().expect("calls lock").len(), 1);
        assert_eq!(
            outbox
                .get_delivery(&valid.event_id, "remote")
                .expect("unselected valid delivery")
                .expect("unselected valid row"),
            valid_before
        );
        assert_eq!(
            outbox
                .next_ready_delivery("remote", clock.now_millis())
                .expect("valid delivery remains eligible")
                .expect("ready valid delivery")
                .row,
            valid_before
        );
    }
    let health = outbox.health(&["remote"], 5).expect("poison queue health");
    assert_eq!(health.sinks[0].dead_count, 1);
    assert_eq!(health.sinks[0].pending_depth, u64::from(deferred));
    drop(outbox);
    drop(sinks);

    let mut sent = calls.lock().expect("calls lock").clone();
    if deferred {
        // Budget exhaustion defers selection, not delivery eligibility. A
        // fresh invocation must recover the untouched row without a delay.
        let (sink, resumed_calls) = ScriptedDurableSink::new("remote", [ScriptedOutcome::Success]);
        let restarted = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
        assert!(
            restarted
                .dispatch_durable_with_clock(&clock)
                .expect("deliver valid event after restart")
                .is_empty()
        );
        sent.extend(resumed_calls.lock().expect("resumed calls lock").clone());
    }

    let outbox = Outbox::open(&outbox_path).expect("reopen completed poison outbox");
    assert_eq!(
        outbox
            .get_delivery(&poison.event_id, "remote")
            .expect("persisted poison delivery")
            .expect("persisted poison row"),
        poison_row
    );
    assert_eq!(
        outbox
            .get_delivery(&valid.event_id, "remote")
            .expect("valid delivery")
            .expect("valid row")
            .state,
        DeliveryState::Acked
    );
    for (payload, event) in sent.iter().zip([&poison, &valid]) {
        assert_eq!(
            payload,
            &outbox
                .get_event(&event.event_id)
                .expect("persisted canonical event")
                .expect("canonical event row")
                .payload
        );
    }
    assert_eq!(sent.len(), 2);
    let health = outbox
        .health(&["remote"], 5)
        .expect("completed queue health");
    assert_eq!(health.sinks[0].dead_count, 1);
    assert_eq!(health.sinks[0].pending_depth, 0);
}

#[test]
fn retryable_failure_at_max_attempts_becomes_dead() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 503 }),
            ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 503 }),
        ],
    );
    let sinks = durable_sink_set(&outbox_path, sink, retry_config(2, 10));
    let clock = FakeClock::new(6_000);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("schedule final retry");
    clock.advance(10);
    sinks
        .dispatch_durable_with_clock(&clock)
        .expect("dead-letter exhausted retry");

    let outbox = Outbox::open(&outbox_path).expect("reopen exhausted outbox");
    let row = outbox
        .get_delivery(&event.event_id, "remote")
        .expect("delivery row")
        .expect("dead row");
    assert_eq!(row.state, DeliveryState::Dead);
    assert_eq!(row.next_attempt_at, None);
    assert_eq!(row.attempts, 2);
    assert_eq!(
        row.last_error_class,
        Some(DeliveryErrorClass::HttpStatus { status: 503 })
    );
    assert_eq!(calls.lock().expect("calls lock").len(), 2);
}

#[test]
fn durable_sinks_keep_success_and_blocked_states_independent() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["healthy", "blocked"]).expect("seed multi-sink event");

    let (healthy, healthy_calls) = ScriptedDurableSink::new("healthy", [ScriptedOutcome::Success]);
    let (blocked, blocked_calls) = ScriptedDurableSink::new(
        "blocked",
        [ScriptedOutcome::Failure(
            DeliveryErrorClass::AuthenticationBlocked { status: 403 },
        )],
    );
    let mut sinks = SinkSet::new();
    sinks.add_best_effort_with_retry("synthetic", Box::new(healthy), retry_config(3, 10));
    sinks.add_best_effort_with_retry("synthetic", Box::new(blocked), retry_config(3, 10));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["healthy".to_string(), "blocked".to_string()],
        CapacityLimits::default(),
    );
    let clock = FakeClock::new(7_000);

    let failures = sinks
        .dispatch_durable_with_clock(&clock)
        .expect("independent sink dispatch");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].name, "blocked");
    assert_eq!(healthy_calls.lock().expect("healthy calls").len(), 1);
    assert_eq!(blocked_calls.lock().expect("blocked calls").len(), 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen multi-sink outbox");
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "healthy")
            .expect("healthy delivery")
            .expect("healthy row")
            .state,
        DeliveryState::Acked
    );
    let blocked_row = outbox
        .get_delivery(&event.event_id, "blocked")
        .expect("blocked delivery")
        .expect("blocked row");
    assert_eq!(blocked_row.state, DeliveryState::Blocked);
    assert_eq!(
        blocked_row.last_error_class,
        Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 })
    );
}

#[test]
fn crash_after_remote_success_before_ack_replays_without_loss() {
    let directory = tempdir().expect("temporary directory");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let event = make_health_event();
    seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

    let (sink, calls) = ScriptedDurableSink::new(
        "remote",
        [ScriptedOutcome::Success, ScriptedOutcome::Success],
    );
    let ready = {
        let outbox = Outbox::open(&outbox_path).expect("open pending outbox");
        outbox
            .next_ready_delivery("remote", 8_000)
            .expect("ready lookup")
            .expect("ready delivery")
    };
    sink.emit_canonical_once(&ready.payload)
        .expect("simulate receiver success");
    assert_eq!(calls.lock().expect("calls lock").len(), 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen after simulated crash");
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("pending row")
            .state,
        DeliveryState::Pending
    );
    drop(outbox);

    let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
    sinks
        .dispatch_durable_with_clock(&FakeClock::new(8_000))
        .expect("replay after restart");
    let calls = calls.lock().expect("calls lock");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
    drop(calls);

    let outbox = Outbox::open(&outbox_path).expect("reopen acknowledged outbox");
    assert_eq!(
        outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("acked row")
            .state,
        DeliveryState::Acked
    );
}
