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

mod admission_backlog;
mod delivery_alerts;
mod dispatch_ownership;
mod persistent_replay;
mod replay_capacity;
mod retry_states;
mod sink_fan_out;
