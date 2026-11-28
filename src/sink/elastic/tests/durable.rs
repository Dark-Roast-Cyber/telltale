use super::*;
use crate::sink::http::RetryConfig;
use crate::sink::outbox::{CapacityLimits, DeliveryClock, DeliveryState, Outbox};
use crate::sink::{DeliveryErrorClass, LocalJsonlSink, RotationConfig, SinkSet};
use std::path::Path;

struct Clock(i64);
impl DeliveryClock for Clock {
    fn now_millis(&self) -> i64 {
        self.0
    }
}

fn sinks(directory: &Path, endpoint: &str) -> SinkSet {
    let log = directory.join("events.jsonl");
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log,
            RotationConfig::disabled(),
        )),
        log,
        None,
    );
    sinks.add_best_effort_with_retry(
        "elastic_bulk",
        Box::new(ElasticBulkSink::new(endpoint, "events")),
        RetryConfig {
            max_attempts: 2,
            base_delay_ms: 10,
        },
    );
    sinks.enable_persistent_replay_with_capacity(
        directory.join("private/outbox.sqlite"),
        vec!["elastic".into()],
        CapacityLimits::default(),
    );
    sinks
}

fn row(directory: &Path, id: &str) -> crate::sink::outbox::DeliveryRow {
    Outbox::open(directory.join("private/outbox.sqlite"))
        .unwrap()
        .get_delivery(id, "elastic")
        .unwrap()
        .unwrap()
}

fn response(id: &str, status: u16) -> String {
    let mut item = serde_json::json!({"_id": id, "status": status});
    if status >= 400 {
        item["error"] = serde_json::json!({"type": "synthetic_exception", "reason": "TT_ENDPOINT_SECRET /home/synthetic/private"});
    } else if status == 200 || status == 201 {
        item["result"] = serde_json::json!(if status == 201 { "created" } else { "updated" });
    }
    serde_json::json!({"errors": status >= 400, "items": [{"index": item}]}).to_string()
}

#[test]
fn durable_elastic_item_retry_replays_exact_journal_bytes_after_restart() {
    for status in [408, 429, 500, 503, 599] {
        let directory = tempfile::tempdir().unwrap();
        let event = make_health_event();
        let (endpoint, request) = start_mock_elastic(response(&event.event_id, status));
        let first = sinks(directory.path(), &endpoint);
        first
            .persist_for_durable_replay(std::slice::from_ref(&event))
            .unwrap();
        let journal = std::fs::read(directory.path().join("events.jsonl")).unwrap();
        assert_eq!(row(directory.path(), &event.event_id).attempts, 0);
        let failures = first.dispatch_durable_with_clock(&Clock(1000)).unwrap();
        let sent = request.join().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].class, DeliveryErrorClass::HttpStatus { status });
        assert!(!failures[0].error.contains("TT_ENDPOINT_SECRET"));
        let pending = row(directory.path(), &event.event_id);
        assert_eq!(pending.state, DeliveryState::Pending);
        assert_eq!(pending.attempts, 1);
        assert_eq!(pending.next_attempt_at, Some(1010));
        drop(first);

        let (endpoint, request) = start_mock_elastic(response(&event.event_id, 200));
        let restarted = sinks(directory.path(), &endpoint);
        assert!(
            restarted
                .dispatch_durable_with_clock(&Clock(1009))
                .unwrap()
                .is_empty()
        );
        assert_eq!(row(directory.path(), &event.event_id), pending);
        assert!(
            restarted
                .dispatch_durable_with_clock(&Clock(1010))
                .unwrap()
                .is_empty()
        );
        let replay = request.join().unwrap();
        let body = sent.split_once("\r\n\r\n").unwrap().1;
        assert_eq!(body, replay.split_once("\r\n\r\n").unwrap().1);
        assert_eq!(body.split_once('\n').unwrap().1.as_bytes(), journal);
        let acked = row(directory.path(), &event.event_id);
        assert_eq!(acked.state, DeliveryState::Acked);
        assert_eq!(acked.attempts, 2);
        assert_eq!(acked.next_attempt_at, None);
    }
}

#[test]
fn durable_elastic_auth_and_ambiguous_responses_block_without_poisoning() {
    let event = make_health_event();
    let mut cases = vec![
        (
            response(&event.event_id, 401),
            DeliveryErrorClass::AuthenticationBlocked { status: 401 },
        ),
        (
            response(&event.event_id, 403),
            DeliveryErrorClass::AuthenticationBlocked { status: 403 },
        ),
    ];
    let success: serde_json::Value = serde_json::from_str(&response(&event.event_id, 201)).unwrap();
    let mut inconsistent = success.clone();
    inconsistent["errors"] = true.into();
    let mut hidden_failure: serde_json::Value =
        serde_json::from_str(&response(&event.event_id, 400)).unwrap();
    hidden_failure["errors"] = false.into();
    let mut extra = success.clone();
    extra["items"]
        .as_array_mut()
        .unwrap()
        .push(success["items"][0].clone());
    let mut wrong_action = success.clone();
    wrong_action["items"][0] = serde_json::json!({"create": success["items"][0]["index"]});
    let mut missing_status = success.clone();
    missing_status["items"][0]["index"]
        .as_object_mut()
        .unwrap()
        .remove("status");
    let mut missing_error: serde_json::Value =
        serde_json::from_str(&response(&event.event_id, 400)).unwrap();
    missing_error["items"][0]["index"]
        .as_object_mut()
        .unwrap()
        .remove("error");
    let mut missing_result = success.clone();
    missing_result["items"][0]["index"]
        .as_object_mut()
        .unwrap()
        .remove("result");
    let mut wrong_result = success.clone();
    wrong_result["items"][0]["index"]["result"] = "updated".into();
    let mut null_error = success.clone();
    null_error["items"][0]["index"]["error"] = serde_json::Value::Null;
    let mut multiple_actions = success.clone();
    multiple_actions["items"][0]["delete"] = success["items"][0]["index"].clone();
    let mut empty_error: serde_json::Value =
        serde_json::from_str(&response(&event.event_id, 400)).unwrap();
    empty_error["items"][0]["index"]["error"] = serde_json::json!({});
    for body in [
        "TT_ENDPOINT_SECRET /home/synthetic/private".to_string(),
        r#"{"errors":false}"#.into(),
        r#"{"errors":false,"items":[]}"#.into(),
        response("TT_ENDPOINT_SECRET /home/synthetic/private", 201),
        response(&event.event_id, 302),
        response(&event.event_id, 404),
        response(&event.event_id, 409),
        inconsistent.to_string(),
        hidden_failure.to_string(),
        extra.to_string(),
        wrong_action.to_string(),
        missing_status.to_string(),
        missing_error.to_string(),
        missing_result.to_string(),
        wrong_result.to_string(),
        null_error.to_string(),
        multiple_actions.to_string(),
        empty_error.to_string(),
    ] {
        cases.push((body, DeliveryErrorClass::SinkResponseBlocked));
    }
    for (body, class) in cases {
        let directory = tempfile::tempdir().unwrap();
        let (endpoint, request) = start_mock_elastic(body);
        let sinks = sinks(directory.path(), &endpoint);
        sinks
            .persist_for_durable_replay(std::slice::from_ref(&event))
            .unwrap();
        let failures = sinks.dispatch_durable_with_clock(&Clock(1000)).unwrap();
        request.join().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].class, class);
        assert!(failures[0].error.len() < 200);
        assert!(!failures[0].error.contains("TT_ENDPOINT_SECRET"));
        assert!(!failures[0].error.contains("/home/synthetic/private"));
        let blocked = row(directory.path(), &event.event_id);
        assert_eq!(blocked.state, DeliveryState::Blocked);
        assert_eq!(blocked.last_error_class, Some(class));
        assert_eq!(blocked.next_attempt_at, None);
        assert!(
            sinks
                .dispatch_durable_with_clock(&Clock(2000))
                .unwrap()
                .is_empty()
        );
        assert_eq!(row(directory.path(), &event.event_id), blocked);
    }
}

#[test]
fn durable_elastic_permanent_item_does_not_prevent_next_event() {
    let directory = tempfile::tempdir().unwrap();
    let poison = make_health_event();
    let (endpoint, request) = start_mock_elastic(response(&poison.event_id, 400));
    let first = sinks(directory.path(), &endpoint);
    first
        .persist_for_durable_replay(std::slice::from_ref(&poison))
        .unwrap();
    let failures = first.dispatch_durable_with_clock(&Clock(1000)).unwrap();
    request.join().unwrap();
    assert_eq!(
        failures[0].class,
        DeliveryErrorClass::SinkApplicationRejected
    );
    assert_eq!(
        row(directory.path(), &poison.event_id).state,
        DeliveryState::Dead
    );
    drop(first);
    let valid = make_health_event();
    let (endpoint, request) = start_mock_elastic(response(&valid.event_id, 201));
    let next = sinks(directory.path(), &endpoint);
    next.persist_for_durable_replay(std::slice::from_ref(&valid))
        .unwrap();
    assert!(
        next.dispatch_durable_with_clock(&Clock(2000))
            .unwrap()
            .is_empty()
    );
    request.join().unwrap();
    assert_eq!(
        row(directory.path(), &valid.event_id).state,
        DeliveryState::Acked
    );
}

#[test]
fn durable_elastic_item_retries_obey_persisted_attempt_budget() {
    let directory = tempfile::tempdir().unwrap();
    let event = make_health_event();
    for (now, state) in [(1000, DeliveryState::Pending), (1010, DeliveryState::Dead)] {
        let (endpoint, request) = start_mock_elastic(response(&event.event_id, 503));
        let sinks = sinks(directory.path(), &endpoint);
        if now == 1000 {
            sinks
                .persist_for_durable_replay(std::slice::from_ref(&event))
                .unwrap();
        }
        sinks.dispatch_durable_with_clock(&Clock(now)).unwrap();
        request.join().unwrap();
        assert_eq!(row(directory.path(), &event.event_id).state, state);
    }
    assert_eq!(row(directory.path(), &event.event_id).attempts, 2);
}
