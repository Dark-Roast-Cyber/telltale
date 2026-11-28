use super::*;

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
        super::super::super::DeliveryPosture::BestEffortNoReplay
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
