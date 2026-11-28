use super::*;

#[test]
fn scanner_health_alert_thresholds_are_strict_and_error_alert_precedes_duration_alert() {
    let config = OperationalAlertConfig {
        max_scanner_errors: 3,
        max_scan_duration_ms: 100,
    };
    for (errors, duration, expected) in [
        (2, 99, vec![]),
        (3, 100, vec![]),
        (4, 100, vec!["scanner_error_threshold"]),
        (3, 101, vec!["scan_duration_threshold"]),
        (
            4,
            101,
            vec!["scanner_error_threshold", "scan_duration_threshold"],
        ),
    ] {
        // The scan path applies the latch. This locks the strict comparison.
        let alerts = scanner_health_alerts(&config, errors, duration, true);
        assert_eq!(
            alerts
                .iter()
                .map(|event| event.check_name.as_deref().unwrap())
                .collect::<Vec<_>>(),
            expected,
            "errors={errors}, duration={duration}",
        );
    }
}

#[test]
fn source_parse_outage_alerts_only_when_every_source_of_a_client_fails() {
    let outcomes = client_parse_outcomes([
        (ClientId::Claude, true),
        (ClientId::Codex, true),
        (ClientId::Claude, true),
        (ClientId::Codex, false),
        (ClientId::Qwen, false),
    ]);
    assert_eq!(
        outcomes,
        vec![
            (ClientId::Claude, 2, true),
            (ClientId::Codex, 2, false),
            (ClientId::Qwen, 1, false),
        ]
    );
    assert!(client_parse_outcomes([]).is_empty());

    // New outage alerts; unchanged stays quiet; recovery re-arms it.
    let mut state = ScanState::default();
    assert!(state.enter_source_outage("claude"));
    assert!(!state.enter_source_outage("claude"));
    assert!(state.enter_source_outage("codex"));
    state.clear_source_outage("claude");
    assert!(state.enter_source_outage("claude"));
    assert!(!state.enter_source_outage("codex"));

    let alert = &source_parse_outage_alert(ClientId::Claude, 2);
    assert_eq!(alert.event_type, "operational_alert");
    assert_eq!(alert.severity, "warning");
    assert_eq!(alert.check_name.as_deref(), Some("operational_alert"));
    assert_eq!(alert.status.as_deref(), Some("degraded"));
    let evidence = |field: &str| {
        alert
            .evidence
            .iter()
            .find(|evidence| evidence.field == field)
            .map(|evidence| evidence.redacted_value.as_str())
    };
    assert_eq!(evidence("alert_type"), Some("source_parse_outage"));
    assert_eq!(
        evidence("actual_value"),
        Some("client=claude; selected_sources=2; processed_sources=0")
    );
    assert!(
        telltale_schema::event::Event3Record::from_json(&serde_json::to_vec(alert).unwrap())
            .is_ok()
    );
}

#[test]
fn operational_json_omits_hostile_sink_names() {
    let sink_name = "https://sink-owner.example.invalid/private";
    let alert = sink_failure_alert_event(&SinkFailure {
        name: sink_name.to_string(),
        kind: "splunk_hec".to_string(),
        class: crate::sink::DeliveryErrorClass::UnknownInternal,
        attempts: 1,
        error: "connection refused".to_string(),
        prior_attempts: 0,
        prior_error_class: None,
    });
    let alert_bytes = serde_json::to_vec(&alert).expect("serialize sink alert");
    assert!(
        !String::from_utf8_lossy(&alert_bytes).contains(sink_name),
        "operational alert exposed a hostile sink name"
    );
}

#[test]
fn status_json_omits_hostile_health_fields() {
    let marker = "sk-abcdefgh";
    let hostile_health = serde_json::json!({
        "schema_version": "3.0",
        "event_type": "health",
        "timestamp": "2026-05-01T00:00:00Z",
        "component": marker,
        "check_name": marker,
        "status": marker,
        "active_policy_name": marker,
        "source_counts": { marker: 1 },
    });
    let status = status_json(
        "ok",
        Some(&hostile_health),
        0,
        std::path::Path::new("/tmp/telltale-events.jsonl"),
        std::path::Path::new("/tmp/telltale-state.json"),
        serde_json::json!({"mode": "not_configured", "sinks": {}}),
    );
    let status_bytes = serde_json::to_vec(&status).expect("serialize status");
    assert!(
        !String::from_utf8_lossy(&status_bytes).contains(marker),
        "status output exposed hostile health metadata"
    );
    assert_eq!(
        status["durable_queue_health"],
        serde_json::json!({"mode": "not_configured", "sinks": {}})
    );
    assert_eq!(status["attention_required"], serde_json::Value::Null);
}

#[test]
fn scanner_error_counts_are_positive_in_every_numeric_form() {
    let health = |count: &str| {
        serde_json::from_str::<serde_json::Value>(&format!(r#"{{"scanner_error_count":{count}}}"#))
            .expect("health json")
    };
    assert_eq!(scanner_errors_recorded(&health("0")), Some(false));
    assert_eq!(scanner_errors_recorded(&health("3")), Some(true));
    assert_eq!(
        scanner_errors_recorded(&health("18446744073709551616")),
        Some(true)
    );
    assert_eq!(scanner_errors_recorded(&health("2.0e19")), Some(true));
    assert_eq!(scanner_errors_recorded(&health("\"1\"")), None);
    assert_eq!(scanner_errors_recorded(&health("null")), None);
    assert_eq!(scanner_errors_recorded(&serde_json::json!({})), None);
}

#[test]
fn iteration_budget_counts_down_without_wrapping() {
    let mut unlimited = None;
    assert!(!iteration_budget_exhausted(&mut unlimited));
    let mut two = Some(2);
    assert!(!iteration_budget_exhausted(&mut two));
    assert!(iteration_budget_exhausted(&mut two));
    assert!(iteration_budget_exhausted(&mut Some(1)));
    // The CLI rejects zero; the counter still never wraps.
    let mut zero = Some(0);
    assert!(iteration_budget_exhausted(&mut zero));
    assert_eq!(zero, Some(0));
}

#[test]
fn health_heartbeat_is_due_once_the_interval_elapses_and_never_waits_on_a_clock_rollback() {
    let wait = health_heartbeat_wait;
    // Nothing recorded yet.
    assert_eq!(wait(None, 10_000, 60), Duration::ZERO);
    // Sooner than the interval: wait out the remainder.
    assert_eq!(wait(Some(10_000), 10_000, 60), Duration::from_secs(60));
    assert_eq!(wait(Some(10_000), 69_999, 60), Duration::from_millis(1));
    // Exactly one interval, and later, are due.
    assert_eq!(wait(Some(10_000), 70_000, 60), Duration::ZERO);
    assert_eq!(wait(Some(10_000), 10_000_000, 60), Duration::ZERO);
    // A recorded time ahead of the clock is due rather than silent.
    assert_eq!(wait(Some(10_001), 10_000, 60), Duration::ZERO);
    // Huge intervals saturate instead of overflowing.
    assert_eq!(wait(Some(0), 0, u64::MAX), Duration::from_millis(u64::MAX));
}

#[test]
fn operational_alert_reasons_are_closed_codes() {
    let alert = |alert_type: &str| {
        serde_json::json!({
            "event_type": "operational_alert",
            "evidence": [{"field": "alert_type", "redacted_value": alert_type}],
        })
    };
    assert_eq!(
        operational_alert_reason(&alert("source_parse_outage")),
        "source_parse_outage"
    );
    assert_eq!(
        operational_alert_reason(&alert("sk-abcdefgh")),
        "operational_alert"
    );
    assert_eq!(
        operational_alert_reason(&serde_json::json!({"evidence": "sk-abcdefgh"})),
        "operational_alert"
    );
}
