use super::{
    build_session_timelines, correlation_events_from_filtered, export_summary_counts,
    format_timeline_text,
};
use telltale_schema::event::opaque_identifier;

fn canonical_detection(
    event_id: &str,
    session_id: &str,
    agent: &str,
    model: &str,
    provider: &str,
    timestamp: &str,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "3.0",
        "event_id": event_id,
        "event_type": "detection",
        "timestamp": timestamp,
        "observed_at": timestamp,
        "ingested_at": timestamp,
        "severity": "high",
        "risk_score": 80,
        "client": "codex",
        "agent": agent,
        "model": model,
        "provider": provider,
        "session_id": session_id,
        "rule_ids": ["rule.test"],
        "categories": ["test"],
        "detection_classes": ["security_detection"],
        "signal_types": ["atomic"],
        "analytic_intents": ["alert"],
        "risk_contributions": [],
    })
}

#[test]
fn historical_summary_and_timeline_terminalize_event_type_and_severity() {
    let marker = "CONTROLLED_HISTORICAL_LABEL_SECRET";
    let historical = serde_json::json!({
        "schema_version": "1.0",
        "event_id": "historical-labels",
        "timestamp": "2026-05-01T00:00:00Z",
        "event_type": format!("event-{marker}"),
        "severity": format!("severity-{marker}"),
        "risk_score": 0,
        "client": "codex",
        "session_id": "historical-label-session",
        "rule_ids": [],
        "categories": [],
        "evidence": [],
    });
    let events = [&historical];

    let counts = export_summary_counts(&events);
    assert!(
        !serde_json::to_string(&counts.event_types)
            .expect("summary event types JSON")
            .contains(marker),
        "summary emitted a controlled event type"
    );
    assert!(
        !serde_json::to_string(&counts.severities)
            .expect("summary severities JSON")
            .contains(marker),
        "summary emitted a controlled severity"
    );

    let timelines = build_session_timelines(&events);
    let timeline = timelines.first().expect("historical timeline");
    assert!(
        !serde_json::to_string(timeline)
            .expect("timeline JSON")
            .contains(marker),
        "timeline JSON emitted a controlled event label"
    );
    assert!(
        !format_timeline_text(timeline).contains(marker),
        "timeline text emitted a controlled event label"
    );
}

#[test]
fn historical_timeline_preserves_outer_summary_semantics() {
    let severity = "historical-custom-severity";
    let historical = serde_json::json!({
        "schema_version": "1.0",
        "event_id": "historical-summary-semantics",
        "timestamp": "2026-05-01T00:00:00Z",
        "event_type": "activity",
        "severity": severity,
        "risk_score": 0,
        "client": "codex",
        "session_id": "historical-summary-session",
        "rule_ids": [],
        "categories": [],
        "evidence": [],
        "triage": {"verdict": "benign"},
    });
    let timelines = build_session_timelines(&[&historical]);
    let timeline = timelines.first().expect("historical timeline");

    assert_eq!(
        timeline["max_severity"],
        opaque_identifier("severity", severity)
    );
    assert_eq!(timeline["risk_summary"]["max_severity"], "informational");
    assert_eq!(timeline["has_triage"], true);
    assert_eq!(timeline["risk_summary"]["triage_ran"], false);
    assert_eq!(timeline["record_status"], "historical");

    let native = canonical_detection(
        "telltale-00000000-0000-4000-8000-000000000003",
        "historical-summary-session",
        "codex",
        "gpt-5",
        "openai",
        "2026-05-01T00:01:00Z",
    );
    let mixed = build_session_timelines(&[&historical, &native]);
    assert_eq!(mixed[0]["record_status"], "mixed");
}

#[test]
fn historical_timeline_and_correlation_preserve_exact_canonical_links() {
    let first_session = opaque_identifier("session", "first source session");
    let second_session = opaque_identifier("session", "second source session");
    let agent = opaque_identifier("agent", "first source agent");
    let model = opaque_identifier("model", "first source model");
    let provider = opaque_identifier("provider", "first source provider");
    let first = canonical_detection(
        "telltale-00000000-0000-4000-8000-000000000001",
        &first_session,
        &agent,
        &model,
        &provider,
        "2026-05-01T00:00:00Z",
    );
    let second = canonical_detection(
        "telltale-00000000-0000-4000-8000-000000000002",
        &second_session,
        &agent,
        &model,
        &provider,
        "2026-05-01T00:20:00Z",
    );
    let events = [&first, &second];

    let timelines = build_session_timelines(&events);
    assert_eq!(timelines.len(), 2);
    assert!(
        timelines
            .iter()
            .all(|timeline| timeline["record_status"] == "native")
    );
    assert!(timelines.iter().any(|timeline| {
        timeline["session_id"] == first_session
            && timeline["agent"] == agent
            && timeline["model"] == model
            && timeline["provider"] == provider
    }));
    assert_eq!(build_session_timelines(&events), timelines);

    let correlations =
        correlation_events_from_filtered(&events).expect("historical correlation output");
    assert_eq!(correlations.len(), 1);
    let serialized = serde_json::to_string(&correlations).expect("correlation JSON");
    for marker in [&first_session, &second_session, &agent, &model, &provider] {
        assert!(
            serialized.contains(marker),
            "historical derived output rehashed a canonical marker"
        );
    }
    let repeated = correlation_events_from_filtered(&events).expect("repeat correlation output");
    let repeated_serialized = serde_json::to_string(&repeated).expect("repeated correlation JSON");
    for marker in [&first_session, &second_session, &agent, &model, &provider] {
        assert!(
            repeated_serialized.contains(marker),
            "repeated historical derived output rehashed a canonical marker"
        );
    }
}
