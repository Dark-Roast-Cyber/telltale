use serde_json::{Value, json};
use telltale_core::{Event3Record, FeedBatch};

pub fn terminal(family: &str, id: u64) -> Value {
    let mut value = json!({
        "schema_version": "3.0", "event_id": format!("telltale-00000000-0000-4000-8000-{id:012x}"),
        "telltale_version": "0.5.0", "event_type": family,
        "timestamp": "2026-05-01T00:00:00Z", "observed_at": "2026-05-01T00:00:00Z",
        "ingested_at": "2026-05-01T00:00:01Z", "time_source": "observed", "time_confidence": "low",
        "time_override_reason": "source_time_unavailable",
        "severity": "informational", "risk_score": 0, "risk_contributions": [],
        "client": "codex", "session_id": "synthetic-session", "tags": [], "evidence": []
    });
    let extra = match family {
        "detection" | "process_chain" => json!({
            "source_path_hash": "a".repeat(64), "tool_name": "synthetic-tool",
            "rule_ids": ["rule.synthetic.test"], "categories": ["execution"],
            "detection_classes": ["security_detection"], "signal_types": ["atomic"],
            "analytic_intents": ["alert"], "atlas_tags": ["atlas:execution"],
            "response": {"recommended_action": "investigate", "response_playbook": "telltale-playbook-synthetic",
                "investigation_summary": "Review terminal evidence", "escalation": "routine_review"},
            "evidence": [{"field": "command", "redacted_value": "TERMINAL_SYNTHETIC_MARKER",
                "hash": "b".repeat(64), "rule_id": "rule.synthetic.test"}]
        }),
        "correlation" => json!({
            "session_id": "correlation", "event_time": "2026-05-01T00:00:00Z",
            "rule_ids": ["rule.synthetic.test"], "categories": ["cross_session_correlation"],
            "detection_classes": ["security_detection"], "signal_types": ["correlation"],
            "analytic_intents": ["alert"],
            "evidence": [
                {"field": "session_ids", "redacted_value": "synthetic-a, synthetic-b"},
                {"field": "event_ids", "redacted_value": "synthetic-event-a, synthetic-event-b"},
                {"field": "window_start", "redacted_value": "2026-05-01T00:00:00Z"},
                {"field": "window_end", "redacted_value": "2026-05-01T00:01:00Z"}
            ]
        }),
        "health" => json!({
            "client": "scanner", "session_id": "scanner", "component": "scanner",
            "check_name": "source_discovery", "status": "ok", "source_counts": {"codex": 2},
            "scan_duration_ms": 12, "rule_count": 34, "emitted_count": 3, "suppressed_count": 1,
            "scanner_error_count": 0, "threshold_config": {"low": 1, "medium": 5, "high": 10, "critical": 20},
            "active_policy_name": "synthetic-policy"
        }),
        "scanner_error" => json!({
            "session_id": "scanner", "component": "scanner", "check_name": "source_parse",
            "status": "degraded", "source_path_hash": "a".repeat(64)
        }),
        "operational_alert" => json!({
            "client": "scanner", "session_id": "scanner", "severity": "warning",
            "component": "scanner", "check_name": "sink_delivery", "status": "degraded",
            "categories": ["operational_health"], "detection_classes": ["operational_health"],
            "signal_types": ["atomic"], "analytic_intents": ["alert"],
            "scan_duration_ms": 12, "scanner_error_count": 1
        }),
        "activity" => json!({"source_path_hash": "a".repeat(64)}),
        "session_risk_summary" => json!({}),
        _ => panic!("unknown synthetic family"),
    };
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    if family == "correlation" {
        value["time_source"] = json!("source");
        value
            .as_object_mut()
            .unwrap()
            .remove("time_override_reason");
    }
    if family == "process_chain" {
        value.as_object_mut().unwrap().remove("atlas_tags");
        value["signal_types"] = json!(["chain"]);
        let process = json!({
            "informational": true, "confidence": "high", "detection_reason": "Synthetic reason",
            "mitre_attack_techniques": ["T1059"], "risk_entity_type": "session",
            "risk_entity_value": "synthetic-session",
            "process": {"source_process_name": "synthetic-parent", "target_process_name": "synthetic-child",
                "source_process_inferred": true, "rule_name": "Synthetic process rule", "secondary_rule_ids": [],
                "investigation_fields": ["command"], "falsepositives": ["Synthetic expected use"],
                "dedup_key": "synthetic-key", "suppression_window_seconds": 60, "rule_severity": "low"}
        });
        value
            .as_object_mut()
            .unwrap()
            .extend(process.as_object().unwrap().clone());
    }
    value
}

pub fn parse(value: Value) -> Event3Record {
    Event3Record::from_json(&serde_json::to_vec(&value).unwrap())
        .expect("synthetic terminal Event3")
}

pub fn record(family: &str, id: u64) -> Event3Record {
    parse(terminal(family, id))
}

pub fn batch(records: Vec<Event3Record>) -> FeedBatch {
    FeedBatch {
        records,
        notices: vec![],
        bytes_read: 0,
        caught_up: true,
        suppressed_replays: 0,
        event_id_collisions: 0,
        dedup_evictions: 0,
    }
}
