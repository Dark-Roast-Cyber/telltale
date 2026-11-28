use super::*;

#[test]
fn health_event_has_steady_state_check_dimensions() {
    let event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 7,
        rule_count: 3,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });

    assert_eq!(event.event_type, "health");
    assert_eq!(event.component.as_deref(), Some("scanner"));
    assert_eq!(event.check_name.as_deref(), Some("source_discovery"));
    assert_eq!(event.status.as_deref(), Some("ok"));
}

#[test]
fn health_event_can_include_source_inventory_change_marker() {
    let change = crate::source::SourceInventoryChangeSummary {
        baseline: false,
        added: 0,
        removed: 0,
        unchanged: 2,
        hash: "0".repeat(64),
    };
    let event = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: Some(&change),
        scan_duration_ms: 7,
        rule_count: 3,
        threshold_config: crate::scoring::load_thresholds(),
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });

    let evidence = event
        .evidence
        .iter()
        .find(|item| item.field == "source_inventory_change")
        .expect("source inventory change evidence");
    assert_eq!(
        evidence.redacted_value,
        "baseline=false; added=0; removed=0; unchanged=2"
    );
    assert_eq!(
        evidence.hash.as_deref(),
        Some("0000000000000000000000000000000000000000000000000000000000000000")
    );
}

#[test]
fn scanner_error_event_has_correct_shape() {
    use crate::clients::SourceKind;
    use crate::source::Source;
    use std::path::PathBuf;

    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: PathBuf::from("/home/user/.local/share/opencode/opencode.db"),
    };
    let error = "sqlite error: Query is not read-only";

    let event = scanner_error_event(&source, &error);

    assert_eq!(event.event_type, "scanner_error");
    assert_eq!(event.severity, "informational");
    assert_eq!(event.risk_score, 0);
    assert_eq!(event.client, "opencode");
    assert_eq!(event.session_id, "scanner");
    assert_eq!(event.agent, None);
    assert_eq!(event.model, None);
    assert_eq!(event.tool_name, None);
    assert_eq!(event.rule_ids.len(), 0);
    assert!(event.source_path_hash.is_some());
    assert_eq!(event.tags, vec!["scanner", "parse_failure"]);
    assert_eq!(event.evidence.len(), 2);
    assert_eq!(event.evidence[0].field, "error");
    assert_eq!(event.evidence[0].redacted_value, error);
    assert_eq!(event.evidence[1].field, "source_path");
    assert!(event.evidence[1].hash.is_some());
    assert!(event.timeline_anchors.is_empty());
    assert_eq!(event.response, None);
    assert_eq!(event.source_counts, None);
    assert_eq!(event.component.as_deref(), Some("scanner"));
    assert_eq!(event.check_name.as_deref(), Some("source_parse"));
    assert_eq!(event.status.as_deref(), Some("degraded"));
}

#[test]
fn scanner_error_event_preserves_redacted_state_fingerprint_input() {
    use crate::clients::SourceKind;
    use crate::source::Source;
    use std::path::PathBuf;

    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_string(),
        path: PathBuf::from("/synthetic/opencode.db"),
    };
    let raw_error =
        "failed at /home/TT_PRIVACY_SCANNER_25/.config/state TOKEN=TT_PRIVACY_SCANNER_25";
    let event = scanner_error_event(&source, &raw_error);

    assert_eq!(
        event.evidence[0].redacted_value,
        super::super::PrivacySanitizer::sanitize(
            super::super::SanitizationContext::Diagnostic,
            raw_error
        )
    );
    assert!(
        !event.evidence[0]
            .redacted_value
            .contains("TT_PRIVACY_SCANNER_25")
    );
}

#[test]
fn operational_alert_event_has_correct_shape() {
    let event = operational_alert_event(OperationalAlertInput {
        alert_type: "scanner_error_threshold_exceeded".to_string(),
        threshold: "max_scanner_errors=3".to_string(),
        actual_value: "scanner_error_count=5".to_string(),
        scan_duration_ms: Some(1500),
        scanner_error_count: Some(5),
    });

    assert_eq!(event.event_type, "operational_alert");
    assert_eq!(event.severity, "warning");
    assert_eq!(event.risk_score, 0);
    assert_eq!(event.client, "scanner");
    assert_eq!(event.session_id, "scanner");
    assert_eq!(event.component.as_deref(), Some("scanner"));
    assert_eq!(event.check_name.as_deref(), Some("scanner_error_threshold"));
    assert_eq!(event.status.as_deref(), Some("degraded"));
    assert_eq!(event.categories, vec!["operational"]);
    assert!(event.tags.contains(&"operational".to_string()));
    assert!(event.tags.contains(&"scanner_health".to_string()));
    assert_eq!(event.scan_duration_ms, Some(1500));
    assert_eq!(event.telltale_version, env!("CARGO_PKG_VERSION"));
    assert!(event.timeline_anchors.is_empty());
    assert_eq!(event.response, None);
    assert!(event.source_path_hash.is_none());

    let alert_type = event
        .evidence
        .iter()
        .find(|e| e.field == "alert_type")
        .expect("alert_type evidence");
    assert_eq!(
        alert_type.redacted_value,
        "scanner_error_threshold_exceeded"
    );

    let threshold = event
        .evidence
        .iter()
        .find(|e| e.field == "threshold")
        .expect("threshold evidence");
    assert_eq!(threshold.redacted_value, "max_scanner_errors=3");

    let actual = event
        .evidence
        .iter()
        .find(|e| e.field == "actual_value")
        .expect("actual_value evidence");
    assert_eq!(actual.redacted_value, "scanner_error_count=5");

    let error_count = event
        .evidence
        .iter()
        .find(|e| e.field == "scanner_error_count")
        .expect("scanner_error_count evidence");
    assert_eq!(error_count.redacted_value, "5");

    let duration = event
        .evidence
        .iter()
        .find(|e| e.field == "scan_duration_ms")
        .expect("scan_duration_ms evidence");
    assert_eq!(duration.redacted_value, "1500");
}

#[test]
fn operational_alert_event_includes_duration_evidence() {
    let event = operational_alert_event(OperationalAlertInput {
        alert_type: "scan_duration_threshold_exceeded".to_string(),
        threshold: "max_scan_duration_ms=300000".to_string(),
        actual_value: "scan_duration_ms=600000".to_string(),
        scan_duration_ms: Some(600_000),
        scanner_error_count: None,
    });

    assert_eq!(event.event_type, "operational_alert");
    assert_eq!(event.severity, "warning");
    assert_eq!(event.check_name.as_deref(), Some("scan_duration_threshold"));
    assert_eq!(event.status.as_deref(), Some("degraded"));
    assert!(event.evidence.iter().any(|e| e.field == "scan_duration_ms"));
    assert!(
        event
            .evidence
            .iter()
            .all(|e| e.field != "scanner_error_count")
    );
}

#[test]
fn operational_alert_config_defaults() {
    let config = super::super::OperationalAlertConfig::default();
    assert_eq!(config.max_scanner_errors, 3);
    assert_eq!(config.max_scan_duration_ms, 300_000);
}
