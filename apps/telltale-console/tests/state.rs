mod support;

use serde_json::json;
use support::{batch, parse, record, terminal};
use telltale_console::state::{
    ConsoleState, FeedStatus, FindingFilter, NO_FINDINGS, NO_HEALTH, RETENTION,
};
use telltale_core::{FeedNotice, FeedNoticeCode};
use telltale_schema::event::{Event3Family, Event3Severity};

macro_rules! ingestion {
    ($name:ident, $family:literal, $variant:ident, $findings:expr) => {
        #[test]
        fn $name() {
            let mut state = ConsoleState::default();
            state.ingest(batch(vec![record($family, 1)]));
            assert!(matches!(
                state.records().back().unwrap().family(),
                Event3Family::$variant(_)
            ));
            assert_eq!(state.summary().findings, $findings);
        }
    };
}
ingestion!(detection_ingestion, "detection", Detection, 1);
ingestion!(process_chain_ingestion, "process_chain", ProcessChain, 1);
ingestion!(correlation_ingestion, "correlation", Correlation, 1);
ingestion!(health_ingestion, "health", Health, 0);
ingestion!(scanner_error_ingestion, "scanner_error", ScannerError, 0);
ingestion!(
    operational_alert_ingestion,
    "operational_alert",
    OperationalAlert,
    0
);

#[test]
fn feed_notice_ingestion_aggregates_and_saturates() {
    let mut state = ConsoleState::default();
    for count in [u64::MAX, 2] {
        let mut b = batch(vec![]);
        b.notices.push(FeedNotice {
            code: FeedNoticeCode::ParserMalformed,
            count,
        });
        state.ingest(b);
    }
    assert_eq!(state.notices()[&FeedNoticeCode::ParserMalformed], u64::MAX);
    assert_eq!(state.notice_count(), u64::MAX);
    assert_eq!(state.status(), FeedStatus::Degraded);
}

#[test]
fn bounded_event_retention() {
    let mut state = ConsoleState::default();
    for id in 0..RETENTION as u64 + 3 {
        state.ingest(batch(vec![record("activity", id)]));
    }
    assert_eq!(state.records().len(), RETENTION);
    assert_eq!(
        state.records().front().unwrap().common().event_id,
        record("activity", 3).common().event_id
    );
}

#[test]
fn all_derived_indexes_are_bounded_after_eviction() {
    let mut state = ConsoleState::with_capacity(2);
    for id in 0..50 {
        let mut v = terminal("detection", id);
        v["client"] = json!(format!("synthetic-client-{id}"));
        state.ingest(batch(vec![parse(v)]));
        assert!(state.clients().len() <= 2);
        assert!(state.findings(&FindingFilter::default()).len() <= 2);
    }
    // Evicted identities must not remain in the dedup index.
    state.ingest(batch(vec![record("detection", 0)]));
    assert_eq!(
        state.records().back().unwrap().common().event_id,
        record("detection", 0).common().event_id
    );
}

#[test]
fn duplicate_retained_id_does_not_duplicate_or_replace() {
    let mut state = ConsoleState::default();
    let original = record("detection", 1);
    state.ingest(batch(vec![
        original.clone(),
        record("health", 1),
        original.clone(),
    ]));
    assert_eq!(state.records().len(), 1);
    assert_eq!(state.records().front(), Some(&original));
}

#[test]
fn journal_order_is_retained_not_timestamp_sorted() {
    let mut state = ConsoleState::default();
    let first = record("detection", 1);
    let mut older = terminal("detection", 2);
    older["timestamp"] = json!("2025-05-01T00:00:00Z");
    older["observed_at"] = older["timestamp"].clone();
    let second = parse(older);
    state.ingest(batch(vec![first.clone(), second.clone()]));
    assert_eq!(
        state.records().iter().collect::<Vec<_>>(),
        vec![&first, &second]
    );
}

#[test]
fn newest_first_presentation_and_selection() {
    let mut state = ConsoleState::default();
    state.ingest(batch(vec![
        record("detection", 1),
        record("process_chain", 2),
    ]));
    let ids: Vec<_> = state
        .findings(&FindingFilter::default())
        .iter()
        .map(|r| r.common().event_id.clone())
        .collect();
    assert_eq!(ids[0], record("process_chain", 2).common().event_id);
    state.select(&ids[0]);
    assert!(matches!(
        state.selected().unwrap().family(),
        Event3Family::ProcessChain(_)
    ));
}

#[test]
fn critical_high_counts_cover_retained_findings_only() {
    let mut state = ConsoleState::with_capacity(3);
    for (id, severity) in [(1, "critical"), (2, "high"), (3, "critical"), (4, "low")] {
        let mut v = terminal("detection", id);
        v["severity"] = json!(severity);
        state.ingest(batch(vec![parse(v)]));
    }
    assert_eq!((state.summary().critical, state.summary().high), (1, 1));
}

#[test]
fn highest_risk_is_event_level_not_summed() {
    let mut state = ConsoleState::with_capacity(2);
    for (id, risk) in [(1, 20), (2, 10)] {
        let mut v = terminal("correlation", id);
        v["risk_score"] = json!(risk);
        state.ingest(batch(vec![parse(v)]));
    }
    assert_eq!(state.summary().highest_event_risk, Some(20));
    state.ingest(batch(vec![record("health", 3)]));
    assert_eq!(state.summary().highest_event_risk, Some(10));
}

#[test]
fn latest_health_follows_journal_order() {
    let mut state = ConsoleState::default();
    let mut older = terminal("health", 2);
    older["timestamp"] = json!("2025-05-01T00:00:00Z");
    older["observed_at"] = older["timestamp"].clone();
    older["rule_count"] = json!(77);
    state.ingest(batch(vec![
        record("health", 1),
        parse(older),
        record("scanner_error", 3),
    ]));
    assert_eq!(state.latest_health().unwrap().1.rule_count, 77);
}

#[test]
fn no_health_is_neutral_unavailable() {
    let state = ConsoleState::default();
    assert!(state.latest_health().is_none());
    assert_eq!(NO_HEALTH, "No scanner health event has been observed yet.");
    assert_eq!(state.status(), FeedStatus::Waiting);
}

#[test]
fn no_findings_does_not_claim_safety() {
    let mut state = ConsoleState::default();
    state.ingest(batch(vec![
        record("activity", 1),
        record("session_risk_summary", 2),
    ]));
    assert_eq!(state.summary().findings, 0);
    assert_eq!(
        NO_FINDINGS,
        "No security findings in the retained local window"
    );
}

#[test]
fn response_is_guidance_only() {
    use telltale_console::ui::GUIDANCE_HEADING;
    assert_eq!(
        GUIDANCE_HEADING,
        "Recommended response / Investigation guidance"
    );
    let r = record("process_chain", 1);
    let Event3Family::ProcessChain(p) = r.family() else {
        panic!("typed chain")
    };
    assert_eq!(p.response.recommended_action, "investigate");
}

#[test]
fn filters_use_severity_client_and_safe_metadata_not_evidence() {
    let mut state = ConsoleState::default();
    state.ingest(batch(vec![record("detection", 1)]));
    let mut filter = FindingFilter::default();
    for query in ["RULE.SYNTHETIC", "Execution", "synthetic-session"] {
        filter.query = query.into();
        assert_eq!(state.findings(&filter).len(), 1);
    }
    for query in [
        "TERMINAL_SYNTHETIC_MARKER",
        "synthetic-tool",
        "a".repeat(64).as_str(),
    ] {
        filter.query = query.into();
        assert!(state.findings(&filter).is_empty());
    }
    filter.query.clear();
    filter.client = Some("other".into());
    assert!(state.findings(&filter).is_empty());
    filter.client = Some("codex".into());
    filter.severity = Some(Event3Severity::High);
    assert!(state.findings(&filter).is_empty());
    filter.severity = Some(Event3Severity::Informational);
    assert_eq!(state.findings(&filter).len(), 1);
}

#[test]
fn selected_event_eviction_clears_selection() {
    let mut state = ConsoleState::with_capacity(1);
    let first = record("detection", 1);
    state.ingest(batch(vec![first.clone()]));
    state.select(&first.common().event_id);
    assert!(state.selected().is_some());
    state.ingest(batch(vec![record("health", 2)]));
    assert!(state.selected().is_none());
    state.select(&first.common().event_id);
    assert!(state.selected().is_none());
}
