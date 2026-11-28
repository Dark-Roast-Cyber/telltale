use super::*;

#[test]
fn session_summary_unions_exact_contributions_by_source_identity() {
    use crate::event::{ActivityEventInput, activity_event};
    use crate::scoring::{RiskContribution, RiskContributionType};

    let contribution = || {
        RiskContribution::new(
            "baseline.synthetic",
            RiskContributionType::BaselineDeviation,
            30,
            "synthetic rule match",
        )
        .expect("contribution")
    };
    let event = || {
        activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session-union".to_string(),
            source_path_hash: "path".to_string(),
            tool_name: Some("shell".to_string()),
            tags: vec!["activity".to_string()],
            evidence: Vec::new(),
            risk_contributions: vec![contribution()],
            event_time: None,
        })
        .expect("build activity event")
    };
    let source_a = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "source-a".to_string(),
        path: PathBuf::from("a.jsonl"),
    };
    let source_b = Source {
        source_id: "source-b".to_string(),
        path: PathBuf::from("b.jsonl"),
        ..source_a.clone()
    };
    let source_alias = Source {
        path: PathBuf::from("alias.jsonl"),
        ..source_a.clone()
    };
    let mut first_event = event();
    first_event.agent = Some("first-agent".to_string());
    first_event.timestamp = "2026-05-01T00:00:00Z".to_string();
    let mut later_event = event();
    later_event.agent = Some("later-agent".to_string());
    later_event.timestamp = "2026-05-02T00:00:00Z".to_string();

    let summaries = summarize_session_risk_events(
        &[
            (source_b, event()),
            (source_a.clone(), first_event),
            (source_alias, later_event),
        ],
        &[],
    )
    .expect("summary");
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].0, source_a);
    assert_eq!(summaries[1].0.source_id, "source-b");
    assert_eq!(summaries[0].1.agent.as_deref(), Some("first-agent"));
    assert_eq!(summaries[0].1.timestamp, "2026-05-02T00:00:00.000Z");
    assert!(
        summaries
            .iter()
            .all(|(_, summary)| summary.risk_score == 30)
    );
    assert!(
        summaries
            .iter()
            .all(|(_, summary)| summary.risk_contributions.len() == 1)
    );
    let serialized = serde_json::to_value(&summaries[0].1).expect("serialize summary");
    assert_eq!(serialized["risk_score"], 30);
    assert_eq!(
        serialized["risk_contributions"][0]["id"],
        "baseline.synthetic"
    );
}

#[test]
fn session_summary_rejects_conflicting_contribution_metadata() {
    use crate::event::{ActivityEventInput, activity_event};
    use crate::scoring::{RiskContribution, RiskContributionType};

    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "source-conflict".to_string(),
        path: PathBuf::from("conflict.jsonl"),
    };
    let make_event = |points| {
        activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session-conflict".to_string(),
            source_path_hash: "path".to_string(),
            tool_name: None,
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: vec![
                RiskContribution::new(
                    "baseline.synthetic",
                    RiskContributionType::BaselineDeviation,
                    points,
                    "synthetic rule match",
                )
                .expect("contribution"),
            ],
            event_time: None,
        })
        .expect("build activity event")
    };

    let result = summarize_session_risk_events(
        &[(source.clone(), make_event(30)), (source, make_event(31))],
        &[],
    );
    assert!(matches!(
        result,
        Err(RiskAccountingError::ConflictingContribution(id)) if id == "baseline.synthetic"
    ));
}

#[test]
fn session_risk_summary_default_is_off_and_growth_dedups_until_a_rule_id_is_added() {
    use crate::event::{ActivityEventInput, DetectionEventInput, activity_event, detection_event};
    use crate::scoring::{RiskContribution, RiskContributionType};

    let emit_session_risk_summary = crate::settings::Settings::default()
        .emit_session_risk_summary
        .value;
    assert!(!emit_session_risk_summary);

    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "synthetic-session".to_string(),
        path: PathBuf::from("synthetic-session.jsonl"),
    };
    let contribution = RiskContribution::new(
        "rule.synthetic",
        RiskContributionType::DeterministicRule,
        30,
        "synthetic rule match",
    )
    .expect("contribution");
    let activity = |tool_calls: u64, event_time: &str| {
        (
            source.clone(),
            activity_event(ActivityEventInput {
                client: ClientId::Codex,
                agent: Some("synthetic-agent".to_string()),
                model: Some("synthetic-model".to_string()),
                provider: Some("synthetic-provider".to_string()),
                session_id: "synthetic-session".to_string(),
                source_path_hash: "synthetic-path".to_string(),
                tool_name: Some("shell".to_string()),
                tags: vec!["activity".to_string()],
                evidence: vec![Evidence {
                    field: "record_counts".to_string(),
                    redacted_value: format!(r#"{{"tool_call":{tool_calls}}}"#),
                    hash: None,
                    rule_id: None,
                }],
                risk_contributions: Vec::new(),
                event_time: Some(event_time.to_string()),
            })
            .expect("activity"),
        )
    };
    let detection =
        |rule_id: &str, contributions: Vec<RiskContribution>, event_time: &str, marker: &str| {
            (
                source.clone(),
                detection_event(DetectionEventInput {
                    client: ClientId::Codex,
                    agent: Some("synthetic-agent".to_string()),
                    model: Some("synthetic-model".to_string()),
                    provider: Some("synthetic-provider".to_string()),
                    session_id: "synthetic-session".to_string(),
                    source_path_hash: "synthetic-path".to_string(),
                    tool_name: Some("shell".to_string()),
                    rule_ids: vec![rule_id.to_string()],
                    categories: vec!["execution".to_string()],
                    detection_classes: vec!["security_detection".to_string()],
                    signal_types: vec!["atomic".to_string()],
                    analytic_intents: vec!["alert".to_string()],
                    atlas_tags: Vec::new(),
                    tags: vec!["synthetic".to_string()],
                    evidence: vec![Evidence {
                        field: "match".to_string(),
                        redacted_value: marker.to_string(),
                        hash: None,
                        rule_id: None,
                    }],
                    risk_contributions: contributions,
                    event_time: Some(event_time.to_string()),
                })
                .expect("detection"),
            )
        };
    let initial = (
        vec![activity(1, "2026-05-01T00:00:00Z")],
        vec![detection(
            "rule.synthetic",
            vec![contribution.clone()],
            "2026-05-01T00:00:01Z",
            "one",
        )],
    );
    let grown = (
        vec![activity(4, "2026-05-02T00:00:00Z")],
        vec![
            detection(
                "rule.synthetic",
                vec![contribution.clone()],
                "2026-05-01T00:00:01Z",
                "one",
            ),
            detection(
                "rule.synthetic",
                vec![contribution],
                "2026-05-02T00:00:01Z",
                "two",
            ),
        ],
    );
    let added_rule = (grown.0.clone(), {
        let mut detections = grown.1.clone();
        detections.push(detection(
            "rule.added",
            Vec::new(),
            "2026-05-03T00:00:00Z",
            "three",
        ));
        detections
    });

    fn emitted_summaries(
        state: &mut ScanState,
        emit: bool,
        activities: Vec<(Source, Event)>,
        detections: Vec<(Source, Event)>,
    ) -> Vec<Event> {
        let summaries =
            session_risk_summaries_for_scan(emit, &activities, &detections).expect("summaries");
        select_source_events(
            state,
            false,
            activities,
            detections,
            summaries,
            &BTreeSet::new(),
        )
        .events
        .into_iter()
        .filter(|event| event.event_type == "session_risk_summary")
        .collect()
    }
    fn built_summary(activities: &[(Source, Event)], detections: &[(Source, Event)]) -> Event {
        let mut summaries = summarize_session_risk_events(activities, detections).expect("summary");
        assert_eq!(summaries.len(), 1);
        summaries.pop().expect("summary").1
    }

    let mut state = ScanState::default();
    assert!(
        emitted_summaries(
            &mut state,
            emit_session_risk_summary,
            initial.0.clone(),
            initial.1.clone(),
        )
        .is_empty()
    );

    let first = emitted_summaries(&mut state, true, initial.0.clone(), initial.1.clone());
    assert_eq!(first.len(), 1);
    let built = built_summary(&initial.0, &initial.1);
    let evidence = |event: &Event| serde_json::to_value(&event.evidence).expect("evidence");
    assert_eq!(evidence(&first[0]), evidence(&built));
    assert_eq!(first[0].event_time, built.event_time);
    assert!(first[0].event_time.is_some());
    assert!(first[0].evidence.iter().any(|item| {
        matches!(
            item.field.as_str(),
            "event_counts" | "risky_action_count" | "tool_call_count"
        )
    }));

    let grown_summary = built_summary(&grown.0, &grown.1);
    assert_eq!(grown_summary.severity, first[0].severity);
    assert_eq!(grown_summary.risk_score, first[0].risk_score);
    assert_eq!(grown_summary.rule_ids, first[0].rule_ids);
    assert_ne!(evidence(&grown_summary), evidence(&first[0]));
    assert_ne!(grown_summary.event_time, first[0].event_time);
    assert!(emitted_summaries(&mut state, true, grown.0, grown.1).is_empty());

    let second = emitted_summaries(&mut state, true, added_rule.0, added_rule.1);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].severity, first[0].severity);
    assert_eq!(second[0].risk_score, first[0].risk_score);
    assert_eq!(
        second[0].rule_ids,
        vec!["rule.added".to_string(), "rule.synthetic".to_string()]
    );
}
