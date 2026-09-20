use super::activity::{BaselineReplacement, evaluate_activity};
use super::*;
use crate::baseline::{
    BaselineDeviationConfig, BaselineSnapshotStore, PathClass, baseline_host_identity,
    baseline_snapshot_id,
};
use telltale_schema::clients::ClientId;
use telltale_schema::observation::CorrelationId;
use telltale_sources::acquisition::{
    AccountingCoverage, AttestedValue, NativeCounts, RecordCounts, SessionAccounting,
    SessionMetadata, SourceAccounting,
};

fn session(id: &str) -> SessionAccounting {
    let mut counts = NativeCounts {
        native_units: 6,
        record_counts: RecordCounts {
            tool_call: 6,
            ..Default::default()
        },
        ..Default::default()
    };
    counts.contributions.tool_calls.insert("shell".into(), 6);
    counts
        .contributions
        .path_classes
        .insert(PathClass::Source, 3);
    counts
        .contributions
        .network_hosts
        .insert("recognizable.synthetic.example".into(), 2);
    SessionAccounting {
        session_id: CorrelationId::source_reported(id).unwrap(),
        metadata: SessionMetadata {
            agent: AttestedValue::Known("agent".into()),
            model: AttestedValue::Known("model".into()),
            provider: AttestedValue::Known("provider".into()),
        },
        counts,
    }
}

fn accounting() -> SourceAccounting {
    SourceAccounting {
        coverage: AccountingCoverage::CompleteSource,
        sessions: vec![session("s")],
        ..Default::default()
    }
}

fn run(
    accounting: &SourceAccounting,
    prior: &BaselineSnapshotStore,
) -> Result<activity::ActivityBaselineResult, ProcessingError> {
    let rules = telltale_rules::load_default_rule_set().unwrap();
    let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: None,
            observations: &[],
        },
        &plan,
        None,
    )
    .unwrap();
    evaluate_activity(
        &evaluation,
        accounting,
        &"a".repeat(64),
        prior,
        BaselineDeviationConfig {
            enabled: true,
            min_previous_tool_calls: 5,
        },
    )
}

fn replacement(result: &activity::ActivityBaselineResult) -> &[crate::baseline::BaselineSummary] {
    match &result.replacement {
        BaselineReplacement::Replace(summaries) => summaries,
        BaselineReplacement::NoReplacement => panic!("expected explicit replacement"),
    }
}

#[test]
fn complete_accounting_preserves_multiplicity_hashes_hosts_and_uses_sparse_counts() {
    let input = accounting();
    let result = run(&input, &BaselineSnapshotStore::default()).unwrap();
    let summaries = replacement(&result);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].observations.records, 6);
    assert_eq!(summaries[0].tool_call_counts["shell"], 6);
    assert_eq!(summaries[0].path_class_counts[&PathClass::Source], 3);
    assert_eq!(
        summaries[0].network_host_counts[&baseline_host_identity("recognizable.synthetic.example")],
        2
    );
    assert!(
        input.sessions[0]
            .counts
            .contributions
            .network_hosts
            .contains_key("recognizable.synthetic.example")
    );
    assert!(
        !serde_json::to_string(summaries)
            .unwrap()
            .contains("recognizable")
    );
    assert!(!format!("{:?}", result.replacement).contains("recognizable"));
    assert!(
        !serde_json::to_string(&result.events)
            .unwrap()
            .contains("recognizable")
    );
    assert_eq!(result.events.len(), 1);
    let event = &result.events[0];
    assert_eq!(event.event_type, "activity");
    assert_eq!(event.agent.as_deref(), Some("agent"));
    assert_eq!(
        event
            .evidence
            .iter()
            .find(|e| e.field == "record_counts")
            .unwrap()
            .redacted_value,
        r#"{"tool_call":6}"#
    );
}

#[test]
fn partial_activity_is_successful_without_replacement_or_deviation() {
    let mut input = accounting();
    let previous = replacement(&run(&input, &BaselineSnapshotStore::default()).unwrap())[0].clone();
    let mut prior = BaselineSnapshotStore::default();
    prior
        .snapshots
        .insert(baseline_snapshot_id(&previous.key), previous);
    input.coverage = AccountingCoverage::PartialSource;
    input.sessions[0]
        .counts
        .contributions
        .tool_calls
        .insert("novel".into(), 1);
    let before = prior.clone();
    let result = run(&input, &prior).unwrap();
    assert!(matches!(
        result.replacement,
        BaselineReplacement::NoReplacement
    ));
    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].risk_score, 0);
    assert!(
        !result.events[0]
            .tags
            .iter()
            .any(|t| t == "baseline_deviation")
    );
    assert_eq!(prior, before);
}

#[test]
fn missing_stores_optional_keys_but_ambiguous_never_enters_missing_partition() {
    for field in 0..3 {
        for ambiguous in [false, true] {
            let mut input = accounting();
            let metadata = &mut input.sessions[0].metadata;
            let target = match field {
                0 => &mut metadata.agent,
                1 => &mut metadata.model,
                _ => &mut metadata.provider,
            };
            *target = if ambiguous {
                AttestedValue::Ambiguous
            } else {
                AttestedValue::Missing
            };
            let result = run(&input, &BaselineSnapshotStore::default()).unwrap();
            let stored = replacement(&result);
            assert_eq!(stored.len(), usize::from(!ambiguous));
            let event = &result.events[0];
            assert_eq!(event.agent.as_deref(), (field != 0).then_some("agent"));
            assert_eq!(event.model.as_deref(), (field != 1).then_some("model"));
            assert_eq!(
                event.provider.as_deref(),
                (field != 2).then_some("provider")
            );
            if !ambiguous {
                let previous = stored[0].clone();
                let mut prior = BaselineSnapshotStore::default();
                prior
                    .snapshots
                    .insert(baseline_snapshot_id(&previous.key), previous);
                input.sessions[0]
                    .counts
                    .contributions
                    .tool_calls
                    .insert("novel".into(), 1);
                let compared = run(&input, &prior).unwrap();
                assert_eq!(
                    compared.events[0].risk_score,
                    if field == 0 { 5 } else { 0 }
                );
            }
        }
    }
}

#[test]
fn mixed_and_unscoped_accounting_have_explicit_replacement_semantics() {
    let mut input = accounting();
    let mut ambiguous = session("ambiguous");
    ambiguous.metadata.model = AttestedValue::Ambiguous;
    input.sessions.push(ambiguous);
    input.unscoped = session("ignored").counts;
    let mixed = run(&input, &BaselineSnapshotStore::default()).unwrap();
    assert_eq!(replacement(&mixed).len(), 1);
    assert_eq!(replacement(&mixed)[0].observations.tool_calls, 6);
    assert_eq!(mixed.events.len(), 2);
    input.sessions.remove(0);
    assert!(replacement(&run(&input, &BaselineSnapshotStore::default()).unwrap()).is_empty());
    input.sessions.clear();
    let empty = run(&input, &BaselineSnapshotStore::default()).unwrap();
    assert!(replacement(&empty).is_empty());
    assert!(empty.events.is_empty());
    input.coverage = AccountingCoverage::PartialSource;
    let partial = run(&input, &BaselineSnapshotStore::default()).unwrap();
    assert!(matches!(
        partial.replacement,
        BaselineReplacement::NoReplacement
    ));
    assert!(partial.events.is_empty());
}

#[test]
fn prior_snapshot_is_immutable_and_current_sample_does_not_self_train() {
    let mut input = accounting();
    let empty = BaselineSnapshotStore::default();
    let first = run(&input, &empty).unwrap();
    assert_eq!(first.events[0].risk_score, 0);
    let previous = replacement(&first)[0].clone();
    let mut prior = BaselineSnapshotStore::default();
    prior
        .snapshots
        .insert(baseline_snapshot_id(&previous.key), previous);
    let before = prior.clone();
    input.sessions[0]
        .counts
        .contributions
        .tool_calls
        .insert("novel".into(), 1);
    let next = run(&input, &prior).unwrap();
    assert_eq!(next.events[0].risk_score, 5);
    assert_eq!(prior, before);
    let current = replacement(&next)[0].clone();
    let mut self_trained = prior.clone();
    self_trained
        .snapshots
        .insert(baseline_snapshot_id(&current.key), current);
    assert_eq!(run(&input, &self_trained).unwrap().events[0].risk_score, 0);
}

#[test]
fn conversion_and_contribution_overflow_fail_the_entire_source() {
    let mut input = accounting();
    let mut bad = session("late-failure");
    bad.counts.record_counts.other = u64::from(u32::MAX) + 1;
    input.sessions.push(bad);
    assert!(run(&input, &BaselineSnapshotStore::default()).is_err());
    input.sessions[1].counts.record_counts.other = 0;
    input.sessions[1]
        .counts
        .contributions
        .tool_calls
        .insert("shell".into(), u64::MAX);
    assert!(run(&input, &BaselineSnapshotStore::default()).is_err());
}

#[test]
fn duplicate_visible_session_identity_fails_closed() {
    let mut input = accounting();
    input.sessions.push(session("s"));
    assert!(run(&input, &BaselineSnapshotStore::default()).is_err());
}

#[test]
fn all_six_record_kinds_and_same_key_sessions_are_aggregated_without_recounting() {
    let mut input = accounting();
    input.sessions[0].counts.record_counts = RecordCounts {
        user_message: 1,
        assistant_message: 2,
        tool_call: 3,
        tool_result: 4,
        session_meta: 5,
        other: 6,
    };
    input.sessions.push(session("second"));
    let result = run(&input, &BaselineSnapshotStore::default()).unwrap();
    assert_eq!(
        result.events[0]
            .evidence
            .iter()
            .find(|e| e.field == "record_counts")
            .unwrap()
            .redacted_value,
        r#"{"assistant_message":2,"other":6,"session_meta":5,"tool_call":3,"tool_result":4,"user_message":1}"#
    );
    let stored = replacement(&result);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].observations.records, 27);
    assert_eq!(stored[0].observations.tool_calls, 9);
    // Contribution multiplicity comes from accounting, not the histogram.
    assert_eq!(stored[0].tool_call_counts["shell"], 12);
    assert_eq!(stored[0].path_class_counts[&PathClass::Source], 6);
    assert_eq!(
        stored[0].network_host_counts[&baseline_host_identity("recognizable.synthetic.example")],
        4
    );
}

#[test]
fn durable_host_normalization_aggregation_is_checked() {
    let mut input = accounting();
    let hosts = &mut input.sessions[0].counts.contributions.network_hosts;
    hosts.clear();
    hosts.insert("SYNTHETIC.example".into(), u64::MAX);
    hosts.insert("synthetic.example".into(), 1);
    assert!(run(&input, &BaselineSnapshotStore::default()).is_err());
}
