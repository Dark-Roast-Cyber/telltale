use std::path::PathBuf;

use crate::detection::{account_policy_matches, detect_parsed_source_records_with_snapshot};
use telltale_rules::{CompiledRuleSet, load_rule_set_from_documents};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::source::Source;

const RULES: &str = r#"
version: 1
description: accounting fixtures
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: test.first
    category: test
    severity: medium
    score: 1
    targets: [command]
    regex: "first"
    tags: []
    explanation: first test match
  - id: test.second
    category: test
    severity: medium
    score: 1
    targets: [command]
    regex: "second"
    tags: []
    explanation: second test match
modifiers:
  - id: chain.test
    score: 1
    when_all_rule_ids: [test.first]
    explanation: test modifier
"#;

fn source(source_id: &str) -> Source {
    Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: source_id.to_string(),
        path: PathBuf::from(format!("/synthetic/{source_id}.jsonl")),
    }
}

fn record(session_id: &str, content: &str) -> NormalizedRecord {
    NormalizedRecord {
        session_id: session_id.to_string(),
        client: "codex".to_string(),
        agent: None,
        model: None,
        provider: None,
        timestamp: None,
        kind: RecordKind::ToolCall,
        tool_name: Some("shell".to_string()),
        arguments: None,
        content: content.to_string(),
    }
}

fn compiled(policy: Option<&str>) -> CompiledRuleSet {
    load_rule_set_from_documents(&[RULES], policy).expect("compile accounting rules")
}

#[test]
fn counts_all_filtered_candidates_and_rule_references() {
    let policy = "disabled_categories: [test]\n";
    let records = vec![
        record("session-a", "first second"),
        record("session-b", "first second"),
    ];
    let (_, snapshot) = detect_parsed_source_records_with_snapshot(
        &source("source-a"),
        &compiled(Some(policy)),
        &records,
    );

    let accounting = account_policy_matches(&snapshot, &compiled(None)).expect("accounting");
    assert_eq!(accounting.pre_policy_detection_candidate_count, 2);
    assert_eq!(accounting.fully_filtered_detection_candidate_count, 2);
    assert_eq!(accounting.filtered_rule_id_count, 6);
}

#[test]
fn counts_partial_filtering_and_modifier_ids() {
    let policy = "disabled_rules: [test.second, chain.test]\n";
    let records = vec![record("session-a", "first second")];
    let (_, snapshot) = detect_parsed_source_records_with_snapshot(
        &source("source-a"),
        &compiled(Some(policy)),
        &records,
    );

    let accounting = account_policy_matches(&snapshot, &compiled(None)).expect("accounting");
    assert_eq!(accounting.pre_policy_detection_candidate_count, 1);
    assert_eq!(accounting.fully_filtered_detection_candidate_count, 0);
    assert_eq!(accounting.filtered_rule_id_count, 2);
}

#[test]
fn preserves_source_and_session_boundaries_and_noop_policy_is_zero() {
    let records = vec![record("session-a", "first"), record("session-b", "second")];
    let no_op_policy = "name: no-op\n";
    let (_, first_snapshot) = detect_parsed_source_records_with_snapshot(
        &source("source-a"),
        &compiled(Some(no_op_policy)),
        &records,
    );
    let (_, second_snapshot) = detect_parsed_source_records_with_snapshot(
        &source("source-b"),
        &compiled(Some(no_op_policy)),
        &records,
    );

    for snapshot in [&first_snapshot, &second_snapshot] {
        let accounting = account_policy_matches(snapshot, &compiled(None)).expect("accounting");
        assert_eq!(accounting.pre_policy_detection_candidate_count, 2);
        assert_eq!(accounting.fully_filtered_detection_candidate_count, 0);
        assert_eq!(accounting.filtered_rule_id_count, 0);
    }
}

#[test]
fn rejects_invalid_effective_snapshot_without_partial_accounting() {
    let records = vec![record("session-a", "first")];
    let (_, mut snapshot) =
        detect_parsed_source_records_with_snapshot(&source("source-a"), &compiled(None), &records);
    snapshot.sessions[0].effective_rule_ids = Some(vec!["test.missing".to_string()]);

    assert!(account_policy_matches(&snapshot, &compiled(None)).is_err());
}

#[test]
fn rejects_duplicate_pre_policy_rule_ids_before_counting() {
    let mut duplicate_rule_set: telltale_rules::RuleSet =
        serde_yaml::from_str(RULES).expect("parse accounting rules");
    duplicate_rule_set
        .rules
        .push(duplicate_rule_set.rules[0].clone());
    let duplicate_pre_policy_rules = duplicate_rule_set.compile(None).expect("compile rules");
    let (_, snapshot) = detect_parsed_source_records_with_snapshot(
        &source("source-a"),
        &compiled(None),
        &[record("session-a", "first")],
    );

    assert!(account_policy_matches(&snapshot, &duplicate_pre_policy_rules).is_err());
}
