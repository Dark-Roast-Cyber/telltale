use std::path::PathBuf;

use crate::detection::{detect_parsed_source_records, evaluate_session_matches};
use telltale_rules::{CompiledRuleSet, load_rule_set_from_documents};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::source::Source;

const RULES: &str = r#"
version: 1
description: direct-record compatibility fixtures
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

fn compiled() -> CompiledRuleSet {
    load_rule_set_from_documents(&[RULES], None).expect("compile direct-record rules")
}

#[test]
fn direct_record_session_retains_flat_match_and_event3_contract() {
    let rules = compiled();
    let records = [
        record("session-a", "first second"),
        record("session-a", "first"),
    ];
    let result = evaluate_session_matches(&rules, &records).unwrap().unwrap();
    assert_eq!(result.rule_ids, ["test.first", "test.second", "chain.test"]);
    assert_eq!(result.score, 3);
    assert_eq!(result.evidence.len(), 2);
    assert_eq!(result.evidence[0].field, "command");
    let events = detect_parsed_source_records(&source("source-a"), &rules, &records);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "detection");
    assert_eq!(
        events[0].rule_ids,
        ["test.first", "test.second", "chain.test"]
    );
    assert_eq!(events[0].risk_score, 3);
}
