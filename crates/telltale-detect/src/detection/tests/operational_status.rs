use std::path::PathBuf;

use crate::detection::detect_parsed_source_attempt;
use telltale_rules::load_rule_set_from_documents;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::source::Source;

const RULES: &str = r#"
version: 1
description: operational status fixtures
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: test.operational
    category: test
    severity: medium
    score: 1
    targets: [command]
    regex: "match-me"
    tags: []
    explanation: operational status test match
modifiers: []
"#;

fn source() -> Source {
    Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from("/synthetic/operational.jsonl"),
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

fn rules() -> telltale_rules::CompiledRuleSet {
    load_rule_set_from_documents(&[RULES], None).expect("compile operational status rules")
}

#[test]
fn no_match_completes_operationally_without_findings() {
    let attempt = detect_parsed_source_attempt(
        &source(),
        &rules(),
        &[record("session-a", "nothing relevant")],
        false,
    );
    assert!(attempt.completed_operationally);
    assert!(attempt.events.is_empty());
    assert!(attempt.snapshot.is_none());
}

#[test]
fn match_completes_operationally() {
    let attempt = detect_parsed_source_attempt(
        &source(),
        &rules(),
        &[record("session-a", "match-me")],
        false,
    );
    assert!(attempt.completed_operationally);
    assert_eq!(attempt.events.len(), 1);
    assert_eq!(attempt.events[0].event_type, "detection");
}

#[test]
fn operational_failure_emits_scanner_error_and_is_not_success() {
    let attempt =
        detect_parsed_source_attempt(&source(), &rules(), &[record("", "match-me")], false);
    assert!(!attempt.completed_operationally);
    assert_eq!(attempt.events.len(), 1);
    assert_eq!(attempt.events[0].event_type, "scanner_error");
}
