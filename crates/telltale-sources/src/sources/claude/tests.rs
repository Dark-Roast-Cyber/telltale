use crate::source_read::SourceReadError;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

#[test]
fn malformed_jsonl_is_a_json_read_error() {
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path: crate::test_fixture_path("rule_samples/malformed-source.jsonl"),
    };
    let error = super::native::extract_claude_native_records(&source).expect_err("malformed");
    let message = error.to_string();
    assert!(matches!(error, SourceReadError::Json(_)));
    assert!(message.contains("json parse error"));
    assert!(!message.contains("malformed-source"));
}

#[test]
fn missing_jsonl_is_an_io_read_error() {
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path: "missing-session.jsonl".into(),
    };
    let error = super::native::extract_claude_native_records(&source).expect_err("missing");
    assert!(matches!(error, SourceReadError::Io(_)));
    assert!(error.to_string().contains("io error"));
}

#[test]
fn non_object_envelope_is_schema_drift() {
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path: crate::test_fixture_path("parser_maturity/non_discovered/schema-drift.jsonl"),
    };
    let error = super::native::extract_claude_native_records(&source).expect_err("drift");
    let message = error.to_string();
    assert!(matches!(error, SourceReadError::SchemaDrift { .. }));
    assert!(message.contains("schema drift"));
    assert!(!message.contains("Synthetic schema envelope drift"));
}
