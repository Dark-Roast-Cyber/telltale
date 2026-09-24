use crate::source_read::SourceReadError;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

#[test]
fn malformed_jsonl_is_a_json_read_error() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: crate::test_fixture_path(
            "parser_maturity/non_discovered/malformed-known-parser.jsonl",
        ),
    };
    let error = super::native::extract_codex_native_records(&source).expect_err("malformed");
    assert!(matches!(error, SourceReadError::Json(_)));
}

#[test]
fn non_object_envelope_is_schema_drift() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: crate::test_fixture_path("parser_maturity/non_discovered/schema-drift.jsonl"),
    };
    let error = super::native::extract_codex_native_records(&source).expect_err("drift");
    let message = error.to_string();
    assert!(matches!(error, SourceReadError::SchemaDrift { .. }));
    assert!(message.contains("schema drift"));
    assert!(!message.contains(source.path.to_string_lossy().as_ref()));
}
