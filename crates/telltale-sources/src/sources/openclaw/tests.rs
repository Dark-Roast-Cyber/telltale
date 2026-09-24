use std::fs;

use tempfile::tempdir;

use crate::source_read::SourceReadError;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

fn openclaw_source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::OpenClaw,
        kind: SourceKind::Jsonl,
        source_id: "openclaw.agents".to_string(),
        path,
    }
}

#[test]
fn non_object_envelope_is_schema_drift() {
    let source = openclaw_source(crate::test_fixture_path(
        "parser_maturity/non_discovered/schema-drift.jsonl",
    ));
    let error = super::native::extract_openclaw_native_records(&source).expect_err("drift");
    assert!(matches!(error, SourceReadError::SchemaDrift { .. }));
    assert!(error.to_string().contains("schema drift"));
}

#[test]
fn malformed_jsonl_is_a_json_read_error() {
    let source = openclaw_source(crate::test_fixture_path(
        "parser_maturity/non_discovered/malformed-known-parser.jsonl",
    ));
    let error = super::native::extract_openclaw_native_records(&source).expect_err("malformed");
    assert!(matches!(error, SourceReadError::Json(_)));
}

#[test]
fn empty_jsonl_has_no_native_records() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("empty.jsonl");
    fs::write(&path, b"\n  \n").expect("empty fixture");
    assert!(
        super::native::extract_openclaw_native_records(&openclaw_source(path))
            .expect("empty")
            .is_empty()
    );
}

#[test]
fn native_records_keep_direct_tool_call_structure() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("native-tool.jsonl");
    fs::write(
        &path,
        b"{\"type\":\"session_meta\",\"agent\":\"fixture-agent\",\"provider\":\"fixture-provider\",\"model\":\"fixture-model\"}\n{\"type\":\"assistant\",\"content\":\"Synthetic response.\",\"tool_calls\":[{\"id\":\"fixture-call\",\"name\":\"read_file\",\"arguments\":{\"path\":\"synthetic.txt\"}}]}\n",
    )
    .expect("fixture");
    let native = super::native::extract_openclaw_native_records(&openclaw_source(path))
        .expect("native records");
    assert_eq!(native.len(), 2);
    assert_eq!(native[1].attestation.as_ref().unwrap().agent.known(), None);
    assert_eq!(native[1].tool_calls.len(), 1);
    assert_eq!(
        native[1].tool_calls[0].call_id.as_deref(),
        Some("fixture-call")
    );
}
