use crate::acquisition::{
    AccountingCoverage, AcquisitionError, AcquisitionOptions, AcquisitionProgress,
    DirectReadLimits, acquire_source, acquire_source_bounded,
};
use crate::source_read::SourceReadError;
use serde_json::{Value, json};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{FactProvenance, JsonValue, ObservationBody, ObservedAt};
use telltale_schema::source::Source;

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new("2026-10-16T00:00:00Z").unwrap())
}

fn conversation_forms(content: &Value) -> [Value; 7] {
    [
        json!({"type":"user","sessionId":"synthetic","message":{"role":"user","content":content}}),
        json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":content}}),
        json!({"type":"user","sessionId":"synthetic","content":content}),
        json!({"role":"assistant","sessionId":"synthetic","content":content}),
        json!({"sessionId":"synthetic","message":{"role":"user","content":content}}),
        json!({"type":"assistant_message","sessionId":"synthetic","content":content}),
        json!({"type":"assistant","sessionId":"synthetic","content":[null],"message":{"role":"assistant","content":content}}),
    ]
}

#[test]
fn malformed_content_block_envelopes_fail_acquisition_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("PRIVATE-malformed-block.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid prefix"});
    let bad_blocks = [
        json!(null),
        json!(false),
        json!(9),
        json!("PRIVATE-block"),
        json!([]),
        json!({"text":"PRIVATE-block"}),
        json!({"type":null,"text":"PRIVATE-block"}),
        json!({"type":9,"text":"PRIVATE-block"}),
        json!({"type":false,"text":"PRIVATE-block"}),
        json!({"type":{"PRIVATE-key":true},"text":"PRIVATE-block"}),
        json!({"type":["PRIVATE-type"],"text":"PRIVATE-block"}),
    ];
    for (case, bad) in bad_blocks.iter().enumerate() {
        let content = json!([{"type":"text","text":"valid part before malformed tail"},bad]);
        for (form, record) in conversation_forms(&content).iter().enumerate() {
            std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
            let error = match acquire_source(&source, options()) {
                Err(error) => error,
                Ok(_) => panic!(
                    "case {case}, form {form}: malformed envelope preserved a successful prefix"
                ),
            };
            assert_eq!(error, AcquisitionError::SourceRead);
            assert!(!format!("{error} {error:?}").contains("PRIVATE"));
            let bounded =
                match acquire_source_bounded(&source, options(), DirectReadLimits::default()) {
                    Err(error) => error,
                    Ok(_) => panic!(
                        "case {case}, form {form}: bounded acquisition accepted malformed envelope"
                    ),
                };
            assert_eq!(
                bounded,
                AcquisitionError::BoundedSourceRead(
                    crate::source_read::BoundedReadError::MalformedSource
                )
            );
            let native = match super::native::extract_claude_native_records(&source) {
                Err(error) => error,
                Ok(_) => {
                    panic!("case {case}, form {form}: extraction must reject malformed envelopes")
                }
            };
            assert!(matches!(native, SourceReadError::SchemaDrift { .. }));
            assert!(!format!("{native} {native:?}").contains("PRIVATE"));
        }
    }
}

#[test]
fn well_formed_unknown_content_types_quarantine_only_their_record() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-unknown-block.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid prefix"});
    let content = json!([{"type":"text","text":"excluded valid part"},{"type":"Future","data":"PRIVATE-unknown"}]);
    for record in conversation_forms(&content) {
        std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
        assert_eq!(batch.accounting.sessions.len(), 1);
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 2);
        assert_eq!(batch.progress, AcquisitionProgress::None);
        assert_eq!(batch.quarantined.len(), 1);
        assert_eq!(batch.quarantined[0].code, "unknown_content_block");
        assert_eq!(batch.quarantined[0].source_sequence, 1);
        assert_eq!(batch.observations.len(), 1);
        let ObservationBody::Message(message) = batch.observations[0].body() else {
            panic!("valid prefix must remain a message")
        };
        assert!(message.content() == Some(&JsonValue::string("valid prefix")));
        assert!(!format!("{:?}", batch.quarantined).contains("PRIVATE"));
    }
}

#[test]
fn malformed_known_part_fields_remain_atomic_mapping_failures() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("PRIVATE-known-part.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid prefix"});
    for (block, code) in [
        (json!({"type":"text","text":null}), "invalid_content_block"),
        (
            json!({"type":"text","text":{"PRIVATE-key":true}}),
            "invalid_content_block",
        ),
        (
            json!({"type":"tool_use","id":null,"name":"Read","input":{}}),
            "missing_tool_id",
        ),
        (
            json!({"type":"tool_use","id":"call","name":false,"input":{}}),
            "missing_tool_name",
        ),
        (
            json!({"type":"tool_result","tool_use_id":null,"content":"PRIVATE-result"}),
            "missing_tool_id",
        ),
        (
            json!({"type":"tool_result","tool_use_id":"call","is_error":null}),
            "invalid_content_block",
        ),
    ] {
        for record in conversation_forms(&json!([block])) {
            std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
            let error = match acquire_source(&source, options()) {
                Err(error) => error,
                Ok(_) => panic!("malformed known part preserved a successful prefix"),
            };
            assert_eq!(error, AcquisitionError::CanonicalMapping { code });
            assert!(!format!("{error} {error:?}").contains("PRIVATE"));
        }
    }
}

#[test]
fn direct_message_structures_are_not_content_block_envelopes() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-direct-content.jsonl"),
    };
    let content = json!({"type":false,"content":[null]});
    let expected = JsonValue::object([
        ("type".into(), JsonValue::Bool(false)),
        ("content".into(), JsonValue::array(vec![JsonValue::Null])),
    ])
    .unwrap();
    for record in conversation_forms(&content) {
        std::fs::write(&source.path, format!("{record}\n")).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert!(batch.quarantined.is_empty());
        assert_eq!(
            batch.accounting.coverage,
            AccountingCoverage::CompleteSource
        );
        assert_eq!(batch.observations.len(), 1);
        let ObservationBody::Message(message) = batch.observations[0].body() else {
            panic!("expected direct message")
        };
        assert!(message.content() == Some(&expected));
        assert_eq!(
            batch.observations[0].fact_metadata()["message.content"].provenance(),
            FactProvenance::Reported
        );
    }
}

#[test]
fn tool_values_and_ignored_payloads_are_not_content_block_envelopes() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-opaque-content.jsonl"),
    };
    let opaque = json!([null,{"type":false,"content":[null]}]);
    let expected = JsonValue::array(vec![
        JsonValue::Null,
        JsonValue::object([
            ("type".into(), JsonValue::Bool(false)),
            ("content".into(), JsonValue::array(vec![JsonValue::Null])),
        ])
        .unwrap(),
    ]);
    let request = json!({"type":"assistant","sessionId":"synthetic","content":[{"type":"tool_use","id":"call","name":"Read","input":opaque}]});
    let result = json!({"type":"user","sessionId":"synthetic","content":[{"type":"tool_result","tool_use_id":"call","content":opaque}]});
    let ignored = json!({"type":"assistant","sessionId":"synthetic","content":[
        {"type":"thinking","thinking":{"content":[null,{"type":false}],"text":"PRIVATE-reasoning"}},
        {"type":"image","source":{"content":[false],"type":null}},
        {"type":"text","text":"kept"}
    ]});
    std::fs::write(&source.path, format!("{request}\n{result}\n{ignored}\n")).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert!(batch.quarantined.is_empty());
    assert_eq!(
        batch.accounting.coverage,
        AccountingCoverage::CompleteSource
    );
    assert_eq!(batch.observations.len(), 4);
    let tools = batch
        .observations
        .iter()
        .filter_map(|observation| match observation.body() {
            ObservationBody::Tool(tool) => Some((observation, tool)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(tools.len(), 2);
    assert!(tools[0].1.arguments() == Some(&expected));
    assert!(tools[1].1.result() == Some(&expected));
    assert_eq!(
        tools[1].0.fact_metadata()["tool.result"].provenance(),
        FactProvenance::Reported
    );
    assert!(!format!("{:?}", batch.observations).contains("PRIVATE"));
}

#[test]
fn skipped_or_unknown_record_payloads_remain_opaque() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-opaque-record.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid prefix"});
    for (kind, coverage) in [
        ("queue-operation", AccountingCoverage::CompleteSource),
        ("Future", AccountingCoverage::PartialSource),
    ] {
        let record = json!({"type":kind,"sessionId":"synthetic","content":[null,{"type":false}]});
        std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert_eq!(batch.accounting.coverage, coverage);
        assert_eq!(batch.progress, AcquisitionProgress::None);
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 2);
        if kind == "Future" {
            assert_eq!(batch.quarantined.len(), 1);
            assert_eq!(batch.quarantined[0].code, "unknown_discriminator");
        } else {
            assert!(batch.quarantined.is_empty());
        }
    }
}

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
