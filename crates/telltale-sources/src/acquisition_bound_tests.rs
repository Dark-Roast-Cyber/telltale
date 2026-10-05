use super::*;
use serde_json::{Value, json};
use telltale_schema::observation::{
    BoundDimension, CanonicalFieldCategory, JsonValue, ObservationBody,
};

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new("2026-09-18T12:00:00Z").unwrap())
}

#[test]
fn codex_bound_diagnostics_cover_conversion_and_assembled_values() {
    let nested = |count| (0..count).fold(Value::Null, |value, _| json!([value]));
    let object = |count| {
        Value::Object(
            (0..count)
                .map(|i| (format!("synthetic_key_{i}"), Value::Null))
                .collect(),
        )
    };
    let dimensions = [
        (
            json!("é".repeat(2048)),
            json!(format!("{}x", "é".repeat(2048))),
            BoundDimension::StringBytes,
        ),
        (nested(5), nested(6), BoundDimension::Depth),
        (
            json!(vec![Value::Null; 64]),
            json!(vec![Value::Null; 65]),
            BoundDimension::ArrayItems,
        ),
        (object(32), object(33), BoundDimension::ObjectMembers),
        (
            json!({"k".repeat(64): null}),
            json!({"k".repeat(65): null}),
            BoundDimension::KeyBytes,
        ),
        (
            json!(["\u{1}".repeat(2730)]),
            json!(["\u{1}".repeat(2731)]),
            BoundDimension::EncodedBytes,
        ),
    ];
    let directory = tempfile::tempdir().unwrap();
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: directory.path().join("synthetic-bound.jsonl"),
        };
        let acquire = |record: Value| {
            // Late failures may not expose the already-valid message or accounting.
            let prefix = json!({"type":"user", "session_id":"synthetic", "content":"ok"});
            std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
            acquire_source(&source, options())
        };
        for (exact, excess, dimension) in &dimensions {
            for (key, kind, category) in [
                (
                    "arguments",
                    "tool_call",
                    CanonicalFieldCategory::ToolArguments,
                ),
                ("output", "tool_result", CanonicalFieldCategory::ToolResult),
            ] {
                let record = |value: &Value| json!({"type":kind, "session_id":"synthetic", "name":"exec", key:value});
                let batch = acquire(record(exact)).expect("exact bound");
                assert_eq!(batch.observations.len(), 2);
                let ObservationBody::Tool(tool) = batch.observations[1].body() else {
                    panic!("expected tool")
                };
                let retained = if key == "arguments" {
                    tool.arguments()
                } else {
                    tool.result()
                };
                assert!(
                    retained == Some(&JsonValue::try_from_source_value(exact).unwrap()),
                    "payload changed"
                );
                let error = acquire(record(excess))
                    .err()
                    .expect("whole-source rejection");
                assert_eq!(
                    error.bound_context(),
                    Some(CanonicalBoundContext {
                        category,
                        dimension: *dimension
                    })
                );
                assert_eq!(error.to_string(), "unbounded_value");
                let diagnostic = format!("{error:?}");
                for forbidden in [
                    "synthetic_key",
                    "synthetic-bound",
                    "synthetic",
                    "exec",
                    "arguments",
                    "output",
                ] {
                    assert!(!diagnostic.contains(forbidden), "source content retained");
                }
            }
        }
        for (record, category, dimension) in [
            (
                json!({"type":"assistant", "session_id":"synthetic", "content":vec![json!({"type":"text", "text":"x".repeat(4096)});4]}),
                CanonicalFieldCategory::MessageContentParts,
                BoundDimension::EncodedBytes,
            ),
            (
                json!({"type":"assistant", "session_id":"synthetic", "content":[{"type":"tool_use", "name":"exec", "input":nested(3)}]}),
                CanonicalFieldCategory::MessageContentParts,
                BoundDimension::Depth,
            ),
            (
                json!({"type":"assistant", "session_id":"synthetic", "content":vec![json!({"type":"text", "text":"ok"});65]}),
                CanonicalFieldCategory::MessageContentParts,
                BoundDimension::ArrayItems,
            ),
            (
                json!({"type":"assistant", "session_id":"synthetic", "content":[{"type":"tool_use", "name":"exec", "input":{"private_key":"x".repeat(4097)}}]}),
                CanonicalFieldCategory::MessageContentParts,
                BoundDimension::StringBytes,
            ),
            (
                json!({"type":"assistant", "session_id":"synthetic", "content":[{"type":"tool_result", "content":{"private_key":"x".repeat(4097)}}]}),
                CanonicalFieldCategory::MessageContentParts,
                BoundDimension::StringBytes,
            ),
            (
                json!({"type":"tool_call", "session_id":"synthetic", "name":"exec", "command":"x".repeat(4097)}),
                CanonicalFieldCategory::CommandText,
                BoundDimension::StringBytes,
            ),
        ] {
            let error = acquire(record).err().expect("assembled bound rejection");
            assert_eq!(
                error.bound_context(),
                Some(CanonicalBoundContext {
                    category,
                    dimension
                })
            );
            assert!(
                !format!("{error:?} {error}").contains("private_key"),
                "key leaked"
            );
        }
        let decomposed = "e\u{301}".repeat(1366);
        let batch = acquire(json!({"type":"assistant", "session_id":"synthetic", "content":[{"type":"text", "text":decomposed}]})).expect("existing normalized part behavior");
        let ObservationBody::Message(message) = batch.observations[1].body() else {
            panic!("expected message")
        };
        assert!(
            message.content_parts()[0].value() == &JsonValue::string(&decomposed),
            "NFC projection changed"
        );
        let error = acquire(json!({"type":"user", "session_id":"synthetic", "content":decomposed}))
            .err()
            .expect("original scalar byte check");
        assert_eq!(
            error.bound_context(),
            Some(CanonicalBoundContext {
                category: CanonicalFieldCategory::MessageContent,
                dimension: BoundDimension::StringBytes
            })
        );
        // Native accounting owns attestation failures and precedes canonical mapping.
        let error = acquire(json!({"type":"user", "session_id":42, "content":"x".repeat(4097)}))
            .err()
            .expect("invalid attestation");
        assert_eq!(error, AcquisitionError::InvalidAttestation);
        assert_eq!(error.bound_context(), None);
    }
}
