use super::*;

#[test]
fn claude_tool_result_value_and_provenance_follow_native_representation() {
    use telltale_schema::observation::{FactProvenance, Sensitivity};
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic-results.jsonl"),
    };
    let text_part = JsonValue::object([
        ("type".to_owned(), JsonValue::string("text")),
        ("text".to_owned(), JsonValue::string("first")),
    ])
    .unwrap();
    for (case, content, expected, provenance) in [
        (
            "direct",
            json!("first\nsecond"),
            JsonValue::string("first\nsecond"),
            FactProvenance::Reported,
        ),
        (
            "direct-empty",
            json!(""),
            JsonValue::string(""),
            FactProvenance::Reported,
        ),
        (
            "one-part",
            json!([{"type":"text","text":"first"}]),
            JsonValue::string("first"),
            FactProvenance::Derived,
        ),
        (
            "multipart",
            json!([{"type":"text","text":"first"},{"type":"text","text":"second"}]),
            JsonValue::string("first\nsecond"),
            FactProvenance::Derived,
        ),
        (
            "one-empty-part",
            json!([{"type":"text","text":""}]),
            JsonValue::string(""),
            FactProvenance::Derived,
        ),
        (
            "empty-entries",
            json!([{"type":"text","text":""},{"type":"text","text":"middle"},{"type":"text","text":""}]),
            JsonValue::string("\nmiddle\n"),
            FactProvenance::Derived,
        ),
        (
            "all-empty-entries",
            json!([{"type":"text","text":""},{"type":"text","text":""}]),
            JsonValue::string("\n"),
            FactProvenance::Derived,
        ),
        (
            "empty-array",
            json!([]),
            JsonValue::array(vec![]),
            FactProvenance::Reported,
        ),
        (
            "mixed-array",
            json!([{"type":"text","text":"first"},null]),
            JsonValue::array(vec![text_part, JsonValue::Null]),
            FactProvenance::Reported,
        ),
        (
            "nontext-value",
            json!([{"type":"text","text":null}]),
            JsonValue::array(vec![
                JsonValue::object([
                    ("type".to_owned(), JsonValue::string("text")),
                    ("text".to_owned(), JsonValue::Null),
                ])
                .unwrap(),
            ]),
            FactProvenance::Reported,
        ),
        (
            "object",
            json!({"text":"structured"}),
            JsonValue::object([("text".to_owned(), JsonValue::string("structured"))]).unwrap(),
            FactProvenance::Reported,
        ),
        (
            "empty-object",
            json!({}),
            JsonValue::object([]).unwrap(),
            FactProvenance::Reported,
        ),
    ] {
        let record = json!({"type":"user","sessionId":"synthetic","message":{"role":"user","content":[{
            "type":"tool_result","tool_use_id":"synthetic-call","content":content,"is_error":false
        }]}});
        std::fs::write(&source.path, format!("{record}\n")).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert!(
            batch.quarantined.is_empty(),
            "{case}: unexpected quarantine"
        );
        assert_eq!(
            batch.accounting.coverage,
            AccountingCoverage::CompleteSource
        );
        assert_eq!(batch.progress, AcquisitionProgress::None);
        assert_eq!(batch.observations.len(), 1);
        let observation = &batch.observations[0];
        let ObservationBody::Tool(tool) = observation.body() else {
            panic!("{case}: expected tool result")
        };
        assert!(
            tool.result() == Some(&expected),
            "{case}: representation changed"
        );
        assert_eq!(
            observation.fact_metadata()["tool.result"].provenance(),
            provenance,
            "{case}"
        );
        assert_eq!(
            observation.fact_metadata()["tool.result"].sensitivity(),
            Sensitivity::Normal
        );
        assert_eq!(tool.is_error(), Some(false));
        assert_eq!(
            observation.fact_metadata()["tool.is_error"].provenance(),
            FactProvenance::Reported
        );
        assert_eq!(observation.fact_metadata().len(), 2);
    }
}

#[test]
fn claude_tool_result_bounds_replace_values_and_keep_valid_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic-result-bounds.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","message":{"role":"user","content":"valid prefix"}});
    for (case, content, expected, failure) in [
        (
            "direct-inclusive",
            json!("x".repeat(65_534)),
            Some(JsonValue::string("x".repeat(65_534))),
            None,
        ),
        (
            "joined-inclusive",
            json!([{"type":"text","text":"x".repeat(65_534)}]),
            Some(JsonValue::string("x".repeat(65_534))),
            None,
        ),
        (
            "joined-aggregate-overflow",
            json!([{"type":"text","text":"x".repeat(65_535)}]),
            None,
            Some(BoundDimension::EncodedBytes),
        ),
        (
            "direct-string-overflow",
            json!("x".repeat(65_537)),
            None,
            Some(BoundDimension::StringBytes),
        ),
        (
            "joined-string-overflow",
            json!([{"type":"text","text":"x".repeat(65_537)}]),
            None,
            Some(BoundDimension::StringBytes),
        ),
        (
            "structured-inclusive",
            json!({"text":"x".repeat(4_096)}),
            Some(
                JsonValue::object([("text".to_owned(), JsonValue::string("x".repeat(4_096)))])
                    .unwrap(),
            ),
            None,
        ),
        (
            "structured-string-overflow",
            json!({"text":"x".repeat(4_097)}),
            None,
            Some(BoundDimension::StringBytes),
        ),
        (
            "mixed-keeps-structured-bound",
            json!([{"type":"text","text":"x".repeat(4_097)},null]),
            None,
            Some(BoundDimension::StringBytes),
        ),
    ] {
        let record = json!({"type":"user","sessionId":"synthetic","message":{"role":"user","content":[{
            "type":"tool_result","tool_use_id":"synthetic-call","content":content
        }]}});
        std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert_eq!(batch.progress, AcquisitionProgress::None);
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 2);
        if let Some(dimension) = failure {
            // The result is replaced and recorded, and the source reads as
            // partly evaluated; the valid prefix survives either way.
            assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
            assert_eq!(batch.observations.len(), 2, "{case}");
            assert!(matches!(
                batch.observations[0].body(),
                ObservationBody::Message(_)
            ));
            assert!(batch.quarantined.is_empty(), "{case}");
            let [unit] = batch.bounded.as_slice() else {
                panic!("{case}: expected one bounded unit")
            };
            assert_eq!(unit.source_sequence, 1);
            assert_eq!(unit.session_id.as_deref(), Some("synthetic"));
            assert_eq!(unit.target, BoundedTarget::Result);
            assert_eq!(unit.dimension, dimension, "{case}");
            let ObservationBody::Tool(tool) = batch.observations[1].body() else {
                panic!("{case}: expected result")
            };
            assert!(!format!("{:?}", tool.result()).contains("xxxx"), "{case}");
        } else {
            assert_eq!(
                batch.accounting.coverage,
                AccountingCoverage::CompleteSource
            );
            assert!(batch.quarantined.is_empty());
            assert!(batch.bounded.is_empty());
            assert_eq!(batch.observations.len(), 2);
            let ObservationBody::Tool(tool) = batch.observations[1].body() else {
                panic!("{case}: expected result")
            };
            assert!(
                tool.result() == expected.as_ref(),
                "{case}: bounded result changed"
            );
        }
    }
}

#[cfg(feature = "opencode-sqlite")]
#[test]
fn opencode_large_results_preserve_content_identity_and_atomic_bounds() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: directory.path().join("opencode.db"),
    };
    let writer = rusqlite::Connection::open(&source.path).unwrap();
    writer.execute_batch("pragma journal_mode=WAL; pragma wal_autocheckpoint=0;
        create table part (id text primary key, session_id text, time_updated integer, data text);
        insert into part values ('prefix','synthetic',10,'{\"type\":\"text\",\"role\":\"user\",\"text\":\"ok\"}');").unwrap();
    let mut ids = None;
    // Include realistic multiline output and exact encoded aggregate boundaries:
    // name 'bash' costs six bytes and result JSON quotes cost two bytes.
    // Text over its own budget, or over the observation's aggregate together
    // with the call's other fields, is replaced and recorded; the call keeps
    // its identity either way.
    for (text, whole) in [
        ("build output\n".repeat(4_000), true),
        ("x".repeat(65_528), true),
        ("x".repeat(65_529), false),
    ] {
        writer.execute("insert or replace into part values ('output','synthetic',20,?1)",
            [json!({"type":"tool","tool":"bash","state":{"status":"completed","output":text}}).to_string()]).unwrap();
        let result = acquire_opencode_sqlite(
            &source,
            options(),
            OpenCodeSqliteReadOptions {
                part_min_time_updated: Some(0),
                part_limit: 10,
                resume_high_water: None,
                ..Default::default()
            },
        );
        let batch = result.unwrap();
        assert_eq!(
            batch.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: Some(20)
            }
        );
        let tools = batch
            .observations
            .iter()
            .filter(|o| matches!(o.body(), ObservationBody::Tool(_)))
            .collect::<Vec<_>>();
        assert_eq!(tools.len(), 2);
        for observation in &tools {
            let ObservationBody::Tool(body) = observation.body() else {
                unreachable!()
            };
            assert_eq!(body.name(), Some("bash"));
            if whole {
                assert_eq!(body.result(), Some(&JsonValue::string(&text)));
                assert!(body.bounded_values().is_empty());
            } else {
                assert_eq!(body.result(), Some(&JsonValue::Null));
                assert_eq!(
                    body.bounded_values()
                        .iter()
                        .map(|value| (value.target(), value.dimension()))
                        .collect::<Vec<_>>(),
                    [(BoundedTarget::Result, BoundDimension::EncodedBytes)]
                );
            }
        }
        if whole {
            assert!(batch.bounded.is_empty());
        } else {
            assert_eq!(
                bounded_units(&batch),
                [(
                    "output",
                    4,
                    BoundedTarget::Result,
                    BoundDimension::EncodedBytes
                )]
            );
            assert!(!format!("{:?}{:?}", batch.bounded, batch.observations).contains("xxxx"));
        }
        let current = tools
            .iter()
            .map(|o| o.observation_id().to_owned())
            .collect::<Vec<_>>();
        if let Some(previous) = &ids {
            assert_eq!(&current, previous);
        }
        ids = Some(current);
    }
    // Rows that are not a tool call's values still fail atomically.
    for data in [
        json!({"type":"tool","tool":"bash","state":[]}),
        json!({"type":"tool","tool":"bash","state":{"status":5,"output":"ok"}}),
    ] {
        writer
            .execute(
                "update part set data=?1 where id='output'",
                [data.to_string()],
            )
            .unwrap();
        assert!(acquire_source(&source, options()).is_err());
    }
    // A tool value over its bound is replaced; the call stays visible.
    for (data, target, dimension) in [
        (
            json!({"type":"tool","tool":"bash","state":{"status":"completed","output":"x".repeat(65_537)}}),
            BoundedTarget::Result,
            BoundDimension::StringBytes,
        ),
        (
            json!({"type":"tool","tool":"bash","state":{"status":"completed","output":{"text":"x".repeat(4_097)}}}),
            BoundedTarget::Result,
            BoundDimension::StringBytes,
        ),
        (
            json!({"type":"tool","tool":"bash","state":{"status":"completed","input":"x".repeat(4_097),"output":"ok"}}),
            BoundedTarget::Arguments,
            BoundDimension::StringBytes,
        ),
    ] {
        writer
            .execute(
                "update part set data=?1 where id='output'",
                [data.to_string()],
            )
            .unwrap();
        let batch = acquire_source(&source, options()).expect("replaced, not refused");
        assert_eq!(bounded_units(&batch), [("output", 4, target, dimension)]);
        assert!(!format!("{:?}", batch.bounded).contains("xxxx"));
        let tools = batch
            .observations
            .iter()
            .filter_map(|observation| match observation.body() {
                ObservationBody::Tool(tool) => Some(tool),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(!tools.is_empty());
        for tool in tools {
            assert_eq!(tool.name(), Some("bash"));
            let replaced = tool
                .bounded_values()
                .iter()
                .map(|value| (value.target(), value.dimension()))
                .collect::<Vec<_>>();
            assert_eq!(replaced, [(target, dimension)]);
            let retained = match target {
                BoundedTarget::Arguments => tool.arguments(),
                BoundedTarget::Result => tool.result(),
                other => unreachable!("{other:?} is no tool value"),
            };
            assert!(!format!("{retained:?}").contains("xxxx"));
        }
    }
}
