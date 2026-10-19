use super::*;
use serde_json::{Value, json};
use telltale_schema::observation::{
    BoundDimension, CanonicalFieldCategory, JsonValue, ObservationBody,
};

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new("2026-09-18T12:00:00Z").unwrap())
}

#[test]
fn adapter_error_mapping_preserves_existing_bound_context_and_codes() {
    use telltale_schema::observation::{ObservationError, ValidationCode};

    let bound =
        JsonValue::try_from_source_value(&json!({"private_key":"x".repeat(4097)})).unwrap_err();
    for error in [
        bound.with_bound_category(CanonicalFieldCategory::ToolArguments),
        bound,
        ObservationError::from_validation_code(ValidationCode::InvalidTime),
        ObservationError::from_validation_code(ValidationCode::UnboundedValue),
    ] {
        // Exercise error transport only, without adding legacy format coverage.
        for mapped in [
            map_openclaw_error(error.into()),
            map_qwen_error(error.into()),
            map_copilot_error(error.into()),
        ] {
            assert_eq!(mapped.code(), error.code());
            assert_eq!(mapped.to_string(), error.code());
            assert_eq!(mapped.bound_context(), error.bound_context());
            assert_eq!(
                matches!(mapped, AcquisitionError::CanonicalBoundValidation { .. }),
                error.bound_context().is_some()
            );
            assert!(!format!("{mapped:?}").contains("private_key"));
        }
    }
    for mapped in [
        map_openclaw_error(OpenClawCanonicalError::Mapping {
            code: "unknown_discriminator",
            detail: "private-detail",
        }),
        map_qwen_error(QwenCanonicalError::Mapping {
            code: "unknown_discriminator",
            detail: "private-detail",
        }),
        map_copilot_error(CopilotCanonicalError::Mapping {
            code: "unknown_discriminator",
            detail: "private-detail",
        }),
    ] {
        assert_eq!(
            mapped,
            AcquisitionError::CanonicalMapping {
                code: "unknown_discriminator"
            }
        );
        assert_eq!(mapped.bound_context(), None);
        assert!(!format!("{mapped:?} {mapped}").contains("private-detail"));
    }
}

#[test]
fn qwen_and_copilot_acquisition_preserve_assembled_message_bound_context() {
    let directory = tempfile::tempdir().unwrap();
    for (client, source_id, kind, category) in [
        (
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            CanonicalFieldCategory::MessageContent,
        ),
        (
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            CanonicalFieldCategory::MessageContentParts,
        ),
    ] {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind,
            path: directory.path().join("synthetic-bound.log"),
        };
        for bytes in [65_536, 65_537] {
            let text = format!("{}private-suffix", "x".repeat(bytes - 14));
            let input = if client == ClientId::Copilot {
                format!(
                    "Workspace initialized: synthetic (checkpoints: 0)\nAccumulated output items (1): {}\n",
                    json!([{"type":"message", "role":"assistant", "content":[{"type":"output_text", "text":text}]}])
                )
            } else {
                format!(
                    "{}\n",
                    json!({"type":"user", "sessionId":"synthetic", "content":text})
                )
            };
            std::fs::write(&source.path, input).unwrap();
            let error = acquire_source(&source, options())
                .err()
                .expect("bound failure must not return a partial batch");
            assert_eq!(error.code(), "unbounded_value");
            assert_eq!(error.to_string(), "unbounded_value");
            // 65_536 passes direct-text conversion and fails assembled encoded size.
            // 65_537 fails at pre-assembly conversion; category must not change dimension.
            let dimension = match bytes {
                65_536 => BoundDimension::EncodedBytes,
                65_537 => BoundDimension::StringBytes,
                _ => unreachable!("only the two boundary sizes are exercised"),
            };
            assert_eq!(
                error.bound_context(),
                Some(CanonicalBoundContext {
                    category,
                    dimension,
                }),
                "{client:?}, {bytes} bytes"
            );
            let diagnostic = format!("{error:?} {error}");
            for forbidden in ["private-suffix", "synthetic", "output_text"] {
                assert!(!diagnostic.contains(forbidden));
            }
        }
    }
}

#[test]
fn qwen_and_copilot_conversion_sites_report_field_category_and_dimension() {
    let directory = tempfile::tempdir().unwrap();
    // Direct message text uses the 65_536 budget. Nested conversion uses the
    // ordinary 4_096 string bound and must keep that dimension.
    let over_text = format!("{}private-suffix", "x".repeat(65_537 - 14));
    let over_structured = format!("{}private-suffix", "x".repeat(4_097 - 14));
    let object_members = Value::Object(
        (0..33)
            .map(|index| (format!("k{index}"), Value::Null))
            .collect(),
    );
    let qwen = |record: Value| format!("{record}\n");
    let copilot = |items: Value| {
        format!(
            "Workspace initialized: synthetic (checkpoints: 0)\nAccumulated output items (1): {items}\n"
        )
    };
    let cases = [
        (
            "qwen-content-part-text",
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            qwen(
                json!({"type":"assistant","sessionId":"synthetic","content":[{"type":"text","text":over_text}]}),
            ),
            CanonicalFieldCategory::MessageContentParts,
            BoundDimension::StringBytes,
        ),
        (
            "qwen-content-part-tool-input",
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            qwen(
                json!({"type":"assistant","sessionId":"synthetic","content":[{"type":"tool_use","name":"exec","input":over_structured.clone()}]}),
            ),
            CanonicalFieldCategory::MessageContentParts,
            BoundDimension::StringBytes,
        ),
        (
            "qwen-content-part-tool-result",
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            qwen(
                json!({"type":"assistant","sessionId":"synthetic","content":[{"type":"text","text":"ok"},{"type":"tool_result","content":over_structured.clone()}]}),
            ),
            CanonicalFieldCategory::MessageContentParts,
            BoundDimension::StringBytes,
        ),
        (
            "qwen-tool-arguments",
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            qwen(
                json!({"type":"tool_call","sessionId":"synthetic","tool_name":"exec","arguments":over_structured.clone()}),
            ),
            CanonicalFieldCategory::ToolArguments,
            BoundDimension::StringBytes,
        ),
        (
            "qwen-tool-result",
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            qwen(
                json!({"type":"tool_result","sessionId":"synthetic","content":over_structured.clone()}),
            ),
            CanonicalFieldCategory::ToolResult,
            BoundDimension::StringBytes,
        ),
        (
            "qwen-tool-arguments-object-members",
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            qwen(
                json!({"type":"tool_call","sessionId":"synthetic","tool_name":"exec","arguments":object_members}),
            ),
            CanonicalFieldCategory::ToolArguments,
            BoundDimension::ObjectMembers,
        ),
        (
            "copilot-tool-arguments",
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            copilot(
                json!([{"type":"function_call","name":"exec","arguments":format!("{{\"note\":\"{}\"}}", over_structured)}]),
            ),
            CanonicalFieldCategory::ToolArguments,
            BoundDimension::StringBytes,
        ),
    ];
    for (label, client, source_id, kind, input, category, dimension) in cases {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind,
            path: directory.path().join("synthetic-conversion.log"),
        };
        std::fs::write(&source.path, &input).unwrap();
        let error = acquire_source(&source, options())
            .err()
            .expect("bound failure must not return a partial batch");
        assert_eq!(error.code(), "unbounded_value", "{label}");
        assert_eq!(error.to_string(), "unbounded_value", "{label}");
        assert_eq!(
            error.bound_context(),
            Some(CanonicalBoundContext {
                category,
                dimension,
            }),
            "{label}"
        );
        let diagnostic = format!("{error:?} {error}");
        for forbidden in [
            "private-suffix",
            "synthetic",
            "output_text",
            "tool_use",
            "tool_result",
            "function_call",
            "exec",
        ] {
            assert!(
                !diagnostic.contains(forbidden),
                "{label} leaked {forbidden}"
            );
        }
    }
}

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
fn claude_tool_result_bounds_preserve_quarantine_and_valid_prefix() {
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
            assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
            assert_eq!(
                batch.observations.len(),
                1,
                "{case}: valid prefix must survive"
            );
            assert!(matches!(
                batch.observations[0].body(),
                ObservationBody::Message(_)
            ));
            assert_eq!(batch.quarantined.len(), 1);
            let excluded = &batch.quarantined[0];
            assert_eq!(excluded.source_sequence, 1);
            assert_eq!(excluded.code, "unbounded_value");
            assert_eq!(
                excluded.bound.unwrap().category,
                CanonicalFieldCategory::ToolResult
            );
            assert_eq!(excluded.bound.unwrap().dimension, dimension);
        } else {
            assert_eq!(
                batch.accounting.coverage,
                AccountingCoverage::CompleteSource
            );
            assert!(batch.quarantined.is_empty());
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
    for (text, accepted) in [
        ("build output\n".repeat(4_000), true),
        ("x".repeat(65_528), true),
        ("x".repeat(65_529), false),
        ("x".repeat(65_537), false),
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
        if accepted {
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
                assert_eq!(body.result(), Some(&JsonValue::string(&text)));
            }
            let current = tools
                .iter()
                .map(|o| o.observation_id().to_owned())
                .collect::<Vec<_>>();
            if let Some(previous) = &ids {
                assert_eq!(&current, previous);
            }
            ids = Some(current);
        } else {
            let error = result
                .err()
                .expect("no observations, accounting or cursor escape");
            assert_eq!(error.code(), "unbounded_value");
            assert_eq!(
                error.bound_context().unwrap().category,
                CanonicalFieldCategory::ToolResult
            );
            assert!(!format!("{error:?}").contains("synthetic"));
        }
    }
    for data in [
        json!({"type":"tool","tool":"bash","state":[]}),
        json!({"type":"tool","tool":"bash","state":{"status":5,"output":"ok"}}),
        json!({"type":"tool","tool":"bash","state":{"status":"completed","output":{"text":"x".repeat(4_097)}}}),
        json!({"type":"tool","tool":"bash","state":{"status":"completed","input":"x".repeat(4_097),"output":"ok"}}),
    ] {
        writer
            .execute(
                "update part set data=?1 where id='output'",
                [data.to_string()],
            )
            .unwrap();
        assert!(acquire_source(&source, options()).is_err());
    }
}

#[test]
fn long_message_text_is_narrowly_acquired_by_each_json_and_process_adapter() {
    use telltale_schema::{
        clients::{ClientId, SourceKind},
        source::Source,
    };
    let directory = tempfile::tempdir().unwrap();
    for (client, source_id, kind) in [
        (ClientId::Claude, "claude.projects", SourceKind::Jsonl),
        (ClientId::Codex, "codex.sessions", SourceKind::Jsonl),
        (ClientId::OpenClaw, "openclaw.agents", SourceKind::Jsonl),
        (ClientId::Qwen, "qwen.projects", SourceKind::Jsonl),
        (
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
        ),
    ] {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind,
            path: directory.path().join("synthetic-long.log"),
        };
        for (bytes, accepted) in [(9_000, true), (65_537, false)] {
            let text = format!("{}suffix", "x".repeat(bytes - 6));
            let input = if client == ClientId::Copilot {
                format!(
                    "Workspace initialized: synthetic (checkpoints: 0)\nAccumulated output items (1): {}\n",
                    json!([{"type":"message", "role":"assistant", "content":[{"type":"output_text", "text":text}]}])
                )
            } else {
                format!(
                    "{}\n",
                    json!({"type":"user", "sessionId":"synthetic", "session_id":"synthetic", "content":text})
                )
            };
            std::fs::write(&source.path, input).unwrap();
            let result = acquire_source(&source, options());
            if accepted {
                let batch = result.unwrap();
                let message = batch
                    .observations
                    .iter()
                    .find_map(|observation| match observation.body() {
                        ObservationBody::Message(message) => Some(message),
                        _ => None,
                    })
                    .unwrap();
                assert!(
                    message.content() == Some(&JsonValue::string(&text))
                        || message
                            .content_parts()
                            .iter()
                            .any(|part| part.value() == &JsonValue::string(&text))
                );
            } else if matches!(client, ClientId::Claude | ClientId::Codex) {
                // Claude and Codex quarantine the oversized record by itself.
                let batch = result.unwrap();
                assert!(batch.observations.is_empty());
                assert_eq!(batch.quarantined[0].code, "unbounded_value");
            } else {
                assert_eq!(result.err().unwrap().code(), "unbounded_value");
            }
        }
    }
}

#[test]
fn canonical_collector_checks_source_wide_retention_before_each_push() {
    use telltale_schema::observation::*;
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User)
                .with_content(JsonValue::string("x".repeat(65_528))),
        ),
        ObservationStage::MessageObserved,
        options().observed_at,
        SourceProvenance::new(
            IngestionMode::Import,
            "synthetic",
            "retention",
            Fidelity::FullNative,
        )
        .unwrap()
        .with_native_id("one")
        .unwrap(),
    )
    .fact_metadata("message.role", FactMetadata::reported().unwrap())
    .fact_metadata("message.content", FactMetadata::reported().unwrap())
    .build()
    .unwrap();
    assert_eq!(observation.retained_byte_len(), 65_536);
    let mut collector = CanonicalCollector::default();
    for _ in 0..128 {
        collector.push(observation.clone()).unwrap();
    }
    assert_eq!(collector.retained_bytes, MAX_CANONICAL_RETAINED_BYTES);
    assert_eq!(
        collector.push(observation).unwrap_err().code(),
        "unbounded_value"
    );
    assert_eq!(collector.observations.len(), 128);
}

#[test]
fn long_message_source_batch_retention_failure_is_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-retention.jsonl");
    let record =
        json!({"type":"user", "session_id":"synthetic", "content":"x".repeat(65_528)}).to_string();
    std::fs::write(&path, format!("{}\n", vec![record; 129].join("\n"))).unwrap();
    for (client, source_id) in [
        (ClientId::Codex, "codex.sessions"),
        (ClientId::Claude, "claude.projects"),
    ] {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind: SourceKind::Jsonl,
            path: path.clone(),
        };
        let error = acquire_source(&source, options())
            .err()
            .expect("no batch/accounting/progress may escape, including Claude's source-wide retention failure");
        assert_eq!(error.code(), "unbounded_value");
        assert!(!format!("{error:?} {error}").contains("synthetic"));
    }
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
    // A direct result string, or an `exec` script, gets the text budget; a
    // string nested in a structured value keeps the ordinary bound.
    let dimensions = [
        (
            json!(["é".repeat(2048)]),
            json!([format!("{}x", "é".repeat(2048))]),
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
            let prefix = json!({"type":"user", "session_id":"synthetic", "content":"ok"});
            std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
            acquire_source(&source, options())
        };
        // A late bound failure quarantines that record alone; the valid
        // message before it is still acquired and the source is partial.
        let quarantined = |record: Value| {
            let batch = acquire(record).expect("record quarantine");
            assert_eq!(batch.observations.len(), 1);
            assert_eq!(batch.quarantined.len(), 1);
            assert_eq!(batch.quarantined[0].code, "unbounded_value");
            assert_eq!(batch.quarantined[0].source_sequence, 1);
            assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
            let diagnostic = format!("{:?}", batch.quarantined);
            for forbidden in ["synthetic_key", "synthetic-bound", "private_key", "exec"] {
                assert!(!diagnostic.contains(forbidden), "source content retained");
            }
            batch.quarantined[0].bound
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
                assert_eq!(
                    quarantined(record(excess)),
                    Some(CanonicalBoundContext {
                        category,
                        dimension: *dimension
                    })
                );
            }
        }
        for (record, category, dimension) in [
            (
                json!({"type":"assistant", "session_id":"synthetic", "content":vec![json!({"type":"text", "text":"x".repeat(4096)});16]}),
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
            assert_eq!(
                quarantined(record),
                Some(CanonicalBoundContext {
                    category,
                    dimension
                })
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
        assert_eq!(
            quarantined(
                json!({"type":"user", "session_id":"synthetic", "content":"e\u{301}".repeat(21_846)})
            ),
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
