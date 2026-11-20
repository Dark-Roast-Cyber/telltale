use super::*;
use serde_json::{Value, json};
use telltale_schema::observation::{
    BoundDimension, BoundedTarget, CanonicalFieldCategory, JsonValue, ObservationBody,
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
            // The raw argument text is not kept as searchable text beside
            // replaced values, so the call is admitted.
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
        // A tool call's own over-bound value is replaced and recorded; the
        // call is admitted. Message content keeps the source-level failure.
        if matches!(
            category,
            CanonicalFieldCategory::ToolArguments | CanonicalFieldCategory::ToolResult
        ) {
            let batch = acquire_source(&source, options())
                .unwrap_or_else(|error| panic!("{label}: {error} {:?}", error.bound_context()));
            let replaced = batch
                .observations
                .iter()
                .filter_map(|observation| match observation.body() {
                    ObservationBody::Tool(tool) => Some(tool.bounded_values()),
                    _ => None,
                })
                .flatten()
                .map(|value| value.dimension())
                .collect::<Vec<_>>();
            assert_eq!(replaced, [dimension], "{label}");
            continue;
        }
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
    // Text over its own budget is replaced and recorded. Text within it that
    // overflows the aggregate only together with the tool name is still
    // refused, as before.
    for (text, accepted) in [
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
            };
            assert!(!format!("{retained:?}").contains("xxxx"));
        }
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
        collector.push(observation.clone()).unwrap_err().code(),
        "unbounded_value"
    );
    assert_eq!(collector.observations.len(), 128);

    let mut collector = CanonicalCollector::scaled(SourceScale::for_source_bytes(2 << 20));
    for _ in 0..256 {
        collector.push(observation.clone()).unwrap();
    }
    assert_eq!(collector.retained_bytes, 2 * MAX_CANONICAL_RETAINED_BYTES);
    assert_eq!(
        collector.push(observation).unwrap_err().code(),
        "unbounded_value"
    );
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
        // About 8.45 MiB read scales the retention budget past this source.
        let batch = acquire_source(&source, options()).expect("scaled retention");
        assert_eq!(batch.observations.len(), 129);
        assert!(batch.quarantined.is_empty());
        // At the floor, the source-wide failure is the whole projection's,
        // not a quarantined unit, so no batch/accounting/progress escapes.
        let error = match client {
            ClientId::Claude => {
                let (records, _) = extract_claude_native_records_with_limits(
                    &source,
                    crate::acquisition::SourceAccess::ByName,
                )
                .unwrap();
                map_claude_error(
                    project_claude_native_records(
                        &records,
                        &ClaudeCanonicalOptions::new(options().observed_at),
                    )
                    .expect_err("Claude's source-wide retention failure"),
                )
            }
            _ => {
                let (records, _) = extract_codex_native_records_with_limits(
                    &source,
                    crate::acquisition::SourceAccess::ByName,
                )
                .unwrap();
                map_codex_error(
                    project_codex_native_records(
                        &records,
                        &CodexCanonicalOptions::new(options().observed_at),
                    )
                    .expect_err("Codex's source-wide retention failure"),
                )
            }
        };
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
                // One past the bound, the call is still projected: the
                // over-bound value is replaced and recorded, not quarantined.
                let batch = acquire(record(excess)).expect("replaced, not refused");
                assert!(batch.quarantined.is_empty(), "{category:?}");
                assert_eq!(batch.observations.len(), 2);
                let ObservationBody::Tool(tool) = batch.observations[1].body() else {
                    panic!("expected tool")
                };
                assert_eq!(tool.name(), Some("exec"));
                let (target, retained) = if key == "arguments" {
                    (BoundedTarget::Arguments, tool.arguments())
                } else {
                    (BoundedTarget::Result, tool.result())
                };
                assert!(
                    tool.bounded_values()
                        .iter()
                        .all(|value| value.target() == target && value.dimension() == *dimension),
                    "{category:?}"
                );
                assert_eq!(tool.bounded_values().len(), 1, "{category:?}");
                assert!(
                    retained.unwrap().encoded_byte_len().unwrap()
                        < serde_json::to_string(excess).unwrap().len(),
                    "over-bound value retained"
                );
                let diagnostic = format!("{:?}", tool.bounded_values());
                assert!(!diagnostic.contains("synthetic_key") && !diagnostic.contains('é'));
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

/// One synthetic tool call and its result for each adapter whose generic
/// record shape the router accepts.
fn tool_call_corpus(
    name: &str,
    arguments: &Value,
    result: &Value,
) -> Vec<(ClientId, &'static str, SourceKind, String)> {
    let claude = format!(
        "{}\n{}\n",
        json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_synthetic","name":name,"input":arguments}]}}),
        json!({"type":"user","sessionId":"synthetic","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_synthetic","content":result}]}}),
    );
    let codex = format!(
        "{}\n{}\n",
        json!({"type":"tool_call","session_id":"synthetic","name":name,"arguments":arguments}),
        json!({"type":"tool_result","session_id":"synthetic","name":name,"output":result}),
    );
    let qwen = format!(
        "{}\n{}\n",
        json!({"type":"tool_call","sessionId":"synthetic","tool_name":name,"arguments":arguments}),
        json!({"type":"tool_result","sessionId":"synthetic","content":result}),
    );
    let copilot = format!(
        "Workspace initialized: synthetic (checkpoints: 0)\nAccumulated output items (1): {}\n",
        json!([{"type":"function_call","name":name,"call_id":"call_synthetic","arguments":arguments.to_string()}])
    );
    vec![
        (
            ClientId::Claude,
            "claude.projects",
            SourceKind::Jsonl,
            claude,
        ),
        (ClientId::Codex, "codex.sessions", SourceKind::Jsonl, codex),
        (
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            qwen.clone(),
        ),
        (
            ClientId::OpenClaw,
            "openclaw.agents",
            SourceKind::Jsonl,
            qwen,
        ),
        (
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            copilot,
        ),
    ]
}

fn acquire_input(
    client: ClientId,
    source_id: &str,
    kind: SourceKind,
    input: &str,
) -> AcquisitionBatch {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client,
        source_id: source_id.into(),
        kind,
        path: directory.path().join("synthetic-input.log"),
    };
    std::fs::write(&source.path, input).unwrap();
    acquire_source(&source, options()).unwrap_or_else(|error| panic!("{client:?}: {error}"))
}

/// Exactly-at-bound tool values keep their observation ids and semantic
/// content byte for byte in every adapter with tool calls. The pin is a
/// digest, so the corpus outcome stays reviewable without listing it.
#[test]
fn in_bound_tool_calls_keep_identity_and_semantic_content() {
    use sha2::{Digest, Sha256};
    use telltale_schema::observation::{CanonicalObservationV2, canonical_identity_json};
    let nested = |count| (0..count).fold(Value::Null, |value, _| json!([value]));
    let members = |count| {
        Value::Object(
            (0..count)
                .map(|index| (format!("k{index}"), json!(index)))
                .collect(),
        )
    };
    let mut cases = [
        json!({"note":"s".repeat(4096), "path":"/synthetic/project/file.txt"}),
        json!({"tree":nested(4)}),
        json!({"items":vec![json!(1); 64]}),
        members(32),
        json!({"k".repeat(64): "v"}),
        json!(["\u{1}".repeat(2730)]),
    ]
    .map(|arguments| (arguments, json!({"structured":"ok"})))
    .to_vec();
    cases.push((json!({"command":"x".repeat(64)}), json!("x".repeat(4096))));
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut tools = 0;
    let absorb = |observation: &CanonicalObservationV2| {
        let mut line = observation.observation_id().as_bytes().to_vec();
        line.extend(format!("|{:?}|{:?}|", observation.kind(), observation.stage()).bytes());
        if let ObservationBody::Tool(tool) = observation.body() {
            line.extend(tool.name().unwrap_or("").bytes());
            for value in [tool.arguments(), tool.result()].into_iter().flatten() {
                line.extend(canonical_identity_json(value).unwrap());
                line.push(b'|');
            }
        }
        for (name, facet) in observation.facets() {
            line.extend(name.bytes());
            line.extend(canonical_identity_json(facet.value()).unwrap());
        }
        for (path, metadata) in observation.fact_metadata() {
            line.extend(
                format!(
                    "{path}:{:?}:{:?}",
                    metadata.provenance(),
                    metadata.sensitivity()
                )
                .bytes(),
            );
        }
        line.extend(observation.semantic_comparison().to_string().bytes());
        line
    };
    let mut absorb_batch = |batch: &AcquisitionBatch, lines: &mut Vec<Vec<u8>>| {
        for observation in &batch.observations {
            tools += usize::from(matches!(observation.body(), ObservationBody::Tool(_)));
            lines.push(absorb(observation));
        }
    };
    for (arguments, result) in &cases {
        for (client, source_id, kind, input) in
            tool_call_corpus("mcp__synthetic__probe", arguments, result)
        {
            let directory = tempfile::tempdir().unwrap();
            let source = Source {
                client,
                source_id: source_id.into(),
                kind,
                path: directory.path().join("synthetic-input.log"),
            };
            std::fs::write(&source.path, input).unwrap();
            // Pin what each adapter does today, a refusal included.
            match acquire_source(&source, options()) {
                Ok(batch) => {
                    lines.push(format!("{client:?}:{:?}", batch.quarantined).into_bytes());
                    absorb_batch(&batch, &mut lines);
                }
                Err(error) => lines.push(format!("{client:?}:{error}").into_bytes()),
            }
        }
    }
    // A Claude command over the structured string bound keeps the
    // authored-text budget.
    let input = format!(
        "{}\n",
        json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_authored","name":"Bash","input":{"command":"x".repeat(65_000),"description":"synthetic"}}]}})
    );
    let batch = acquire_input(
        ClientId::Claude,
        "claude.projects",
        SourceKind::Jsonl,
        &input,
    );
    assert!(batch.quarantined.is_empty());
    absorb_batch(&batch, &mut lines);
    assert!(tools >= 45, "corpus produced {tools} tool observations");
    let mut digest = Sha256::new();
    for line in &lines {
        digest.update(Sha256::digest(line));
    }
    let digest: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        digest, "6e1f07c60e8aaf0bcb2be8cc6aa07395fef25f0c1926e6598ca2ce64677abf66",
        "in-bound projection changed"
    );
}

/// The router admits a call whose over-bound value was replaced. Nothing is
/// derived from a value the observation does not carry: like a quarantined
/// unit, the call takes no part in contribution accounting, so a long
/// path-like token in the replaced value can no longer quarantine it. A
/// neighbouring call with whole values is still counted.
#[test]
fn replaced_tool_values_admit_the_unit_and_contribute_nothing() {
    let call = |id: &str, value: String| {
        format!(
            "{}\n",
            json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":id,"name":"mcp__synthetic__run","input":{"query":value,"file_path":"/synthetic/project/notes.txt"}}]}})
        )
    };
    let neighbour = call(
        "toolu_neighbour",
        "ok https://neighbour.example.test/".into(),
    );
    for value in ["z ".repeat(2_500), "synthetic/".repeat(500)] {
        let batch = acquire_input(
            ClientId::Claude,
            "claude.projects",
            SourceKind::Jsonl,
            &format!("{}{neighbour}", call("toolu_synthetic", value)),
        );
        assert!(batch.quarantined.is_empty());
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
        let [unit] = batch.bounded.as_slice() else {
            panic!("expected one bounded unit: {:?}", batch.bounded)
        };
        assert_eq!(
            (unit.source_sequence, unit.target, unit.dimension),
            (0, BoundedTarget::Arguments, BoundDimension::StringBytes)
        );
        let (observation, tool) = batch
            .observations
            .iter()
            .find_map(|observation| match observation.body() {
                ObservationBody::Tool(tool) if !tool.bounded_values().is_empty() => {
                    Some((observation, tool))
                }
                _ => None,
            })
            .expect("the call is projected");
        assert_eq!(tool.name(), Some("mcp__synthetic__run"));
        assert!(observation.facets().contains_key("resource.path"));
        // Only the neighbour contributes: one call, its host, no path of the
        // replaced value.
        let counts = &batch.accounting.sessions[0].counts;
        assert_eq!(
            counts.contributions.tool_calls.values().sum::<u64>(),
            1,
            "{:?}",
            counts.contributions
        );
        assert_eq!(counts.contributions.network_hosts.len(), 1);
        assert_eq!(
            counts
                .tool_usage
                .values()
                .map(|usage| usage.count)
                .sum::<u64>(),
            1
        );
        assert_eq!(counts.native_units, 2);
    }
}

/// Copilot keeps the raw request text as searchable text. Beside arguments
/// with a replaced value it is omitted, or it would carry what was replaced.
#[test]
fn copilot_drops_searchable_text_beside_replaced_arguments() {
    let items = (0..65).map(|_| json!("replaced-item")).collect::<Vec<_>>();
    let arguments = json!({"items": items, "path": "/synthetic/kept"}).to_string();
    assert!(arguments.len() < 4_096);
    let log = format!(
        "Workspace initialized: synthetic (checkpoints: 0)\nAccumulated output items (1): {}\n",
        json!([{"type":"function_call","name":"exec","call_id":"call_synthetic","arguments":arguments}])
    );
    let batch = acquire_input(
        ClientId::Copilot,
        "copilot.process_log",
        SourceKind::CopilotProcessLog,
        &log,
    );
    let ObservationBody::Tool(tool) = batch.observations[0].body() else {
        panic!("expected the call")
    };
    assert_eq!(
        tool.bounded_values()
            .iter()
            .map(|value| (value.target(), value.dimension()))
            .collect::<Vec<_>>(),
        [(BoundedTarget::Arguments, BoundDimension::ArrayItems)]
    );
    assert_eq!(tool.searchable_arguments(), None);
    assert!(!format!("{:?}", batch.observations).contains("replaced-item"));
    assert!(format!("{:?}", tool.arguments()).contains("/synthetic/kept"));
    assert_eq!(batch.bounded.len(), 1);
}

/// The contribution labels are checked for every call, with or without
/// replaced values: a call whose name or time is not a valid label keeps
/// exactly the outcome it has with in-bound values.
#[test]
fn replaced_values_keep_the_contribution_label_checks() {
    let name = "exec\u{1}tool";
    let outcome = |client: ClientId, source_id: &str, input: String| {
        let directory = tempfile::tempdir().unwrap();
        let source = Source {
            client,
            source_id: source_id.into(),
            kind: SourceKind::Jsonl,
            path: directory.path().join("synthetic-label.jsonl"),
        };
        std::fs::write(&source.path, input).unwrap();
        match acquire_source(&source, options()) {
            Ok(batch) => format!(
                "ok observations={} quarantined={:?} bounded={}",
                batch.observations.len(),
                batch
                    .quarantined
                    .iter()
                    .map(|unit| unit.code)
                    .collect::<Vec<_>>(),
                batch.bounded.len()
            ),
            Err(error) => format!("error {}", error.code()),
        }
    };
    for value in ["small".to_owned(), "z".repeat(5_000)] {
        let claude = format!(
            "{}\n",
            json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_synthetic","name":name,"input":{"note":value}}]}})
        );
        let qwen = format!(
            "{}\n",
            json!({"type":"tool_call","sessionId":"synthetic","tool_name":name,"arguments":{"note":value}})
        );
        // A per-record adapter quarantines the call; a whole-source adapter
        // fails the source, with or without a replaced value.
        assert_eq!(
            outcome(ClientId::Claude, "claude.projects", claude),
            "ok observations=0 quarantined=[\"invalid_native_contribution\"] bounded=0",
            "{}",
            value.len()
        );
        assert_eq!(
            outcome(ClientId::Qwen, "qwen.projects", qwen),
            "error invalid_native_contribution",
            "{}",
            value.len()
        );
    }
}

/// A call whose operand was replaced for its size is counted as replaced,
/// not as a call whose table row lost its operand.
#[test]
fn a_replaced_operand_is_not_tool_table_drift() {
    let call = |input: Value| {
        format!(
            "{}\n",
            json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_synthetic","name":"Bash","input":input}]}})
        )
    };
    let drift = |input: Value| {
        let batch = acquire_input(
            ClientId::Claude,
            "claude.projects",
            SourceKind::Jsonl,
            &call(input),
        );
        (
            batch.bounded.len(),
            batch.accounting.tool_table.tool_operand_drift,
        )
    };
    // Without its command the row has drifted; a replaced command has not.
    assert_eq!(drift(json!({"description": "synthetic"})), (0, 1));
    assert_eq!(drift(json!({"command": "z ".repeat(40_000)})), (1, 0));
}

/// The command facet is decided per argument key: a replaced `command` does
/// not hide an in-bound `cmd`, and `command` stays preferred when admitted.
#[test]
fn codex_command_facet_is_decided_per_argument_key() {
    let command_text = |arguments: Value| {
        let input = format!(
            "{}\n",
            json!({"type":"tool_call","session_id":"synthetic","name":"exec_command","arguments":arguments})
        );
        let batch = acquire_input(ClientId::Codex, "codex.sessions", SourceKind::Jsonl, &input);
        let observation = &batch.observations[0];
        (
            batch.bounded.len(),
            observation
                .facets()
                .get("command.text")
                .map(|facet| format!("{:?}", facet.value())),
        )
    };
    let over = "z ".repeat(40_000);
    assert_eq!(
        command_text(json!({"command": over, "cmd": "synthetic fallback"})),
        (
            1,
            Some(format!("{:?}", JsonValue::string("synthetic fallback")))
        )
    );
    assert_eq!(
        command_text(json!({"command": "printf synthetic", "cmd": over})),
        (
            1,
            Some(format!("{:?}", JsonValue::string("printf synthetic")))
        )
    );
    assert_eq!(
        command_text(json!({"command": "printf synthetic", "cmd": "synthetic fallback"})),
        (
            0,
            Some(format!("{:?}", JsonValue::string("printf synthetic")))
        )
    );
    assert_eq!(command_text(json!({"command": over})), (1, None));
}

/// A Copilot call with a replaced value is matched to its native item by the
/// session id the observation carries, so a session id the projection
/// normalizes still keeps that call out of contribution accounting.
#[test]
fn copilot_replaced_call_in_a_normalized_session_contributes_nothing() {
    let items = (0..65).map(|_| json!("item")).collect::<Vec<_>>();
    let calls = |session: &str| {
        let log = format!(
            "Workspace initialized: {session} (checkpoints: 0)\nAccumulated output items (1): {}\n",
            json!([{"type":"function_call","name":"exec","call_id":"call_synthetic","arguments":json!({"items": items}).to_string()}])
        );
        let batch = acquire_input(
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            &log,
        );
        assert_eq!(batch.bounded.len(), 1, "{session}");
        batch
            .accounting
            .sessions
            .iter()
            .map(|session| session.counts.contributions.tool_calls.get("exec").copied())
            .collect::<Vec<_>>()
    };
    // Composed and decomposed spellings of one session id.
    assert_eq!(calls("synthetic-caf\u{e9}"), [None]);
    assert_eq!(calls("synthetic-cafe\u{301}"), [None]);
}
