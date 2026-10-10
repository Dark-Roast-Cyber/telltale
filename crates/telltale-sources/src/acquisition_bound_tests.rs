use super::*;
use serde_json::{Value, json};
use telltale_schema::observation::{
    BoundDimension, CanonicalFieldCategory, JsonValue, ObservationBody,
};

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new("2026-09-18T12:00:00Z").unwrap())
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
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path,
    };
    let error = acquire_source(&source, options())
        .err()
        .expect("no batch/accounting/progress may escape");
    assert_eq!(error.code(), "unbounded_value");
    assert!(!format!("{error:?} {error}").contains("synthetic"));
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
        let error = acquire(
            json!({"type":"user", "session_id":"synthetic", "content":"e\u{301}".repeat(21_846)}),
        )
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
