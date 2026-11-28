use super::*;

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
            let target = if category == CanonicalFieldCategory::ToolArguments {
                BoundedTarget::Arguments
            } else {
                BoundedTarget::Result
            };
            // A line-based record without a native id reports its line.
            assert_eq!(
                bounded_units(&batch),
                [("", 0, target, dimension)],
                "{label}"
            );
            assert!(
                !format!("{:?}", batch.bounded).contains("private-suffix"),
                "{label}"
            );
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
                // A legacy record without a native id reports its line.
                assert_eq!(
                    bounded_units(&batch),
                    [("", 1, target, *dimension)],
                    "{category:?}"
                );
                let reported = format!("{:?}", batch.bounded);
                for forbidden in ["synthetic_key", "synthetic-bound", "exec", "é", "\u{1}"] {
                    assert!(!reported.contains(forbidden), "source content retained");
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
