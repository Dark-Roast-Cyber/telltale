use super::*;

#[test]
fn codex_auxiliary_closed_categories_are_other_without_observations() {
    use serde_json::json;
    let directory = tempdir().unwrap();
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: directory.path().join("synthetic.jsonl"),
        };
        for mut auxiliary in codex_auxiliary_records() {
            // Bogus conversational/tool fields cannot change auxiliary semantics.
            auxiliary["role"] = json!("assistant");
            auxiliary["payload"]["role"] = json!("assistant");
            auxiliary["payload"]["name"] = json!("bogus-shell");
            auxiliary["payload"]["arguments"] = json!({"url":"https://bogus.example.test/"});
            if auxiliary["type"] != "response_item" {
                auxiliary["payload"]["content"] =
                    json!([{"type":"tool_use","name":"bogus-shell","input":{"command":"true"}}]);
            }
            std::fs::write(&source.path, format!("{{\"type\":\"session_meta\",\"payload\":{{\"session_id\":\"s\"}}}}\n{auxiliary}\n")).unwrap();
            let batch = acquire_source(&source, options()).unwrap();
            assert!(batch.observations.is_empty(), "{auxiliary}");
            assert_eq!(batch.progress, AcquisitionProgress::None);
            let session = &batch.accounting.sessions[0];
            assert_eq!(session.counts.native_units, 2);
            assert_eq!(
                session.counts.record_counts,
                RecordCounts {
                    session_meta: 1,
                    other: 1,
                    ..Default::default()
                }
            );
            assert_eq!(
                session.counts.contributions,
                ActivityContributions::default()
            );
            if auxiliary["type"] == "turn_context" {
                assert_eq!(session.metadata.model.known(), Some("synthetic-model"));
                assert_eq!(
                    session.metadata.provider.known(),
                    Some("synthetic-provider")
                );
            }
        }
    }
}

#[test]
fn codex_auxiliary_preserves_messages_tools_ordinals_and_replay() {
    use telltale_schema::observation::ObservationStage;
    let directory = tempdir().unwrap();
    let messages = [
        r#"{"type":"user","content":"synthetic user"}"#,
        r#"{"type":"tool_call","name":"shell","call_id":"call-a","arguments":{"command":"true"}}"#,
        r#"{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"synthetic assistant"}]}}"#,
        r#"{"type":"tool_result","name":"shell","call_id":"call-a","output":{"text":"synthetic result"}}"#,
    ];
    let metadata = r#"{"type":"session_meta","payload":{"session_id":"s"}}"#;
    let auxiliaries = codex_auxiliary_records()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: directory.path().join("synthetic.jsonl"),
        };
        std::fs::write(
            &source.path,
            format!("{metadata}\n{}\n", messages.join("\n")),
        )
        .unwrap();
        let reference = acquire_source(&source, options()).unwrap();
        std::fs::write(
            &source.path,
            format!(
                "{metadata}\n{}\n{}\n{auxiliaries}\n{}\n{}\n",
                messages[0], messages[1], messages[2], messages[3]
            ),
        )
        .unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        let replay = acquire_source(&source, options()).unwrap();
        assert_eq!(batch.observations.len(), 4);
        assert_eq!(batch.accounting, replay.accounting);
        assert_eq!(
            batch.accounting.sessions[0].counts.record_counts,
            RecordCounts {
                session_meta: 1,
                user_message: 1,
                assistant_message: 1,
                tool_call: 1,
                tool_result: 1,
                other: codex_auxiliary_records().len() as u64
            }
        );
        for (index, ((actual, repeated), expected)) in batch
            .observations
            .iter()
            .zip(&replay.observations)
            .zip(&reference.observations)
            .enumerate()
        {
            assert_eq!(actual.body(), expected.body());
            assert_eq!(actual.correlation(), expected.correlation());
            assert_eq!(actual.session_id().unwrap().value(), "s");
            assert_eq!(actual.source().adapter_id(), source_id);
            let after = 3 + codex_auxiliary_records().len() as u64;
            assert_eq!(actual.sequence(), Some([1, 2, after, after + 1][index]));
            assert_eq!(actual.observation_id(), repeated.observation_id());
            assert_eq!(actual.source(), repeated.source());
            assert_eq!(
                actual.stage(),
                [
                    ObservationStage::MessageObserved,
                    ObservationStage::ToolRequested,
                    ObservationStage::MessageObserved,
                    ObservationStage::ToolResultReturned
                ][index]
            );
        }
    }
}

#[test]
fn codex_auxiliary_rejects_wrong_wrappers_and_quarantines_late_unknowns() {
    use serde_json::json;
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    let accepted = codex_auxiliary_records()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let mut rejected = vec![
        json!({"type":"turn_context"}),
        json!({"type":"turn_context","payload":null}),
        json!({"type":"turn_context","payload":[]}),
        json!({"type":"event_msg","payload":[]}),
        json!({"type":"response_item","payload":"reasoning"}),
    ];
    for auxiliary in codex_auxiliary_records()
        .into_iter()
        .filter(|v| v["type"] != "turn_context")
    {
        let payload = auxiliary["payload"].clone();
        rejected.extend([payload.clone(), json!({"type":"unknown_wrapper","payload":payload}), json!({"type":auxiliary["type"],"payload":{"payload":payload}}), json!({"type":if auxiliary["type"] == "event_msg" {"response_item"} else {"event_msg"},"payload":payload})]);
    }
    // Unknown event_msg variants must quarantine by themselves, never fail
    // the source.
    let mut unknown_variants = Vec::new();
    for kind in [
        "exec_command_begin",
        "exec_command_end",
        "item_completed",
        "item_started",
        "turn_started",
        "turn_complete",
        "future_variant",
    ] {
        let value = json!({"type":"event_msg","payload":{"type":kind,"item":{"type":"Reasoning"}}});
        if kind == "item_completed" {
            rejected.push(value);
        } else {
            unknown_variants.push(value);
        }
    }
    rejected.extend([
        json!({"type":"event_msg","payload":{"type":null}}),
        json!({"type":"response_item","payload":{"type":123}}),
    ]);
    let write = |value: &serde_json::Value| {
        std::fs::write(&source.path, format!("{{\"type\":\"session_meta\",\"payload\":{{\"session_id\":\"s\"}}}}\n{{\"type\":\"user\",\"content\":\"synthetic\"}}\n{accepted}\n{value}\n")).unwrap();
    };
    for value in unknown_variants {
        write(&value);
        let batch = acquire_source(&source, options())
            .unwrap_or_else(|error| panic!("{value}: {}", error.code()));
        assert_eq!(batch.observations.len(), 1, "{value}");
        assert_eq!(batch.quarantined.len(), 1, "{value}");
        assert_eq!(batch.quarantined[0].code, "unknown_discriminator");
        assert!(!format!("{:?}", batch.quarantined).contains("PRIVATE"));
    }
    for value in rejected {
        write(&value);
        let result = acquire_source(&source, options());
        if value["type"] == "response_item" && value["payload"]["type"] == 123 {
            assert_eq!(result.err().unwrap().code(), "unsupported_record");
        } else if value["payload"]["type"] == "item_completed" {
            assert_eq!(
                result.err().unwrap().code(),
                "source_read",
                "completed coordinates are missing"
            );
        } else {
            match result {
                // An unknown discriminator quarantines its record by itself;
                // the user message is still acquired.
                Ok(batch) => {
                    assert_eq!(batch.observations.len(), 1, "{value}");
                    assert_eq!(batch.quarantined.len(), 1, "{value}");
                    assert_eq!(batch.quarantined[0].code, "unknown_discriminator");
                    assert!(!format!("{:?}", batch.quarantined).contains("PRIVATE"));
                }
                // A wrong wrapper on a known type, or an untyped record, is
                // still schema drift for the whole source.
                Err(error) => {
                    assert!(
                        matches!(error.code(), "source_read" | "unsupported_record"),
                        "{value}: {}",
                        error.code()
                    );
                    assert!(!format!("{error:?}").contains("PRIVATE"));
                }
            }
        }
    }
    std::fs::write(&source.path, format!("{{\"type\":\"session_meta\",\"payload\":{{\"session_id\":\"s\"}}}}\n{accepted}\n{{\"type\":\"assistant\",\"content\":[{{\"type\":\"future_block\",\"text\":\"PRIVATE\"}}]}}\n")).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(batch.quarantined.len(), 1);
    assert_eq!(batch.quarantined[0].code, "unknown_content_block");
}

#[test]
fn codex_auxiliary_preserves_metadata_and_session_validation() {
    use serde_json::json;
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    // Bookkeeping payloads are opaque: a token usage record's payload names
    // the root session, not this thread. Their envelope is still validated.
    let (opaque, auxiliaries): (Vec<_>, Vec<_>) = codex_auxiliary_records()
        .into_iter()
        .partition(|v| matches!(v["type"].as_str(), Some("token_usage_record" | "compacted")));
    for mut value in opaque {
        value["session_id"] = json!(42);
        std::fs::write(&source.path, value.to_string()).unwrap();
        assert!(acquire_source(&source, options()).is_err(), "{value}");
    }
    for auxiliary in auxiliaries {
        for invalid in [
            json!({"session_id":"a", "payload_session_id":"b"}),
            json!({"session_id":"a", "model":123}),
            json!({"session_id":"a", "model_provider":[]}),
        ] {
            let mut value = auxiliary.clone();
            value["session_id"] = invalid["session_id"].clone();
            if invalid.get("payload_session_id").is_some() {
                value["payload"]["session_id"] = invalid["payload_session_id"].clone();
            }
            for field in ["model", "model_provider"] {
                if let Some(invalid_field) = invalid.get(field) {
                    value["payload"][field] = invalid_field.clone();
                }
            }
            std::fs::write(&source.path, value.to_string()).unwrap();
            assert!(acquire_source(&source, options()).is_err(), "{value}");
        }
    }
}

#[test]
fn codex_auxiliary_correction_turn_context_rejects_discriminator_wrappers() {
    use serde_json::json;
    let directory = tempdir().unwrap();
    let accepted = codex_auxiliary_records()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let mut payloads = Vec::new();
    for tag in [
        json!("exec_command_begin"),
        json!("future_variant"),
        json!("message"),
        json!("tool_call"),
        json!("tool_result"),
        json!("reasoning"),
        json!(null),
        json!(123),
        json!({}),
        json!([]),
    ] {
        payloads.push(json!({"type":tag,"role":"assistant","name":"shell","arguments":{"command":"true"},"output":"synthetic","content":"PRIVATE fallback"}));
        payloads.push(json!({"payload":{"type":tag,"content":"PRIVATE fallback"}}));
    }
    payloads.extend([
        json!({"payload":null}),
        json!({"payload":123}),
        json!({"payload":[]}),
    ]);
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: directory.path().join("synthetic.jsonl"),
        };
        for payload in &payloads {
            let value = json!({"type":"turn_context","payload":payload});
            std::fs::write(&source.path, format!("{{\"type\":\"session_meta\",\"payload\":{{\"session_id\":\"a\"}}}}\n{{\"type\":\"user\",\"content\":\"synthetic\"}}\n{accepted}\n{value}\n")).unwrap();
            let error = acquire_source(&source, options())
                .err()
                .expect("unsupported turn_context shape must reject whole acquisition");
            assert!(matches!(error, AcquisitionError::SourceRead));
            assert!(!format!("{error:?}").contains("PRIVATE"));
        }
    }
}

#[test]
fn codex_auxiliary_correction_cannot_establish_inherited_session_namespace() {
    use serde_json::json;
    let directory = tempdir().unwrap();
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: directory.path().join("synthetic.jsonl"),
        };
        for mut auxiliary in codex_auxiliary_records() {
            auxiliary["session_id"] = json!("b");
            auxiliary["session_meta"] = json!({});
            std::fs::write(&source.path, auxiliary.to_string()).unwrap();
            let batch = acquire_source(&source, options()).unwrap();
            assert!(batch.observations.is_empty());
            assert_eq!(batch.accounting.sessions[0].session_id.value(), "b");
            assert_eq!(batch.accounting.sessions[0].counts.record_counts.other, 1);
            std::fs::write(
                &source.path,
                format!("{auxiliary}\n{{\"type\":\"user\",\"content\":\"synthetic\"}}\n"),
            )
            .unwrap();
            let error = acquire_source(&source, options())
                .err()
                .expect("auxiliary must not supply later message identity");
            assert_eq!(error.code(), "replay_unverifiable");
            std::fs::write(&source.path, format!("{{\"type\":\"session_meta\",\"payload\":{{\"session_id\":\"a\"}}}}\n{auxiliary}\n{{\"type\":\"user\",\"content\":\"synthetic\"}}\n")).unwrap();
            let batch = acquire_source(&source, options()).unwrap();
            assert_eq!(batch.observations.len(), 1);
            assert_eq!(batch.observations[0].session_id().unwrap().value(), "a");
            assert_eq!(batch.observations[0].sequence(), Some(2));
        }
    }
}
