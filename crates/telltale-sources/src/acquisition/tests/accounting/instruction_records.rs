use super::*;

#[test]
fn codex_developer_input_text_canonical_string_bound_quarantines_the_record() {
    use telltale_schema::observation::{JsonValue, MessageRole, ObservationBody};
    let directory = tempdir().unwrap();
    let prefix = concat!(
        "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"s\"}}\n",
        "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":\"synthetic user\"}}\n"
    );
    let marker = "SYNTHETIC-CODEX-BOUND-";
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
        for bytes in [65_497, 65_537] {
            let text = format!("{marker}{}", "x".repeat(bytes - marker.len()));
            assert_eq!(text.len(), bytes);
            let instruction = serde_json::json!({"type":"response_item","payload":{
                "type":"message","role":"developer",
                "content":[{"type":"input_text","text":text}]
            }});
            std::fs::write(&source.path, format!("{prefix}{instruction}\n")).unwrap();
            let result = acquire_source(&source, options());
            if bytes == 65_497 {
                let batch = result.unwrap();
                assert_eq!(batch.observations.len(), 2);
                let ObservationBody::Message(message) = batch.observations[1].body() else {
                    panic!("expected developer message")
                };
                assert_eq!(message.role(), Some(MessageRole::Developer));
                assert_eq!(
                    message.content_parts()[0].value(),
                    &JsonValue::string(&text)
                );
                assert_eq!(batch.accounting.sessions[0].counts.native_units, 3);
            } else {
                // The oversized record is left out by itself; the user
                // message before it is still acquired.
                let batch = result.expect("late bound failure quarantines one record");
                assert_eq!(batch.observations.len(), 1);
                assert_eq!(batch.quarantined.len(), 1);
                assert_eq!(batch.quarantined[0].code, "unbounded_value");
                assert_eq!(batch.quarantined[0].source_sequence, 2);
                assert_eq!(
                    batch.quarantined[0].bound,
                    Some(telltale_schema::observation::CanonicalBoundContext {
                        category: telltale_schema::observation::CanonicalFieldCategory::MessageContentParts,
                        dimension: telltale_schema::observation::BoundDimension::StringBytes,
                    })
                );
                assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
                assert!(!format!("{:?}", batch.quarantined).contains(marker));
            }
        }
    }
}

#[test]
fn codex_instruction_roles_preserve_order_identity_and_other_accounting() {
    use telltale_schema::observation::{MessageRole, ObservationBody, ObservationStage};
    let directory = tempdir().unwrap();
    let contents = r#"{"type":"session_meta","payload":{"session_id":"s"}}
{"type":"response_item","payload":{"type":"message","role":"system","content":[{"type":"output_text","text":"synthetic system"}]}}
{"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"synthetic developer first"},{"type":"input_text","text":"synthetic developer second"}]}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"synthetic user"}]}}
{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"synthetic assistant"}]}}"#;
    let mut identities = Vec::new();
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
        std::fs::write(&source.path, contents).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        let replay = acquire_source(&source, options()).unwrap();
        assert_eq!(batch.observations.len(), 4);
        assert_eq!(batch.accounting, replay.accounting);
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 5);
        assert_eq!(
            batch.accounting.sessions[0].counts.record_counts,
            RecordCounts {
                session_meta: 1,
                user_message: 1,
                assistant_message: 1,
                other: 2,
                ..Default::default()
            }
        );
        assert_eq!(
            batch.accounting.sessions[0].counts.contributions,
            ActivityContributions::default()
        );
        for (index, (observation, role)) in batch
            .observations
            .iter()
            .zip([
                MessageRole::System,
                MessageRole::Developer,
                MessageRole::User,
                MessageRole::Assistant,
            ])
            .enumerate()
        {
            let ObservationBody::Message(message) = observation.body() else {
                panic!("expected message")
            };
            assert_eq!(message.role(), Some(role));
            assert_eq!(observation.stage(), ObservationStage::MessageObserved);
            assert_eq!(observation.sequence(), Some(index as u64 + 1));
            assert_eq!(observation.identity_basis().child_ordinal(), 0);
            assert_eq!(observation.source().adapter_id(), source_id);
            assert_eq!(observation.session_id().unwrap().value(), "s");
            assert_eq!(observation.body(), replay.observations[index].body());
            assert_eq!(
                observation.observation_id(),
                replay.observations[index].observation_id()
            );
            assert_eq!(
                observation.fact_metadata()["message.role"].provenance(),
                telltale_schema::observation::FactProvenance::Reported
            );
            if role == MessageRole::Developer {
                assert_eq!(
                    message
                        .content_parts()
                        .iter()
                        .map(|part| part.value().clone())
                        .collect::<Vec<_>>(),
                    vec![
                        telltale_schema::observation::JsonValue::string(
                            "synthetic developer first"
                        ),
                        telltale_schema::observation::JsonValue::string(
                            "synthetic developer second"
                        )
                    ]
                );
            }
        }
        identities.push(batch.observations[0].observation_id().to_owned());
        for role in ["system", "developer"] {
            for discriminator in [
                "message",
                "text",
                "user",
                "user_message",
                "assistant",
                "assistant_message",
                "model",
            ] {
                std::fs::write(&source.path, format!("{{\"type\":\"session_meta\",\"payload\":{{\"session_id\":\"s\"}}}}\n{{\"type\":\"{discriminator}\",\"role\":\"{role}\",\"content\":\"synthetic instruction\"}}\n")).unwrap();
                let instruction = acquire_source(&source, options()).unwrap();
                let ObservationBody::Message(message) = instruction.observations[0].body() else {
                    panic!("expected instruction message")
                };
                assert_eq!(
                    message.role(),
                    Some(if role == "system" {
                        MessageRole::System
                    } else {
                        MessageRole::Developer
                    })
                );
                assert_eq!(
                    instruction.accounting.sessions[0].counts.record_counts,
                    RecordCounts {
                        session_meta: 1,
                        other: 1,
                        ..Default::default()
                    }
                );
            }
        }
        for (role, content, code) in [
            (
                "future_role",
                r#"[{"type":"input_text","text":"PRIVATE"}]"#,
                "unsupported_role",
            ),
            (
                "System",
                r#"[{"type":"input_text","text":"PRIVATE"}]"#,
                "unsupported_role",
            ),
            (
                "tool",
                r#"[{"type":"input_text","text":"PRIVATE"}]"#,
                "unsupported_role",
            ),
            (
                "developer",
                r#"[{"type":"future_block","text":"PRIVATE"}]"#,
                "unknown_content_block",
            ),
            (
                "system",
                r#"[{"type":"input_text","text":123}]"#,
                "invalid_content_block",
            ),
        ] {
            std::fs::write(&source.path, format!("{contents}\n{{\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"{role}\",\"content\":{content}}}}}\n")).unwrap();
            if code == "unknown_content_block" {
                // An unknown block quarantines its record by itself.
                let batch = acquire_source(&source, options()).unwrap();
                assert_eq!(batch.quarantined.len(), 1);
                assert_eq!(batch.quarantined[0].code, code);
                assert!(!format!("{:?}", batch.quarantined).contains("PRIVATE"));
                continue;
            }
            let error = acquire_source(&source, options())
                .err()
                .expect("source-atomic rejection");
            assert_eq!(error.code(), code);
            assert!(!format!("{error:?} {error}").contains("PRIVATE"));
        }
    }
    assert!(
        identities
            .iter()
            .enumerate()
            .all(|(index, id)| !identities[..index].contains(id))
    );
}
