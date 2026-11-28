use super::*;

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
