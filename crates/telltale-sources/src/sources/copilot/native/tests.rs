use std::fs;

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;
use tempfile::tempdir;

use super::{CopilotNativeEvent, extract_copilot_native_events};

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::Copilot,
        kind: SourceKind::CopilotProcessLog,
        source_id: "copilot.process_log".to_owned(),
        path,
    }
}

#[test]
fn production_limits_reject_ignored_bytes_and_accumulated_items_atomically() {
    use crate::acquisition::{AcquisitionError, AcquisitionOptions, acquire_source};
    use telltale_schema::observation::ObservedAt;
    let directory = tempdir().unwrap();
    let path = directory.path().join("bounded.log");
    let input = source(path.clone());
    let prefix = "Workspace initialized: synthetic-session (checkpoints: 0)\n";
    fs::write(&path, " ".repeat(8 * 1024 * 1024)).unwrap();
    assert!(extract_copilot_native_events(&input).unwrap().is_empty());
    let at_limit = format!(
        "{prefix}Accumulated output items: [{}]\n",
        vec!["{}"; 99_999].join(",")
    );
    fs::write(&path, at_limit).unwrap();
    assert_eq!(
        extract_copilot_native_events(&input).unwrap().len(),
        100_000
    );
    for raw in [
        format!("{prefix}{}", " ".repeat(8 * 1024 * 1024 + 1)),
        format!(
            "{prefix}Accumulated output items: [{}]\n",
            vec!["{}"; 100_001].join(",")
        ),
    ] {
        fs::write(&path, raw).unwrap();
        assert!(extract_copilot_native_events(&input).is_err());
        assert_eq!(
            acquire_source(
                &input,
                AcquisitionOptions::new(ObservedAt::new("2026-09-04T12:00:00Z").unwrap())
            )
            .err(),
            Some(AcquisitionError::BoundedSourceRead(
                crate::source_read::BoundedReadError::LimitExceeded
            ))
        );
    }
    let file = fs::File::create(&path).unwrap();
    file.set_len(128 * 1024 * 1024 + 1).unwrap();
    assert!(extract_copilot_native_events(&input).is_err());
}

#[test]
fn malformed_known_strings_fail_extraction_and_acquisition_atomically() {
    use crate::acquisition::{AcquisitionError, AcquisitionOptions, acquire_source};
    use serde_json::json;
    use telltale_schema::observation::ObservedAt;

    let directory = tempdir().unwrap();
    let path = directory.path().join("private-path-marker.log");
    let source = source(path.clone());
    for field in [
        "type",
        "id",
        "call_id",
        "name",
        "arguments",
        "message",
        "role",
    ] {
        for invalid in [
            json!({"command": "private-command-marker"}),
            json!(["private-array-marker"]),
            json!(42),
            json!(false),
        ] {
            for same_array in [false, true] {
                let good = json!({"type": "function_call", "name": "bash", "arguments": "{\"command\":\"synthetic-command\"}"});
                let mut bad = good.clone();
                bad[field] = invalid.clone();
                let rows = if same_array {
                    format!("Accumulated output items (2): {}\n", json!([good, bad]))
                } else {
                    format!(
                        "Accumulated output items (1): {}\nAccumulated output items (1): {}\n",
                        json!([good]),
                        json!([bad])
                    )
                };
                fs::write(
                    &path,
                    format!(
                        "Workspace initialized: private-session-marker (checkpoints: 0)\n{rows}"
                    ),
                )
                .unwrap();
                let error = extract_copilot_native_events(&source)
                    .err()
                    .expect("malformed known field must reject all native events");
                assert!(
                    matches!(
                        error,
                        crate::source_read::SourceReadError::SchemaDrift { .. }
                    ),
                    "{field}"
                );
                assert!(!format!("{error} {error:?}").contains("private-"));
                let error = acquire_source(
                    &source,
                    AcquisitionOptions::new(ObservedAt::new("2026-09-04T12:00:00Z").unwrap()),
                )
                .err()
                .expect("no successful prefix, accounting, or progress");
                assert_eq!(error, AcquisitionError::SourceRead, "{field}");
                assert_eq!(format!("{error}"), "source_read");
                assert!(!format!("{error:?}").contains("private-"));
            }
        }
    }
}

#[test]
fn multiple_malformed_fields_and_message_item_strings_are_rejected() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("malformed.log");
    for bad in [
        serde_json::json!({"type":"function_call", "name":"bash", "arguments":{"command":"synthetic-command"}, "call_id":42, "message":false}),
        serde_json::json!({"type":"message", "role":"assistant", "id":42, "content":[{"type":"output_text", "text":"synthetic-text"}]}),
    ] {
        fs::write(&path, format!("Workspace initialized: synthetic-session (checkpoints: 0)\nAccumulated output items (1): {}\n", serde_json::json!([bad]))).unwrap();
        assert!(extract_copilot_native_events(&source(path.clone())).is_err());
    }
}

#[test]
fn reasoning_native_item_keeps_only_type_and_consumes_ordinal() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("reasoning.log");
    fs::write(
            &path,
            "Workspace initialized: reasoning-session (checkpoints: 0)\nAccumulated output items (2): [{\"type\":\"reasoning\",\"id\":\"reasoning-id-marker\",\"call_id\":\"reasoning-call-id-marker\",\"name\":\"reasoning-name-marker\",\"arguments\":\"reasoning-arguments-marker\",\"message\":\"reasoning-message-marker\",\"model\":\"reasoning-model-marker\",\"provider\":\"reasoning-provider-marker\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"reasoning-output-text-marker\"}],\"output_text\":\"reasoning-top-level-output-marker\",\"encrypted_content\":\"reasoning-encrypted-marker\"},{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

    let events = extract_copilot_native_events(&source(path)).unwrap();
    let items = events
        .iter()
        .filter_map(|event| match event {
            CopilotNativeEvent::AccumulatedOutputItem { ordinal, item, .. } => {
                Some((*ordinal, item.as_ref()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].0, Some(0));
    assert_eq!(items[1].0, Some(1));

    let reasoning = items[0].1;
    assert_eq!(reasoning.item_type.as_deref(), Some("reasoning"));
    assert!(reasoning.call_id.is_none());
    assert!(reasoning.name.is_none());
    assert!(reasoning.arguments.is_none());
    assert!(reasoning.message.is_none());
    assert_eq!(
        reasoning.attestation.as_ref().unwrap(),
        &crate::acquisition::SessionMetadata::default()
    );
    assert!(reasoning.role.is_none());
    assert!(!reasoning.content_present);
    assert!(reasoning.content.is_none());

    assert!(matches!(
        items[1].1.item_type.as_deref(),
        Some("function_call")
    ));
}

#[test]
fn unknown_and_missing_type_items_keep_only_discriminator_and_consume_ordinal() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("unknown-items.log");
    fs::write(
            &path,
            "Workspace initialized: unknown-items-session (checkpoints: 0)\nAccumulated output items (3): [{\"type\":\"Reasoning\",\"id\":\"case-id-marker\",\"call_id\":\"case-call-id-marker\",\"name\":\"case-name-marker\",\"arguments\":\"case-arguments-marker\",\"message\":\"case-message-marker\",\"model\":\"case-model-marker\",\"provider\":\"case-provider-marker\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"case-output-text-marker\"}],\"output_text\":\"case-top-level-output-marker\",\"encrypted_content\":\"case-encrypted-marker\"},{\"id\":\"missing-id-marker\",\"call_id\":\"missing-call-id-marker\",\"name\":\"missing-name-marker\",\"arguments\":\"missing-arguments-marker\",\"message\":\"missing-message-marker\",\"model\":\"missing-model-marker\",\"provider\":\"missing-provider-marker\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"missing-output-text-marker\"}],\"output_text\":\"missing-top-level-output-marker\",\"encrypted_content\":\"missing-encrypted-marker\"},{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

    let events = extract_copilot_native_events(&source(path)).unwrap();
    let items = events
        .iter()
        .filter_map(|event| match event {
            CopilotNativeEvent::AccumulatedOutputItem { ordinal, item, .. } => {
                Some((*ordinal, item.as_ref()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        items
            .iter()
            .map(|(ordinal, item)| (*ordinal, item.item_type.as_deref()))
            .collect::<Vec<_>>(),
        vec![
            (Some(0), Some("Reasoning")),
            (Some(1), None),
            (Some(2), Some("function_call")),
        ]
    );

    for item in [items[0].1, items[1].1] {
        assert!(item.call_id.is_none());
        assert!(item.name.is_none());
        assert!(item.arguments.is_none());
        assert!(item.message.is_none());
        assert_eq!(
            item.attestation.as_ref().unwrap(),
            &crate::acquisition::SessionMetadata::default()
        );
        assert!(item.role.is_none());
        assert!(!item.content_present);
        assert!(item.content.is_none());
    }
}
