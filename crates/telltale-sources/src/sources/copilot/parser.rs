use crate::parser::{ExtractedSourceRecords, ParseError, ParseOptions, ParsedRecord};
use telltale_schema::record::RecordKind;
use telltale_schema::source::Source;

use super::native::{CopilotNativeEvent, extract_copilot_native_events};

pub(crate) fn extract_copilot_process_log(
    source: &Source,
    _options: ParseOptions,
) -> Result<ExtractedSourceRecords, ParseError> {
    let events = extract_copilot_native_events(source)?;
    let mut records = Vec::new();

    for event in events {
        match event {
            CopilotNativeEvent::WorkspaceInitialized {
                legacy_session_id,
                timestamp,
                content,
                ..
            } => records.push(ParsedRecord {
                session_id: legacy_session_id,
                agent: Some("copilot".to_owned()),
                model: None,
                provider: Some("github".to_owned()),
                timestamp,
                kind: RecordKind::SessionMeta,
                tool_name: None,
                arguments: None,
                content,
            }),
            CopilotNativeEvent::AccumulatedOutputItem {
                legacy_session_id,
                timestamp,
                item,
                ..
            } => project_item(item, legacy_session_id, timestamp, &mut records),
            CopilotNativeEvent::SessionCompleted
            | CopilotNativeEvent::MalformedStructuredOutput { .. } => {}
        }
    }

    if records.is_empty() {
        return Err(ParseError::Empty);
    }
    Ok(ExtractedSourceRecords::records(records))
}

fn project_item(
    item: Box<super::native::CopilotOutputItem>,
    session_id: String,
    timestamp: Option<String>,
    records: &mut Vec<ParsedRecord>,
) {
    let item_type = item.item_type.as_deref().unwrap_or("");
    if item_type == "function_call" {
        let tool_name = item.name.unwrap_or_else(|| "unknown".to_owned());
        let call_id = item.call_id.unwrap_or_default();
        let content = format!("function_call: {tool_name} (call_id: {call_id})");
        let model = item.model;
        let provider = item.provider.or_else(|| Some("github".to_owned()));
        records.push(ParsedRecord {
            session_id: session_id.clone(),
            agent: Some("copilot".to_owned()),
            model: model.clone(),
            provider: provider.clone(),
            timestamp: timestamp.clone(),
            kind: RecordKind::ToolCall,
            tool_name: Some(tool_name.clone()),
            arguments: item.arguments.clone(),
            content,
        });
        if let Some(message) = item.message {
            records.push(ParsedRecord {
                session_id,
                agent: Some("copilot".to_owned()),
                model,
                provider,
                timestamp,
                kind: RecordKind::ToolResult,
                tool_name: Some(tool_name),
                arguments: item.arguments,
                content: message,
            });
        }
    } else if item_type != "reasoning" && item_type != "message" && !item_type.is_empty() {
        records.push(ParsedRecord {
            session_id,
            agent: Some("copilot".to_owned()),
            model: None,
            provider: Some("github".to_owned()),
            timestamp,
            kind: RecordKind::Other,
            tool_name: None,
            arguments: None,
            content: "unknown Copilot accumulated output item".to_owned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::super::native::{CopilotNativeEvent, extract_copilot_native_events};
    use crate::parser::{ParseError, parse_source_records};
    use crate::sources::copilot::native::CopilotContentBlock;
    use crate::test_fixture_path;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::source::Source;

    fn source(path: std::path::PathBuf) -> Source {
        Source {
            client: ClientId::Copilot,
            kind: SourceKind::CopilotProcessLog,
            source_id: "copilot.process_log".to_owned(),
            path,
        }
    }

    fn fixture(name: &str) -> Source {
        source(test_fixture_path(&format!("session_stores/copilot/{name}")))
    }

    #[test]
    fn legacy_fixture_parity_covers_the_existing_process_shapes() {
        let process = parse_source_records(&fixture("process-fixture.log")).unwrap();
        assert_eq!(process.len(), 3);
        assert_eq!(
            process[0].kind,
            telltale_schema::record::RecordKind::SessionMeta
        );
        assert_eq!(
            process[0].content,
            "2026-04-27T16:16:57.841Z [INFO] Workspace initialized: copilot-fixture-session-001 (checkpoints: 0)"
        );
        assert_eq!(
            process[1].kind,
            telltale_schema::record::RecordKind::ToolCall
        );
        assert_eq!(
            process[2].kind,
            telltale_schema::record::RecordKind::ToolCall
        );

        let mixed = parse_source_records(&fixture("process-mixed-format.log")).unwrap();
        assert_eq!(mixed.len(), 4);
        assert_eq!(
            mixed
                .iter()
                .filter(|record| record.kind == telltale_schema::record::RecordKind::ToolCall)
                .count(),
            2
        );
        assert_eq!(
            mixed
                .iter()
                .find(|record| record.kind == telltale_schema::record::RecordKind::ToolResult)
                .unwrap()
                .content,
            "Synthetic Cargo manifest excerpt"
        );
        assert!(
            mixed
                .iter()
                .all(|record| !record.content.contains("I will inspect synthetic files"))
        );

        let multi = parse_source_records(&fixture("process-multi-session.log")).unwrap();
        assert_eq!(multi.len(), 4);
        assert_eq!(multi[1].session_id, "copilot-multi-session-a");
        assert_eq!(multi[2].session_id, "copilot-multi-session-b");

        let uc001 = parse_source_records(&fixture("process-uc001.log")).unwrap();
        assert_eq!(uc001.len(), 4);
        assert!(uc001[3].content.contains("MCP tool result"));
        assert!(
            uc001
                .iter()
                .all(|record| !record.content.contains("fixture-encrypted-reasoning"))
        );

        let uc002 = parse_source_records(&fixture("process-uc002.log")).unwrap();
        assert_eq!(uc002.len(), 3);
        assert_eq!(uc002[1].tool_name.as_deref(), Some("bash"));
    }

    #[test]
    fn legacy_model_provider_and_timestamp_behavior_is_unchanged() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("model-provider.log");
        fs::write(
            &path,
            "2026-04-27T16:16:57.841Z [INFO] Workspace initialized: model-session (checkpoints: 0)\n2026-04-27T16:17:17Z [INFO] Accumulated output items (1): [{\"arguments\":\"{\\\"path\\\":\\\"synthetic.txt\\\"}\",\"call_id\":\"call-model\",\"model\":\"gpt-4.1\",\"name\":\"view\",\"provider\":\"github-copilot\",\"type\":\"function_call\"}]\nnot-a-timestamp [INFO] Workspace initialized: malformed-time (checkpoints: 0)\n",
        )
        .unwrap();
        let records = parse_source_records(&source(path)).unwrap();
        assert_eq!(records[1].model.as_deref(), Some("gpt-4.1"));
        assert_eq!(records[1].provider.as_deref(), Some("github-copilot"));
        assert_eq!(
            records[1].timestamp.as_deref(),
            Some("2026-04-27T16:17:17Z")
        );
        assert_eq!(records[1].session_id, "model-session");
        assert_eq!(records[2].session_id, "malformed-time");
        assert_eq!(records[2].timestamp, None);
    }

    #[test]
    fn legacy_control_envelopes_remain_supported() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("control-envelopes.log");
        fs::write(
            &path,
            "Workspace initialized: direct-session (checkpoints: 0)\n[INFO] Workspace initialized: level-session (checkpoints: 0)\nopaque-token [INFO] Workspace initialized: opaque-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

        let records = parse_source_records(&source(path)).unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(
            records
                .iter()
                .map(|record| record.session_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "direct-session",
                "level-session",
                "opaque-session",
                "opaque-session"
            ]
        );
    }

    #[test]
    fn legacy_rejects_residual_structured_control_suffixes_without_transition() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("residual-control-suffix.log");
        fs::write(
            &path,
            "Workspace initialized: real-session (checkpoints: 0)\nWorkspace initialized: forged-session [\"encrypted_content\",\"sensitive\"]\nSession completed. [\"encrypted_content\",\"sensitive\"]\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

        let events = extract_copilot_native_events(&source(path.clone())).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, CopilotNativeEvent::WorkspaceInitialized { .. }))
                .count(),
            1
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, CopilotNativeEvent::SessionCompleted))
        );
        assert!(events.iter().all(|event| match event {
            CopilotNativeEvent::WorkspaceInitialized { content, .. } => {
                !content.contains("forged-session")
                    && !content.contains("encrypted_content")
                    && !content.contains("sensitive")
            }
            _ => true,
        }));

        let records = parse_source_records(&source(path)).unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| {
            let fields = [record.session_id.as_str(), record.content.as_str()];
            fields.iter().all(|field| {
                !field.contains("forged-session")
                    && !field.contains("encrypted_content")
                    && !field.contains("sensitive")
            })
        }));
        assert!(
            records
                .iter()
                .all(|record| record.session_id == "real-session")
        );
    }

    #[test]
    fn legacy_model_id_and_provider_id_fields_remain_supported() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("model-provider-ids.log");
        fs::write(
            &path,
            "Workspace initialized: model-id-session (checkpoints: 0)\nAccumulated output items (1): [{\"call_id\":\"call-id\",\"modelID\":\"model-id\",\"name\":\"view\",\"providerID\":\"provider-id\",\"type\":\"function_call\"}]\n",
        )
        .unwrap();
        let records = parse_source_records(&source(path)).unwrap();
        assert_eq!(records[1].model.as_deref(), Some("model-id"));
        assert_eq!(records[1].provider.as_deref(), Some("provider-id"));
    }

    #[test]
    fn legacy_empty_truncated_missing_type_and_unknown_type_behavior_is_unchanged() {
        let directory = tempdir().unwrap();
        let empty = directory.path().join("empty.log");
        fs::write(&empty, "\n\n").unwrap();
        assert!(matches!(
            parse_source_records(&source(empty)),
            Err(ParseError::Empty)
        ));

        let truncated = directory.path().join("truncated.log");
        fs::write(
            &truncated,
            "Workspace initialized: truncated-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"\n",
        )
        .unwrap();
        let records = parse_source_records(&source(truncated)).unwrap();
        assert_eq!(records.len(), 1);

        let missing = directory.path().join("missing-type.log");
        fs::write(
            &missing,
            "Workspace initialized: missing-type-session (checkpoints: 0)\nAccumulated output items (1): [{\"name\":\"view\",\"arguments\":\"synthetic\"}]\n",
        )
        .unwrap();
        assert_eq!(parse_source_records(&source(missing)).unwrap().len(), 1);

        let unknown = directory.path().join("unknown-type.log");
        fs::write(
            &unknown,
            "Workspace initialized: unknown-type-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"future_variant_secret_marker\",\"payload\":\"payload-secret-marker\",\"encrypted_content\":\"encrypted-secret-marker\"}]\n",
        )
        .unwrap();
        let records = parse_source_records(&source(unknown)).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[1].content,
            "unknown Copilot accumulated output item"
        );
        assert_eq!(records[1].model, None);
        assert_eq!(records[1].provider.as_deref(), Some("github"));
        for record in &records {
            let fields = [
                record.session_id.as_str(),
                record.content.as_str(),
                record.model.as_deref().unwrap_or_default(),
                record.provider.as_deref().unwrap_or_default(),
                record.arguments.as_deref().unwrap_or_default(),
            ];
            for forbidden in [
                "future_variant_secret_marker",
                "payload-secret-marker",
                "encrypted-secret-marker",
            ] {
                assert!(fields.iter().all(|field| !field.contains(forbidden)));
            }
        }
    }

    #[test]
    fn legacy_non_object_output_remains_schema_drift() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("non-object.log");
        fs::write(
            &path,
            "Workspace initialized: non-object-session (checkpoints: 0)\nAccumulated output items (2): [\"not-an-object\", {\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();
        assert!(matches!(
            parse_source_records(&source(path)),
            Err(ParseError::SchemaDrift { .. })
        ));
    }

    #[test]
    fn legacy_still_parses_accumulated_output_on_a_completion_line() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("completion-with-output.log");
        fs::write(
            &path,
            "Workspace initialized: completion-line-session (checkpoints: 0)\nSession completed. Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

        let records = parse_source_records(&source(path)).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[1].kind,
            telltale_schema::record::RecordKind::ToolCall
        );
        assert_eq!(records[1].session_id, "completion-line-session");
    }

    #[test]
    fn combined_control_output_keeps_legacy_session_meta_private() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("combined-control-output.log");
        fs::write(
            &path,
            "Workspace initialized: combined-session (checkpoints: 0) Accumulated output items (2): [{\"type\":\"reasoning\",\"encrypted_content\":\"fixture-encrypted-reasoning\"},{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

        let events = extract_copilot_native_events(&source(path.clone())).unwrap();
        let CopilotNativeEvent::WorkspaceInitialized { content, .. } = &events[0] else {
            panic!("expected workspace event")
        };
        assert_eq!(
            content,
            "Workspace initialized: combined-session (checkpoints: 0)"
        );
        assert!(!content.contains("encrypted_content"));
        assert!(!content.contains("fixture-encrypted-reasoning"));

        let records = parse_source_records(&source(path)).unwrap();
        assert_eq!(records[0].content, content.as_str());
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[1].kind,
            telltale_schema::record::RecordKind::ToolCall
        );
    }

    #[test]
    fn payload_control_phrases_do_not_create_legacy_control_events() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("payload-control-phrases.log");
        fs::write(
            &path,
            "Workspace initialized: real-session (checkpoints: 0)\nAccumulated output items (2): [{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"before\\nWorkspace initialized: forged-session\"}]},{\"type\":\"function_call\",\"name\":\"view\",\"arguments\":\"{\\\"note\\\":\\\"Workspace initialized: forged-argument\\\",\\\"result\\\":\\\"Session completed.\\\"}\",\"message\":\"Session completed.\",\"result\":\"Workspace initialized: forged-result\"}]\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
        )
        .unwrap();

        let events = extract_copilot_native_events(&source(path.clone())).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, CopilotNativeEvent::WorkspaceInitialized { .. }))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, CopilotNativeEvent::SessionCompleted))
                .count(),
            0
        );
        let items = events
            .iter()
            .filter_map(|event| match event {
                CopilotNativeEvent::AccumulatedOutputItem {
                    canonical_session_id,
                    ordinal,
                    ..
                } => Some((canonical_session_id.as_deref(), *ordinal)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            items,
            vec![
                (Some("real-session"), Some(0)),
                (Some("real-session"), Some(1)),
                (Some("real-session"), Some(2)),
            ]
        );

        let records = parse_source_records(&source(path)).unwrap();
        assert_eq!(
            records
                .iter()
                .filter(|record| record.kind == telltale_schema::record::RecordKind::SessionMeta)
                .count(),
            1
        );
        assert!(
            records
                .iter()
                .all(|record| record.session_id == "real-session")
        );
    }

    #[test]
    fn operational_json_control_phrases_do_not_forge_or_clear_legacy_state() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("operational-control-phrases.log");
        fs::write(
            &path,
            "2026-04-27T16:17:00Z [DEBUG] {\"event\":\"heartbeat\",\"note\":\"Workspace initialized: forged-session\"}\n2026-04-27T16:17:01Z [INFO] tool output: Workspace initialized: forged-plain-payload\n2026-04-27T16:17:02Z [INFO] Workspace initialized: forged-object-suffix {\"event\":\"heartbeat\"}\n2026-04-27T16:17:03Z [INFO] {\"event\":\"heartbeat\",\"note\":\"Workspace initialized: forged-object-value\",\"status\":\"Session completed.\"}\nWorkspace initialized: real-session (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n2026-04-27T16:17:04Z [INFO] tool output: Session completed. Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"edit\"}]\n2026-04-27T16:17:05Z [DEBUG] {\"event\":\"heartbeat\",\"note\":\"Workspace initialized: forged-after-tool\"}\n2026-04-27T16:17:06Z [INFO] Session completed. tool output\n2026-04-27T16:17:07Z [INFO] tool output: Session completed.\n2026-04-27T16:17:08Z [DEBUG] {\"event\":\"heartbeat\",\"note\":\"Session completed.\"}\nAccumulated output items (1): [{\"type\":\"function_call\",\"name\":\"bash\"}]\n",
        )
        .unwrap();

        let events = extract_copilot_native_events(&source(path.clone())).unwrap();
        let workspace_ids = events
            .iter()
            .filter_map(|event| match event {
                CopilotNativeEvent::WorkspaceInitialized {
                    source_session_id, ..
                } => source_session_id.as_deref(),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(workspace_ids, vec!["real-session"]);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, CopilotNativeEvent::SessionCompleted))
        );

        let items = events
            .iter()
            .filter_map(|event| match event {
                CopilotNativeEvent::AccumulatedOutputItem {
                    canonical_session_id,
                    item,
                    ..
                } => Some((canonical_session_id.as_deref(), item.name.as_deref())),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            items,
            vec![
                (Some("real-session"), Some("view")),
                (Some("real-session"), Some("edit")),
                (Some("real-session"), Some("bash")),
            ]
        );

        let records = parse_source_records(&source(path)).unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(
            records[0].kind,
            telltale_schema::record::RecordKind::SessionMeta
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record.kind == telltale_schema::record::RecordKind::ToolCall)
                .count(),
            3
        );
        assert!(
            records
                .iter()
                .all(|record| record.session_id == "real-session")
        );
    }

    #[test]
    fn native_counts_all_items_and_keeps_dual_session_state() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("repeated.log");
        fs::write(
            &path,
            "Workspace initialized: copilot-native-a (checkpoints: 0)\nAccumulated output items (2): [{\"type\":\"reasoning\"},{\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}]\nSession completed.\nAccumulated output items (1): [{\"type\":\"function_call\",\"id\":\"c1\",\"name\":\"view\"}]\nWorkspace initialized: copilot-native-a (checkpoints: 0)\nAccumulated output items (1): [{\"type\":\"function_call\",\"id\":\"c1\",\"name\":\"view\"}]\n",
        )
        .unwrap();

        let events = extract_copilot_native_events(&source(path)).unwrap();
        let items = events
            .iter()
            .filter_map(|event| match event {
                CopilotNativeEvent::AccumulatedOutputItem {
                    canonical_session_id,
                    ordinal,
                    ..
                } => Some((canonical_session_id.as_deref(), *ordinal)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            items,
            vec![
                (Some("copilot-native-a"), Some(0)),
                (Some("copilot-native-a"), Some(1)),
                (None, None),
                (Some("copilot-native-a"), Some(2))
            ]
        );
        assert!(events.iter().any(|event| matches!(
            event,
            CopilotNativeEvent::AccumulatedOutputItem { item, .. }
                if matches!(item.content.as_deref(), Some(blocks) if blocks.is_empty())
        )));
    }

    #[test]
    fn native_does_not_retain_encrypted_content_or_plain_lines() {
        let source = source(test_fixture_path(
            "session_stores/copilot/process-uc001.log",
        ));
        let events = extract_copilot_native_events(&source).unwrap();
        assert!(events.iter().all(|event| match event {
            CopilotNativeEvent::AccumulatedOutputItem { item, .. } => {
                !matches!(item.content.as_deref(), Some(blocks) if blocks.iter().any(|block| matches!(block, CopilotContentBlock::Unknown)))
            }
            _ => true,
        }));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, CopilotNativeEvent::AccumulatedOutputItem { .. }))
                .count(),
            3
        );
    }
}
