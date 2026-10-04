use std::collections::BTreeMap;
use std::fs;

use crate::acquisition::{AcquisitionError, SessionMetadata};
use serde_json::Value;
use telltale_schema::record::RecordKind;

use crate::source_read::SourceReadError;
use telltale_schema::clients::ClientId;
use telltale_schema::source::Source;

pub(crate) enum CopilotNativeEvent {
    WorkspaceInitialized {
        source_session_id: Option<String>,
    },
    AccumulatedOutputItem {
        canonical_session_id: Option<String>,
        ordinal: Option<u64>,
        timestamp: Option<String>,
        item: Box<CopilotOutputItem>,
    },
    SessionCompleted,
    MalformedStructuredOutput {
        canonical_session_id: Option<String>,
    },
}

pub(crate) struct CopilotOutputItem {
    pub(crate) attestation: Result<SessionMetadata, AcquisitionError>,
    pub(crate) item_type: Option<String>,
    pub(crate) call_id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) arguments: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) content_present: bool,
    pub(crate) content: Option<Vec<CopilotContentBlock>>,
}

pub(crate) enum CopilotContentBlock {
    OutputText { text: Option<String> },
    Unknown,
}

fn item_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn copilot_metadata(value: &Value) -> Result<SessionMetadata, AcquisitionError> {
    // Explicit accumulated-item labels only, never the workspace/client defaults.
    SessionMetadata::from_fields(
        value,
        &["agent"],
        &["model", "modelID"],
        &["provider", "providerID"],
    )
}

pub(crate) fn extract_copilot_native_events(
    source: &Source,
) -> Result<Vec<CopilotNativeEvent>, SourceReadError> {
    let raw = fs::read_to_string(&source.path)?;
    let mut events = Vec::new();
    let mut canonical_active_session_id = None;
    let mut item_ordinals = BTreeMap::<String, u64>::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let timestamp = copilot_log_timestamp(line);
        let accumulated_line = line.contains("Accumulated output items");
        let accumulated = copilot_accumulated_output_array(line);
        let control = copilot_trusted_control(line, accumulated);

        if accumulated.is_none()
            && let Some(TrustedControl::WorkspaceInitialized { message }) = control
        {
            let source_session_id = copilot_workspace_session_id(message);
            canonical_active_session_id = source_session_id.clone();
            events.push(CopilotNativeEvent::WorkspaceInitialized { source_session_id });
            continue;
        }

        if accumulated.is_none() && matches!(control, Some(TrustedControl::SessionCompleted)) {
            canonical_active_session_id = None;
            events.push(CopilotNativeEvent::SessionCompleted);
        }

        let Some((_, json_str)) = accumulated else {
            if accumulated_line {
                events.push(CopilotNativeEvent::MalformedStructuredOutput {
                    canonical_session_id: canonical_active_session_id.clone(),
                });
            }
            continue;
        };

        if let Some(TrustedControl::WorkspaceInitialized { message }) = control {
            let source_session_id = copilot_workspace_session_id(message);
            canonical_active_session_id = source_session_id.clone();
            events.push(CopilotNativeEvent::WorkspaceInitialized { source_session_id });
        }

        let parsed = serde_json::from_str::<Value>(json_str);
        let items = match parsed {
            Ok(Value::Array(items)) => items,
            Ok(_) | Err(_) => {
                events.push(CopilotNativeEvent::MalformedStructuredOutput {
                    canonical_session_id: canonical_active_session_id.clone(),
                });
                if matches!(control, Some(TrustedControl::SessionCompleted)) {
                    canonical_active_session_id = None;
                    events.push(CopilotNativeEvent::SessionCompleted);
                }
                continue;
            }
        };
        if items.iter().any(|item| !item.is_object()) {
            return Err(SourceReadError::SchemaDrift {
                client: ClientId::Copilot,
                source_id: source.source_id.clone(),
                detail: "Copilot accumulated output items must be objects",
            });
        }

        for item in items {
            let item = CopilotOutputItem::from_value(&item).map_err(|detail| {
                SourceReadError::SchemaDrift {
                    client: ClientId::Copilot,
                    source_id: source.source_id.clone(),
                    detail,
                }
            })?;
            let ordinal = canonical_active_session_id.as_ref().map(|session_id| {
                let ordinal = item_ordinals.entry(session_id.clone()).or_default();
                let current = *ordinal;
                *ordinal += 1;
                current
            });
            events.push(CopilotNativeEvent::AccumulatedOutputItem {
                canonical_session_id: canonical_active_session_id.clone(),
                ordinal,
                timestamp: timestamp.clone(),
                item: Box::new(item),
            });
        }

        if matches!(control, Some(TrustedControl::SessionCompleted)) {
            canonical_active_session_id = None;
            events.push(CopilotNativeEvent::SessionCompleted);
        }
    }

    Ok(events)
}

impl CopilotOutputItem {
    pub(crate) fn record_kinds(&self) -> &'static [RecordKind] {
        match self.item_type.as_deref() {
            Some("function_call") if self.message.is_some() => {
                &[RecordKind::ToolCall, RecordKind::ToolResult]
            }
            Some("function_call") => &[RecordKind::ToolCall],
            None | Some("" | "reasoning" | "message") => &[],
            Some(_) => &[RecordKind::Other],
        }
    }

    fn from_value(value: &Value) -> Result<Self, &'static str> {
        let object = value
            .as_object()
            .expect("native schema checked before conversion");
        if object
            .get("type")
            .is_some_and(|value| !matches!(value, Value::Null | Value::String(_)))
        {
            return Err("Copilot output item type must be a string or null");
        }
        let item_type = object
            .get("type")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if !matches!(
            item_type.as_deref(),
            Some("function_call") | Some("message")
        ) {
            return Ok(Self {
                attestation: Ok(SessionMetadata::default()),
                item_type,
                call_id: None,
                name: None,
                arguments: None,
                message: None,
                role: None,
                content_present: false,
                content: None,
            });
        }
        for key in ["id", "call_id", "name", "arguments", "message", "role"] {
            if object
                .get(key)
                .is_some_and(|value| !matches!(value, Value::Null | Value::String(_)))
            {
                return Err("Copilot known output item string field has an invalid type");
            }
        }
        let content = object.get("content");
        Ok(Self {
            attestation: copilot_metadata(value),
            item_type,
            call_id: item_string(value, "call_id"),
            name: item_string(value, "name"),
            arguments: item_string(value, "arguments"),
            message: value
                .get("message")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            role: item_string(value, "role"),
            content_present: content.is_some(),
            content: content
                .and_then(Value::as_array)
                .map(|blocks| blocks.iter().map(CopilotContentBlock::from_value).collect()),
        })
    }
}

#[cfg(test)]
mod tests {
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
}

impl CopilotContentBlock {
    fn from_value(value: &Value) -> Self {
        let Some(object) = value.as_object() else {
            return Self::Unknown;
        };
        match object.get("type").and_then(Value::as_str) {
            Some("output_text") => Self::OutputText {
                text: object
                    .get("text")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            },
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy)]
enum TrustedControl<'a> {
    WorkspaceInitialized { message: &'a str },
    SessionCompleted,
}

fn copilot_trusted_control<'a>(
    line: &'a str,
    accumulated: Option<(&'a str, &'a str)>,
) -> Option<TrustedControl<'a>> {
    let prefix = accumulated.map_or(line, |(prefix, _)| prefix);
    let control_end = prefix
        .find("Accumulated output items")
        .unwrap_or(prefix.len());
    let content = prefix[..control_end].trim_end();
    let message = copilot_log_message(content)?;
    if message.starts_with("Workspace initialized:") && !message.contains(['[', ']', '{', '}']) {
        return Some(TrustedControl::WorkspaceInitialized { message });
    }
    if message == "Session completed." {
        return Some(TrustedControl::SessionCompleted);
    }
    None
}

fn copilot_log_message(line: &str) -> Option<&str> {
    let line = line.trim_start();
    if line.starts_with("Workspace initialized:") || line.starts_with("Session completed.") {
        return Some(line);
    }

    let after_level = if line.starts_with('[') {
        line.find(']')
            .and_then(|end| line.get(end + 1..))
            .map(str::trim_start)
    } else {
        let (_, rest) = line.split_once(char::is_whitespace)?;
        let rest = rest.trim_start();
        if !rest.starts_with('[') {
            return None;
        }
        rest.find(']')
            .and_then(|end| rest.get(end + 1..))
            .map(str::trim_start)
    }?;

    Some(after_level)
}

fn copilot_workspace_session_id(message: &str) -> Option<String> {
    let marker = "Workspace initialized: ";
    let rest = message.strip_prefix(marker)?;
    Some(
        rest.find(' ')
            .map_or_else(|| rest.to_owned(), |end| rest[..end].to_owned()),
    )
}

fn copilot_accumulated_output_array(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('[') && starts_like_json_array(trimmed) {
        let prefix = &line[..line.len() - trimmed.len()];
        return Some((prefix, trimmed));
    }

    let marker = "Accumulated output items";
    let marker_start = line.find(marker)?;
    let after_marker = &line[marker_start + marker.len()..];
    let array_start = after_marker.find('[')?;
    let array_start = marker_start + marker.len() + array_start;
    Some((&line[..array_start], &line[array_start..]))
}

fn starts_like_json_array(value: &str) -> bool {
    let Some(after_opening_bracket) = value.get(1..) else {
        return false;
    };
    match after_opening_bracket.trim_start().chars().next() {
        None | Some(']') | Some('{') | Some('[') | Some('"') | Some('-') | Some('0'..='9')
        | Some('t') | Some('f') | Some('n') => true,
        Some(_) => false,
    }
}

fn copilot_log_timestamp(line: &str) -> Option<String> {
    let token = line.split_whitespace().next()?;
    time::OffsetDateTime::parse(token, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|_| token.to_owned())
}
