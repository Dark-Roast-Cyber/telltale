#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;

use serde_json::Value;

use crate::parser::{
    ParseError, default_source_file_stem, model_field, provider_field, string_field,
};
use telltale_schema::clients::ClientId;
use telltale_schema::source::Source;

pub(crate) enum CopilotNativeEvent {
    WorkspaceInitialized {
        legacy_session_id: String,
        source_session_id: Option<String>,
        timestamp: Option<String>,
        content: String,
    },
    AccumulatedOutputItem {
        legacy_session_id: String,
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
    pub(crate) item_type: Option<String>,
    pub(crate) id: Option<String>,
    pub(crate) call_id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) arguments: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) content_present: bool,
    pub(crate) content: Option<Vec<CopilotContentBlock>>,
}

pub(crate) enum CopilotContentBlock {
    OutputText { text: Option<String> },
    Unknown,
}

pub(crate) fn extract_copilot_native_events(
    source: &Source,
) -> Result<Vec<CopilotNativeEvent>, ParseError> {
    let raw = fs::read_to_string(&source.path)?;
    let mut events = Vec::new();
    let mut legacy_effective_session_id = default_source_file_stem(source);
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
            && let Some(TrustedControl::WorkspaceInitialized {
                message, content, ..
            }) = control
        {
            let source_session_id = copilot_workspace_session_id(message);
            if let Some(session_id) = &source_session_id {
                legacy_effective_session_id = session_id.clone();
            }
            canonical_active_session_id = source_session_id.clone();
            events.push(CopilotNativeEvent::WorkspaceInitialized {
                legacy_session_id: legacy_effective_session_id.clone(),
                source_session_id,
                timestamp,
                content: content.to_owned(),
            });
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

        if let Some(TrustedControl::WorkspaceInitialized {
            message, content, ..
        }) = control
        {
            let source_session_id = copilot_workspace_session_id(message);
            if let Some(session_id) = &source_session_id {
                legacy_effective_session_id = session_id.clone();
            }
            canonical_active_session_id = source_session_id.clone();
            events.push(CopilotNativeEvent::WorkspaceInitialized {
                legacy_session_id: legacy_effective_session_id.clone(),
                source_session_id,
                timestamp: timestamp.clone(),
                content: content.to_owned(),
            });
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
            return Err(ParseError::SchemaDrift {
                client: ClientId::Copilot,
                source_id: source.source_id.clone(),
                detail: "Copilot accumulated output items must be objects",
            });
        }

        for item in items {
            let item = CopilotOutputItem::from_value(&item);
            let ordinal = canonical_active_session_id.as_ref().map(|session_id| {
                let ordinal = item_ordinals.entry(session_id.clone()).or_default();
                let current = *ordinal;
                *ordinal += 1;
                current
            });
            events.push(CopilotNativeEvent::AccumulatedOutputItem {
                legacy_session_id: legacy_effective_session_id.clone(),
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
    fn from_value(value: &Value) -> Self {
        let object = value
            .as_object()
            .expect("native schema checked before conversion");
        let item_type = object
            .get("type")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if !matches!(
            item_type.as_deref(),
            Some("function_call") | Some("message")
        ) {
            return Self {
                item_type,
                id: None,
                call_id: None,
                name: None,
                arguments: None,
                message: None,
                model: None,
                provider: None,
                role: None,
                content_present: false,
                content: None,
            };
        }
        let content = object.get("content");
        Self {
            item_type,
            id: string_field(value, "id"),
            call_id: string_field(value, "call_id"),
            name: string_field(value, "name"),
            arguments: string_field(value, "arguments"),
            message: string_field(value, "message"),
            model: model_field(value),
            provider: provider_field(value),
            role: string_field(value, "role"),
            content_present: content.is_some(),
            content: content
                .and_then(Value::as_array)
                .map(|blocks| blocks.iter().map(CopilotContentBlock::from_value).collect()),
        }
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
        assert!(reasoning.id.is_none());
        assert!(reasoning.call_id.is_none());
        assert!(reasoning.name.is_none());
        assert!(reasoning.arguments.is_none());
        assert!(reasoning.message.is_none());
        assert!(reasoning.model.is_none());
        assert!(reasoning.provider.is_none());
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
            assert!(item.id.is_none());
            assert!(item.call_id.is_none());
            assert!(item.name.is_none());
            assert!(item.arguments.is_none());
            assert!(item.message.is_none());
            assert!(item.model.is_none());
            assert!(item.provider.is_none());
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
    WorkspaceInitialized { message: &'a str, content: &'a str },
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
        return Some(TrustedControl::WorkspaceInitialized { message, content });
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
