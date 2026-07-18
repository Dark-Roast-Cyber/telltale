use std::fs;

use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::discovery::Source;
use crate::parser::{
    ParseError, ParsedRecord, RecordKind, model_field, provider_field, string_field,
};

pub(crate) fn extract_copilot_process_log(
    source: &Source,
) -> Result<Vec<ParsedRecord>, ParseError> {
    let raw = fs::read_to_string(&source.path)?;
    let mut records = Vec::new();
    let mut session_id = source
        .path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let timestamp = copilot_log_timestamp(line);

        // Extract session ID from "Workspace initialized: <uuid>" lines
        if line.contains("Workspace initialized:") {
            if let Some(start) = line.find("Workspace initialized: ") {
                let rest = &line[start + "Workspace initialized: ".len()..];
                if let Some(end) = rest.find(' ') {
                    session_id = rest[..end].to_string();
                } else {
                    session_id = rest.to_string();
                }
            }
            records.push(ParsedRecord {
                session_id: session_id.clone(),
                agent: Some("copilot".to_string()),
                model: None,
                provider: Some("github".to_string()),
                timestamp: timestamp.clone(),
                kind: RecordKind::SessionMeta,
                tool_name: None,
                arguments: None,
                content: line.to_string(),
            });
            continue;
        }

        // Parse JSON arrays containing function_call entries
        if let Some(json_start) = line.find("[{") {
            let json_str = &line[json_start..];
            if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json_str) {
                for item in &items {
                    let item_type = item.get("type").and_then(Value::as_str).unwrap_or("");
                    if item_type == "function_call" {
                        let tool_name =
                            string_field(item, "name").unwrap_or_else(|| "unknown".to_string());
                        let arguments = string_field(item, "arguments");
                        let model = model_field(item);
                        let provider = provider_field(item).or_else(|| Some("github".to_string()));
                        let call_id = string_field(item, "call_id").unwrap_or_default();
                        let content =
                            format!("function_call: {} (call_id: {})", tool_name, call_id);
                        records.push(ParsedRecord {
                            session_id: session_id.clone(),
                            agent: Some("copilot".to_string()),
                            model: model.clone(),
                            provider: provider.clone(),
                            timestamp: timestamp.clone(),
                            kind: RecordKind::ToolCall,
                            tool_name: Some(tool_name.clone()),
                            arguments: arguments.clone(),
                            content,
                        });
                        // If the function_call has a "message" field, emit it as a ToolResult
                        if let Some(message) = string_field(item, "message") {
                            records.push(ParsedRecord {
                                session_id: session_id.clone(),
                                agent: Some("copilot".to_string()),
                                model,
                                provider,
                                timestamp: timestamp.clone(),
                                kind: RecordKind::ToolResult,
                                tool_name: Some(tool_name),
                                arguments,
                                content: message,
                            });
                        }
                    }
                }
            }
        }
    }

    if records.is_empty() {
        return Err(ParseError::Empty);
    }
    Ok(records)
}

fn copilot_log_timestamp(line: &str) -> Option<String> {
    let token = line.split_whitespace().next()?;
    OffsetDateTime::parse(token, &Rfc3339)
        .ok()
        .map(|_| token.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use crate::clients::{ClientId, SourceKind};
    use crate::discovery::discover_sources;
    use crate::parser::{ParseError, RecordKind, parse_source_records};

    #[test]
    fn parses_copilot_function_call_model_and_provider_fields() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("process-model-provider.log");
        fs::write(
            &log_path,
            r#"2026-04-27T16:16:57.841Z [INFO] Workspace initialized: copilot-model-session (checkpoints: 0)
2026-04-27T16:17:17.990Z [INFO] Accumulated output items (1): [{"arguments":"{\"path\":\"README.md\"}","call_id":"call_fixture_003","id":"c3","model":"gpt-4.1","name":"view","provider":"github-copilot","status":"completed","type":"function_call","message":"Synthetic README excerpt"}]
"#,
        )
        .expect("write copilot fixture");
        let source = crate::discovery::Source {
            client: ClientId::Copilot,
            kind: SourceKind::CopilotProcessLog,
            source_id: "copilot.model_provider".to_string(),
            path: log_path,
        };

        let records = parse_source_records(&source).expect("records");
        let tool_call = records
            .iter()
            .find(|record| record.kind == RecordKind::ToolCall)
            .expect("tool call");
        let tool_result = records
            .iter()
            .find(|record| record.kind == RecordKind::ToolResult)
            .expect("tool result");

        assert_eq!(records.len(), 3);
        assert_eq!(tool_call.session_id, "copilot-model-session");
        assert_eq!(tool_call.tool_name.as_deref(), Some("view"));
        assert_eq!(
            tool_call.arguments.as_deref(),
            Some("{\"path\":\"README.md\"}")
        );
        assert_eq!(tool_call.model.as_deref(), Some("gpt-4.1"));
        assert_eq!(tool_call.provider.as_deref(), Some("github-copilot"));
        assert_eq!(tool_result.model.as_deref(), Some("gpt-4.1"));
        assert_eq!(tool_result.provider.as_deref(), Some("github-copilot"));
    }

    #[test]
    fn parses_copilot_rfc3339_log_prefix_timestamps() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("process-timestamps.log");
        fs::write(
            &log_path,
            r#"2026-04-27T16:16:57.847Z [INFO] Workspace initialized: copilot-timestamp-info (checkpoints: 0)
2026-04-27T16:17:17Z Workspace initialized: copilot-timestamp-token (checkpoints: 0)
not-a-timestamp [INFO] Workspace initialized: copilot-timestamp-malformed (checkpoints: 0)
"#,
        )
        .expect("write copilot fixture");
        let source = crate::discovery::Source {
            client: ClientId::Copilot,
            kind: SourceKind::CopilotProcessLog,
            source_id: "copilot.timestamps".to_string(),
            path: log_path,
        };

        let records = parse_source_records(&source).expect("records");

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].session_id, "copilot-timestamp-info");
        assert_eq!(
            records[0].timestamp.as_deref(),
            Some("2026-04-27T16:16:57.847Z")
        );
        assert_eq!(records[1].session_id, "copilot-timestamp-token");
        assert_eq!(
            records[1].timestamp.as_deref(),
            Some("2026-04-27T16:17:17Z")
        );
        assert_eq!(records[2].session_id, "copilot-timestamp-malformed");
        assert_eq!(records[2].timestamp, None);
    }

    #[test]
    fn parses_copilot_multi_session_process_log_boundaries() {
        let source = discover_sources(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/session_stores"
        )))
        .into_iter()
        .find(|source| {
            source.client == ClientId::Copilot
                && source.kind == SourceKind::CopilotProcessLog
                && source.path.file_name().and_then(|name| name.to_str())
                    == Some("process-multi-session.log")
        })
        .expect("fixture source");

        let records = parse_source_records(&source).expect("records");
        let tool_calls = records
            .iter()
            .filter(|record| record.kind == RecordKind::ToolCall)
            .collect::<Vec<_>>();

        assert_eq!(records.len(), 4);
        assert_eq!(records[0].kind, RecordKind::SessionMeta);
        assert_eq!(records[0].session_id, "copilot-multi-session-a");
        assert_eq!(tool_calls.len(), 2);
        assert_eq!(tool_calls[0].session_id, "copilot-multi-session-a");
        assert_eq!(tool_calls[0].tool_name.as_deref(), Some("view"));
        assert_eq!(tool_calls[1].session_id, "copilot-multi-session-b");
        assert_eq!(tool_calls[1].tool_name.as_deref(), Some("run_in_terminal"));
    }

    #[test]
    fn parses_copilot_mixed_format_process_log_items() {
        let source = discover_sources(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/session_stores"
        )))
        .into_iter()
        .find(|source| {
            source.client == ClientId::Copilot
                && source.kind == SourceKind::CopilotProcessLog
                && source.path.file_name().and_then(|name| name.to_str())
                    == Some("process-mixed-format.log")
        })
        .expect("fixture source");

        let records = parse_source_records(&source).expect("records");
        let tool_calls = records
            .iter()
            .filter(|record| record.kind == RecordKind::ToolCall)
            .collect::<Vec<_>>();
        let tool_results = records
            .iter()
            .filter(|record| record.kind == RecordKind::ToolResult)
            .collect::<Vec<_>>();

        assert_eq!(records.len(), 4);
        assert_eq!(records[0].kind, RecordKind::SessionMeta);
        assert_eq!(records[0].session_id, "copilot-mixed-format-session");
        assert_eq!(tool_calls.len(), 2);
        assert!(tool_calls.iter().all(|record| {
            record.session_id == "copilot-mixed-format-session"
                && record.tool_name.as_deref() == Some("view")
        }));
        assert_eq!(tool_results.len(), 1);
        assert_eq!(tool_results[0].tool_name.as_deref(), Some("view"));
        assert_eq!(tool_results[0].content, "Synthetic Cargo manifest excerpt");
    }

    #[test]
    fn parses_copilot_uc001_tool_result_fixture() {
        let source = discover_sources(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/session_stores"
        )))
        .into_iter()
        .find(|source| {
            source.client == ClientId::Copilot
                && source.kind == SourceKind::CopilotProcessLog
                && source.path.file_name().and_then(|name| name.to_str())
                    == Some("process-uc001.log")
        })
        .expect("fixture source");

        let records = parse_source_records(&source).expect("records");
        let tool_calls = records
            .iter()
            .filter(|record| record.kind == RecordKind::ToolCall)
            .collect::<Vec<_>>();
        let tool_result = records
            .iter()
            .find(|record| record.kind == RecordKind::ToolResult)
            .expect("tool result");

        assert_eq!(records.len(), 4);
        assert_eq!(records[0].kind, RecordKind::SessionMeta);
        assert_eq!(records[0].session_id, "copilot-uc001-tool-result");
        assert_eq!(tool_calls.len(), 2);
        assert!(tool_calls.iter().all(|record| {
            record.session_id == "copilot-uc001-tool-result"
                && record.tool_name.as_deref() == Some("repo_status")
        }));
        assert_eq!(tool_result.session_id, "copilot-uc001-tool-result");
        assert_eq!(tool_result.tool_name.as_deref(), Some("repo_status"));
        assert!(tool_result.content.contains("darkroastcyber.io/mcp-lab"));
    }

    #[test]
    fn rejects_empty_copilot_process_log() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("process-empty.log");
        fs::write(&log_path, "\n\n").expect("write empty copilot fixture");
        let source = crate::discovery::Source {
            client: ClientId::Copilot,
            kind: SourceKind::CopilotProcessLog,
            source_id: "copilot.empty".to_string(),
            path: log_path,
        };

        let error = parse_source_records(&source).expect_err("empty log should fail");

        assert!(matches!(error, ParseError::Empty));
    }

    #[test]
    fn ignores_truncated_copilot_json_without_tool_records() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("process-truncated.log");
        fs::write(
            &log_path,
            r#"2026-04-27T16:16:57.841Z [INFO] Workspace initialized: copilot-truncated-session (checkpoints: 0)
2026-04-27T16:17:17.990Z [INFO] Accumulated output items (1): [{"arguments":"{\"path\":\"README.md\"}","call_id":"call_fixture_004","name":"view","type":"function_call"
"#,
        )
        .expect("write truncated copilot fixture");
        let source = crate::discovery::Source {
            client: ClientId::Copilot,
            kind: SourceKind::CopilotProcessLog,
            source_id: "copilot.truncated".to_string(),
            path: log_path,
        };

        let records = parse_source_records(&source).expect("workspace metadata should parse");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].session_id, "copilot-truncated-session");
        assert_eq!(records[0].kind, RecordKind::SessionMeta);
        assert!(
            records
                .iter()
                .all(|record| record.kind != RecordKind::ToolCall
                    && record.kind != RecordKind::ToolResult)
        );
    }
}
