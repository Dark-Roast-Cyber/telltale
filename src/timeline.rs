//! Session timeline helpers over the canonical normalized schema.
//!
//! The timeline model is intentionally read-only and side-effect free. It gives
//! detection, triage, and future response code a shared ordered view without
//! changing current detection behavior.

#![allow(dead_code)] // Consumed incrementally as P13 wiring lands.

use std::collections::BTreeMap;

use crate::event::{Event, evidence_hash, redact_sensitive_text};
use crate::schema::NormalizedRecordV1;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TimelineEntryKind {
    UserMessage,
    AssistantMessage,
    ToolCall,
    ToolResult,
    SessionMeta,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimelineEntry {
    /// Stable zero-based order within this assembled timeline.
    pub index: usize,
    pub kind: TimelineEntryKind,
    pub session_id: String,
    pub client: String,
    pub timestamp: Option<String>,
    pub tool_name: Option<String>,
    pub call_id: Option<String>,
    /// Index of the linked tool call/result when the source exposes a call id.
    pub linked_entry_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimelineRuleAnchor {
    pub entry_index: usize,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub evidence_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTimeline {
    pub session_id: String,
    pub entries: Vec<TimelineEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportedSessionTimeline {
    pub event_type: &'static str,
    pub session_id: String,
    pub client: String,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub entry_count: usize,
    pub entries: Vec<ExportedTimelineEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportedTimelineEntry {
    pub index: usize,
    pub timestamp: Option<String>,
    pub event_type: &'static str,
    pub client: String,
    pub tool_name: Option<String>,
    pub call_id: Option<String>,
    pub linked_entry_index: Option<usize>,
    pub evidence: Vec<TimelineEvidenceSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimelineEvidenceSummary {
    pub field: String,
    pub redacted_value: String,
    pub hash: String,
}

impl SessionTimeline {
    /// Returns a bounded context window around an entry index, inclusive.
    pub fn context_window(
        &self,
        anchor_index: usize,
        before: usize,
        after: usize,
    ) -> &[TimelineEntry] {
        if self.entries.is_empty() {
            return &self.entries[0..0];
        }

        let start = anchor_index.saturating_sub(before);
        let end = (anchor_index + after + 1).min(self.entries.len());
        &self.entries[start.min(self.entries.len())..end]
    }

    pub fn anchor_detection_event(&self, event: &Event) -> Vec<TimelineRuleAnchor> {
        if event.event_type != "detection" || event.session_id != self.session_id {
            return Vec::new();
        }

        let evidence_fields = event
            .evidence
            .iter()
            .map(|item| item.field.clone())
            .collect::<Vec<_>>();
        self.entries
            .iter()
            .filter(|entry| {
                event
                    .tool_name
                    .as_deref()
                    .is_some_and(|tool_name| entry.tool_name.as_deref() == Some(tool_name))
                    || evidence_fields
                        .iter()
                        .any(|field| entry_kind_matches_evidence_field(&entry.kind, field))
            })
            .map(|entry| TimelineRuleAnchor {
                entry_index: entry.index,
                rule_ids: event.rule_ids.clone(),
                categories: event.categories.clone(),
                evidence_fields: evidence_fields.clone(),
            })
            .collect()
    }
}

pub fn build_session_timeline(records: &[NormalizedRecordV1]) -> Option<SessionTimeline> {
    let session_id = records.first()?.session_id().to_string();
    let mut entries = records
        .iter()
        .enumerate()
        .map(|(index, record)| timeline_entry(index, record))
        .collect::<Vec<_>>();

    link_tool_pairs(&mut entries);

    Some(SessionTimeline {
        session_id,
        entries,
    })
}

pub fn build_exported_session_timeline(
    records: &[NormalizedRecordV1],
) -> Option<ExportedSessionTimeline> {
    let timeline = build_session_timeline(records)?;
    let first_meta = records.first()?.meta();
    let entries = timeline
        .entries
        .iter()
        .zip(records.iter())
        .map(|(entry, record)| exported_timeline_entry(entry, record))
        .collect::<Vec<_>>();

    Some(ExportedSessionTimeline {
        event_type: "timeline",
        session_id: timeline.session_id,
        client: first_meta.client.clone(),
        agent: first_meta.agent.clone(),
        model: first_meta.model.clone(),
        provider: first_meta.provider.clone(),
        entry_count: entries.len(),
        entries,
    })
}

fn timeline_entry(index: usize, record: &NormalizedRecordV1) -> TimelineEntry {
    let meta = record.meta();
    let (kind, call_id) = match record {
        NormalizedRecordV1::UserMessage(_) => (TimelineEntryKind::UserMessage, None),
        NormalizedRecordV1::AssistantMessage(_) => (TimelineEntryKind::AssistantMessage, None),
        NormalizedRecordV1::ToolCall(call) => (TimelineEntryKind::ToolCall, call.call_id.clone()),
        NormalizedRecordV1::ToolResult(result) => {
            (TimelineEntryKind::ToolResult, result.call_id.clone())
        }
        NormalizedRecordV1::SessionMeta(_) => (TimelineEntryKind::SessionMeta, None),
        NormalizedRecordV1::Other(_) => (TimelineEntryKind::Other, None),
    };

    TimelineEntry {
        index,
        kind,
        session_id: meta.session_id.clone(),
        client: meta.client.clone(),
        timestamp: meta.timestamp.clone(),
        tool_name: record.tool_name().map(ToOwned::to_owned),
        call_id,
        linked_entry_index: None,
    }
}

fn exported_timeline_entry(
    entry: &TimelineEntry,
    record: &NormalizedRecordV1,
) -> ExportedTimelineEntry {
    ExportedTimelineEntry {
        index: entry.index,
        timestamp: entry.timestamp.clone(),
        event_type: exported_entry_type(&entry.kind),
        client: entry.client.clone(),
        tool_name: entry.tool_name.clone(),
        call_id: entry.call_id.clone(),
        linked_entry_index: entry.linked_entry_index,
        evidence: record_evidence(record),
    }
}

fn exported_entry_type(kind: &TimelineEntryKind) -> &'static str {
    match kind {
        TimelineEntryKind::UserMessage => "user_message",
        TimelineEntryKind::AssistantMessage => "assistant_message",
        TimelineEntryKind::ToolCall => "tool_call",
        TimelineEntryKind::ToolResult => "tool_result",
        TimelineEntryKind::SessionMeta => "session_meta",
        TimelineEntryKind::Other => "other",
    }
}

fn record_evidence(record: &NormalizedRecordV1) -> Vec<TimelineEvidenceSummary> {
    match record {
        NormalizedRecordV1::UserMessage(message) => {
            evidence_vec_from_value("user_context", &message.content)
        }
        NormalizedRecordV1::AssistantMessage(message) => {
            evidence_vec_from_value("assistant_context", &message.content)
        }
        NormalizedRecordV1::ToolCall(call) => {
            let mut evidence = Vec::new();
            evidence.push(redacted_evidence("tool_name", &call.tool_name));
            if let Some(arguments) = call.arguments_string.as_deref() {
                evidence.push(redacted_evidence("arguments", arguments));
            } else if let Some(arguments) = call.arguments.as_ref() {
                evidence.push(redacted_evidence("arguments", &arguments.to_string()));
            }
            evidence
        }
        NormalizedRecordV1::ToolResult(result) => {
            let mut evidence = Vec::new();
            if let Some(tool_name) = result.tool_name.as_deref() {
                evidence.push(redacted_evidence("tool_name", tool_name));
            }
            if let Some(result_string) = result.result_string.as_deref() {
                evidence.push(redacted_evidence("tool_result", result_string));
            } else if let Some(result_value) = result.result.as_ref() {
                evidence.push(redacted_evidence("tool_result", &result_value.to_string()));
            }
            evidence
        }
        NormalizedRecordV1::SessionMeta(session) => {
            let mut evidence = Vec::new();
            if let Some(workspace) = session.workspace.as_deref() {
                evidence.push(redacted_evidence("workspace", workspace));
            }
            evidence
        }
        NormalizedRecordV1::Other(other) => {
            evidence_vec_from_value("source_context", &other.content)
        }
    }
}

fn evidence_vec_from_value(field: &str, value: &str) -> Vec<TimelineEvidenceSummary> {
    if value.trim().is_empty() {
        Vec::new()
    } else {
        vec![redacted_evidence(field, value)]
    }
}

fn redacted_evidence(field: &str, value: &str) -> TimelineEvidenceSummary {
    TimelineEvidenceSummary {
        field: field.to_string(),
        redacted_value: redact_sensitive_text(value),
        hash: evidence_hash(value),
    }
}

fn link_tool_pairs(entries: &mut [TimelineEntry]) {
    let mut calls_by_id = BTreeMap::new();
    let mut links = Vec::new();

    for entry in entries.iter() {
        let Some(call_id) = entry.call_id.as_ref() else {
            continue;
        };

        match entry.kind {
            TimelineEntryKind::ToolCall => {
                calls_by_id.entry(call_id.clone()).or_insert(entry.index);
            }
            TimelineEntryKind::ToolResult => {
                if let Some(call_index) = calls_by_id.get(call_id) {
                    links.push((*call_index, entry.index));
                }
            }
            _ => {}
        }
    }

    for (call_index, result_index) in links {
        if let Some(call) = entries.get_mut(call_index) {
            call.linked_entry_index = Some(result_index);
        }
        if let Some(result) = entries.get_mut(result_index) {
            result.linked_entry_index = Some(call_index);
        }
    }
}

fn entry_kind_matches_evidence_field(kind: &TimelineEntryKind, field: &str) -> bool {
    matches!(
        (kind, field),
        (TimelineEntryKind::AssistantMessage, "assistant_context")
            | (TimelineEntryKind::UserMessage, "user_context")
            | (TimelineEntryKind::ToolCall, "command")
            | (TimelineEntryKind::ToolCall, "arguments")
            | (TimelineEntryKind::ToolCall, "file_path")
            | (TimelineEntryKind::ToolCall, "url")
            | (TimelineEntryKind::ToolCall, "tool_name")
            | (TimelineEntryKind::ToolResult, "tool_result")
            | (TimelineEntryKind::ToolResult, "file_path")
            | (TimelineEntryKind::ToolResult, "url")
            | (TimelineEntryKind::ToolResult, "tool_name")
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::event::{Event, Evidence};
    use crate::schema::{
        ConversationMessage, Provenance, RecordMeta, ToolCallRecord, ToolResultRecord,
    };

    use super::*;

    fn meta(timestamp: &str) -> RecordMeta {
        RecordMeta {
            session_id: "session-a".to_string(),
            client: "codex".to_string(),
            agent: Some("codex".to_string()),
            model: Some("gpt-5".to_string()),
            provider: Some("openai".to_string()),
            timestamp: Some(timestamp.to_string()),
            provenance: Provenance {
                source_path_hash: "sha256:fixture".to_string(),
                source_event_id: None,
                offset: None,
            },
            extensions: BTreeMap::new(),
        }
    }

    fn user_message(timestamp: &str) -> NormalizedRecordV1 {
        NormalizedRecordV1::UserMessage(ConversationMessage {
            meta: meta(timestamp),
            content: "check status".to_string(),
            content_parts: None,
        })
    }

    fn assistant_message(timestamp: &str) -> NormalizedRecordV1 {
        NormalizedRecordV1::AssistantMessage(ConversationMessage {
            meta: meta(timestamp),
            content: "I will inspect the working tree.".to_string(),
            content_parts: None,
        })
    }

    fn tool_call(timestamp: &str, call_id: Option<&str>) -> NormalizedRecordV1 {
        NormalizedRecordV1::ToolCall(ToolCallRecord {
            meta: meta(timestamp),
            tool_name: "shell".to_string(),
            arguments: None,
            arguments_string: Some("git status --short".to_string()),
            call_id: call_id.map(ToOwned::to_owned),
        })
    }

    fn tool_result(timestamp: &str, call_id: Option<&str>) -> NormalizedRecordV1 {
        NormalizedRecordV1::ToolResult(ToolResultRecord {
            meta: meta(timestamp),
            tool_name: Some("shell".to_string()),
            result: None,
            result_string: Some("clean".to_string()),
            call_id: call_id.map(ToOwned::to_owned),
            is_error: Some(false),
        })
    }

    fn detection_event(session_id: &str, tool_name: Option<&str>, field: &str) -> Event {
        Event {
            timestamp: "2026-05-09T00:00:03Z".to_string(),
            event_time: Some("2026-05-09T00:00:03Z".to_string()),
            observed_at: "2026-05-09T00:00:03Z".to_string(),
            ingested_at: "2026-05-09T00:00:03Z".to_string(),
            time_source: "source".to_string(),
            time_confidence: "high".to_string(),
            time_override_reason: None,
            schema_version: "1.0".to_string(),
            event_id: "adr-test".to_string(),
            event_type: "detection".to_string(),
            severity: "critical".to_string(),
            risk_score: 90,
            client: "codex".to_string(),
            agent: Some("codex".to_string()),
            model: Some("gpt-5".to_string()),
            provider: Some("openai".to_string()),
            session_id: session_id.to_string(),
            workspace: None,
            source_path_hash: Some("sha256:fixture".to_string()),
            tool_name: tool_name.map(ToOwned::to_owned),
            rule_ids: vec!["mcp.tool_metadata.prompt_injection".to_string()],
            categories: vec!["mcp_prompt_injection".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: vec!["atlas:AML.T0051".to_string()],
            tags: vec!["mcp".to_string()],
            evidence: vec![Evidence {
                field: field.to_string(),
                redacted_value: "[REDACTED]".to_string(),
                hash: Some("sha256:evidence".to_string()),
                rule_id: Some("mcp.tool_metadata.prompt_injection".to_string()),
            }],
            triage: None,
            response: None,
            source_counts: None,
            component: None,
            check_name: None,
            status: None,
            adr_version: None,
            scan_duration_ms: None,
            rule_count: None,
            threshold_config: None,
            active_policy_name: None,
            emitted_count: None,
            suppressed_count: None,
            scanner_error_count: None,
        }
    }

    #[test]
    fn builds_ordered_timeline_entries_from_canonical_records() {
        let records = vec![
            user_message("2026-05-09T00:00:00Z"),
            tool_call("2026-05-09T00:00:01Z", None),
            tool_result("2026-05-09T00:00:02Z", None),
        ];

        let timeline = build_session_timeline(&records).expect("timeline");

        assert_eq!(timeline.session_id, "session-a");
        assert_eq!(timeline.entries.len(), 3);
        assert_eq!(timeline.entries[0].index, 0);
        assert_eq!(timeline.entries[0].kind, TimelineEntryKind::UserMessage);
        assert_eq!(timeline.entries[1].kind, TimelineEntryKind::ToolCall);
        assert_eq!(timeline.entries[1].tool_name.as_deref(), Some("shell"));
        assert_eq!(timeline.entries[2].kind, TimelineEntryKind::ToolResult);
    }

    #[test]
    fn links_tool_call_and_result_when_call_id_is_available() {
        let records = vec![
            tool_call("2026-05-09T00:00:01Z", Some("call-1")),
            tool_result("2026-05-09T00:00:02Z", Some("call-1")),
        ];

        let timeline = build_session_timeline(&records).expect("timeline");

        assert_eq!(timeline.entries[0].linked_entry_index, Some(1));
        assert_eq!(timeline.entries[1].linked_entry_index, Some(0));
    }

    #[test]
    fn leaves_tool_pairs_unlinked_without_explicit_call_id() {
        let records = vec![
            tool_call("2026-05-09T00:00:01Z", None),
            tool_result("2026-05-09T00:00:02Z", None),
        ];

        let timeline = build_session_timeline(&records).expect("timeline");

        assert_eq!(timeline.entries[0].linked_entry_index, None);
        assert_eq!(timeline.entries[1].linked_entry_index, None);
    }

    #[test]
    fn returns_bounded_context_window_around_anchor() {
        let records = vec![
            user_message("2026-05-09T00:00:00Z"),
            tool_call("2026-05-09T00:00:01Z", Some("call-1")),
            tool_result("2026-05-09T00:00:02Z", Some("call-1")),
        ];
        let timeline = build_session_timeline(&records).expect("timeline");

        let window = timeline.context_window(1, 1, 1);

        assert_eq!(window.len(), 3);
        assert_eq!(window[0].kind, TimelineEntryKind::UserMessage);
        assert_eq!(window[1].kind, TimelineEntryKind::ToolCall);
        assert_eq!(window[2].kind, TimelineEntryKind::ToolResult);
    }

    #[test]
    fn anchors_detection_events_to_matching_timeline_entries() {
        let records = vec![
            user_message("2026-05-09T00:00:00Z"),
            tool_call("2026-05-09T00:00:01Z", Some("call-1")),
            tool_result("2026-05-09T00:00:02Z", Some("call-1")),
        ];
        let timeline = build_session_timeline(&records).expect("timeline");
        let event = detection_event("session-a", Some("shell"), "tool_result");

        let anchors = timeline.anchor_detection_event(&event);

        assert_eq!(anchors.len(), 2);
        assert_eq!(anchors[0].entry_index, 1);
        assert_eq!(anchors[0].rule_ids, event.rule_ids);
        assert_eq!(anchors[1].entry_index, 2);
        assert_eq!(anchors[1].evidence_fields, vec!["tool_result"]);
    }

    #[test]
    fn ignores_detection_events_for_other_sessions() {
        let records = vec![tool_result("2026-05-09T00:00:02Z", Some("call-1"))];
        let timeline = build_session_timeline(&records).expect("timeline");
        let event = detection_event("session-b", None, "tool_result");

        assert!(timeline.anchor_detection_event(&event).is_empty());
    }

    #[test]
    fn builds_exported_timeline_from_canonical_records() {
        let mut sensitive_call = tool_call("2026-05-09T00:00:02Z", Some("call-1"));
        if let NormalizedRecordV1::ToolCall(call) = &mut sensitive_call {
            call.arguments_string =
                Some("cat /home/example/project/.env && echo sk-1234567890abcdef1234".into());
        }
        let records = vec![
            user_message("2026-05-09T00:00:00Z"),
            assistant_message("2026-05-09T00:00:01Z"),
            sensitive_call,
            tool_result("2026-05-09T00:00:03Z", Some("call-1")),
        ];

        let exported = build_exported_session_timeline(&records).expect("exported timeline");

        assert_eq!(exported.event_type, "timeline");
        assert_eq!(exported.session_id, "session-a");
        assert_eq!(exported.client, "codex");
        assert_eq!(exported.agent.as_deref(), Some("codex"));
        assert_eq!(exported.model.as_deref(), Some("gpt-5"));
        assert_eq!(exported.provider.as_deref(), Some("openai"));
        assert_eq!(exported.entry_count, 4);
        assert_eq!(exported.entries[0].event_type, "user_message");
        assert_eq!(exported.entries[1].event_type, "assistant_message");
        assert_eq!(exported.entries[2].event_type, "tool_call");
        assert_eq!(exported.entries[3].event_type, "tool_result");
        assert_eq!(exported.entries[2].linked_entry_index, Some(3));
        assert_eq!(exported.entries[3].linked_entry_index, Some(2));

        let arguments = exported.entries[2]
            .evidence
            .iter()
            .find(|item| item.field == "arguments")
            .expect("arguments evidence");
        assert!(arguments.hash.len() >= 64);
        assert!(!arguments.redacted_value.contains("/home/example"));
        assert!(!arguments.redacted_value.contains(".env"));
        assert!(!arguments.redacted_value.contains("sk-1234567890abcdef1234"));
        assert!(arguments.redacted_value.contains("[redacted-secret]"));
    }
}
