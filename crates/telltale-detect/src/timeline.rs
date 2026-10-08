//! Content-free session timeline projected from canonical observations.
//!
//! The timeline is read-only and side-effect free; local investigation uses it
//! to expose ordering, safe tool labels, and call/result links without content.

use std::collections::BTreeMap;

use serde::Serialize;
use telltale_schema::event::{
    opaque_identifier, parse_event_timestamp, terminal_identifier, terminal_session_id,
};

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

/// Content-free investigation bridge from the authoritative native canonical
/// path. Unlike transcript export, it never constructs evidence summaries (even
/// redacted prose is record content). The existing exported timeline contract
/// remains unchanged; empty evidence is intentional for this surface.
pub fn build_content_free_canonical_timeline(
    observations: &[telltale_schema::observation::CanonicalObservationV2],
    client: &str,
) -> Option<ExportedSessionTimeline> {
    use telltale_schema::observation::{MessageRole, ObservationBody, ObservationStage};
    let session = observations.first()?.session_id()?.value();
    let mut entries = Vec::new();
    for (index, observation) in observations.iter().enumerate() {
        if observation.session_id()?.value() != session {
            return None;
        }
        let (kind, tool_name, call_id) = match observation.body() {
            ObservationBody::Message(message) => (
                match message.role() {
                    Some(MessageRole::User) => TimelineEntryKind::UserMessage,
                    Some(MessageRole::Assistant) => TimelineEntryKind::AssistantMessage,
                    _ => TimelineEntryKind::Other,
                },
                None,
                None,
            ),
            ObservationBody::Tool(tool) => (
                if observation.stage() == ObservationStage::ToolResultReturned {
                    TimelineEntryKind::ToolResult
                } else {
                    TimelineEntryKind::ToolCall
                },
                tool.name().map(ToOwned::to_owned),
                observation
                    .correlation()
                    .call_id()
                    .map(|id| id.value().to_owned()),
            ),
            ObservationBody::Session(_) => (TimelineEntryKind::SessionMeta, None, None),
            _ => (TimelineEntryKind::Other, None, None),
        };
        entries.push(TimelineEntry {
            index,
            kind,
            session_id: session.to_owned(),
            client: client.to_owned(),
            timestamp: observation.occurred_at().map(|v| v.as_str().to_owned()),
            tool_name,
            call_id,
            linked_entry_index: None,
        });
    }
    // Only one call and one later result may link. Repeated lifecycle stages or
    // reused call IDs are not guessed into pairs.
    let mut counts = BTreeMap::<&str, (usize, usize)>::new();
    for entry in &entries {
        if let Some(id) = entry.call_id.as_deref() {
            let count = counts.entry(id).or_default();
            match entry.kind {
                TimelineEntryKind::ToolCall => count.0 += 1,
                TimelineEntryKind::ToolResult => count.1 += 1,
                _ => {}
            }
        }
    }
    let ambiguous = counts
        .into_iter()
        .filter(|(_, v)| *v != (1, 1))
        .map(|(k, _)| k.to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    link_tool_pairs(&mut entries);
    for entry in &mut entries {
        if entry
            .call_id
            .as_ref()
            .is_some_and(|id| ambiguous.contains(id))
        {
            entry.linked_entry_index = None;
        }
    }
    let entries = entries
        .into_iter()
        .map(|entry| ExportedTimelineEntry {
            index: entry.index,
            timestamp: entry.timestamp.as_deref().map(terminal_timeline_timestamp),
            event_type: exported_entry_type(&entry.kind),
            client: terminal_identifier("client", client),
            tool_name: entry
                .tool_name
                .as_deref()
                .map(|v| terminal_identifier("tool", v)),
            call_id: entry
                .call_id
                .as_deref()
                .map(|v| opaque_identifier("call", v)),
            linked_entry_index: entry.linked_entry_index,
            evidence: Vec::new(),
        })
        .collect::<Vec<_>>();
    Some(ExportedSessionTimeline {
        event_type: "timeline",
        session_id: terminal_session_id(session),
        client: terminal_identifier("client", client),
        agent: None,
        model: None,
        provider: None,
        entry_count: entries.len(),
        entries,
    })
}

fn terminal_timeline_timestamp(value: &str) -> String {
    if parse_event_timestamp(value).is_some() {
        value.to_string()
    } else {
        opaque_identifier("invalid-timestamp", value)
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
