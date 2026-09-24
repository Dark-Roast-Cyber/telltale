use std::collections::HashMap;

use crate::timeline::{TimelineRuleAnchor, build_session_timeline};
#[cfg(all(test, feature = "source-io"))]
use telltale_rules::load_default_rule_set;
use telltale_rules::{CompiledRuleSet, MatchResult};
use telltale_schema::canonical::{NormalizedRecordV1, Provenance};
#[cfg(all(test, feature = "source-io"))]
use telltale_schema::event::scanner_error_event;
use telltale_schema::event::{DetectionEventInput, Event, parse_event_timestamp, path_hash};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::source::Source;
#[cfg(all(test, feature = "source-io"))]
use telltale_sources::parser::{ParseError, parse_source_records};

#[cfg(all(test, feature = "source-io"))]
#[allow(dead_code)]
pub fn detect_sources(sources: &[Source]) -> Vec<(Source, Event)> {
    let rule_set = load_default_rule_set().expect("rule set");
    detect_sources_with_rules(sources, &rule_set)
}

#[cfg(all(test, feature = "source-io"))]
pub fn detect_sources_with_rules(
    sources: &[Source],
    rule_set: &CompiledRuleSet,
) -> Vec<(Source, Event)> {
    sources
        .iter()
        .flat_map(|source| {
            detect_source(source, rule_set)
                .into_iter()
                .map(|event| (source.clone(), event))
        })
        .collect()
}

#[cfg(all(test, feature = "source-io"))]
fn detect_source(source: &Source, rule_set: &telltale_rules::CompiledRuleSet) -> Vec<Event> {
    let parsed = match parse_source_records(source) {
        Ok(records) => records,
        Err(ParseError::Empty) => return vec![],
        Err(e) => return vec![scanner_error_event(source, &e)],
    };

    detect_parsed_source_records(source, rule_set, &parsed)
}

pub fn detect_parsed_source_records(
    source: &Source,
    rule_set: &telltale_rules::CompiledRuleSet,
    parsed: &[NormalizedRecord],
) -> Vec<Event> {
    let sessions = group_records_by_session(parsed.to_vec());
    let mut events = Vec::new();

    for (_, records) in sessions {
        match detect_records(source, rule_set, &records) {
            Ok(Some(event)) => events.push(event),
            Ok(None) => {}
            Err(error) => events.push(telltale_schema::event::scanner_error_event(source, &error)),
        }
    }

    events
}

fn group_records_by_session(parsed: Vec<NormalizedRecord>) -> Vec<(String, Vec<NormalizedRecord>)> {
    let mut map: HashMap<String, Vec<NormalizedRecord>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for record in parsed {
        let sid = record.session_id.clone();
        if !map.contains_key(&sid) {
            order.push(sid.clone());
        }
        map.entry(sid).or_default().push(record);
    }
    order
        .into_iter()
        .map(|sid| {
            let records = map.remove(&sid).unwrap_or_default();
            (sid, records)
        })
        .collect()
}

fn detect_records(
    source: &Source,
    rule_set: &telltale_rules::CompiledRuleSet,
    parsed: &[NormalizedRecord],
) -> Result<Option<Event>, telltale_schema::scoring::RiskAccountingError> {
    detect_records_with_timeline(source, rule_set, parsed)
        .map(|analysis| analysis.map(DetectionAnalysis::into_event))
}

pub fn evaluate_session_matches(
    rule_set: &CompiledRuleSet,
    parsed: &[NormalizedRecord],
) -> Result<Option<MatchResult>, telltale_schema::scoring::RiskAccountingError> {
    let fields = legacy_evaluation_fields(parsed);
    rule_set.evaluate(&fields)
}

/// Builds the exact legacy field view used by session evaluation.
fn legacy_evaluation_fields(parsed: &[NormalizedRecord]) -> Vec<(&str, &str)> {
    parsed
        .iter()
        .flat_map(|record| {
            let context = context_fields(record);
            [
                ("assistant_context", context.assistant_context),
                ("user_context", context.user_context),
                ("tool_result", context.tool_result),
                ("command", context.command),
                ("arguments", record.arguments.as_deref().unwrap_or_default()),
                ("file_path", context.file_path),
                ("url", context.url),
                ("tool_name", record.tool_name.as_deref().unwrap_or_default()),
            ]
        })
        .collect()
}

struct DetectionAnalysis {
    event: Event,
    timeline_anchors: Vec<TimelineRuleAnchor>,
}

impl DetectionAnalysis {
    fn into_event(mut self) -> Event {
        attach_timeline_anchors(&mut self.event, &self.timeline_anchors);
        self.event
    }
}

fn attach_timeline_anchors(event: &mut Event, timeline_anchors: &[TimelineRuleAnchor]) {
    if timeline_anchors.is_empty() {
        return;
    }
    event.timeline_anchors =
        telltale_schema::event::canonicalize_timeline_anchors(timeline_anchors.to_vec());
}

fn detect_records_with_timeline(
    source: &Source,
    rule_set: &telltale_rules::CompiledRuleSet,
    parsed: &[NormalizedRecord],
) -> Result<Option<DetectionAnalysis>, telltale_schema::scoring::RiskAccountingError> {
    let Some(matches) = evaluate_session_matches(rule_set, parsed)? else {
        return Ok(None);
    };

    let rule_ids = matches.rule_ids;
    let tags = tags_for_matches(&rule_ids, matches.tags);

    let event = telltale_schema::event::detection_event(DetectionEventInput {
        client: source.client,
        agent: first_field(parsed, |record| record.agent.clone())
            .or_else(|| Some(source.client.as_str().to_string())),
        model: first_field(parsed, |record| record.model.clone()),
        provider: first_field(parsed, |record| record.provider.clone()),
        session_id: parsed
            .first()
            .map(|record| record.session_id.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        source_path_hash: path_hash(&source.path),
        tool_name: tool_name(parsed),
        rule_ids,
        categories: matches.categories,
        detection_classes: matches.detection_classes,
        signal_types: matches.signal_types,
        analytic_intents: matches.analytic_intents,
        atlas_tags: matches.atlas_tags,
        tags,
        evidence: matches.evidence,
        risk_contributions: matches.contributions,
        event_time: canonical_session_event_time(parsed),
    })?;
    let timeline_anchors = detection_timeline_anchors(source, parsed, &event);

    Ok(Some(DetectionAnalysis {
        event,
        timeline_anchors,
    }))
}

fn detection_timeline_anchors(
    source: &Source,
    parsed: &[NormalizedRecord],
    event: &Event,
) -> Vec<TimelineRuleAnchor> {
    let source_path_hash = path_hash(&source.path);
    let canonical_records = parsed
        .iter()
        .cloned()
        .map(|record| {
            NormalizedRecordV1::from_legacy(
                record,
                Provenance {
                    source_path_hash: source_path_hash.clone(),
                    source_event_id: None,
                    offset: None,
                },
            )
        })
        .collect::<Vec<_>>();

    build_session_timeline(&canonical_records)
        .map(|timeline| timeline.anchor_detection_event(event))
        .unwrap_or_default()
}

fn canonical_session_event_time(parsed: &[NormalizedRecord]) -> Option<String> {
    parsed
        .iter()
        .filter_map(|record| record.timestamp.as_deref())
        .filter_map(parse_event_timestamp)
        .max()
        .map(telltale_schema::event::format_timestamp)
}

fn tags_for_matches(rule_ids: &[String], mut tags: Vec<String>) -> Vec<String> {
    if rule_ids.iter().any(|id| id.starts_with("chain.")) {
        tags.push("chain".to_string());
    }
    tags.sort();
    tags.dedup();
    tags
}

struct ContextFields<'a> {
    assistant_context: &'a str,
    user_context: &'a str,
    tool_result: &'a str,
    command: &'a str,
    file_path: &'a str,
    url: &'a str,
}

fn context_fields(record: &NormalizedRecord) -> ContextFields<'_> {
    match record.kind {
        RecordKind::AssistantMessage => ContextFields {
            assistant_context: record.content.as_str(),
            user_context: "",
            tool_result: "",
            command: "",
            file_path: "",
            url: "",
        },
        RecordKind::UserMessage => ContextFields {
            assistant_context: "",
            user_context: record.content.as_str(),
            tool_result: "",
            command: "",
            file_path: "",
            url: "",
        },
        RecordKind::ToolResult => ContextFields {
            assistant_context: "",
            user_context: "",
            tool_result: record.content.as_str(),
            command: "",
            file_path: record.content.as_str(),
            url: record.content.as_str(),
        },
        RecordKind::ToolCall => ContextFields {
            assistant_context: "",
            user_context: "",
            tool_result: "",
            command: record.content.as_str(),
            file_path: record.content.as_str(),
            url: record.content.as_str(),
        },
        RecordKind::SessionMeta | RecordKind::Other => ContextFields {
            assistant_context: "",
            user_context: "",
            tool_result: "",
            command: "",
            file_path: "",
            url: "",
        },
        _ => ContextFields {
            assistant_context: "",
            user_context: "",
            tool_result: "",
            command: "",
            file_path: "",
            url: "",
        },
    }
}

fn tool_name(records: &[NormalizedRecord]) -> Option<String> {
    records
        .iter()
        .filter_map(|record| record.tool_name.clone())
        .next()
        .or_else(|| {
            ["repo_status", "get_compliance_status", "summarize_project"]
                .iter()
                .find_map(|name| {
                    records
                        .iter()
                        .any(|record| record.content.contains(name))
                        .then(|| (*name).to_string())
                })
        })
}

fn first_field<T, F>(records: &[NormalizedRecord], extract: F) -> Option<T>
where
    F: FnMut(&NormalizedRecord) -> Option<T>,
{
    records.iter().find_map(extract)
}

#[cfg(all(test, feature = "source-io"))]
#[allow(clippy::useless_conversion)]
mod tests {
    use super::{detect_records_with_timeline, detect_sources};
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use telltale_rules::load_default_rule_set;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::record::{NormalizedRecord, RecordKind};
    use telltale_schema::source::Source;
    use telltale_sources::clients::supported_clients;
    use telltale_sources::discovery::discover_sources_best_effort;

    #[path = "approval_bypass.rs"]
    mod approval_bypass;
    #[path = "codex_variants.rs"]
    mod codex_variants;
    #[path = "direct_record_compatibility.rs"]
    mod direct_record_compatibility;
    #[path = "download_execute.rs"]
    mod download_execute;
    #[path = "mcp_injection.rs"]
    mod mcp_injection;
    #[path = "resilience.rs"]
    mod resilience;
    #[path = "secret_access.rs"]
    mod secret_access;
    #[path = "timeline.rs"]
    mod timeline;
    #[path = "tool_result_coverage.rs"]
    mod tool_result_coverage;
    #[path = "uc002.rs"]
    mod uc002;
    #[path = "uc003.rs"]
    mod uc003;
}
