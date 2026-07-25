use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::baseline::{
    BaselineDeviationConfig, assess_baseline_deviation, build_baseline_summaries,
};
use crate::baseline::{BaselineSnapshotStore, baseline_snapshot_id};
use crate::timeline::{TimelineRuleAnchor, build_session_timeline};
use telltale_rules::{CompiledRuleSet, MatchResult, load_default_rule_set};
use telltale_schema::canonical::{NormalizedRecordV1, Provenance};
use telltale_schema::event::{
    ActivityEventInput, DetectionEventInput, Event, Evidence, activity_event, evidence_hash,
    parse_event_timestamp, path_hash, scanner_error_event,
};
use telltale_schema::scoring::load_thresholds;
use telltale_sources::discovery::Source;
use telltale_sources::parser::{NormalizedRecord, ParseError, RecordKind, parse_source_records};

const CHAIN_RULE_ID: &str = "chain.mcp_injection_then_egress";

#[allow(dead_code)]
pub fn detect_sources(sources: &[Source]) -> Vec<(Source, Event)> {
    let rule_set = load_default_rule_set().expect("rule set");
    detect_sources_with_rules(sources, &rule_set)
}

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

pub fn summarize_source_activities(sources: &[Source]) -> Vec<(Source, Event)> {
    summarize_source_activities_with_baselines(
        sources,
        &BaselineSnapshotStore::default(),
        BaselineDeviationConfig::default(),
    )
}

pub fn summarize_source_activities_with_baselines(
    sources: &[Source],
    baseline_snapshots: &BaselineSnapshotStore,
    baseline_deviation_config: BaselineDeviationConfig,
) -> Vec<(Source, Event)> {
    sources
        .iter()
        .flat_map(|source| {
            summarize_source_activity(source, baseline_snapshots, baseline_deviation_config)
                .into_iter()
                .map(|event| (source.clone(), event))
        })
        .collect()
}

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

    sessions
        .iter()
        .filter_map(|(_, records)| detect_records(source, rule_set, records))
        .collect()
}

fn summarize_source_activity(
    source: &Source,
    baseline_snapshots: &BaselineSnapshotStore,
    baseline_deviation_config: BaselineDeviationConfig,
) -> Vec<Event> {
    let parsed = match parse_source_records(source) {
        Ok(records) => records,
        Err(ParseError::Empty) => return vec![],
        Err(e) => return vec![scanner_error_event(source, &e)],
    };

    summarize_parsed_source_activity(
        source,
        &parsed,
        baseline_snapshots,
        baseline_deviation_config,
    )
}

pub fn summarize_parsed_source_activity(
    source: &Source,
    parsed: &[NormalizedRecord],
    baseline_snapshots: &BaselineSnapshotStore,
    baseline_deviation_config: BaselineDeviationConfig,
) -> Vec<Event> {
    group_records_by_session(parsed.to_vec())
        .iter()
        .filter_map(|(_, records)| {
            activity_records(
                source,
                records,
                baseline_snapshots,
                baseline_deviation_config,
            )
        })
        .collect()
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
) -> Option<Event> {
    detect_records_with_timeline(source, rule_set, parsed).map(DetectionAnalysis::into_event)
}

pub fn evaluate_session_matches(
    rule_set: &CompiledRuleSet,
    parsed: &[NormalizedRecord],
) -> Option<MatchResult> {
    let fields = parsed
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
        .collect::<Vec<_>>();
    rule_set.evaluate(&fields)
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

    let Some(triage) = event
        .triage
        .as_mut()
        .and_then(|value| value.as_object_mut())
    else {
        return;
    };

    triage.insert(
        "timeline_anchors".to_string(),
        serde_json::to_value(timeline_anchors).expect("timeline anchors serialize"),
    );
}

fn detect_records_with_timeline(
    source: &Source,
    rule_set: &telltale_rules::CompiledRuleSet,
    parsed: &[NormalizedRecord],
) -> Option<DetectionAnalysis> {
    let matches = evaluate_session_matches(rule_set, parsed)?;

    let mut rule_ids = matches.rule_ids;
    if !rule_ids.iter().any(|id| id == CHAIN_RULE_ID)
        && matches
            .categories
            .contains(&"mcp_prompt_injection".to_string())
        && matches.categories.contains(&"exfiltration".to_string())
    {
        rule_ids.push(CHAIN_RULE_ID.to_string());
    }
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
        risk_score: matches.score,
        event_time: canonical_session_event_time(parsed),
    });
    let timeline_anchors = detection_timeline_anchors(source, parsed, &event);

    Some(DetectionAnalysis {
        event,
        timeline_anchors,
    })
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

fn activity_records(
    source: &Source,
    parsed: &[NormalizedRecord],
    baseline_snapshots: &BaselineSnapshotStore,
    baseline_deviation_config: BaselineDeviationConfig,
) -> Option<Event> {
    let thresholds = load_thresholds();
    let mut record_counts = BTreeMap::new();
    let mut tool_names = BTreeSet::new();
    let mut tool_call_count: u32 = 0;
    let mut has_error_marker = false;

    for record in parsed {
        let key = match record.kind {
            RecordKind::UserMessage => "user_message",
            RecordKind::AssistantMessage => "assistant_message",
            RecordKind::ToolCall => "tool_call",
            RecordKind::ToolResult => "tool_result",
            RecordKind::SessionMeta => "session_meta",
            RecordKind::Other => "other",
        };
        *record_counts.entry(key.to_string()).or_insert(0_u32) += 1;

        if record.kind == RecordKind::ToolCall || record.kind == RecordKind::ToolResult {
            tool_call_count += 1;
        }
        if let Some(tool_name) = &record.tool_name {
            tool_names.insert(tool_name.clone());
        }
        if record.content.to_ascii_lowercase().contains("error") {
            has_error_marker = true;
        }
    }

    let unique_tool_count = tool_names.len() as u32;
    let high_risk_tools = [
        "bash", "sh", "curl", "wget", "write", "exec", "execute", "network", "download", "Bash",
        "Shell", "Write",
    ];
    let high_risk_count = tool_names
        .iter()
        .filter(|name| {
            high_risk_tools
                .iter()
                .any(|hr| name.eq_ignore_ascii_case(hr))
        })
        .count() as u32;

    // Scaled scoring: base + per-call + unique tools + high-risk tools + error
    let mut risk_score: u32 = 0;
    if tool_call_count > 0 {
        risk_score += 10; // base for any tool activity
        risk_score += (tool_call_count * 2).min(30); // scale by call volume
        risk_score += (unique_tool_count * 5).min(20); // scale by tool diversity
        risk_score += (high_risk_count * 15).min(30); // bonus for high-risk tools
    }
    if has_error_marker {
        risk_score += 10;
    }
    let mut evidence = Vec::new();
    let mut tags = vec!["activity".to_string(), "session".to_string()];

    if let Some(current_baseline) = build_baseline_summaries(parsed).into_iter().next() {
        let previous_baseline = baseline_snapshots
            .snapshots
            .get(&baseline_snapshot_id(&current_baseline.key))
            .filter(|snapshot| snapshot.key == current_baseline.key);
        if let Some(deviation) = assess_baseline_deviation(
            previous_baseline,
            &current_baseline,
            baseline_deviation_config,
        ) {
            risk_score = risk_score.saturating_add(deviation.risk_modifier);
            tags.push("baseline_deviation".to_string());
            let deviation_text = serde_json::json!({
                "risk_modifier": deviation.risk_modifier,
                "new_tool_names": deviation.new_tool_names,
                "new_path_classes": deviation.new_path_classes,
                "new_network_hosts": deviation.new_network_hosts,
            })
            .to_string();
            evidence.push(Evidence {
                field: "baseline_deviation".to_string(),
                redacted_value: deviation_text.clone(),
                hash: Some(evidence_hash(&deviation_text)),
                rule_id: None,
            });
        }
    }

    risk_score = risk_score.min(100);

    // Map to severity bands using existing thresholds
    let risk_score = if risk_score >= thresholds.alert {
        thresholds.alert
    } else if risk_score >= thresholds.triage {
        thresholds.triage
    } else if risk_score >= thresholds.medium {
        thresholds.medium
    } else if risk_score >= thresholds.low {
        thresholds.low
    } else if risk_score > 0 {
        risk_score
    } else {
        0
    };

    let counts_text = serde_json::to_string(&record_counts).ok()?;
    evidence.push(Evidence {
        field: "record_counts".to_string(),
        redacted_value: counts_text.clone(),
        hash: Some(evidence_hash(&counts_text)),
        rule_id: None,
    });
    if !tool_names.is_empty() {
        let tool_name_list = tool_names
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        evidence.push(Evidence {
            field: "tool_names".to_string(),
            redacted_value: tool_name_list.clone(),
            hash: Some(evidence_hash(&tool_name_list)),
            rule_id: None,
        });
    }

    if tool_call_count > 0 {
        tags.push("tooling".to_string());
    }
    if high_risk_count > 0 {
        tags.push("high_risk_tools".to_string());
    }
    if has_error_marker {
        tags.push("error".to_string());
    }
    tags.sort();
    tags.dedup();

    Some(activity_event(ActivityEventInput {
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
        tags,
        evidence,
        risk_score,
        event_time: canonical_session_event_time(parsed),
    }))
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
    }
}

fn tool_name(records: &[telltale_sources::parser::NormalizedRecord]) -> Option<String> {
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

fn first_field<T, F>(
    records: &[telltale_sources::parser::NormalizedRecord],
    extract: F,
) -> Option<T>
where
    F: FnMut(&telltale_sources::parser::NormalizedRecord) -> Option<T>,
{
    records.iter().find_map(extract)
}

#[cfg(test)]
#[allow(clippy::useless_conversion)]
mod tests {
    use super::{detect_records_with_timeline, detect_sources};
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use telltale_rules::load_default_rule_set;
    use telltale_sources::clients::{ClientId, SourceKind, supported_clients};
    use telltale_sources::discovery::{Source, discover_sources};
    use telltale_sources::parser::{NormalizedRecord, RecordKind};

    #[path = "approval_bypass.rs"]
    mod approval_bypass;
    #[path = "benign_baselines.rs"]
    mod benign_baselines;
    #[path = "codex_variants.rs"]
    mod codex_variants;
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
