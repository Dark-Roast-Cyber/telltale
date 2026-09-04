use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::baseline::{
    BaselineDeviationConfig, assess_baseline_deviation, build_baseline_summaries,
};
use crate::baseline::{BaselineSnapshotStore, baseline_snapshot_id};
use crate::timeline::{TimelineRuleAnchor, build_session_timeline};
#[cfg(feature = "source-io")]
use telltale_rules::load_default_rule_set;
use telltale_rules::{CompiledRuleSet, MatchResult};
use telltale_schema::canonical::{NormalizedRecordV1, Provenance};
#[cfg(feature = "source-io")]
use telltale_schema::event::scanner_error_event;
use telltale_schema::event::{
    ActivityEventInput, DetectionEventInput, Event, Evidence, activity_event, evidence_hash,
    parse_event_timestamp, path_hash,
};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::scoring::{RiskContribution, RiskContributionType};
use telltale_schema::source::Source;
#[cfg(feature = "source-io")]
use telltale_sources::parser::{ParseError, parse_source_records};

#[cfg(feature = "source-io")]
#[allow(dead_code)]
pub fn detect_sources(sources: &[Source]) -> Vec<(Source, Event)> {
    let rule_set = load_default_rule_set().expect("rule set");
    detect_sources_with_rules(sources, &rule_set)
}

#[cfg(feature = "source-io")]
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

#[cfg(feature = "source-io")]
pub fn summarize_source_activities(sources: &[Source]) -> Vec<(Source, Event)> {
    summarize_source_activities_with_baselines(
        sources,
        &BaselineSnapshotStore::default(),
        BaselineDeviationConfig::default(),
    )
}

#[cfg(feature = "source-io")]
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

#[cfg(feature = "source-io")]
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
    detect_parsed_source_records_internal(source, rule_set, parsed, false).0
}

#[derive(Clone)]
pub struct EffectiveMatchSnapshot {
    sessions: Vec<EffectiveSessionMatchSnapshot>,
}

#[derive(Clone)]
struct EffectiveSessionMatchSnapshot {
    session_id: String,
    records: Vec<NormalizedRecord>,
    effective_rule_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PolicyMatchAccounting {
    pub pre_policy_detection_candidate_count: u64,
    pub fully_filtered_detection_candidate_count: u64,
    pub filtered_rule_id_count: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PolicyMatchAccountingError;

impl std::fmt::Display for PolicyMatchAccountingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("policy match accounting unavailable")
    }
}

impl std::error::Error for PolicyMatchAccountingError {}

/// Runs the authoritative detection pass and retains an opaque snapshot for
/// optional pre-policy accounting. The returned events are identical to
/// `detect_parsed_source_records`.
pub fn detect_parsed_source_records_with_snapshot(
    source: &Source,
    rule_set: &telltale_rules::CompiledRuleSet,
    parsed: &[NormalizedRecord],
) -> (Vec<Event>, EffectiveMatchSnapshot) {
    let (events, snapshot) = detect_parsed_source_records_internal(source, rule_set, parsed, true);
    (
        events,
        snapshot.expect("snapshot requested from detection pass"),
    )
}

fn detect_parsed_source_records_internal(
    source: &Source,
    rule_set: &telltale_rules::CompiledRuleSet,
    parsed: &[NormalizedRecord],
    capture_snapshot: bool,
) -> (Vec<Event>, Option<EffectiveMatchSnapshot>) {
    let sessions = group_records_by_session(parsed.to_vec());
    let mut snapshot = capture_snapshot.then(|| EffectiveMatchSnapshot {
        sessions: Vec::with_capacity(sessions.len()),
    });
    let mut events = Vec::new();

    for (session_id, records) in sessions {
        match detect_records(source, rule_set, &records) {
            Ok(Some(event)) => {
                if let Some(snapshot) = snapshot.as_mut() {
                    snapshot.sessions.push(EffectiveSessionMatchSnapshot {
                        session_id,
                        records,
                        effective_rule_ids: Some(event.rule_ids.clone()),
                    });
                }
                events.push(event);
            }
            Ok(None) => {
                if let Some(snapshot) = snapshot.as_mut() {
                    snapshot.sessions.push(EffectiveSessionMatchSnapshot {
                        session_id,
                        records,
                        effective_rule_ids: Some(Vec::new()),
                    });
                }
            }
            Err(error) => {
                if let Some(snapshot) = snapshot.as_mut() {
                    snapshot.sessions.push(EffectiveSessionMatchSnapshot {
                        session_id,
                        records,
                        effective_rule_ids: None,
                    });
                }
                events.push(telltale_schema::event::scanner_error_event(source, &error));
            }
        }
    }

    (events, snapshot)
}

/// Evaluates each source-local session once with the pre-policy rule set and
/// compares those matches with the effective IDs captured by detection.
pub fn account_policy_matches(
    snapshot: &EffectiveMatchSnapshot,
    pre_policy_rule_set: &CompiledRuleSet,
) -> Result<PolicyMatchAccounting, PolicyMatchAccountingError> {
    let mut accounting = PolicyMatchAccounting {
        pre_policy_detection_candidate_count: 0,
        fully_filtered_detection_candidate_count: 0,
        filtered_rule_id_count: 0,
    };

    for session in &snapshot.sessions {
        if session.records.is_empty()
            || session
                .records
                .iter()
                .any(|record| record.session_id != session.session_id)
        {
            return Err(PolicyMatchAccountingError);
        }
        let Some(effective_rule_ids) = &session.effective_rule_ids else {
            return Err(PolicyMatchAccountingError);
        };
        let effective_rule_id_set = effective_rule_ids.iter().collect::<BTreeSet<_>>();
        if effective_rule_id_set.len() != effective_rule_ids.len() {
            return Err(PolicyMatchAccountingError);
        }

        let pre_policy_matches = evaluate_session_matches(pre_policy_rule_set, &session.records)
            .map_err(|_| PolicyMatchAccountingError)?;
        let Some(pre_policy_matches) = pre_policy_matches else {
            if !effective_rule_ids.is_empty() {
                return Err(PolicyMatchAccountingError);
            }
            continue;
        };

        let pre_policy_rule_id_set = pre_policy_matches.rule_ids.iter().collect::<BTreeSet<_>>();
        if pre_policy_rule_id_set.len() != pre_policy_matches.rule_ids.len() {
            return Err(PolicyMatchAccountingError);
        }
        accounting.pre_policy_detection_candidate_count = accounting
            .pre_policy_detection_candidate_count
            .checked_add(1)
            .ok_or(PolicyMatchAccountingError)?;

        if !effective_rule_id_set.is_subset(&pre_policy_rule_id_set) {
            return Err(PolicyMatchAccountingError);
        }
        if effective_rule_ids.is_empty() {
            accounting.fully_filtered_detection_candidate_count = accounting
                .fully_filtered_detection_candidate_count
                .checked_add(1)
                .ok_or(PolicyMatchAccountingError)?;
        }
        for rule_id in pre_policy_matches.rule_ids {
            if !effective_rule_id_set.contains(&rule_id) {
                accounting.filtered_rule_id_count = accounting
                    .filtered_rule_id_count
                    .checked_add(1)
                    .ok_or(PolicyMatchAccountingError)?;
            }
        }
    }

    Ok(accounting)
}

#[cfg(feature = "source-io")]
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
        .flat_map(|(_, records)| {
            match activity_records(
                source,
                records,
                baseline_snapshots,
                baseline_deviation_config,
            ) {
                Ok(Some(event)) => vec![event],
                Ok(None) => Vec::new(),
                Err(error) => vec![telltale_schema::event::scanner_error_event(source, &error)],
            }
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

/// Builds the exact legacy field view used by session evaluation. This shared
/// crate-private view is used by both production evaluation and the
/// experimental shadow comparator, which can identify legacy post-match
/// filtering without reimplementing legacy flattening.
pub(crate) fn legacy_evaluation_fields(parsed: &[NormalizedRecord]) -> Vec<(&str, &str)> {
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

fn activity_records(
    source: &Source,
    parsed: &[NormalizedRecord],
    baseline_snapshots: &BaselineSnapshotStore,
    baseline_deviation_config: BaselineDeviationConfig,
) -> Result<Option<Event>, telltale_schema::scoring::RiskAccountingError> {
    let mut record_counts = BTreeMap::new();
    let mut tool_names = BTreeSet::new();

    for record in parsed {
        let key = match record.kind {
            RecordKind::UserMessage => "user_message",
            RecordKind::AssistantMessage => "assistant_message",
            RecordKind::ToolCall => "tool_call",
            RecordKind::ToolResult => "tool_result",
            RecordKind::SessionMeta => "session_meta",
            RecordKind::Other => "other",
            _ => "other",
        };
        *record_counts.entry(key.to_string()).or_insert(0_u32) += 1;

        if let Some(tool_name) = &record.tool_name {
            tool_names.insert(tool_name.clone());
        }
    }

    let mut risk_contributions = Vec::new();
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
        )? {
            risk_contributions.push(RiskContribution::new(
                "baseline.deviation",
                RiskContributionType::BaselineDeviation,
                deviation.risk_modifier,
                "baseline deviation observed",
            )?);
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

    let counts_text = serde_json::to_string(&record_counts)
        .map_err(|_| telltale_schema::scoring::RiskAccountingError::Overflow)?;
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

    if record_counts
        .get("tool_call")
        .is_some_and(|count| *count > 0)
    {
        tags.push("tooling".to_string());
    }
    tags.sort();
    tags.dedup();

    Ok(Some(activity_event(ActivityEventInput {
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
        risk_contributions,
        event_time: canonical_session_event_time(parsed),
    })?))
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
    #[path = "benign_baselines.rs"]
    mod benign_baselines;
    #[path = "codex_variants.rs"]
    mod codex_variants;
    #[path = "download_execute.rs"]
    mod download_execute;
    #[path = "mcp_injection.rs"]
    mod mcp_injection;
    #[path = "policy_accounting.rs"]
    mod policy_accounting;
    #[path = "process_chain.rs"]
    mod process_chain;
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
