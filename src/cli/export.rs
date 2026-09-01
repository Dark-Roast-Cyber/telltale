use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use time::OffsetDateTime;

use crate::correlation::{CorrelationConfig, correlation_events_from_detections};
use crate::event::{
    Event, PrivacySanitizer, SanitizationContext, evidence_hash,
    is_canonical_opaque_identifier_for_kind, is_canonical_sha256_hex, opaque_identifier,
    parse_event_timestamp, sanitize_serialized_event, terminal_historical_identifier,
    terminal_historical_product_metadata, terminal_historical_session_id, terminal_identifier,
    terminal_product_metadata, terminal_rule_identifier, terminal_session_id,
    validate_risk_accounting_scope, validate_rule_ids,
};
use crate::rules::{CompiledRuleSet, load_default_rule_set};
use crate::schema::{NormalizedRecordV1, Provenance};
use crate::scoring::{
    RiskAccountingError, assess_risk_with_thresholds, canonicalize_contributions, load_thresholds,
};
use crate::timeline::build_exported_session_timeline;

pub(crate) struct ExportConfig<'a> {
    pub(crate) log_path: &'a Path,
    pub(crate) severities: &'a [String],
    pub(crate) clients: &'a [String],
    pub(crate) session_ids: &'a [String],
    pub(crate) rule_ids: &'a [String],
    pub(crate) since: Option<&'a str>,
    pub(crate) until: Option<&'a str>,
    pub(crate) format: super::ExportFormat,
    pub(crate) correlate: bool,
    pub(crate) timeline: bool,
    pub(crate) source_root: Option<&'a Path>,
}

struct ParsedExportRange {
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
}

struct ExportSummaryCounts {
    event_types: BTreeMap<String, usize>,
    severities: BTreeMap<String, usize>,
    clients: BTreeMap<String, usize>,
    rule_ids: BTreeMap<String, usize>,
}

pub(crate) fn run_export(config: ExportConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    validate_export_config(&config)?;
    let range = parse_export_range(&config)?;

    if let Some(source_root) = config.source_root.filter(|_| config.timeline) {
        return run_source_backed_timeline_export(&config, source_root);
    }

    let events = super::read_jsonl_events(config.log_path)?;
    validate_imported_event_accounting(&events)?;
    let filtered = filtered_export_events(&events, &config, &range);

    if config.timeline {
        let timeline_events = build_session_timelines(&filtered);
        return print_single_session_timeline(
            &timeline_events,
            config.session_ids[0].as_str(),
            config.format,
        );
    }

    let correlation_events = if config.correlate {
        Some(correlation_events_from_filtered(&filtered)?)
    } else {
        None
    };
    let output_events = correlation_events
        .as_ref()
        .map(|events| events.iter().collect::<Vec<_>>())
        .unwrap_or(filtered);
    print_export_events(&output_events, config.format)
}

fn validate_export_config(config: &ExportConfig<'_>) -> Result<(), Box<dyn std::error::Error>> {
    if config.timeline && config.session_ids.is_empty() {
        return Err("--timeline requires --session-id to select a session".into());
    }
    if config.timeline && config.session_ids.len() > 1 {
        return Err("--timeline requires exactly one --session-id".into());
    }
    if config.timeline && config.correlate {
        return Err("--correlate does not support --timeline".into());
    }
    if config.source_root.is_some() && !config.timeline {
        return Err("--source-root requires --timeline".into());
    }
    if !config.timeline && config.format == super::ExportFormat::TimelineText {
        return Err("--format timeline-text requires --timeline".into());
    }
    if config.timeline && config.format == super::ExportFormat::Summary {
        return Err("--format summary does not support --timeline".into());
    }
    if config.timeline && config.format == super::ExportFormat::ElasticBulk {
        return Err("--format elastic-bulk does not support --timeline".into());
    }
    if config.source_root.is_some() {
        if !config.severities.is_empty() {
            return Err("--source-root does not support --severity filters".into());
        }
        if !config.rule_ids.is_empty() {
            return Err("--source-root does not support --rule-id filters".into());
        }
        if config.since.is_some() || config.until.is_some() {
            return Err("--source-root does not support --since/--until filters".into());
        }
        if let Some(unsupported_client) = config
            .clients
            .iter()
            .find(|client| !is_supported_client_filter(client))
        {
            let expected = telltale_sources::clients::supported_clients()
                .iter()
                .map(|client| client.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "--source-root does not support unknown client '{unsupported_client}'; expected one of: {expected}"
            )
            .into());
        }
    }
    Ok(())
}

fn is_supported_client_filter(value: &str) -> bool {
    telltale_sources::clients::supported_clients()
        .iter()
        .any(|client| client.id.as_str() == value)
}

fn parse_export_range(
    config: &ExportConfig<'_>,
) -> Result<ParsedExportRange, Box<dyn std::error::Error>> {
    let since = parse_export_filter_timestamp(config.since, "--since")?;
    let until = parse_export_filter_timestamp(config.until, "--until")?;
    if let (Some(since), Some(until)) = (since, until)
        && since > until
    {
        return Err("--since must be less than or equal to --until".into());
    }
    Ok(ParsedExportRange { since, until })
}

fn run_source_backed_timeline_export(
    config: &ExportConfig<'_>,
    source_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let client_filters = string_set(config.clients);
    let session_filters = string_set(config.session_ids);
    let timeline_events =
        build_source_backed_session_timelines(source_root, &session_filters, &client_filters)?;
    print_single_session_timeline(
        &timeline_events,
        config.session_ids[0].as_str(),
        config.format,
    )
}

fn filtered_export_events<'a>(
    events: &'a [serde_json::Value],
    config: &ExportConfig<'_>,
    range: &ParsedExportRange,
) -> Vec<&'a serde_json::Value> {
    let severity_filters = lowercase_set(config.severities);
    let client_filters = string_set(config.clients);
    let session_filters = string_set(config.session_ids);
    let rule_filters = string_set(config.rule_ids);

    events
        .iter()
        .filter(|event| {
            event_matches_export_filters(
                event,
                &severity_filters,
                &client_filters,
                &session_filters,
                &rule_filters,
                range.since,
                range.until,
            )
        })
        .collect()
}

fn print_single_session_timeline(
    timeline_events: &[serde_json::Value],
    requested_session_id: &str,
    format: super::ExportFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_single_timeline_match(timeline_events, requested_session_id)?;
    print_timeline_events(timeline_events, format)
}

fn validate_imported_event_accounting(
    events: &[serde_json::Value],
) -> Result<(), Box<dyn std::error::Error>> {
    for event in events {
        let schema_version = event
            .get("schema_version")
            .and_then(serde_json::Value::as_str)
            .ok_or("event is missing schema_version")?;
        let event_type = event
            .get("event_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if schema_version != "2.0" && schema_version != "3.0"
            || !matches!(
                event_type,
                "activity" | "detection" | "session_risk_summary" | "process_chain"
            )
        {
            if schema_version == "2.0" || schema_version == "3.0" {
                let rule_ids = imported_rule_ids(event)?;
                validate_rule_ids(&rule_ids)?;
            }
            continue;
        }
        let rule_ids = imported_rule_ids(event)?;
        validate_rule_ids(&rule_ids)?;
        let raw = event
            .get("risk_contributions")
            .ok_or("risk-bearing event is missing risk_contributions")?
            .clone();
        let contributions: Vec<telltale_schema::scoring::RiskContribution> =
            serde_json::from_value(raw)?;
        let canonical = canonicalize_contributions(contributions.clone())?;
        if contributions != canonical {
            return Err(RiskAccountingError::NonCanonicalContributions.into());
        }
        let accounting_event_type = if schema_version == "3.0" && event_type == "process_chain" {
            "detection"
        } else {
            event_type
        };
        validate_risk_accounting_scope(
            accounting_event_type,
            &string_array(event, "rule_ids"),
            &canonical,
        )?;
        let declared = event
            .get("risk_score")
            .and_then(serde_json::Value::as_u64)
            .ok_or("risk-bearing event has an invalid risk_score")?;
        let computed = crate::scoring::checked_risk_sum(&canonical)?;
        if declared != computed {
            return Err(RiskAccountingError::ScoreMismatch { declared, computed }.into());
        }
    }
    Ok(())
}

fn imported_rule_ids(event: &serde_json::Value) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let Some(value) = event.get("rule_ids") else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or("imported event has an invalid rule_ids array")?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "imported event has a non-string rule_id".into())
        })
        .collect()
}

fn correlation_events_from_filtered(
    filtered: &[&serde_json::Value],
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let detection_events = filtered
        .iter()
        .filter(|event| {
            event.get("event_type").and_then(serde_json::Value::as_str) == Some("detection")
        })
        .map(|event| {
            let mut parsed = event_from_json_value(event)?;
            if !is_canonical_historical_event(event)
                && let Some(parsed) = parsed.as_mut()
            {
                terminalize_noncanonical_correlation_input(parsed);
            }
            parsed.ok_or_else(|| "correlation input event is not schema-shaped".into())
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

    correlation_events_from_detections(&detection_events, &CorrelationConfig::default())?
        .into_iter()
        .map(|event| serde_json::to_value(event.historical_derived()).map_err(Into::into))
        .collect()
}

fn is_canonical_historical_event(event: &serde_json::Value) -> bool {
    event
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        == Some("3.0")
}

fn terminalize_noncanonical_correlation_input(event: &mut Event) {
    event.client = terminal_identifier("client", &event.client);
    event.agent = event
        .agent
        .as_deref()
        .map(|value| terminal_product_metadata("agent", value));
    event.model = event
        .model
        .as_deref()
        .map(|value| terminal_product_metadata("model", value));
    event.provider = event
        .provider
        .as_deref()
        .map(|value| terminal_product_metadata("provider", value));
    event.session_id = terminal_session_id(&event.session_id);
    event.event_id = terminal_identifier("event", &event.event_id);
    event.rule_ids = event
        .rule_ids
        .iter()
        .map(|value| terminal_identifier("rule", value))
        .collect();
}

fn print_export_events(
    events: &[&serde_json::Value],
    format: super::ExportFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        super::ExportFormat::Jsonl => {
            for event in events {
                let mut terminal = (*event).clone();
                sanitize_serialized_event(&mut terminal);
                println!("{}", serde_json::to_string(&terminal)?);
            }
            Ok(())
        }
        super::ExportFormat::Summary => {
            print_export_summary(events);
            Ok(())
        }
        super::ExportFormat::ElasticBulk => print_elastic_bulk(events),
        super::ExportFormat::TimelineText => {
            Err("--format timeline-text requires --timeline".into())
        }
    }
}

fn print_timeline_events(
    timeline_events: &[serde_json::Value],
    format: super::ExportFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        super::ExportFormat::TimelineText => {
            for (index, event) in timeline_events.iter().enumerate() {
                if index > 0 {
                    println!();
                }
                print!("{}", format_timeline_text(event));
            }
        }
        super::ExportFormat::Jsonl
        | super::ExportFormat::Summary
        | super::ExportFormat::ElasticBulk => {
            for event in timeline_events {
                println!("{}", serde_json::to_string(event)?);
            }
        }
    }

    Ok(())
}

fn ensure_single_timeline_match(
    timeline_events: &[serde_json::Value],
    requested_session_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match timeline_events.len() {
        0 => Err(format!("no timeline found for session_id '{requested_session_id}'").into()),
        1 => Ok(()),
        count => Err(format!(
            "--timeline resolved {count} sessions for session_id '{requested_session_id}'; add --client to disambiguate"
        )
        .into()),
    }
}

fn print_elastic_bulk(events: &[&serde_json::Value]) -> Result<(), Box<dyn std::error::Error>> {
    for event in events {
        let mut terminal = (*event).clone();
        sanitize_serialized_event(&mut terminal);
        let event_id = terminal.get("event_id").and_then(|value| value.as_str());
        let action =
            crate::sink::elastic_bulk_action_json(crate::sink::DEFAULT_ELASTIC_INDEX, event_id);
        println!("{}", serde_json::to_string(&action)?);
        println!("{}", serde_json::to_string(&terminal)?);
    }
    Ok(())
}

fn format_timeline_text(timeline: &serde_json::Value) -> String {
    let session_id = json_str(timeline, "session_id").unwrap_or("unknown");
    let client = json_str(timeline, "client").unwrap_or("unknown");
    let agent = json_str(timeline, "agent").unwrap_or("unknown");
    let model = json_str(timeline, "model").unwrap_or("unknown");
    let provider = json_str(timeline, "provider").unwrap_or("unknown");
    let entry_count = timeline
        .get("entry_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let detection_count = timeline
        .get("detection_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let max_severity = json_str(timeline, "max_severity").unwrap_or("informational");
    let has_triage = timeline
        .get("has_triage")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let mut output = String::new();
    output.push_str(&format!("Timeline {session_id} ({client})\n"));
    output.push_str(&format!(
        "Agent: {agent} | Model: {model} | Provider: {provider}\n"
    ));
    output.push_str(&format!(
        "Entries: {entry_count} | Detections: {detection_count} | Max severity: {max_severity} | Triage: {}\n",
        if has_triage { "yes" } else { "no" }
    ));

    if let Some(risk_summary) = timeline.get("risk_summary") {
        output.push_str(&format_risk_summary_text(risk_summary));
    }

    if let Some(entries) = timeline.get("entries").and_then(|value| value.as_array()) {
        for entry in entries {
            output.push_str(&format_timeline_entry_text(entry));
        }
    }

    output
}

fn format_risk_summary_text(summary: &serde_json::Value) -> String {
    let tool_calls = summary
        .get("tool_call_count")
        .and_then(|value| value.as_u64())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_string());
    let risky_actions = summary
        .get("risky_action_count")
        .and_then(|value| value.as_u64())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "0".to_string());
    let max_severity = json_str(summary, "max_severity").unwrap_or("informational");
    let triage_ran = summary
        .get("triage_ran")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let top_rules = json_string_array(summary, "top_rule_ids").join(", ");
    let top_categories = json_string_array(summary, "top_categories").join(", ");
    let top_rules = if top_rules.is_empty() {
        "none".to_string()
    } else {
        top_rules
    };
    let top_categories = if top_categories.is_empty() {
        "none".to_string()
    } else {
        top_categories
    };

    format!(
        "Risk: tool_calls={tool_calls} risky_actions={risky_actions} max_severity={max_severity} triage_ran={} top_rules={top_rules} top_categories={top_categories}\n",
        if triage_ran { "yes" } else { "no" }
    )
}

fn format_timeline_entry_text(entry: &serde_json::Value) -> String {
    let index = entry
        .get("index")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let timestamp = json_str(entry, "timestamp").unwrap_or("unknown");
    let event_type = json_str(entry, "event_type").unwrap_or("unknown");
    let severity = json_str(entry, "severity").unwrap_or("informational");
    let mut line = format!("[{index}] {timestamp} {severity} {event_type}");
    if let Some(tool_name) = json_str(entry, "tool_name") {
        line.push_str(&format!(" tool={tool_name}"));
    }
    if let Some(call_id) = json_str(entry, "call_id") {
        line.push_str(&format!(" call_id={call_id}"));
    }
    if let Some(linked_index) = entry
        .get("linked_entry_index")
        .and_then(|value| value.as_u64())
    {
        line.push_str(&format!(" linked_entry={linked_index}"));
    }
    line.push('\n');

    let mut output = line;
    let rule_ids = json_string_array(entry, "rule_ids");
    if !rule_ids.is_empty() {
        output.push_str(&format!("  Rules: {}\n", rule_ids.join(", ")));
    }
    let categories = json_string_array(entry, "categories");
    if !categories.is_empty() {
        output.push_str(&format!("  Categories: {}\n", categories.join(", ")));
    }
    if let Some(evidence) = entry.get("evidence").and_then(|value| value.as_array()) {
        for item in evidence {
            let field = json_str(item, "field").unwrap_or("unknown");
            let hash = json_str(item, "hash").unwrap_or("unavailable");
            if let Some(redacted_value) = json_str(item, "redacted_value") {
                output.push_str(&format!(
                    "  Evidence: {field} hash={hash} value={redacted_value}\n"
                ));
            } else {
                output.push_str(&format!("  Evidence: {field} hash={hash}\n"));
            }
        }
    }
    if let Some(triage) = entry.get("triage") {
        let verdict = json_str(triage, "verdict").unwrap_or("unknown");
        let confidence = triage
            .get("confidence")
            .and_then(|value| value.as_f64())
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let reason = json_str(triage, "reason").unwrap_or("unavailable");
        output.push_str(&format!(
            "  Triage: {verdict} confidence={confidence} reason={reason}\n"
        ));
    }
    if let Some(response) = entry.get("response") {
        if let Some(action) = json_str(response, "recommended_action") {
            output.push_str(&format!(
                "  Recommended action: {}\n",
                PrivacySanitizer::sanitize(SanitizationContext::Summary, action)
            ));
        }
        if let Some(playbook) = json_str(response, "response_playbook") {
            output.push_str(&format!(
                "  Playbook: {}\n",
                PrivacySanitizer::sanitize(SanitizationContext::Summary, playbook)
            ));
        }
        if let Some(summary) = json_str(response, "investigation_summary") {
            output.push_str(&format!(
                "  Summary: {}\n",
                PrivacySanitizer::sanitize(SanitizationContext::Summary, summary)
            ));
        }
        if let Some(escalation) = json_str(response, "escalation") {
            output.push_str(&format!(
                "  Escalation: {}\n",
                PrivacySanitizer::sanitize(SanitizationContext::Summary, escalation)
            ));
        }
    }

    output
}

fn json_str<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(|value| value.as_str())
}

fn json_string_array(value: &serde_json::Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Build redacted session timelines from filtered JSONL events.
///
/// Groups events by `(session_id, client)`, sorts by timestamp, and produces
/// one timeline JSON object per session identity containing ordered entries
/// with detection anchors and triage context.
fn build_session_timelines(events: &[&serde_json::Value]) -> Vec<serde_json::Value> {
    use std::collections::BTreeMap;

    // Group events by `(session_id, client)` so client-local session ids do not collide.
    let mut by_session: BTreeMap<(String, String), Vec<&serde_json::Value>> = BTreeMap::new();
    for event in events {
        let session_id = event
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let client = event
            .get("client")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        by_session
            .entry((session_id, client))
            .or_default()
            .push(event);
    }

    let mut timelines = Vec::new();

    for ((session_id, client), mut session_events) in by_session {
        // Sort by timestamp.
        session_events.sort_by(|a, b| {
            let ts_a = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let ts_b = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            ts_a.cmp(ts_b)
        });

        // Extract session metadata from the first event.
        let first = session_events.first();
        let agent = first
            .and_then(|e| e.get("agent").and_then(|v| v.as_str()))
            .map(|value| terminal_timeline_product_metadata(first, "agent", value));
        let model = first
            .and_then(|e| e.get("model").and_then(|v| v.as_str()))
            .map(|value| terminal_timeline_product_metadata(first, "model", value));
        let provider = first
            .and_then(|e| e.get("provider").and_then(|v| v.as_str()))
            .map(|value| terminal_timeline_product_metadata(first, "provider", value));

        // Build timeline entries.
        let entries: Vec<serde_json::Value> = session_events
            .iter()
            .enumerate()
            .map(|(index, event)| {
                let event_type = event
                    .get("event_type")
                    .and_then(|v| v.as_str())
                    .map(terminal_export_event_type)
                    .unwrap_or_else(|| opaque_identifier("event-type", "missing"));
                let severity = event
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .map(terminal_export_severity)
                    .unwrap_or_else(|| "informational".to_string());
                let timestamp = event
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let tool_name = event.get("tool_name").and_then(|v| v.as_str());
                let rule_ids = event
                    .get("rule_ids")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let categories = event
                    .get("categories")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                // Redacted evidence summary: field names and hashes only.
                let evidence_summary: Vec<serde_json::Value> = event
                    .get("evidence")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|item| {
                                let field = item.get("field")?.as_str()?;
                                let hash = item
                                    .get("hash")
                                    .and_then(|value| value.as_str())
                                    .map(terminal_timeline_evidence_hash);
                                Some(serde_json::json!({
                                    "field": terminal_timeline_identifier(event, "evidence-field", field),
                                    "hash": hash,
                                }))
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Historical triage is retained only as a derived export view;
                // native 3.0 events never carry this field.
                let triage = event.get("triage").map(|t| {
                    serde_json::json!({
                        "verdict": t.get("verdict").and_then(|v| v.as_str()).map(|value| PrivacySanitizer::sanitize(SanitizationContext::Summary, value)),
                        "confidence": t.get("confidence").and_then(|v| v.as_f64()),
                        "reason": t.get("reason").and_then(|v| v.as_str()).map(|value| PrivacySanitizer::sanitize(SanitizationContext::Summary, value)),
                    })
                });

                // Response summary.
                let response = event.get("response").map(|r| {
                    serde_json::json!({
                        "recommended_action": r.get("recommended_action").and_then(|v| v.as_str()).map(|value| PrivacySanitizer::sanitize(SanitizationContext::Summary, value)),
                        "response_playbook": r.get("response_playbook").and_then(|v| v.as_str()).map(|value| PrivacySanitizer::sanitize(SanitizationContext::Summary, value)),
                        "investigation_summary": r.get("investigation_summary").and_then(|v| v.as_str()).map(|value| PrivacySanitizer::sanitize(SanitizationContext::Summary, value)),
                        "escalation": r.get("escalation").and_then(|v| v.as_str()).map(|value| PrivacySanitizer::sanitize(SanitizationContext::Summary, value)),
                    })
                });

                let mut entry = serde_json::json!({
                    "index": index,
                    "timestamp": terminal_timeline_timestamp(event, &timestamp),
                    "event_type": event_type,
                    "severity": severity,
                });

                if let Some(tool) = tool_name {
                    entry["tool_name"] = serde_json::Value::String(terminal_timeline_identifier(event, "tool", tool));
                }
                if !rule_ids.is_empty() {
                    entry["rule_ids"] = serde_json::json!(terminal_timeline_identifiers(event, "rule", &rule_ids));
                }
                if !categories.is_empty() {
                    entry["categories"] = serde_json::json!(terminal_timeline_identifiers(event, "category", &categories));
                }
                if let Some(anchors) = event
                    .get("timeline_anchors")
                    .filter(|value| value.is_array())
                    .filter(|value| !value.as_array().is_some_and(Vec::is_empty))
                {
                    let mut anchors = anchors.clone();
                    sanitize_timeline_anchors(&mut anchors, event);
                    entry["timeline_anchors"] = anchors;
                }
                if !evidence_summary.is_empty() {
                    entry["evidence"] = serde_json::json!(evidence_summary);
                }
                if let Some(t) = triage {
                    entry["triage"] = t;
                }
                if let Some(r) = response {
                    entry["response"] = r;
                }

                entry
            })
            .collect();

        // Compute session summary.
        let detection_count = session_events
            .iter()
            .filter(|e| {
                e.get("event_type")
                    .and_then(|v| v.as_str())
                    .is_some_and(|t| t == "detection")
            })
            .count();
        let max_severity = session_events
            .iter()
            .filter_map(|e| e.get("severity").and_then(|v| v.as_str()))
            .map(terminal_export_severity)
            .max_by_key(|severity| severity_rank(severity))
            .unwrap_or_else(|| "informational".to_string());
        // Native events have no triage field. Historical records may retain a
        // terminal model verdict, which is shown only in this derived view.
        let has_triage = session_events
            .iter()
            .any(|event| triage_ran_from_event(event));
        let risk_summary = build_session_risk_summary(&session_events);
        let record_status = session_events
            .iter()
            .map(|event| {
                if event.get("schema_version").and_then(|value| value.as_str()) == Some("3.0") {
                    "native"
                } else {
                    "historical"
                }
            })
            .collect::<BTreeSet<_>>();
        let record_status = match record_status.len() {
            1 if record_status.contains("native") => "native",
            1 => "historical",
            _ => "mixed",
        };

        let timeline = serde_json::json!({
            "event_type": "timeline",
            "session_id": terminal_timeline_session_id(first, &session_id),
            "client": first.map_or_else(
                || terminal_identifier("client", &client),
                |event| terminal_timeline_identifier(event, "client", &client),
            ),
            "agent": agent,
            "model": model,
            "provider": provider,
            "entry_count": entries.len(),
            "detection_count": detection_count,
            "max_severity": max_severity,
            "has_triage": has_triage,
            "record_status": record_status,
            "risk_summary": risk_summary,
            "entries": entries,
        });

        timelines.push(timeline);
    }

    timelines
}

fn terminal_timeline_session_id(event: Option<&&serde_json::Value>, value: &str) -> String {
    if event.is_some_and(|event| is_canonical_historical_event(event)) {
        terminal_historical_session_id(value)
    } else {
        terminal_session_id(value)
    }
}

fn terminal_timeline_product_metadata(
    event: Option<&&serde_json::Value>,
    kind: &str,
    value: &str,
) -> String {
    if event.is_some_and(|event| is_canonical_historical_event(event)) {
        terminal_historical_product_metadata(kind, value)
    } else {
        terminal_product_metadata(kind, value)
    }
}

fn terminal_timeline_timestamp(event: &serde_json::Value, value: &str) -> String {
    if parse_event_timestamp(value).is_some() {
        value.to_string()
    } else if is_canonical_historical_event(event) {
        terminal_historical_identifier("invalid-timestamp", value)
    } else {
        opaque_identifier("invalid-timestamp", value)
    }
}

fn terminal_timeline_identifier(event: &serde_json::Value, kind: &str, value: &str) -> String {
    if is_canonical_historical_event(event) {
        terminal_historical_identifier(kind, value)
    } else {
        terminal_identifier(kind, value)
    }
}

fn terminal_timeline_evidence_hash(value: &str) -> String {
    if is_canonical_sha256_hex(value) {
        value.to_string()
    } else {
        evidence_hash(value)
    }
}

fn terminal_timeline_summary_identifier(
    event: &serde_json::Value,
    kind: &str,
    value: &str,
) -> String {
    if is_canonical_historical_event(event) && is_canonical_opaque_identifier_for_kind(kind, value)
    {
        value.to_string()
    } else {
        terminal_identifier("risk-summary", value)
    }
}

fn terminal_timeline_identifiers(
    event: &serde_json::Value,
    kind: &str,
    values: &[&str],
) -> Vec<String> {
    values
        .iter()
        .map(|value| terminal_timeline_identifier(event, kind, value))
        .collect()
}

fn sanitize_timeline_anchors(anchors: &mut serde_json::Value, event: &serde_json::Value) {
    let mut wrapper = serde_json::json!({
        "schema_version": event
            .get("schema_version")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::String("3.0".to_string())),
        "timeline_anchors": anchors.clone(),
    });
    sanitize_serialized_event(&mut wrapper);
    if let Some(sanitized) = wrapper.get("timeline_anchors") {
        *anchors = sanitized.clone();
    }

    let Some(anchors) = anchors.as_array_mut() else {
        return;
    };
    for anchor in anchors {
        let Some(anchor) = anchor.as_object_mut() else {
            continue;
        };
        for (field, kind) in [
            ("rule_ids", "rule"),
            ("categories", "category"),
            ("evidence_fields", "evidence-field"),
        ] {
            let Some(values) = anchor.get_mut(field).and_then(|value| value.as_array_mut()) else {
                continue;
            };
            for value in values {
                let serde_json::Value::String(value) = value else {
                    continue;
                };
                *value = terminal_timeline_identifier(event, kind, value);
            }
        }
    }
}

fn build_source_backed_session_timelines(
    source_root: &Path,
    session_filters: &BTreeSet<String>,
    client_filters: &BTreeSet<String>,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    type SessionKey = (String, String);
    type CanonicalSessionRecord = (String, usize, NormalizedRecordV1);
    type LegacySessionRecord = (String, usize, telltale_schema::record::NormalizedRecord);

    let rule_set = load_default_rule_set()?;
    let mut by_session: BTreeMap<SessionKey, Vec<CanonicalSessionRecord>> = BTreeMap::new();
    let mut legacy_by_session: BTreeMap<SessionKey, Vec<LegacySessionRecord>> = BTreeMap::new();
    let mut sources = crate::discovery::discover_sources_best_effort(source_root);
    if !client_filters.is_empty() {
        sources.retain(|source| client_filters.contains(source.client.as_str()));
    }

    for source in &sources {
        let records = crate::parser::parse_source_records(source)
            .map_err(|error| format!("source parse failed for {}: {error}", source.source_id))?;
        let client = source.client.as_str().to_string();
        let source_path = source.path.to_string_lossy();
        let source_path_hash = evidence_hash(&source_path);
        for (index, record) in records.into_iter().enumerate() {
            if !session_filters.contains(&record.session_id) {
                continue;
            }
            let session_id = record.session_id.clone();
            let timestamp = record.timestamp.clone().unwrap_or_default();
            legacy_by_session
                .entry((session_id.clone(), client.clone()))
                .or_default()
                .push((timestamp.clone(), index, record.clone()));
            let canonical = NormalizedRecordV1::from_legacy(
                record,
                Provenance {
                    source_path_hash: source_path_hash.clone(),
                    source_event_id: None,
                    offset: Some(index.to_string()),
                },
            );
            by_session
                .entry((session_id, client.clone()))
                .or_default()
                .push((timestamp, index, canonical));
        }
    }

    let timelines = by_session
        .into_iter()
        .map(|(session_key, mut records)| {
            records.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
            let mut legacy_records = legacy_by_session.remove(&session_key).unwrap_or_default();
            legacy_records
                .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
            let canonical_records = records
                .into_iter()
                .map(|(_, _, record)| record)
                .collect::<Vec<_>>();
            let parsed_records = legacy_records
                .into_iter()
                .map(|(_, _, record)| record)
                .collect::<Vec<_>>();
            build_source_backed_timeline_value(&canonical_records, &parsed_records, &rule_set)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(timelines.into_iter().flatten().collect())
}

fn build_source_backed_timeline_value(
    canonical_records: &[NormalizedRecordV1],
    parsed_records: &[telltale_schema::record::NormalizedRecord],
    rule_set: &CompiledRuleSet,
) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error>> {
    let Some(session_timeline) = build_exported_session_timeline(canonical_records) else {
        return Ok(None);
    };
    let mut timeline = serde_json::to_value(session_timeline)?;
    let summary = build_source_backed_risk_summary(parsed_records, rule_set)?;
    let max_severity = summary
        .get("max_severity")
        .and_then(|value| value.as_str())
        .unwrap_or("informational");
    let has_triage = summary
        .get("triage_ran")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let detection_count = summary
        .get("risky_action_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);

    timeline["detection_count"] = serde_json::Value::from(detection_count);
    timeline["max_severity"] = serde_json::Value::String(max_severity.to_string());
    timeline["has_triage"] = serde_json::Value::Bool(has_triage);
    timeline["record_status"] = serde_json::Value::String("source_derived".to_string());
    timeline["risk_summary"] = summary;
    Ok(Some(timeline))
}

fn build_source_backed_risk_summary(
    parsed_records: &[telltale_schema::record::NormalizedRecord],
    rule_set: &CompiledRuleSet,
) -> Result<serde_json::Value, RiskAccountingError> {
    let tool_call_count = parsed_records
        .iter()
        .filter(|record| matches!(record.kind, telltale_schema::record::RecordKind::ToolCall))
        .count() as u64;
    let matches = crate::detection::evaluate_session_matches(rule_set, parsed_records)?;
    let risk_score = matches.as_ref().map(|matches| matches.score).unwrap_or(0);
    let max_severity = if risk_score == 0 {
        "informational"
    } else {
        assess_risk_with_thresholds(risk_score, load_thresholds())
            .severity
            .as_str()
    };
    let risky_action_count = u64::from(matches.is_some());

    Ok(serde_json::json!({
        "tool_call_count": tool_call_count,
        "risky_action_count": risky_action_count,
        "top_rule_ids": matches
            .as_ref()
            .map(|matches| serde_json::json!(matches.rule_ids))
            .unwrap_or(serde_json::Value::Null),
        "top_categories": matches
            .as_ref()
            .map(|matches| serde_json::json!(matches.categories))
            .unwrap_or(serde_json::Value::Null),
        "max_severity": max_severity,
        "triage_ran": false,
    }))
}

fn build_session_risk_summary(session_events: &[&serde_json::Value]) -> serde_json::Value {
    let mut tool_call_count = None;
    let mut detection_count = 0_usize;
    let mut max_severity = "informational".to_string();
    let mut triage_ran = false;
    let mut rule_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut category_counts: BTreeMap<String, usize> = BTreeMap::new();

    for event in session_events {
        if let Some(severity) = event
            .get("severity")
            .and_then(|value| value.as_str())
            .map(terminal_export_severity)
            && severity_rank(&severity) > severity_rank(&max_severity)
        {
            max_severity = severity;
        }

        match event.get("event_type").and_then(|value| value.as_str()) {
            Some("activity") if tool_call_count.is_none() => {
                tool_call_count = extract_tool_call_count(event);
            }
            Some("detection") => {
                detection_count += 1;
                triage_ran |= triage_ran_from_event(event);

                if let Some(values) = event.get("rule_ids").and_then(|value| value.as_array()) {
                    for value in values.iter().filter_map(|value| value.as_str()) {
                        *rule_counts
                            .entry(terminal_timeline_summary_identifier(event, "rule", value))
                            .or_insert(0) += 1;
                    }
                }
                if let Some(values) = event.get("categories").and_then(|value| value.as_array()) {
                    for value in values.iter().filter_map(|value| value.as_str()) {
                        *category_counts
                            .entry(terminal_timeline_summary_identifier(
                                event, "category", value,
                            ))
                            .or_insert(0) += 1;
                    }
                }
            }
            _ => {}
        }
    }

    serde_json::json!({
        "tool_call_count": tool_call_count,
        "risky_action_count": detection_count,
        "top_rule_ids": ranked_summary_values(rule_counts),
        "top_categories": ranked_summary_values(category_counts),
        "max_severity": max_severity,
        "triage_ran": triage_ran,
    })
}

fn ranked_summary_values(counts: BTreeMap<String, usize>) -> serde_json::Value {
    let mut values = counts.into_iter().collect::<Vec<_>>();
    values.sort_by(|(left_value, left_count), (right_value, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_value.cmp(right_value))
    });
    if values.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Array(
            values
                .into_iter()
                .take(3)
                .map(|(value, _)| serde_json::Value::String(value))
                .collect(),
        )
    }
}

fn extract_tool_call_count(event: &serde_json::Value) -> Option<u64> {
    let evidence = event.get("evidence")?.as_array()?;
    let record_counts = evidence
        .iter()
        .find(|item| item.get("field").and_then(|value| value.as_str()) == Some("record_counts"))?;
    let counts = record_counts
        .get("redacted_value")
        .and_then(|value| value.as_str())
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())?;
    counts.get("tool_call").and_then(|value| value.as_u64())
}

fn triage_ran_from_event(event: &serde_json::Value) -> bool {
    event
        .get("triage")
        .and_then(|value| value.get("verdict"))
        .and_then(|value| value.as_str())
        .is_some_and(|verdict| !matches!(verdict, "pending" | "not_required" | "config_missing"))
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn event_from_json_value(
    event: &serde_json::Value,
) -> Result<Option<Event>, Box<dyn std::error::Error>> {
    let required_string = |key: &str| event.get(key).and_then(|value| value.as_str());
    let Some(timestamp) = required_string("timestamp") else {
        return Ok(None);
    };
    let Some(event_id) = required_string("event_id") else {
        return Ok(None);
    };
    let Some(event_type) = required_string("event_type") else {
        return Ok(None);
    };
    let Some(severity) = required_string("severity") else {
        return Ok(None);
    };
    let Some(client) = required_string("client") else {
        return Ok(None);
    };
    let Some(session_id) = required_string("session_id") else {
        return Ok(None);
    };
    let Some(risk_score) = event.get("risk_score").and_then(|value| value.as_u64()) else {
        return Ok(None);
    };
    let risk_contributions = serde_json::from_value(
        event
            .get("risk_contributions")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([])),
    )?;

    Ok(Some(Event {
        timestamp: timestamp.to_string(),
        event_time: optional_string(event, "event_time"),
        observed_at: event
            .get("observed_at")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| {
                event
                    .get("timestamp")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
            })
            .to_string(),
        ingested_at: event
            .get("ingested_at")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| {
                event
                    .get("timestamp")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
            })
            .to_string(),
        time_source: event
            .get("time_source")
            .and_then(|value| value.as_str())
            .unwrap_or("source")
            .to_string(),
        time_confidence: event
            .get("time_confidence")
            .and_then(|value| value.as_str())
            .unwrap_or("high")
            .to_string(),
        time_override_reason: optional_string(event, "time_override_reason"),
        schema_version: event
            .get("schema_version")
            .and_then(|value| value.as_str())
            .ok_or("event is missing schema_version")?
            .to_string(),
        event_id: event_id.to_string(),
        telltale_version: optional_string(event, "telltale_version")
            .unwrap_or_else(|| "historical".to_string()),
        event_type: event_type.to_string(),
        severity: severity.to_string(),
        risk_score,
        risk_contributions,
        client: client.to_string(),
        agent: optional_string(event, "agent"),
        model: optional_string(event, "model"),
        provider: optional_string(event, "provider"),
        session_id: session_id.to_string(),
        source_path_hash: optional_string(event, "source_path_hash"),
        tool_name: optional_string(event, "tool_name"),
        rule_ids: string_array(event, "rule_ids"),
        categories: string_array(event, "categories"),
        detection_classes: string_array(event, "detection_classes"),
        signal_types: string_array(event, "signal_types"),
        analytic_intents: string_array(event, "analytic_intents"),
        atlas_tags: string_array(event, "atlas_tags"),
        tags: string_array(event, "tags"),
        evidence: Vec::new(),
        timeline_anchors: Vec::new(),
        response: None,
        source_counts: None,
        component: optional_string(event, "component"),
        check_name: optional_string(event, "check_name"),
        status: optional_string(event, "status"),
        scan_duration_ms: event
            .get("scan_duration_ms")
            .and_then(|value| value.as_u64()),
        rule_count: event
            .get("rule_count")
            .and_then(|value| value.as_u64())
            .map(|value| value as usize),
        threshold_config: None,
        active_policy_name: optional_string(event, "active_policy_name"),
        emitted_count: event.get("emitted_count").and_then(|value| value.as_u64()),
        suppressed_count: event
            .get("suppressed_count")
            .and_then(|value| value.as_u64()),
        scanner_error_count: event
            .get("scanner_error_count")
            .and_then(|value| value.as_u64()),
        informational: event.get("informational").and_then(|value| value.as_bool()),
        confidence: optional_string(event, "confidence"),
        detection_reason: optional_string(event, "detection_reason"),
        mitre_attack_techniques: string_array(event, "mitre_attack_techniques"),
        risk_entity_type: optional_string(event, "risk_entity_type"),
        risk_entity_value: optional_string(event, "risk_entity_value"),
        process: None,
    }))
}

fn optional_string(event: &serde_json::Value, key: &str) -> Option<String> {
    event
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn string_array(event: &serde_json::Value, key: &str) -> Vec<String> {
    event
        .get(key)
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn lowercase_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn string_set(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn event_matches_export_filters(
    event: &serde_json::Value,
    severity_filters: &BTreeSet<String>,
    client_filters: &BTreeSet<String>,
    session_filters: &BTreeSet<String>,
    rule_filters: &BTreeSet<String>,
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
) -> bool {
    if !severity_filters.is_empty()
        && !event
            .get("severity")
            .and_then(|value| value.as_str())
            .map(|value| severity_filters.contains(&value.to_ascii_lowercase()))
            .unwrap_or(false)
    {
        return false;
    }
    if !client_filters.is_empty()
        && !event
            .get("client")
            .and_then(|value| value.as_str())
            .map(|value| client_filters.contains(value))
            .unwrap_or(false)
    {
        return false;
    }
    if !session_filters.is_empty()
        && !event
            .get("session_id")
            .and_then(|value| value.as_str())
            .map(|value| session_filters.contains(value))
            .unwrap_or(false)
    {
        return false;
    }
    if !rule_filters.is_empty()
        && !event
            .get("rule_ids")
            .and_then(|value| value.as_array())
            .map(|rule_ids| {
                rule_ids
                    .iter()
                    .filter_map(|value| value.as_str())
                    .any(|rule_id| rule_filters.contains(rule_id))
            })
            .unwrap_or(false)
    {
        return false;
    }
    if since.is_some() || until.is_some() {
        let Some(event_timestamp) = event
            .get("timestamp")
            .and_then(|value| value.as_str())
            .and_then(parse_event_timestamp)
        else {
            return false;
        };

        if since.is_some_and(|since| event_timestamp < since) {
            return false;
        }
        if until.is_some_and(|until| event_timestamp > until) {
            return false;
        }
    }
    true
}

fn parse_export_filter_timestamp(
    value: Option<&str>,
    flag: &str,
) -> Result<Option<OffsetDateTime>, Box<dyn std::error::Error>> {
    let Some(value) = value else {
        return Ok(None);
    };

    parse_event_timestamp(value)
        .ok_or_else(|| format!("{flag} requires a valid RFC3339 timestamp").into())
        .map(Some)
}

fn print_export_summary(events: &[&serde_json::Value]) {
    let counts = export_summary_counts(events);

    println!("events: {}", events.len());
    print_count_section("event_types", &counts.event_types);
    print_count_section("severities", &counts.severities);
    print_count_section("clients", &counts.clients);
    print_count_section("rule_ids", &counts.rule_ids);
}

fn export_summary_counts(events: &[&serde_json::Value]) -> ExportSummaryCounts {
    let mut event_types = BTreeMap::new();
    let mut severities = BTreeMap::new();
    let mut clients = BTreeMap::new();
    let mut rule_ids = BTreeMap::new();

    for event in events {
        if let Some(value) = event.get("event_type").and_then(|value| value.as_str()) {
            *event_types
                .entry(terminal_export_event_type(value))
                .or_insert(0) += 1;
        }
        if let Some(value) = event.get("severity").and_then(|value| value.as_str()) {
            *severities
                .entry(terminal_export_severity(value))
                .or_insert(0) += 1;
        }
        increment_terminal_identifier_field(event, "client", "client", &mut clients);
        if let Some(values) = event.get("rule_ids").and_then(|value| value.as_array()) {
            for value in values.iter().filter_map(|value| value.as_str()) {
                *rule_ids
                    .entry(terminal_rule_identifier(value))
                    .or_insert(0_usize) += 1;
            }
        }
    }

    ExportSummaryCounts {
        event_types,
        severities,
        clients,
        rule_ids,
    }
}

fn terminal_export_event_type(value: &str) -> String {
    if matches!(
        value,
        "detection"
            | "activity"
            | "health"
            | "scanner_error"
            | "operational_alert"
            | "session_risk_summary"
            | "correlation"
            | "process_chain"
    ) {
        value.to_string()
    } else {
        opaque_identifier("event-type", value)
    }
}

fn terminal_export_severity(value: &str) -> String {
    if matches!(
        value,
        "informational" | "low" | "medium" | "high" | "critical" | "warning"
    ) {
        value.to_string()
    } else {
        opaque_identifier("severity", value)
    }
}

fn increment_terminal_identifier_field(
    event: &serde_json::Value,
    field: &str,
    kind: &str,
    counts: &mut BTreeMap<String, usize>,
) {
    if let Some(value) = event.get(field).and_then(|value| value.as_str()) {
        *counts
            .entry(terminal_identifier(kind, value))
            .or_insert(0_usize) += 1;
    }
}

fn print_count_section(label: &str, counts: &BTreeMap<String, usize>) {
    println!("{label}:");
    if counts.is_empty() {
        println!("  none: 0");
        return;
    }
    for (value, count) in counts {
        println!("  {value}: {count}");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_session_timelines, correlation_events_from_filtered, export_summary_counts,
        format_timeline_text,
    };
    use telltale_schema::event::opaque_identifier;

    fn canonical_detection(
        event_id: &str,
        session_id: &str,
        agent: &str,
        model: &str,
        provider: &str,
        timestamp: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "schema_version": "3.0",
            "event_id": event_id,
            "event_type": "detection",
            "timestamp": timestamp,
            "observed_at": timestamp,
            "ingested_at": timestamp,
            "severity": "high",
            "risk_score": 80,
            "client": "codex",
            "agent": agent,
            "model": model,
            "provider": provider,
            "session_id": session_id,
            "rule_ids": ["rule.test"],
            "categories": ["test"],
            "detection_classes": ["security_detection"],
            "signal_types": ["atomic"],
            "analytic_intents": ["alert"],
            "risk_contributions": [],
        })
    }

    #[test]
    fn historical_summary_and_timeline_terminalize_event_type_and_severity() {
        let marker = "CONTROLLED_HISTORICAL_LABEL_SECRET";
        let historical = serde_json::json!({
            "schema_version": "1.0",
            "event_id": "historical-labels",
            "timestamp": "2026-05-01T00:00:00Z",
            "event_type": format!("event-{marker}"),
            "severity": format!("severity-{marker}"),
            "risk_score": 0,
            "client": "codex",
            "session_id": "historical-label-session",
            "rule_ids": [],
            "categories": [],
            "evidence": [],
        });
        let events = [&historical];

        let counts = export_summary_counts(&events);
        assert!(
            !serde_json::to_string(&counts.event_types)
                .expect("summary event types JSON")
                .contains(marker),
            "summary emitted a controlled event type"
        );
        assert!(
            !serde_json::to_string(&counts.severities)
                .expect("summary severities JSON")
                .contains(marker),
            "summary emitted a controlled severity"
        );

        let timelines = build_session_timelines(&events);
        let timeline = timelines.first().expect("historical timeline");
        assert!(
            !serde_json::to_string(timeline)
                .expect("timeline JSON")
                .contains(marker),
            "timeline JSON emitted a controlled event label"
        );
        assert!(
            !format_timeline_text(timeline).contains(marker),
            "timeline text emitted a controlled event label"
        );
    }

    #[test]
    fn historical_timeline_and_correlation_preserve_exact_canonical_links() {
        let first_session = opaque_identifier("session", "first source session");
        let second_session = opaque_identifier("session", "second source session");
        let agent = opaque_identifier("agent", "first source agent");
        let model = opaque_identifier("model", "first source model");
        let provider = opaque_identifier("provider", "first source provider");
        let first = canonical_detection(
            "telltale-00000000-0000-4000-8000-000000000001",
            &first_session,
            &agent,
            &model,
            &provider,
            "2026-05-01T00:00:00Z",
        );
        let second = canonical_detection(
            "telltale-00000000-0000-4000-8000-000000000002",
            &second_session,
            &agent,
            &model,
            &provider,
            "2026-05-01T00:20:00Z",
        );
        let events = [&first, &second];

        let timelines = build_session_timelines(&events);
        assert_eq!(timelines.len(), 2);
        assert!(timelines.iter().any(|timeline| {
            timeline["session_id"] == first_session
                && timeline["agent"] == agent
                && timeline["model"] == model
                && timeline["provider"] == provider
        }));
        assert_eq!(build_session_timelines(&events), timelines);

        let correlations =
            correlation_events_from_filtered(&events).expect("historical correlation output");
        assert_eq!(correlations.len(), 1);
        let serialized = serde_json::to_string(&correlations).expect("correlation JSON");
        for marker in [&first_session, &second_session, &agent, &model, &provider] {
            assert!(
                serialized.contains(marker),
                "historical derived output rehashed a canonical marker"
            );
        }
        let repeated =
            correlation_events_from_filtered(&events).expect("repeat correlation output");
        let repeated_serialized =
            serde_json::to_string(&repeated).expect("repeated correlation JSON");
        for marker in [&first_session, &second_session, &agent, &model, &provider] {
            assert!(
                repeated_serialized.contains(marker),
                "repeated historical derived output rehashed a canonical marker"
            );
        }
    }
}
