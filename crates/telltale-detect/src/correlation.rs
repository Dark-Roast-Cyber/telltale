//! Cross-session correlation helpers for detection events.
//!
//! This module is intentionally side-effect free. It gives the scan/export
//! layers a tested way to find repeated suspicious patterns and emit dedicated
//! correlation events without changing the input detections.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use time::{Duration, OffsetDateTime};

use telltale_schema::event::{
    CorrelationEventInput, CorrelationSessionInput, Event, correlation_event,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationConfig {
    pub window: Duration,
    pub min_sessions: usize,
    pub min_risk_score: u64,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            window: Duration::hours(1),
            min_sessions: 2,
            min_risk_score: 70,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ActorKey {
    pub client: String,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CorrelatedSession {
    pub session_id: String,
    pub event_id: String,
    pub timestamp: String,
    pub severity: String,
    pub risk_score: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrossSessionCorrelation {
    pub actor: ActorKey,
    pub shared_rule_ids: Vec<String>,
    pub sessions: Vec<CorrelatedSession>,
    pub window_start: String,
    pub window_end: String,
    pub max_risk_score: u64,
}

#[derive(Debug, Clone)]
struct Candidate<'a> {
    event: &'a Event,
    timestamp: OffsetDateTime,
}

pub fn correlate_detection_events(
    events: &[Event],
    config: &CorrelationConfig,
) -> Vec<CrossSessionCorrelation> {
    if config.min_sessions < 2 {
        return Vec::new();
    }

    let mut groups: BTreeMap<(ActorKey, String), Vec<Candidate<'_>>> = BTreeMap::new();
    for event in events {
        if event.event_type != "detection" || event.risk_score < config.min_risk_score {
            continue;
        }
        let Ok(timestamp) = OffsetDateTime::parse(
            &event.timestamp,
            &time::format_description::well_known::Rfc3339,
        ) else {
            continue;
        };
        let actor = actor_key(event);
        for rule_id in &event.rule_ids {
            groups
                .entry((actor.clone(), rule_id.clone()))
                .or_default()
                .push(Candidate { event, timestamp });
        }
    }

    let mut correlations = aggregate_correlations(
        groups
            .into_iter()
            .filter_map(|((actor, rule_id), mut candidates)| {
                candidates.sort_by_key(|candidate| candidate.timestamp);
                correlate_rule_window(actor, rule_id, candidates, config)
            })
            .collect(),
    );
    correlations.sort_by(|left, right| {
        left.window_start
            .cmp(&right.window_start)
            .then(left.actor.cmp(&right.actor))
            .then(left.shared_rule_ids.cmp(&right.shared_rule_ids))
    });
    correlations
}

fn aggregate_correlations(
    correlations: Vec<CrossSessionCorrelation>,
) -> Vec<CrossSessionCorrelation> {
    let mut aggregated: BTreeMap<
        (ActorKey, Vec<CorrelatedSession>, String, String, u64),
        CrossSessionCorrelation,
    > = BTreeMap::new();

    for mut correlation in correlations {
        correlation.shared_rule_ids.sort();
        correlation.shared_rule_ids.dedup();
        let key = (
            correlation.actor.clone(),
            correlation.sessions.clone(),
            correlation.window_start.clone(),
            correlation.window_end.clone(),
            correlation.max_risk_score,
        );
        if let Some(existing) = aggregated.get_mut(&key) {
            existing.shared_rule_ids.extend(correlation.shared_rule_ids);
            existing.shared_rule_ids.sort();
            existing.shared_rule_ids.dedup();
        } else {
            aggregated.insert(key, correlation);
        }
    }

    aggregated.into_values().collect()
}

pub fn correlation_events_from_detections(
    events: &[Event],
    config: &CorrelationConfig,
) -> Result<Vec<Event>, telltale_schema::scoring::RiskAccountingError> {
    correlate_detection_events(events, config)
        .into_iter()
        .map(correlation_to_event)
        .collect()
}

fn correlate_rule_window(
    actor: ActorKey,
    rule_id: String,
    candidates: Vec<Candidate<'_>>,
    config: &CorrelationConfig,
) -> Option<CrossSessionCorrelation> {
    let mut best: Option<&[Candidate<'_>]> = None;
    let mut start = 0;

    for end in 0..candidates.len() {
        while candidates[end].timestamp - candidates[start].timestamp > config.window {
            start += 1;
        }
        let window = &candidates[start..=end];
        if unique_session_count(window) >= config.min_sessions
            && best.is_none_or(|current| window.len() > current.len())
        {
            best = Some(window);
        }
    }

    let best = best?;
    let sessions = correlated_sessions(best);
    let first = best.first()?.timestamp;
    let last = best.last()?.timestamp;
    let max_risk_score = best
        .iter()
        .map(|candidate| candidate.event.risk_score)
        .max()
        .unwrap_or_default();

    Some(CrossSessionCorrelation {
        actor,
        shared_rule_ids: vec![rule_id],
        sessions,
        window_start: format_timestamp(first),
        window_end: format_timestamp(last),
        max_risk_score,
    })
}

fn actor_key(event: &Event) -> ActorKey {
    ActorKey {
        client: event.client.clone(),
        agent: event.agent.clone(),
        model: event.model.clone(),
        provider: event.provider.clone(),
    }
}

fn unique_session_count(candidates: &[Candidate<'_>]) -> usize {
    candidates
        .iter()
        .map(|candidate| candidate.event.session_id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

fn correlated_sessions(candidates: &[Candidate<'_>]) -> Vec<CorrelatedSession> {
    let mut seen = BTreeSet::new();
    candidates
        .iter()
        .filter_map(|candidate| {
            if !seen.insert(candidate.event.session_id.as_str()) {
                return None;
            }
            Some(CorrelatedSession {
                session_id: candidate.event.session_id.clone(),
                event_id: candidate.event.event_id.clone(),
                timestamp: format_timestamp(candidate.timestamp),
                severity: candidate.event.severity.clone(),
                risk_score: candidate.event.risk_score,
            })
        })
        .collect()
}

fn format_timestamp(timestamp: OffsetDateTime) -> String {
    timestamp
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 timestamp")
}

fn correlation_to_event(
    correlation: CrossSessionCorrelation,
) -> Result<Event, telltale_schema::scoring::RiskAccountingError> {
    correlation_event(CorrelationEventInput {
        client: correlation.actor.client,
        agent: correlation.actor.agent,
        model: correlation.actor.model,
        provider: correlation.actor.provider,
        shared_rule_ids: correlation.shared_rule_ids,
        sessions: correlation
            .sessions
            .into_iter()
            .map(|session| CorrelationSessionInput {
                session_id: session.session_id,
                event_id: session.event_id,
                timestamp: session.timestamp,
                severity: session.severity,
                risk_score: session.risk_score,
            })
            .collect(),
        window_start: correlation.window_start,
        window_end: correlation.window_end,
        max_risk_score: correlation.max_risk_score,
    })
}

#[cfg(test)]
mod tests {
    use telltale_schema::event::Event;

    use super::*;

    fn detection_event(
        session_id: &str,
        timestamp: &str,
        rule_ids: &[&str],
        model: Option<&str>,
        risk_score: u64,
    ) -> Event {
        let event_number = session_id.bytes().fold(0_u64, |total, byte| {
            total.wrapping_mul(31).wrapping_add(u64::from(byte))
        });
        Event {
            timestamp: timestamp.to_string(),
            event_time: Some(timestamp.to_string()),
            observed_at: timestamp.to_string(),
            ingested_at: timestamp.to_string(),
            time_source: "source".to_string(),
            time_confidence: "high".to_string(),
            time_override_reason: None,
            schema_version: "3.0".to_string(),
            event_id: format!("telltale-00000000-0000-4000-8000-{event_number:012x}"),
            telltale_version: env!("CARGO_PKG_VERSION").to_string(),
            event_type: "detection".to_string(),
            severity: "high".to_string(),
            risk_score,
            risk_contributions: Vec::new(),
            client: "codex".to_string(),
            agent: Some("codex".to_string()),
            model: model.map(ToOwned::to_owned),
            provider: Some("openai".to_string()),
            session_id: session_id.to_string(),
            workspace: None,
            source_path_hash: Some("sha256:source".to_string()),
            tool_name: Some("shell".to_string()),
            rule_ids: rule_ids
                .iter()
                .map(|rule_id| (*rule_id).to_string())
                .collect(),
            categories: vec!["mcp_prompt_injection".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
            atlas_tags: vec!["atlas:AML.T0051".to_string()],
            tags: vec!["mcp".to_string()],
            evidence: Vec::new(),
            timeline_anchors: Vec::new(),
            response: None,
            source_counts: None,
            component: None,
            check_name: None,
            status: None,
            scan_duration_ms: None,
            rule_count: None,
            threshold_config: None,
            active_policy_name: None,
            emitted_count: None,
            suppressed_count: None,
            scanner_error_count: None,
            informational: None,
            confidence: None,
            detection_reason: None,
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: None,
            risk_entity_value: None,
            process: None,
        }
    }

    #[test]
    fn correlates_matching_detections_across_sessions_in_window() {
        let events = vec![
            detection_event(
                "session-a",
                "2026-05-10T10:00:00Z",
                &["mcp.tool_metadata.prompt_injection"],
                Some("gpt-5"),
                90,
            ),
            detection_event(
                "session-b",
                "2026-05-10T10:20:00Z",
                &[
                    "mcp.tool_metadata.prompt_injection",
                    "network.controlled_test_domain.darkroast",
                ],
                Some("gpt-5"),
                95,
            ),
        ];

        let correlations = correlate_detection_events(&events, &CorrelationConfig::default());

        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].actor.client, "codex");
        assert_eq!(correlations[0].actor.model.as_deref(), Some("gpt-5"));
        assert_eq!(
            correlations[0].shared_rule_ids,
            vec!["mcp.tool_metadata.prompt_injection".to_string()]
        );
        assert_eq!(correlations[0].sessions.len(), 2);
        assert_eq!(correlations[0].max_risk_score, 95);
    }

    #[test]
    fn ignores_repeated_rule_hits_in_same_session() {
        let events = vec![
            detection_event(
                "session-a",
                "2026-05-10T10:00:00Z",
                &["mcp.tool_metadata.prompt_injection"],
                Some("gpt-5"),
                90,
            ),
            detection_event(
                "session-a",
                "2026-05-10T10:10:00Z",
                &["mcp.tool_metadata.prompt_injection"],
                Some("gpt-5"),
                95,
            ),
        ];

        let correlations = correlate_detection_events(&events, &CorrelationConfig::default());

        assert!(correlations.is_empty());
    }

    #[test]
    fn requires_matching_actor_and_window() {
        let events = vec![
            detection_event(
                "session-a",
                "2026-05-10T10:00:00Z",
                &["mcp.tool_metadata.prompt_injection"],
                Some("gpt-5"),
                90,
            ),
            detection_event(
                "session-b",
                "2026-05-10T10:30:00Z",
                &["mcp.tool_metadata.prompt_injection"],
                Some("other-model"),
                95,
            ),
            detection_event(
                "session-c",
                "2026-05-10T12:30:00Z",
                &["mcp.tool_metadata.prompt_injection"],
                Some("gpt-5"),
                95,
            ),
        ];

        let correlations = correlate_detection_events(&events, &CorrelationConfig::default());

        assert!(correlations.is_empty());
    }

    #[test]
    fn ignores_low_risk_and_malformed_timestamp_events() {
        let events = vec![
            detection_event(
                "session-a",
                "2026-05-10T10:00:00Z",
                &["mcp.tool_metadata.prompt_injection"],
                Some("gpt-5"),
                40,
            ),
            detection_event(
                "session-b",
                "not-a-timestamp",
                &["mcp.tool_metadata.prompt_injection"],
                Some("gpt-5"),
                95,
            ),
        ];

        let correlations = correlate_detection_events(&events, &CorrelationConfig::default());

        assert!(correlations.is_empty());
    }

    #[test]
    fn aggregates_shared_rule_ids_for_identical_actor_windows() {
        let events = vec![
            detection_event(
                "session-a",
                "2026-05-10T10:00:00Z",
                &[
                    "mcp.tool_metadata.prompt_injection",
                    "network.controlled_test_domain.darkroast",
                ],
                Some("gpt-5"),
                90,
            ),
            detection_event(
                "session-b",
                "2026-05-10T10:20:00Z",
                &[
                    "mcp.tool_metadata.prompt_injection",
                    "network.controlled_test_domain.darkroast",
                ],
                Some("gpt-5"),
                95,
            ),
        ];

        let correlations = correlate_detection_events(&events, &CorrelationConfig::default());

        assert_eq!(correlations.len(), 1);
        assert_eq!(
            correlations[0].shared_rule_ids,
            vec![
                "mcp.tool_metadata.prompt_injection".to_string(),
                "network.controlled_test_domain.darkroast".to_string(),
            ]
        );
        assert_eq!(correlations[0].sessions.len(), 2);
    }

    #[test]
    fn builds_schema_shaped_correlation_events() {
        let detections = vec![
            detection_event(
                "session-a",
                "2026-05-10T10:00:00Z",
                &[
                    "mcp.tool_metadata.prompt_injection",
                    "network.controlled_test_domain.darkroast",
                ],
                Some("gpt-5"),
                90,
            ),
            detection_event(
                "session-b",
                "2026-05-10T10:20:00Z",
                &[
                    "mcp.tool_metadata.prompt_injection",
                    "network.controlled_test_domain.darkroast",
                ],
                Some("gpt-5"),
                95,
            ),
        ];

        let events = correlation_events_from_detections(&detections, &CorrelationConfig::default())
            .expect("correlation events");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "correlation");
        assert_eq!(events[0].client, "codex");
        assert_eq!(events[0].session_id, "correlation");
        assert_eq!(
            events[0].rule_ids,
            vec![
                "mcp.tool_metadata.prompt_injection",
                "network.controlled_test_domain.darkroast",
            ]
        );
        assert_eq!(events[0].categories, vec!["cross_session_correlation"]);
        assert_eq!(events[0].risk_score, 95);
        assert_eq!(
            events[0]
                .evidence
                .iter()
                .filter(|item| item.field == "related_detection")
                .count(),
            2
        );
    }
}
