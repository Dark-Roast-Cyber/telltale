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
mod tests;
