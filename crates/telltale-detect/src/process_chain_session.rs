//! Pure process-chain session semantics for Detection v2.
//!
//! This module deliberately knows nothing about Event3, canonical observations,
//! or DetectorResult. The canonical adapter supplies the facts required to
//! suppress repeats and walk compiled correlations, then adapts the decisions.

use std::collections::BTreeMap;

use telltale_rules::process_chain::CompiledProcessChainRules;
use time::{Duration, OffsetDateTime};

pub(crate) const DEFAULT_SUPPRESSION_WINDOW: Duration = Duration::hours(1);
pub(crate) const DEFAULT_MAX_CORRELATIONS_PER_RULE_ENTITY: usize = 1;
pub(crate) const DEFAULT_MAX_CORRELATION_RISK_PER_ENTITY: u64 = 150;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessChainSessionConfig {
    pub(crate) suppression_window: Duration,
    pub(crate) max_correlations_per_rule_entity: usize,
    pub(crate) max_correlation_risk_per_entity: u64,
}

impl Default for ProcessChainSessionConfig {
    fn default() -> Self {
        Self {
            suppression_window: DEFAULT_SUPPRESSION_WINDOW,
            max_correlations_per_rule_entity: DEFAULT_MAX_CORRELATIONS_PER_RULE_ENTITY,
            max_correlation_risk_per_entity: DEFAULT_MAX_CORRELATION_RISK_PER_ENTITY,
        }
    }
}

/// Caller-assigned identity for one outward atomic occurrence. Multiple private
/// matcher variants may share it without making child context part of repeat
/// suppression identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ProcessChainOccurrenceId(usize);

impl ProcessChainOccurrenceId {
    pub(crate) fn new(value: usize) -> Self {
        Self(value)
    }
}

/// The detector-neutral facts needed by repeat/correlation semantics.
///
/// `entity` is already resolved by the caller.  An absent entity or timestamp
/// intentionally makes only the timed session operation ineligible; the
/// caller still retains the atomic detection.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProcessChainSessionCandidate {
    pub(crate) occurrence_id: ProcessChainOccurrenceId,
    pub(crate) rule_id: String,
    pub(crate) category: String,
    pub(crate) child: String,
    pub(crate) dedupe_key: String,
    pub(crate) entity: Option<String>,
    pub(crate) occurred_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepeatSuppression {
    pub(crate) retained: Vec<usize>,
    pub(crate) repeat_counts: BTreeMap<usize, u64>,
    pub(crate) suppressed_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CorrelationDecision {
    pub(crate) rule_index: usize,
    pub(crate) candidate_indexes: Vec<usize>,
    pub(crate) effective_score: u64,
    pub(crate) risk_capped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessChainSessionSemantics {
    pub(crate) suppression: RepeatSuppression,
    pub(crate) correlations: Vec<CorrelationDecision>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SuppressionKey {
    rule_id: String,
    entity: String,
    dedupe_key: String,
}

/// Apply repeat suppression between atomic occurrences, retain every private
/// matcher variant associated with each retained occurrence, then evaluate
/// correlations over only those retained variants.
pub(crate) fn evaluate_process_chain_session(
    candidates: &[ProcessChainSessionCandidate],
    rules: &CompiledProcessChainRules,
    config: &ProcessChainSessionConfig,
) -> ProcessChainSessionSemantics {
    let suppression = suppress_repeats(candidates, config.suppression_window);
    let correlations = correlate_retained(
        candidates,
        &suppression.retained,
        rules,
        config.max_correlations_per_rule_entity,
        config.max_correlation_risk_per_entity,
    );
    ProcessChainSessionSemantics {
        suppression,
        correlations,
    }
}

/// Apply repeat suppression between atomic occurrences.
fn suppress_repeats(
    candidates: &[ProcessChainSessionCandidate],
    window: Duration,
) -> RepeatSuppression {
    let mut anchors: BTreeMap<SuppressionKey, (usize, OffsetDateTime, u64)> = BTreeMap::new();
    let mut retained_occurrences = BTreeMap::new();
    let mut retained = Vec::with_capacity(candidates.len());
    let mut repeat_counts = BTreeMap::new();
    let mut suppressed_count = 0;

    for (index, candidate) in candidates.iter().enumerate() {
        if let Some(&is_retained) = retained_occurrences.get(&candidate.occurrence_id) {
            if is_retained {
                retained.push(index);
            }
            continue;
        }

        let Some(entity) = candidate.entity.as_ref() else {
            retained_occurrences.insert(candidate.occurrence_id, true);
            retained.push(index);
            continue;
        };
        let Some(timestamp) = candidate.occurred_at else {
            retained_occurrences.insert(candidate.occurrence_id, true);
            retained.push(index);
            continue;
        };

        let key = SuppressionKey {
            rule_id: candidate.rule_id.clone(),
            entity: entity.clone(),
            dedupe_key: candidate.dedupe_key.clone(),
        };
        match anchors.get_mut(&key) {
            Some((anchor_index, anchor_time, count)) if timestamp - *anchor_time <= window => {
                *count += 1;
                repeat_counts.insert(*anchor_index, *count);
                suppressed_count += 1;
                retained_occurrences.insert(candidate.occurrence_id, false);
            }
            _ => {
                anchors.insert(key, (index, timestamp, 1));
                retained_occurrences.insert(candidate.occurrence_id, true);
                retained.push(index);
            }
        }
    }

    RepeatSuppression {
        retained,
        repeat_counts,
        suppressed_count,
    }
}

/// Walk the compiled correlation rules over a caller-selected retained set.
/// The rule slice order is authoritative for both output order and risk-cap
/// accounting.  Entity grouping is ordered to avoid map-iteration nondeterminism.
fn correlate_retained(
    candidates: &[ProcessChainSessionCandidate],
    retained: &[usize],
    rules: &CompiledProcessChainRules,
    max_correlations_per_rule_entity: usize,
    max_correlation_risk_per_entity: u64,
) -> Vec<CorrelationDecision> {
    let mut by_entity: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for &index in retained {
        let Some(candidate) = candidates.get(index) else {
            continue;
        };
        if candidate.occurred_at.is_none() {
            continue;
        }
        let Some(entity) = candidate.entity.as_deref() else {
            continue;
        };
        by_entity.entry(entity).or_default().push(index);
    }

    let mut decisions = Vec::new();
    for indexes in by_entity.values_mut() {
        // `sort_by` is stable: equal occurred_at values retain caller order.
        indexes.sort_by(|left, right| {
            candidates[*left]
                .occurred_at
                .cmp(&candidates[*right].occurred_at)
        });
    }

    for indexes in by_entity.values() {
        let mut entity_risk = 0_u64;
        for (rule_index, rule) in rules.correlations().iter().enumerate() {
            let sequences =
                find_sequences(rule, indexes, candidates, max_correlations_per_rule_entity);
            for candidate_indexes in sequences {
                let risk_capped =
                    entity_risk.saturating_add(rule.score) > max_correlation_risk_per_entity;
                let effective_score = if risk_capped { 0 } else { rule.score };
                if !risk_capped {
                    entity_risk = entity_risk.saturating_add(rule.score);
                }
                decisions.push(CorrelationDecision {
                    rule_index,
                    candidate_indexes,
                    effective_score,
                    risk_capped,
                });
            }
        }
    }
    decisions
}

fn find_sequences(
    rule: &telltale_rules::process_chain::CompiledCorrelationRule,
    indexes: &[usize],
    candidates: &[ProcessChainSessionCandidate],
    limit: usize,
) -> Vec<Vec<usize>> {
    let mut sequences = Vec::new();
    let window = Duration::seconds(rule.window_seconds as i64);

    for start in 0..indexes.len() {
        if sequences.len() >= limit {
            break;
        }
        let anchor_index = indexes[start];
        let Some(anchor) = candidates[anchor_index].occurred_at else {
            continue;
        };
        let mut step = 0;
        let mut matched = Vec::new();
        for &candidate_index in &indexes[start..] {
            let candidate = &candidates[candidate_index];
            let Some(timestamp) = candidate.occurred_at else {
                continue;
            };
            if timestamp - anchor > window {
                break;
            }
            let Some(current) = rule.steps.get(step) else {
                break;
            };
            if current.matches(&candidate.category, &candidate.rule_id, &candidate.child) {
                matched.push(candidate_index);
                step += 1;
                if step == rule.steps.len() {
                    break;
                }
            }
        }
        if step == rule.steps.len() {
            sequences.push(matched);
        }
    }
    sequences
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_rules::process_chain::load_process_chain_rules;

    fn candidate(
        occurrence_id: usize,
        rule_id: &str,
        category: &str,
        child: &str,
        dedupe_key: &str,
        entity: Option<&str>,
        occurred_at: Option<&str>,
    ) -> ProcessChainSessionCandidate {
        ProcessChainSessionCandidate {
            occurrence_id: ProcessChainOccurrenceId::new(occurrence_id),
            rule_id: rule_id.to_owned(),
            category: category.to_owned(),
            child: child.to_owned(),
            dedupe_key: dedupe_key.to_owned(),
            entity: entity.map(str::to_owned),
            occurred_at: occurred_at.map(|value| {
                OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                    .unwrap()
            }),
        }
    }

    #[test]
    fn all_shipped_correlation_contracts_use_the_session_kernel() {
        let rules = telltale_rules::process_chain::load_default_process_chain_rules().unwrap();
        // Fixed semantic facts, including stronger parent evidence unavailable
        // from Tool commands. These are kernel contracts, not runtime telemetry.
        let cases = [
            (
                "procchain.correlation.host_then_account_discovery",
                45,
                ("procchain.discovery.cmd_hostname", "discovery", "hostname"),
                ("procchain.discovery.cmd_whoami", "discovery", "whoami"),
            ),
            (
                "procchain.correlation.discovery_then_remote_exec",
                55,
                ("procchain.discovery.cmd_whoami", "discovery", "whoami"),
                (
                    "procchain.lateral.psexec_remote_exec",
                    "lateral_movement",
                    "psexec",
                ),
            ),
            (
                "procchain.correlation.archive_then_cloud_transfer",
                65,
                ("procchain.collection.cmd_7za", "collection", "7za"),
                ("procchain.exfil.cmd_rclone", "exfiltration", "rclone"),
            ),
            (
                "procchain.correlation.office_script_then_download",
                70,
                (
                    "procchain.execution.winword_powershell",
                    "execution",
                    "powershell",
                ),
                (
                    "procchain.c2.certutil_download_cradle",
                    "command_and_control",
                    "certutil",
                ),
            ),
            (
                "procchain.correlation.webshell_then_discovery",
                80,
                ("procchain.execution.w3wp_cmd", "execution", "cmd"),
                ("procchain.discovery.cmd_whoami", "discovery", "whoami"),
            ),
            (
                "procchain.correlation.rmm_then_credential_or_evasion",
                60,
                (
                    "procchain.c2.anydesk_powershell",
                    "command_and_control",
                    "powershell",
                ),
                (
                    "procchain.credaccess.credential_dump_command",
                    "credential_access",
                    "procdump",
                ),
            ),
        ];
        assert_eq!(rules.correlations().len(), cases.len());
        for (id, score, first, second) in cases {
            let candidates = [
                candidate(
                    0,
                    first.0,
                    first.1,
                    first.2,
                    "first",
                    Some("synthetic-session"),
                    Some("2026-01-01T00:00:00Z"),
                ),
                candidate(
                    1,
                    second.0,
                    second.1,
                    second.2,
                    "second",
                    Some("synthetic-session"),
                    Some("2026-01-01T00:00:00Z"),
                ),
            ];
            let config = ProcessChainSessionConfig::default();
            let result = evaluate_process_chain_session(&candidates, &rules, &config);
            let decision = result
                .correlations
                .iter()
                .find(|d| rules.correlations()[d.rule_index].id == id)
                .expect(id);
            assert_eq!(decision.effective_score, score, "{id}");
            assert_eq!(decision.candidate_indexes, [0, 1], "{id}");
            assert!(!decision.risk_capped, "{id}");
            let reversed = [candidates[1].clone(), candidates[0].clone()];
            assert!(
                evaluate_process_chain_session(&reversed, &rules, &config)
                    .correlations
                    .iter()
                    .all(|d| rules.correlations()[d.rule_index].id != id),
                "{id}"
            );
        }
    }

    #[test]
    fn suppression_groups_by_rule_entity_and_matcher_key() {
        let candidates = vec![
            candidate(
                0,
                "rule.a",
                "discovery",
                "hostname",
                "chain:cmd>hostname",
                Some("session:a"),
                Some("2026-01-01T00:00:00Z"),
            ),
            candidate(
                1,
                "rule.a",
                "discovery",
                "hostname",
                "chain:cmd>hostname",
                Some("session:a"),
                Some("2026-01-01T00:30:00Z"),
            ),
            candidate(
                2,
                "rule.a",
                "discovery",
                "hostname",
                "chain:cmd>hostname",
                Some("session:b"),
                Some("2026-01-01T00:30:00Z"),
            ),
            candidate(
                3,
                "rule.b",
                "discovery",
                "hostname",
                "chain:cmd>hostname",
                Some("session:a"),
                Some("2026-01-01T00:30:00Z"),
            ),
        ];
        let result = suppress_repeats(&candidates, Duration::hours(1));
        assert_eq!(result.retained, [0, 2, 3]);
        assert_eq!(result.repeat_counts[&0], 2);
        assert_eq!(result.suppressed_count, 1);
    }

    #[test]
    fn missing_time_or_entity_remains_atomic_only() {
        let candidates = vec![
            candidate(
                0,
                "rule.a",
                "discovery",
                "hostname",
                "same",
                Some("session:a"),
                None,
            ),
            candidate(
                1,
                "rule.a",
                "discovery",
                "hostname",
                "same",
                None,
                Some("2026-01-01T00:00:00Z"),
            ),
        ];
        let result = suppress_repeats(&candidates, Duration::hours(1));
        assert_eq!(result.retained, [0, 1]);
        assert!(result.repeat_counts.is_empty());
    }

    #[test]
    fn correlation_uses_authored_rule_order_for_risk_cap() {
        let rules = load_process_chain_rules(
            r#"
version: 1
description: order
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
  lateral_movement: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone: []
correlations:
  - { id: procchain.correlation.first, title: first, category: discovery, severity: medium, score: 45, confidence: high, reason: first, window_seconds: 60, entity: host, sequence: [{ any_category: [discovery] }, { any_category: [lateral_movement] }] }
  - { id: procchain.correlation.second, title: second, category: discovery, severity: high, score: 55, confidence: high, reason: second, window_seconds: 60, entity: host, sequence: [{ any_category: [discovery] }, { any_category: [lateral_movement] }] }
"#,
        )
        .unwrap();
        let candidates = vec![
            candidate(
                0,
                "rule.discovery",
                "discovery",
                "hostname",
                "a",
                Some("session:a"),
                Some("2026-01-01T00:00:00Z"),
            ),
            candidate(
                1,
                "rule.remote",
                "lateral_movement",
                "psexec",
                "b",
                Some("session:a"),
                Some("2026-01-01T00:01:00Z"),
            ),
        ];
        let result = evaluate_process_chain_session(
            &candidates,
            &rules,
            &ProcessChainSessionConfig {
                max_correlation_risk_per_entity: 50,
                ..Default::default()
            },
        );
        assert_eq!(result.correlations.len(), 2);
        assert_eq!(result.correlations[0].rule_index, 0);
        assert_eq!(result.correlations[0].effective_score, 45);
        assert_eq!(result.correlations[1].rule_index, 1);
        assert!(result.correlations[1].risk_capped);
        assert_eq!(result.correlations[1].effective_score, 0);
    }

    #[test]
    fn risk_cap_isolated_by_entity() {
        let rules = load_process_chain_rules(
            r#"
version: 1
description: entity isolation
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
  lateral_movement: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone: []
correlations:
  - { id: procchain.correlation.one, title: one, category: discovery, severity: high, score: 55, confidence: high, reason: one, window_seconds: 60, entity: host, sequence: [{ any_category: [discovery] }, { any_category: [lateral_movement] }] }
"#,
        )
        .unwrap();
        let candidates = vec![
            candidate(
                0,
                "rule.discovery",
                "discovery",
                "hostname",
                "a1",
                Some("session:a"),
                Some("2026-01-01T00:00:00Z"),
            ),
            candidate(
                1,
                "rule.remote",
                "lateral_movement",
                "psexec",
                "a2",
                Some("session:a"),
                Some("2026-01-01T00:01:00Z"),
            ),
            candidate(
                2,
                "rule.discovery",
                "discovery",
                "hostname",
                "b1",
                Some("session:b"),
                Some("2026-01-01T00:00:00Z"),
            ),
            candidate(
                3,
                "rule.remote",
                "lateral_movement",
                "psexec",
                "b2",
                Some("session:b"),
                Some("2026-01-01T00:01:00Z"),
            ),
        ];
        let result = evaluate_process_chain_session(
            &candidates,
            &rules,
            &ProcessChainSessionConfig {
                max_correlation_risk_per_entity: 55,
                ..Default::default()
            },
        );
        assert_eq!(result.correlations.len(), 2);
        assert!(
            result
                .correlations
                .iter()
                .all(|decision| !decision.risk_capped && decision.effective_score == 55)
        );
    }
}
