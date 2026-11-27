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
#[cfg(test)]
pub(crate) fn evaluate_process_chain_session(
    candidates: &[ProcessChainSessionCandidate],
    rules: &CompiledProcessChainRules,
    config: &ProcessChainSessionConfig,
) -> ProcessChainSessionSemantics {
    try_evaluate_process_chain_session(candidates, rules, config, &mut |_| {
        Ok::<_, std::convert::Infallible>(())
    })
    .expect("infallible session charge")
}

pub(crate) fn try_evaluate_process_chain_session<E>(
    candidates: &[ProcessChainSessionCandidate],
    rules: &CompiledProcessChainRules,
    config: &ProcessChainSessionConfig,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<ProcessChainSessionSemantics, E> {
    let suppression = suppress_repeats(candidates, config.suppression_window, charge)?;
    let correlations = correlate_retained(
        candidates,
        &suppression.retained,
        rules,
        config.max_correlations_per_rule_entity,
        config.max_correlation_risk_per_entity,
        charge,
    )?;
    Ok(ProcessChainSessionSemantics {
        suppression,
        correlations,
    })
}

/// Apply repeat suppression between atomic occurrences.
fn suppress_repeats<E>(
    candidates: &[ProcessChainSessionCandidate],
    window: Duration,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<RepeatSuppression, E> {
    let mut anchors: BTreeMap<SuppressionKey, (usize, OffsetDateTime, u64)> = BTreeMap::new();
    let mut retained_occurrences = BTreeMap::new();
    let mut retained = Vec::with_capacity(candidates.len());
    let mut repeat_counts = BTreeMap::new();
    let mut suppressed_count = 0;

    for (index, candidate) in candidates.iter().enumerate() {
        charge(
            candidate
                .rule_id
                .len()
                .saturating_add(candidate.entity.as_ref().map_or(0, String::len))
                .saturating_add(candidate.dedupe_key.len()),
        )?;
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

    Ok(RepeatSuppression {
        retained,
        repeat_counts,
        suppressed_count,
    })
}

/// Walk the compiled correlation rules over a caller-selected retained set.
/// The rule slice order is authoritative for both output order and risk-cap
/// accounting.  Entity grouping is ordered to avoid map-iteration nondeterminism.
fn correlate_retained<E>(
    candidates: &[ProcessChainSessionCandidate],
    retained: &[usize],
    rules: &CompiledProcessChainRules,
    max_correlations_per_rule_entity: usize,
    max_correlation_risk_per_entity: u64,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<Vec<CorrelationDecision>, E> {
    let mut by_entity: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for &index in retained {
        charge(1)?;
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
        charge(indexes.len().saturating_mul(indexes.len()))?;
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
            let sequences = find_sequences(
                rule,
                indexes,
                candidates,
                max_correlations_per_rule_entity,
                charge,
            )?;
            for candidate_indexes in sequences {
                charge(candidate_indexes.len())?;
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
    Ok(decisions)
}

fn find_sequences<E>(
    rule: &telltale_rules::process_chain::CompiledCorrelationRule,
    indexes: &[usize],
    candidates: &[ProcessChainSessionCandidate],
    limit: usize,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<Vec<Vec<usize>>, E> {
    let mut sequences = Vec::new();
    let window = Duration::seconds(rule.window_seconds as i64);

    for start in 0..indexes.len() {
        charge(1)?;
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
            charge(1)?;
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
            charge(
                candidate
                    .category
                    .len()
                    .saturating_add(candidate.rule_id.len())
                    .saturating_add(candidate.child.len()),
            )?;
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
    Ok(sequences)
}

/// A completion-anchored sequence for streaming action correlations. Work is
/// explicitly debited even for candidates that cannot satisfy a predecessor.
pub(crate) fn ordered_predecessors(
    end_index: usize,
    window: Duration,
    steps: usize,
    timestamp: impl Fn(usize) -> OffsetDateTime,
    matches: impl Fn(usize, usize) -> bool,
    remaining_work: &mut usize,
) -> Result<Option<Vec<usize>>, ()> {
    if steps == 0 || !matches(steps - 1, end_index) {
        return Ok(None);
    }
    let end = timestamp(end_index);
    let mut previous = end;
    let mut support = Vec::with_capacity(steps);
    let mut step = steps - 1;
    for index in (0..=end_index).rev() {
        *remaining_work = remaining_work.checked_sub(1).ok_or(())?;
        let time = timestamp(index);
        if time > previous || end - time > window {
            continue;
        }
        if matches(step, index) {
            support.push(index);
            previous = time;
            if step == 0 {
                support.reverse();
                return Ok(Some(support));
            }
            step -= 1;
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
