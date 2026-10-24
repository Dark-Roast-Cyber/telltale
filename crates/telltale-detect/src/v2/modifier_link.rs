//! Declared chain links: which matched observations a modifier with a `link`
//! may combine. Session scoring and action findings share this search.

use super::session::{ProcessingError, RetentionBudget};
use std::collections::{BTreeMap, BTreeSet};
use telltale_rules::{
    ModifierLink, ModifierLinkOrder, RuleV1CompatibilityExport, RuleV1CompatibilityModifier,
};
use telltale_schema::observation::{CanonicalObservationV2, ObservationBody, ObservationStage};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// The rule IDs and categories one observation matched.
#[derive(Debug, Default)]
pub(super) struct Step {
    pub(super) time: Option<OffsetDateTime>,
    pub(super) ids: BTreeSet<String>,
    pub(super) categories: BTreeSet<String>,
}

/// Matched observations keyed by (tool-call position, observation index).
pub(super) type Steps = BTreeMap<(usize, usize), Step>;

/// The tool-call position of each observation. A call and its result share a
/// position through their call ID. A tool record without one starts a new call,
/// or joins the previous call when it is a result. Messages and other records
/// take the position of the next call, so they add no distance.
pub(super) fn call_positions(
    observations: &[&CanonicalObservationV2],
    budget: &mut RetentionBudget,
) -> Result<Vec<usize>, ProcessingError> {
    let mut calls = BTreeMap::new();
    let mut next = 0usize;
    let mut positions = Vec::with_capacity(observations.len());
    for observation in observations {
        let position = match (observation.body(), observation.correlation().call_id()) {
            (ObservationBody::Tool(_), Some(id)) => {
                budget.charge(id.value().len())?;
                *calls.entry(id.value()).or_insert_with(|| {
                    next += 1;
                    next - 1
                })
            }
            (ObservationBody::Tool(_), None)
                if observation.stage() == ObservationStage::ToolResultReturned =>
            {
                next.saturating_sub(1)
            }
            (ObservationBody::Tool(_), None) => {
                next += 1;
                next - 1
            }
            _ => next,
        };
        positions.push(position);
    }
    Ok(positions)
}

/// A session's matched observations as steps. `occurrences` maps each matched
/// rule ID to the observations it matched.
pub(super) fn session_steps(
    export: &RuleV1CompatibilityExport,
    occurrences: &BTreeMap<String, Vec<usize>>,
    observations: &[&CanonicalObservationV2],
    budget: &mut RetentionBudget,
) -> Result<Steps, ProcessingError> {
    let positions = call_positions(observations, budget)?;
    let mut steps = Steps::new();
    for (id, indexes) in occurrences {
        let category = export
            .rules()
            .iter()
            .find(|rule| &rule.id == id)
            .map(|rule| rule.category.clone());
        for &index in indexes {
            budget.charge(1)?;
            let (Some(&position), Some(observation)) =
                (positions.get(index), observations.get(index))
            else {
                return Err(ProcessingError::Bounds);
            };
            let step = match steps.entry((position, index)) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let time = match observation.occurred_at() {
                        Some(time) => {
                            budget.charge(time.as_str().len())?;
                            OffsetDateTime::parse(time.as_str(), &Rfc3339).ok()
                        }
                        None => None,
                    };
                    entry.insert(Step {
                        time,
                        ..Step::default()
                    })
                }
            };
            step.ids.insert(id.clone());
            step.categories.extend(category.clone());
        }
    }
    Ok(steps)
}

/// The observations that link `modifier`'s steps when the step at `end`
/// completes them, one per requirement (categories, then rule IDs). Every step
/// is `end` or an earlier observation; all lie within `link.calls` calls of
/// each other, in declared order unless the link allows any order, and within
/// `link.minutes` of `end` when both have a source time. One observation may
/// fill several steps. `first` filters the observation for the first
/// requirement, so one start completes a chain once.
pub(super) fn support(
    modifier: &RuleV1CompatibilityModifier,
    link: &ModifierLink,
    steps: &Steps,
    end: (usize, usize),
    first: impl Fn(usize) -> bool,
    remaining_work: &mut usize,
) -> Result<Option<Vec<usize>>, ProcessingError> {
    let requirements = modifier
        .when_all_categories
        .iter()
        .map(|s| (true, s.as_str()))
        .chain(
            modifier
                .when_all_rule_ids
                .iter()
                .map(|s| (false, s.as_str())),
        )
        .collect::<Vec<_>>();
    let Some(last) = steps.get(&end) else {
        return Ok(None);
    };
    let calls = usize::try_from(link.calls).map_err(|_| ProcessingError::Bounds)?;
    let lowest = (end.0.saturating_sub(calls), 0);
    let highest = (
        end.0.checked_add(calls).ok_or(ProcessingError::Bounds)?,
        usize::MAX,
    );
    let mut eligible = |requirement: usize, key: (usize, usize), step: &Step| {
        *remaining_work = remaining_work
            .checked_sub(1)
            .ok_or(ProcessingError::Bounds)?;
        let (category, name) = requirements[requirement];
        Ok::<_, ProcessingError>(
            key.1 <= end.1
                && (requirement != 0 || first(key.1))
                && if category {
                    step.categories.contains(name)
                } else {
                    step.ids.contains(name)
                }
                && match (link.minutes, step.time, last.time) {
                    (Some(minutes), Some(time), Some(end_time)) => {
                        (end_time - time).abs() <= Duration::minutes(minutes.into())
                    }
                    _ => true,
                },
        )
    };
    for own in 0..requirements.len() {
        if !eligible(own, end, last)? {
            continue;
        }
        let mut chosen = vec![end; requirements.len()];
        let linked = match link.order {
            // Earlier requirements take the latest earlier step, later ones the
            // earliest later step: the narrowest span on each side.
            ModifierLinkOrder::Declared => {
                let mut complete = true;
                let mut bound = end;
                for requirement in (0..own).rev() {
                    let mut found = None;
                    for (key, step) in steps.range(lowest..=bound).rev() {
                        if eligible(requirement, *key, step)? {
                            found = Some(*key);
                            break;
                        }
                    }
                    let Some(key) = found else {
                        complete = false;
                        break;
                    };
                    chosen[requirement] = key;
                    bound = key;
                }
                bound = end;
                for (requirement, slot) in chosen.iter_mut().enumerate().skip(own + 1) {
                    if !complete {
                        break;
                    }
                    let mut found = None;
                    for (key, step) in steps.range(bound..=highest) {
                        if eligible(requirement, *key, step)? {
                            found = Some(*key);
                            break;
                        }
                    }
                    let Some(key) = found else {
                        complete = false;
                        break;
                    };
                    *slot = key;
                    bound = key;
                }
                complete && chosen[chosen.len() - 1].0 - chosen[0].0 <= calls
            }
            // Each requirement takes its nearest step on either side; a split
            // links when the farthest left and farthest right fit the window.
            ModifierLinkOrder::Any => {
                let mut nearest = Vec::new();
                for requirement in (0..requirements.len()).filter(|&r| r != own) {
                    let mut left = None;
                    for (key, step) in steps.range(lowest..=end).rev() {
                        if eligible(requirement, *key, step)? {
                            left = Some(*key);
                            break;
                        }
                    }
                    let mut right = None;
                    for (key, step) in steps.range(end..=highest) {
                        if eligible(requirement, *key, step)? {
                            right = Some(*key);
                            break;
                        }
                    }
                    nearest.push((requirement, left, right));
                }
                let mut split = None;
                for reach in std::iter::once(0).chain(
                    nearest
                        .iter()
                        .filter_map(|(_, left, _)| left.map(|key| end.0 - key.0)),
                ) {
                    let right = nearest
                        .iter()
                        .map(|(_, left, right)| match left {
                            Some(key) if end.0 - key.0 <= reach => Some(0),
                            _ => right.map(|key| key.0 - end.0),
                        })
                        .try_fold(0, |farthest, distance| distance.map(|d| d.max(farthest)));
                    if right.is_some_and(|right| reach + right <= calls) {
                        split = Some(reach);
                        break;
                    }
                }
                if let Some(reach) = split {
                    for (requirement, left, right) in &nearest {
                        chosen[*requirement] = match left {
                            Some(key) if end.0 - key.0 <= reach => *key,
                            _ => right.ok_or(ProcessingError::Evaluation)?,
                        };
                    }
                }
                split.is_some()
            }
        };
        if linked {
            return Ok(Some(chosen.into_iter().map(|key| key.1).collect()));
        }
    }
    Ok(None)
}

/// Whether any observation in the session completes `modifier`'s link.
pub(super) fn linked_in_session(
    modifier: &RuleV1CompatibilityModifier,
    link: &ModifierLink,
    steps: &Steps,
) -> Result<bool, ProcessingError> {
    let mut remaining_work = 1_000_000usize;
    for &end in steps.keys() {
        if support(modifier, link, steps, end, |_| true, &mut remaining_work)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}
