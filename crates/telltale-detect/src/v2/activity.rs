//! Source-atomic activity/baseline projection from acquired accounting.
//! Coverage is necessary evidence, never permission to install scanner state.

use super::session::RetentionBudget;
use super::{CanonicalSourceEvaluation, ProcessingError};
use crate::baseline::{
    self, BaselineDeviationConfig, BaselineKey, BaselineSnapshotStore, BaselineSummary,
    assess_baseline_deviation, baseline_snapshot_id,
};
use std::collections::{BTreeMap, BTreeSet};
use telltale_schema::event::Evidence;
use telltale_schema::event::{
    ActivityEventInput, Event, activity_event, evidence_hash, is_canonical_sha256_hex,
};
use telltale_schema::scoring::{RiskAccountingError, RiskContribution, RiskContributionType};
use telltale_sources::acquisition::{AccountingCoverage, RecordCounts, SourceAccounting};

#[derive(Debug, PartialEq, Eq)]
pub enum BaselineReplacement {
    NoReplacement,
    /// Entire current contribution under canonical eligibility policy; empty
    /// explicitly removes stale contributions rather than preserving them.
    Replace(Vec<BaselineSummary>),
}

pub struct ActivityBaselineResult {
    pub events: Vec<Event>,
    pub replacement: BaselineReplacement,
}

pub fn evaluate_activity(
    evaluation: &CanonicalSourceEvaluation,
    accounting: &SourceAccounting,
    source_path_hash: &str,
    prior: &BaselineSnapshotStore,
    config: BaselineDeviationConfig,
) -> Result<ActivityBaselineResult, ProcessingError> {
    if !is_canonical_sha256_hex(source_path_hash) {
        return Err(ProcessingError::Projection);
    }
    let mut identities = BTreeSet::new();
    let mut budget = RetentionBudget::new();
    let mut events = Vec::new();
    let mut summaries = BTreeMap::<BaselineKey, BaselineSummary>::new();
    for session in &accounting.sessions {
        // Event3 erases origin. Reject collisions across the entire accounting
        // population, including sessions with no emitted observations.
        if !identities.insert(session.session_id.value())
            || evaluation.sessions().iter().any(|evaluated| {
                evaluated.session_id().is_some_and(|id| {
                    id.value() == session.session_id.value() && id != &session.session_id
                })
            })
        {
            return Err(ProcessingError::Projection);
        }
        budget.consume(1, 0)?;
        budget.retain_text(session.session_id.value())?;
        let metadata = &session.metadata;
        for value in [
            metadata.agent.known(),
            metadata.model.known(),
            metadata.provider.known(),
        ]
        .into_iter()
        .flatten()
        {
            budget.retain_text(value)?;
        }
        let record_counts = histogram(&session.counts.record_counts)?;
        let tool_names = session
            .counts
            .contributions
            .tool_calls
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        for name in &tool_names {
            budget.retain_text(name)?;
        }
        let mut deviation = None;
        if accounting.coverage == AccountingCoverage::CompleteSource
            && let Some(current) = baseline::accounting::summary(evaluation.client, session)
                .map_err(|_| ProcessingError::Evaluation)?
        {
            let previous = prior
                .snapshots
                .get(&baseline_snapshot_id(&current.key))
                .filter(|previous| previous.key == current.key);
            deviation = assess_baseline_deviation(previous, &current, config)
                .map_err(|_| ProcessingError::Evaluation)?;
            match summaries.entry(current.key.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(current);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    entry
                        .get_mut()
                        .checked_merge_from(current)
                        .map_err(|_| ProcessingError::Evaluation)?;
                }
            }
        }
        let evaluated = evaluation
            .sessions()
            .iter()
            .find(|s| s.session_id() == Some(&session.session_id));
        events.push(
            activity_from_counts(
                ActivityEventInput {
                    client: evaluation.client,
                    agent: metadata.agent.known().map(str::to_owned),
                    model: metadata.model.known().map(str::to_owned),
                    provider: metadata.provider.known().map(str::to_owned),
                    session_id: session.session_id.value().to_owned(),
                    source_path_hash: source_path_hash.to_owned(),
                    tool_name: tool_names.iter().next().cloned(),
                    tags: Vec::new(),
                    evidence: Vec::new(),
                    risk_contributions: Vec::new(),
                    event_time: evaluated.and_then(|s| s.event_time.clone()),
                },
                record_counts,
                tool_names,
                deviation,
            )
            .map_err(|_| ProcessingError::Projection)?,
        );
    }
    let replacement = match accounting.coverage {
        AccountingCoverage::CompleteSource => {
            BaselineReplacement::Replace(summaries.into_values().collect())
        }
        AccountingCoverage::PartialSource => BaselineReplacement::NoReplacement,
    };
    Ok(ActivityBaselineResult {
        events,
        replacement,
    })
}

fn histogram(counts: &RecordCounts) -> Result<BTreeMap<String, u32>, ProcessingError> {
    [
        ("user_message", counts.user_message),
        ("assistant_message", counts.assistant_message),
        ("tool_call", counts.tool_call),
        ("tool_result", counts.tool_result),
        ("session_meta", counts.session_meta),
        ("other", counts.other),
    ]
    .into_iter()
    .filter(|(_, count)| *count != 0)
    .map(|(kind, count)| {
        Ok((
            kind.to_owned(),
            u32::try_from(count).map_err(|_| ProcessingError::Projection)?,
        ))
    })
    .collect()
}

fn activity_from_counts(
    mut input: ActivityEventInput,
    record_counts: BTreeMap<String, u32>,
    tool_names: BTreeSet<String>,
    deviation: Option<crate::baseline::BaselineDeviation>,
) -> Result<Event, RiskAccountingError> {
    let mut risk_contributions = Vec::new();
    let mut evidence = Vec::new();
    let mut tags = vec!["activity".to_string(), "session".to_string()];
    if let Some(deviation) = deviation {
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

    let counts_text =
        serde_json::to_string(&record_counts).map_err(|_| RiskAccountingError::Overflow)?;
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
    input.tags = tags;
    input.evidence = evidence;
    input.risk_contributions = risk_contributions;
    activity_event(input)
}
