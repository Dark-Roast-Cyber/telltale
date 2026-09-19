//! Inactive canonical processing. One invocation is one caller-verified source
//! instance, never a collection of files grouped by their session strings.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use telltale_rules::process_chain::CompiledProcessChainRules;
use telltale_schema::clients::ClientId;
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityId, CorrelationId, CorrelationOrigin,
    ObservationBody,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::DetectionError;
use super::RuleV1CompatibilityPlan;
use super::process_chain::{
    ProcessChainSessionEvaluation, evaluate_tool_process_chain_session_with_budget,
};
use super::rule_v1::{
    RuleV1DetectorSessionEvaluation, RuleV1SessionEvaluation, evaluate_rule_v1_session_with_budget,
};
use crate::process_chain::ProcessChainConfig;
use crate::process_chain_session::ProcessChainSessionConfig;

pub const MAX_SOURCE_OBSERVATIONS: usize = 65_536;
pub const MAX_PROJECTION_ITEMS: usize = 4096;
pub const MAX_COMPATIBILITY_STRING_BYTES: usize =
    telltale_schema::observation::LOCAL_MAX_STRING_BYTES;
pub const MAX_COMPATIBILITY_RETAINED_BYTES: usize = 4 * 1024 * 1024;

/// Source-wide accounting for compatibility material and the bounded work used
/// to retain it. Callers consume capacity before allocating retained values.
pub(crate) struct RetentionBudget {
    items: usize,
    bytes: usize,
}

impl RetentionBudget {
    pub(crate) fn new() -> Self {
        Self { items: 0, bytes: 0 }
    }

    pub(crate) fn consume(&mut self, items: usize, bytes: usize) -> Result<(), ProcessingError> {
        let next_items = self
            .items
            .checked_add(items)
            .ok_or(ProcessingError::Bounds)?;
        let next_bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(ProcessingError::Bounds)?;
        if next_items > MAX_PROJECTION_ITEMS || next_bytes > MAX_COMPATIBILITY_RETAINED_BYTES {
            return Err(ProcessingError::Bounds);
        }
        self.items = next_items;
        self.bytes = next_bytes;
        Ok(())
    }

    pub(crate) fn validate_text(value: &str) -> Result<(), ProcessingError> {
        if value.len() > MAX_COMPATIBILITY_STRING_BYTES {
            Err(ProcessingError::Bounds)
        } else {
            Ok(())
        }
    }

    pub(crate) fn retain_text(&mut self, value: &str) -> Result<(), ProcessingError> {
        Self::validate_text(value)?;
        self.consume(0, value.len())
    }
}

/// No error carries source data, rule text, or an underlying error's Display.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProcessingError {
    InvalidSource,
    DuplicateObservation,
    Bounds,
    Evaluation,
    Projection,
}
impl fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSource => "canonical_invalid_source",
            Self::DuplicateObservation => "canonical_duplicate_observation",
            Self::Bounds => "canonical_processing_bounds",
            Self::Evaluation => "canonical_evaluation_failed",
            Self::Projection => "event3_projection_failed",
        })
    }
}
impl std::error::Error for ProcessingError {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EvaluationCompletion {
    Complete,
    VisibilityLimited,
}

/// The instance is an opaque, caller-verified identity, not a path or a session
/// string. None means unverifiable scope and disables cross-observation grouping.
/// Never combine acquisitions from unrelated instances in this slice.
pub struct CanonicalSourceInput<'a> {
    pub client: ClientId,
    pub source_id: &'a str,
    pub source_instance: Option<&'a CorrelationId>,
    pub observations: &'a [CanonicalObservationV2],
}

/// Accounting, not a synthetic finding or a legacy baseline snapshot.
#[derive(Default)]
pub struct CanonicalActivity {
    pub observation_counts: BTreeMap<String, u64>,
    pub tool_names: Vec<String>,
}

pub struct CanonicalSessionEvaluation {
    pub(crate) session_id: Option<CorrelationId>,
    pub(crate) rules: RuleV1SessionEvaluation,
    pub(crate) processes: Option<ProcessChainSessionEvaluation>,
    pub(crate) event_time: Option<String>,
    pub(crate) tool_name: Option<String>,
    pub(crate) activity: CanonicalActivity,
    pub(crate) completion: EvaluationCompletion,
}
impl CanonicalSessionEvaluation {
    pub fn rule_ids(&self) -> &[String] {
        self.rules.effective_rule_ids()
    }
    pub fn risk_contributions(&self) -> &[telltale_schema::scoring::RiskContribution] {
        self.rules.compatibility_contributions()
    }
    pub fn rule_score(&self) -> u64 {
        self.rules.compatibility_score()
    }
    pub fn suppressed_process_count(&self) -> usize {
        self.processes.as_ref().map_or(0, |p| p.suppressed_count())
    }
    pub fn session_id(&self) -> Option<&CorrelationId> {
        self.session_id.as_ref()
    }
    pub fn detectors(&self) -> &[RuleV1DetectorSessionEvaluation] {
        self.rules.detectors()
    }
    pub fn process_results(&self) -> &[super::DetectorResult] {
        self.processes.as_ref().map_or(&[], |p| p.results())
    }
    pub fn activity(&self) -> &CanonicalActivity {
        &self.activity
    }
    pub fn completion(&self) -> EvaluationCompletion {
        self.completion
    }
}

pub struct CanonicalSourceEvaluation {
    pub(crate) client: ClientId,
    pub(crate) source_id: String,
    source_instance: Option<CorrelationId>,
    pub(crate) sessions: Vec<CanonicalSessionEvaluation>,
    completion: EvaluationCompletion,
}
impl CanonicalSourceEvaluation {
    pub fn source_instance(&self) -> Option<&CorrelationId> {
        self.source_instance.as_ref()
    }
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    pub fn sessions(&self) -> &[CanonicalSessionEvaluation] {
        &self.sessions
    }
    pub fn completion(&self) -> EvaluationCompletion {
        self.completion
    }
}

/// Evaluates both rule families over exactly the same source-scoped ordering.
/// Errors discard the entire source result. No I/O, persistence, allowlisting,
/// clock reads, or production routing occur here.
pub fn evaluate_source(
    input: CanonicalSourceInput<'_>,
    rules: &RuleV1CompatibilityPlan,
    process: Option<(&CompiledProcessChainRules, &ProcessChainConfig)>,
) -> Result<CanonicalSourceEvaluation, ProcessingError> {
    if input.observations.len() > MAX_SOURCE_OBSERVATIONS {
        return Err(ProcessingError::Bounds);
    }
    let adapter_type = match (input.client, input.source_id) {
        (ClientId::Claude, "claude.projects") => "claude_code",
        (
            ClientId::Codex,
            "codex.sessions" | "codex.archived_sessions" | "codex.headless_sessions",
        ) => "codex",
        (ClientId::OpenCode, "opencode.sqlite") => "opencode",
        (ClientId::OpenClaw, "openclaw.agents") => "openclaw",
        (ClientId::Qwen, "qwen.projects") => "qwen",
        (ClientId::Copilot, "copilot.process_log") => "copilot",
        _ => return Err(ProcessingError::InvalidSource),
    };
    if let Some(instance) = input.source_instance {
        RetentionBudget::validate_text(instance.value())?;
    }
    let mut seen = BTreeSet::new();
    for observation in input.observations {
        if observation.source().adapter_id() != input.source_id
            || observation.source().adapter_type() != adapter_type
        {
            return Err(ProcessingError::InvalidSource);
        }
        if !seen.insert(observation.observation_id()) {
            return Err(ProcessingError::DuplicateObservation);
        }
        if let Some(session_id) = observation.session_id() {
            RetentionBudget::validate_text(session_id.value())?;
        }
    }
    let mut sessions = Vec::new();
    let mut budget = RetentionBudget::new();
    budget.retain_text(input.source_id)?;
    if let Some(instance) = input.source_instance {
        budget.retain_text(instance.value())?;
    }
    let mut completion = EvaluationCompletion::Complete;
    for observations in group_sessions(input.observations, input.source_instance.is_some()) {
        let rule_result = evaluate_rule_v1_session_with_budget(rules, &observations, &mut budget)
            .map_err(|error| error.processing_error())?;
        // Match precedence is presentation only: it cannot erase an error.
        if rule_result
            .detectors()
            .iter()
            .any(|d| d.detector_error_count() != 0)
        {
            return Err(ProcessingError::Evaluation);
        }
        let processes = process
            .map(|(rules, config)| {
                evaluate_tool_process_chain_session_with_budget(
                    rules,
                    &observations,
                    &config.context,
                    &ProcessChainSessionConfig {
                        suppression_window: config.suppression_window,
                        max_correlations_per_rule_entity: config.max_correlations_per_rule_entity,
                        max_correlation_risk_per_entity: config.max_correlation_risk_per_entity,
                    },
                    &mut budget,
                )
            })
            .transpose()
            .map_err(|error| match error {
                DetectionError::InvalidBounds => ProcessingError::Bounds,
                _ => ProcessingError::Evaluation,
            })?;
        let limited = input.source_instance.is_none()
            || rules.has_unavailable_url_visibility()
            || observations[0].session_id().is_none()
            || rule_result
                .detectors()
                .iter()
                .any(|d| d.not_evaluated_count() != 0)
            || (process.is_some()
                && observations.iter().any(|o| {
                    matches!(o.body(), ObservationBody::Tool(_))
                        && (o.occurred_at().is_none()
                            || o.capability_context()
                                .map(|c| c.resolve(CapabilityId::ToolCall))
                                != Some(CapabilityAvailability::Supported))
                }));
        let session_completion = if limited {
            EvaluationCompletion::VisibilityLimited
        } else {
            EvaluationCompletion::Complete
        };
        if limited {
            completion = EvaluationCompletion::VisibilityLimited;
        }
        let mut activity = CanonicalActivity::default();
        let mut tools = BTreeSet::new();
        for observation in &observations {
            *activity
                .observation_counts
                .entry(format!(
                    "{}.{}",
                    observation.kind().as_str(),
                    observation.stage().as_str()
                ))
                .or_default() += 1;
            if let ObservationBody::Tool(tool) = observation.body()
                && let Some(name) = tool.name()
            {
                RetentionBudget::validate_text(name)?;
                tools.insert(name);
            }
        }
        for name in tools {
            budget.retain_text(name)?;
            activity.tool_names.push(name.to_owned());
        }
        if let Some(session_id) = observations[0].session_id() {
            budget.retain_text(session_id.value())?;
        }
        let event_time = observations
            .iter()
            .filter_map(|o| o.occurred_at())
            .next_back()
            .map(|t| t.as_str());
        if let Some(value) = event_time {
            budget.retain_text(value)?;
        }
        let tool_name = observations.iter().find_map(|o| match o.body() {
            ObservationBody::Tool(tool) => tool.name(),
            _ => None,
        });
        if let Some(value) = tool_name {
            budget.retain_text(value)?;
        }
        sessions.push(CanonicalSessionEvaluation {
            session_id: observations[0].session_id().cloned(),
            event_time: event_time.map(str::to_owned),
            tool_name: tool_name.map(str::to_owned),
            activity,
            rules: rule_result,
            processes,
            completion: session_completion,
        });
    }
    // These clones are safe because their byte capacity was consumed above.
    Ok(CanonicalSourceEvaluation {
        client: input.client,
        source_id: input.source_id.to_owned(),
        source_instance: input.source_instance.cloned(),
        sessions,
        completion,
    })
}

/// Ordering owner for both evaluators. Unknown scopes are singleton groups.
/// Equal times use source ordering, then child ordinal, then stable caller order;
/// no filesystem location or acquisition clock participates.
pub(crate) fn group_sessions(
    observations: &[CanonicalObservationV2],
    verified_source: bool,
) -> Vec<Vec<&CanonicalObservationV2>> {
    let mut groups: BTreeMap<(u8, &str), Vec<&CanonicalObservationV2>> = BTreeMap::new();
    for observation in observations {
        let key = match (verified_source, observation.session_id()) {
            (true, Some(session)) => (
                match session.origin() {
                    CorrelationOrigin::SourceReported => 0,
                    CorrelationOrigin::TelltaleOriginated => 1,
                },
                session.value(),
            ),
            _ => (2, observation.observation_id()),
        };
        groups.entry(key).or_default().push(observation);
    }
    let mut groups = groups.into_values().collect::<Vec<_>>();
    for group in &mut groups {
        group.sort_by_key(|o| {
            (
                o.occurred_at().is_none(),
                o.occurred_at()
                    .and_then(|t| OffsetDateTime::parse(t.as_str(), &Rfc3339).ok()),
                o.sequence().or(o.source().source_sequence()),
                o.identity_basis().child_ordinal(),
            )
        });
    }
    groups
}
