//! Event3 compatibility adapter for canonical evaluation output. No source
//! access, legacy records, detector reruns, allowlisting, persistence, or custom
//! serialization.

use super::session::{CanonicalSourceEvaluation, EvaluationCompletion, ProcessingError};
use super::{DetectionError, DetectorResult};
use std::collections::{BTreeMap, BTreeSet};
use telltale_rules::process_chain::{
    CompiledCorrelationRule, ProcessChainDetection, ProcessObservation,
};
use telltale_schema::event::{
    DetectionEventInput, Event, Evidence, ProcessChainEventInput, ProcessContext, TimelineAnchor,
    canonicalize_timeline_anchors, detection_event, evidence_hash, is_canonical_sha256_hex,
    process_chain_event, terminal_identifier,
};
use telltale_schema::observation::{
    CanonicalObservationV2, CorrelationId, CorrelationOrigin, ObservationBody,
};
use telltale_schema::scoring::{RiskContribution, RiskContributionType};

/// Projection-only identity and optional *reported* metadata. No filesystem path
/// is accepted. The hash identifies the acquired artifact, never grouping scope.
pub struct Event3CompatibilityContext<'a> {
    pub source_path_hash: &'a str,
    pub sessions: &'a [Event3SessionMetadata<'a>],
}

/// Caller-attested metadata is scoped to the exact canonical session, including
/// identity origin. No first-value propagation between unrelated sessions.
pub struct Event3SessionMetadata<'a> {
    pub session_id: &'a CorrelationId,
    pub agent: Option<&'a str>,
    pub model: Option<&'a str>,
    pub provider: Option<&'a str>,
}

/// Success is operational completion, not permission to persist a cursor.
/// The caller must still durably persist required output before committing progress.
pub struct ProjectedSource {
    pub events: Vec<Event>,
    /// Embedding projection input. Not a supported detector or host API.
    #[doc(hidden)]
    pub occurrences: Vec<ProjectedOccurrence>,
    /// Embedding projection input: session action findings in evaluation order,
    /// each linked to the event projected for it. Not a host API.
    #[doc(hidden)]
    pub action_findings: Vec<super::ActionFinding>,
    pub completion: EvaluationCompletion,
}

/// Projection input for the core embedding facade, not a detector or host API.
#[doc(hidden)]
pub struct ProjectedOccurrence {
    pub observation_id: String,
    pub finding_index: usize,
    pub session_id: String,
    pub timeline_index: Option<usize>,
    pub occurred_at: Option<String>,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    /// Selector-derived field names; empty for process/correlation findings.
    pub evidence_fields: Vec<String>,
}

pub(crate) type ProcessResultKey = (String, Vec<String>, Option<String>);
pub(crate) fn process_result_key(result: &DetectorResult) -> ProcessResultKey {
    (
        result.detector().id().to_owned(),
        result.observation_ids().to_vec(),
        result.dedupe_key().map(str::to_owned),
    )
}

/// Matcher-derived Event3 material only, not a new semantic record or a Process
/// observation. No Debug implementation: internal Event3 context may be private.
#[derive(Clone)]
pub(crate) struct ProcessProjection {
    process: ProcessContext,
    detection_class: String,
    signal_type: String,
    analytic_intent: String,
    reason: String,
    event_time: Option<String>,
    tool_name: Option<String>,
    occurrences: Vec<(String, usize)>,
    supporting: Vec<ProcessResultKey>,
    variants: Vec<ProcessContext>,
    supporting_steps: Vec<String>,
    pub(crate) repeat_count: Option<u64>,
}

impl ProcessProjection {
    pub(crate) fn atomic(
        input: &ProcessObservation,
        detection: &ProcessChainDetection,
        observation: &CanonicalObservationV2,
        occurrence: usize,
        budget: &mut super::session::RetentionBudget,
    ) -> Result<Self, DetectionError> {
        budget
            .charge(
                input
                    .parent
                    .name
                    .len()
                    .saturating_add(input.child.name.len())
                    .saturating_add(
                        input
                            .grandparent
                            .as_ref()
                            .map_or(0, |parent| parent.name.len()),
                    ),
            )
            .map_err(|_| DetectionError::InvalidBounds)?;
        let mut redact = |text: &str| {
            telltale_schema::event::PrivacySanitizer::try_sanitize(
                telltale_schema::event::SanitizationContext::Evidence,
                text,
                &mut |bytes| budget.charge(bytes),
            )
            .map_err(|_| DetectionError::InvalidBounds)
        };
        let source_process_name = input.parent.normalized_name();
        let source_process_path = input.parent.path.as_deref().map(&mut redact).transpose()?;
        let source_process_command_line = input
            .parent
            .command_line
            .as_deref()
            .map(&mut redact)
            .transpose()?;
        let target_process_name = input.child.normalized_name();
        let target_process_path = input.child.path.as_deref().map(&mut redact).transpose()?;
        let target_process_command_line = input
            .child
            .command_line
            .as_deref()
            .map(&mut redact)
            .transpose()?;
        let parent_process_name = input.grandparent.as_ref().map(|p| p.normalized_name());
        let parent_process_path = input
            .grandparent
            .as_ref()
            .and_then(|p| p.path.as_deref())
            .map(&mut redact)
            .transpose()?;
        let event_time = observation.occurred_at().map(|t| t.as_str());
        let tool_name = match observation.body() {
            ObservationBody::Tool(tool) => tool.name(),
            _ => None,
        };
        let strings = [
            Some(source_process_name.as_str()),
            source_process_path.as_deref(),
            source_process_command_line.as_deref(),
            Some(target_process_name.as_str()),
            target_process_path.as_deref(),
            target_process_command_line.as_deref(),
            parent_process_name.as_deref(),
            parent_process_path.as_deref(),
            Some(observation.observation_id()),
            Some(detection.rule_name.as_str()),
            Some(detection.detection_class.as_str()),
            Some(detection.signal_type.as_str()),
            Some(detection.analytic_intent.as_str()),
            Some(detection.detection_reason.as_str()),
            Some(detection.dedup_key.as_str()),
            Some(detection.severity.as_str()),
            detection.risk_adjustment.as_deref(),
            event_time,
            tool_name,
        ];
        let mut bytes = retained_text_bytes(strings.into_iter().flatten())?;
        bytes = add_text_list_bytes(bytes, &detection.secondary_rule_ids)?;
        bytes = add_text_list_bytes(bytes, &detection.investigation_fields)?;
        bytes = add_text_list_bytes(bytes, &detection.falsepositives)?;
        budget
            .consume(
                2,
                bytes
                    .checked_add(observation.observation_id().len())
                    .ok_or(DetectionError::InvalidBounds)?,
            )
            .map_err(|_| DetectionError::InvalidBounds)?;
        Ok(Self {
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name,
                source_process_path,
                source_process_id: None,
                source_process_command_line,
                target_process_name,
                target_process_path,
                target_process_id: None,
                target_process_command_line,
                parent_process_name,
                parent_process_path,
                source_event_id: Some(observation.observation_id().to_owned()),
                source_process_inferred: input.parent_inferred,
                rule_name: detection.rule_name.clone(),
                secondary_rule_ids: detection.secondary_rule_ids.clone(),
                investigation_fields: detection.investigation_fields.clone(),
                falsepositives: detection.falsepositives.clone(),
                dedup_key: detection.dedup_key.clone(),
                suppression_window_seconds: detection.suppression_window_seconds,
                rule_severity: detection.severity.clone(),
                risk_adjustment: detection.risk_adjustment.clone(),
            },
            detection_class: detection.detection_class.clone(),
            signal_type: detection.signal_type.clone(),
            analytic_intent: detection.analytic_intent.clone(),
            reason: detection.detection_reason.clone(),
            event_time: event_time.map(str::to_owned),
            tool_name: tool_name.map(str::to_owned),
            occurrences: vec![(observation.observation_id().to_owned(), occurrence)],
            supporting: Vec::new(),
            variants: Vec::new(),
            supporting_steps: Vec::new(),
            repeat_count: None,
        })
    }

    pub(crate) fn correlation(
        rule: &CompiledCorrelationRule,
        matched: &[(ProcessResultKey, &Self)],
        capped: bool,
        budget: &mut super::session::RetentionBudget,
    ) -> Result<Self, DetectionError> {
        let first = matched.first().ok_or(DetectionError::RuntimeEvaluation)?.1;
        let last = matched.last().ok_or(DetectionError::RuntimeEvaluation)?.1;
        let mut bytes = retained_text_bytes([
            first.process.source_process_name.as_str(),
            last.process.target_process_name.as_str(),
            rule.title.as_str(),
            rule.id.as_str(),
            rule.severity.as_str(),
            rule.detection_class.as_str(),
            rule.analytic_intent.as_str(),
            rule.reason.as_str(),
        ])?;
        bytes = add_text_list_bytes(bytes, &rule.falsepositives)?;
        let mut association_count = 0usize;
        for (key, projection) in matched {
            association_count = association_count
                .checked_add(projection.occurrences.len())
                .ok_or(DetectionError::InvalidBounds)?;
            bytes = bytes
                .checked_add(retained_text_bytes(
                    projection.occurrences.iter().map(|(id, _)| id.as_str()),
                )?)
                .ok_or(DetectionError::InvalidBounds)?;
            bytes = bytes
                .checked_add(retained_text_bytes(
                    std::iter::once(key.0.as_str())
                        .chain(key.1.iter().map(String::as_str))
                        .chain(key.2.as_deref())
                        .chain([
                            projection.process.source_process_name.as_str(),
                            projection.process.target_process_name.as_str(),
                        ]),
                )?)
                .ok_or(DetectionError::InvalidBounds)?;
            let step_len = key
                .1
                .iter()
                .map(String::len)
                .try_fold(0usize, |count, next| count.checked_add(next))
                .ok_or(DetectionError::InvalidBounds)?
                .checked_add(key.1.len().saturating_sub(1))
                .and_then(|value| value.checked_add(6))
                .and_then(|value| value.checked_add(projection.process.source_process_name.len()))
                .and_then(|value| value.checked_add(projection.process.target_process_name.len()))
                .ok_or(DetectionError::InvalidBounds)?;
            if step_len > super::session::MAX_COMPATIBILITY_STRING_BYTES {
                return Err(DetectionError::InvalidBounds);
            }
            bytes = bytes
                .checked_add(step_len)
                .ok_or(DetectionError::InvalidBounds)?;
        }
        if capped {
            bytes = bytes
                .checked_add("per-entity correlation risk cap reached".len())
                .ok_or(DetectionError::InvalidBounds)?;
        }
        bytes = bytes
            .checked_add(retained_text_bytes(last.event_time.as_deref())?)
            .ok_or(DetectionError::InvalidBounds)?;
        budget
            .consume(
                matched
                    .len()
                    .checked_add(1)
                    .and_then(|items| items.checked_add(association_count))
                    .ok_or(DetectionError::InvalidBounds)?,
                bytes,
            )
            .map_err(|_| DetectionError::InvalidBounds)?;
        let mut supporting_steps = Vec::with_capacity(matched.len());
        for (key, projection) in matched {
            supporting_steps.push(format!(
                "{}: {} -> {}",
                key.1.join(","),
                projection.process.source_process_name,
                projection.process.target_process_name
            ));
        }
        Ok(Self {
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name: first.process.source_process_name.clone(),
                source_process_path: None,
                source_process_id: None,
                source_process_command_line: None,
                target_process_name: last.process.target_process_name.clone(),
                target_process_path: None,
                target_process_id: None,
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: None,
                source_process_inferred: matched
                    .iter()
                    .any(|(_, p)| p.process.source_process_inferred),
                rule_name: rule.title.clone(),
                secondary_rule_ids: matched.iter().map(|(key, _)| key.0.clone()).collect(),
                investigation_fields: Vec::new(),
                falsepositives: rule.falsepositives.clone(),
                dedup_key: format!("correlation:{}", rule.id),
                suppression_window_seconds: rule.window_seconds,
                rule_severity: rule.severity.clone(),
                risk_adjustment: capped
                    .then(|| "per-entity correlation risk cap reached".to_owned()),
            },
            detection_class: rule.detection_class.clone(),
            signal_type: "correlation".to_owned(),
            analytic_intent: rule.analytic_intent.clone(),
            reason: rule.reason.clone(),
            event_time: last.event_time.clone(),
            tool_name: None,
            occurrences: matched
                .iter()
                .flat_map(|(_, p)| p.occurrences.iter().cloned())
                .collect(),
            supporting: matched.iter().map(|(key, _)| key.clone()).collect(),
            variants: Vec::new(),
            supporting_steps,
            repeat_count: None,
        })
    }

    pub(crate) fn retain_variant(
        &mut self,
        variant: &Self,
        budget: &mut super::session::RetentionBudget,
    ) -> Result<(), DetectionError> {
        let bytes = process_context_bytes(&variant.process)?;
        let associations = variant
            .occurrences
            .iter()
            .filter(|association| !self.occurrences.contains(association));
        let association_bytes =
            retained_text_bytes(associations.clone().map(|(id, _)| id.as_str()))?;
        budget
            .consume(
                associations
                    .clone()
                    .count()
                    .checked_add(1)
                    .ok_or(DetectionError::InvalidBounds)?,
                bytes
                    .checked_add(association_bytes)
                    .ok_or(DetectionError::InvalidBounds)?,
            )
            .map_err(|_| DetectionError::InvalidBounds)?;
        let associations = associations.cloned().collect::<Vec<_>>();
        self.occurrences.extend(associations);
        self.variants.push(variant.process.clone());
        Ok(())
    }

    pub(crate) fn consume_clone_budget(
        &self,
        budget: &mut super::session::RetentionBudget,
    ) -> Result<(), DetectionError> {
        let mut bytes = process_context_bytes(&self.process)?;
        bytes = bytes
            .checked_add(retained_text_bytes(
                [
                    self.detection_class.as_str(),
                    self.signal_type.as_str(),
                    self.analytic_intent.as_str(),
                    self.reason.as_str(),
                ]
                .into_iter()
                .chain(self.event_time.as_deref())
                .chain(self.tool_name.as_deref())
                .chain(self.supporting_steps.iter().map(String::as_str)),
            )?)
            .ok_or(DetectionError::InvalidBounds)?;
        for variant in &self.variants {
            bytes = bytes
                .checked_add(process_context_bytes(variant)?)
                .ok_or(DetectionError::InvalidBounds)?;
        }
        bytes = bytes
            .checked_add(retained_text_bytes(
                self.occurrences.iter().map(|(id, _)| id.as_str()),
            )?)
            .ok_or(DetectionError::InvalidBounds)?;
        for key in &self.supporting {
            bytes = bytes
                .checked_add(retained_text_bytes(
                    std::iter::once(key.0.as_str())
                        .chain(key.1.iter().map(String::as_str))
                        .chain(key.2.as_deref()),
                )?)
                .ok_or(DetectionError::InvalidBounds)?;
        }
        budget
            .consume(self.occurrences.len(), bytes)
            .map_err(|_| DetectionError::InvalidBounds)
    }
}

fn retained_text_bytes<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<usize, DetectionError> {
    let mut bytes = 0usize;
    for value in values {
        super::session::RetentionBudget::validate_text(value)
            .map_err(|_| DetectionError::InvalidBounds)?;
        bytes = bytes
            .checked_add(value.len())
            .ok_or(DetectionError::InvalidBounds)?;
    }
    Ok(bytes)
}

fn add_text_list_bytes(bytes: usize, values: &[String]) -> Result<usize, DetectionError> {
    bytes
        .checked_add(retained_text_bytes(values.iter().map(String::as_str))?)
        .ok_or(DetectionError::InvalidBounds)
}

fn process_context_bytes(process: &ProcessContext) -> Result<usize, DetectionError> {
    let mut bytes = retained_text_bytes(
        [
            process.host.as_deref(),
            process.user.as_deref(),
            Some(process.source_process_name.as_str()),
            process.source_process_path.as_deref(),
            process.source_process_command_line.as_deref(),
            Some(process.target_process_name.as_str()),
            process.target_process_path.as_deref(),
            process.target_process_command_line.as_deref(),
            process.parent_process_name.as_deref(),
            process.parent_process_path.as_deref(),
            process.source_event_id.as_deref(),
            Some(process.rule_name.as_str()),
            Some(process.dedup_key.as_str()),
            Some(process.rule_severity.as_str()),
            process.risk_adjustment.as_deref(),
        ]
        .into_iter()
        .flatten(),
    )?;
    bytes = add_text_list_bytes(bytes, &process.secondary_rule_ids)?;
    bytes = add_text_list_bytes(bytes, &process.investigation_fields)?;
    add_text_list_bytes(bytes, &process.falsepositives)
}

fn evidence(
    field: &str,
    value: &str,
    rule_id: &str,
    budget: &mut super::session::RetentionBudget,
) -> Result<Evidence, ProcessingError> {
    let redacted_value = telltale_schema::event::PrivacySanitizer::try_sanitize(
        telltale_schema::event::SanitizationContext::Evidence,
        value,
        &mut |bytes| budget.charge(bytes),
    )?;
    budget.charge(value.len())?;
    let hash = evidence_hash(value);
    budget.charge(field.len().saturating_add(rule_id.len()))?;
    Ok(Evidence {
        field: field.to_owned(),
        redacted_value,
        hash: Some(hash),
        rule_id: Some(rule_id.to_owned()),
    })
}

/// All-or-nothing projection. Optional metadata is caller-attested compatibility
/// context, not inferred from client labels or arbitrary tool arguments.
pub fn project_event3(
    evaluation: &CanonicalSourceEvaluation,
    context: &Event3CompatibilityContext<'_>,
) -> Result<ProjectedSource, ProcessingError> {
    if !is_canonical_sha256_hex(context.source_path_hash) {
        return Err(ProcessingError::Projection);
    }
    let evaluation_keys = evaluation
        .sessions
        .iter()
        .filter_map(|session| session.session_id.as_ref())
        .map(correlation_key)
        .collect::<BTreeSet<_>>();
    let mut evaluation_visible = BTreeMap::<&str, BTreeSet<u8>>::new();
    for session in &evaluation.sessions {
        if let Some(id) = session.session_id.as_ref() {
            evaluation_visible
                .entry(id.value())
                .or_default()
                .insert(correlation_key(id).0);
        }
    }
    let mut metadata_index = BTreeMap::new();
    let mut metadata_values = BTreeSet::new();
    let mut budget = super::session::RetentionBudget::with_work(evaluation.work_bytes.clone());
    for metadata in context.sessions {
        super::session::RetentionBudget::validate_text(metadata.session_id.value())?;
        for value in [metadata.agent, metadata.model, metadata.provider]
            .into_iter()
            .flatten()
        {
            super::session::RetentionBudget::validate_text(value)?;
        }
        let key = correlation_key(metadata.session_id);
        let metadata_bytes = projection_text_bytes(
            std::iter::once(metadata.session_id.value())
                .chain(metadata.agent)
                .chain(metadata.model)
                .chain(metadata.provider),
        )?;
        budget.consume(1, metadata_bytes)?;
        let event3_ambiguous = evaluation_visible
            .get(metadata.session_id.value())
            .is_none_or(|origins| origins.len() != 1);
        if event3_ambiguous
            || !evaluation_keys.contains(&key)
            || metadata_index
                .insert((key.0, key.1.to_owned()), metadata)
                .is_some()
            || !metadata_values.insert(metadata.session_id.value())
        {
            return Err(ProcessingError::Projection);
        }
    }
    validate_projection_budget(evaluation, context, &metadata_index, &mut budget)?;
    let mut events = Vec::new();
    let mut occurrences = Vec::new();
    let mut action_findings = Vec::new();
    for session in &evaluation.sessions {
        // Process events by the native finding ID their action findings carry.
        // It covers the full result identity, including the dedupe key that
        // separates same-rule variants on one observation.
        let mut process_events = BTreeMap::<String, Vec<usize>>::new();
        let metadata_context = session.session_id.as_ref().and_then(|id| {
            metadata_index
                .get(&(correlation_key(id).0, id.value().to_owned()))
                .copied()
        });
        let agent = metadata_context.and_then(|m| m.agent).map(str::to_owned);
        let model = metadata_context.and_then(|m| m.model).map(str::to_owned);
        let provider = metadata_context.and_then(|m| m.provider).map(str::to_owned);
        let session_id = session.session_id.as_ref().map(|s| s.value());
        let mut ordinary_detection = None;
        let mut session_occurrences = Vec::new();
        if !session.rules.effective_rule_ids().is_empty() {
            let session_id = session_id.ok_or(ProcessingError::Projection)?;
            let metadata = session.rules.compatibility_metadata();
            let mut tags = metadata.tags().to_vec();
            if session
                .rules
                .effective_rule_ids()
                .iter()
                .any(|id| id.starts_with("chain."))
            {
                tags.push("chain".to_owned());
            }
            tags.sort();
            tags.dedup();
            let mut evidence_items = Vec::new();
            for projection in session.rules.projection() {
                budget.charge(projection.evidence.redacted_value.len())?;
                evidence_items.push(projection.evidence.clone());
                evidence_items.push(evidence(
                    "canonical_observation_id",
                    &projection.observation_id,
                    projection.evidence.rule_id.as_deref().unwrap_or_default(),
                    &mut budget,
                )?);
            }
            let mut event = detection_event(DetectionEventInput {
                client: evaluation.client,
                agent: agent.clone(),
                model: model.clone(),
                provider: provider.clone(),
                session_id: session_id.to_owned(),
                source_path_hash: context.source_path_hash.to_owned(),
                tool_name: session.tool_name.clone(),
                rule_ids: session.rules.effective_rule_ids().to_vec(),
                categories: metadata.categories().to_vec(),
                detection_classes: metadata.detection_classes().to_vec(),
                signal_types: metadata.signal_types().to_vec(),
                analytic_intents: metadata.analytic_intents().to_vec(),
                atlas_tags: metadata.atlas_tags().to_vec(),
                tags,
                evidence: evidence_items,
                risk_contributions: session.rules.compatibility_contributions().to_vec(),
                event_time: session.event_time.clone(),
            })
            .map_err(|_| ProcessingError::Projection)?;
            let mut anchors = BTreeMap::new();
            for projection in session.rules.projection() {
                let (anchor, retained) =
                    anchors.entry(projection.occurrence).or_insert_with(|| {
                        (
                            TimelineAnchor {
                                entry_index: projection.occurrence,
                                rule_ids: Vec::new(),
                                categories: metadata.categories().to_vec(),
                                evidence_fields: Vec::new(),
                            },
                            projection,
                        )
                    });
                if retained.observation_id != projection.observation_id
                    || retained.occurred_at != projection.occurred_at
                {
                    return Err(ProcessingError::Projection);
                }
                if let Some(rule_id) = &projection.evidence.rule_id {
                    anchor.rule_ids.push(rule_id.clone());
                }
                anchor
                    .evidence_fields
                    .push(projection.evidence.field.clone());
            }
            for (mut anchor, retained) in anchors.into_values() {
                anchor
                    .rule_ids
                    .extend(session.rules.triggered_modifier_ids().iter().cloned());
                anchor.rule_ids.sort();
                anchor.rule_ids.dedup();
                anchor.evidence_fields.sort();
                anchor.evidence_fields.dedup();
                session_occurrences.push(ProjectedOccurrence {
                    observation_id: retained.observation_id.clone(),
                    finding_index: 0,
                    session_id: event.session_id.clone(),
                    timeline_index: Some(anchor.entry_index),
                    occurred_at: retained.occurred_at.clone(),
                    rule_ids: anchor.rule_ids.clone(),
                    categories: anchor.categories.clone(),
                    evidence_fields: anchor.evidence_fields.clone(),
                });
                event.timeline_anchors.push(anchor);
            }
            event.timeline_anchors = canonicalize_timeline_anchors(event.timeline_anchors);
            ordinary_detection = Some(event);
        }
        if let Some(processes) = &session.processes {
            let mut projected_ids = BTreeMap::new();
            for result in processes.results() {
                let session_id = session_id.ok_or(ProcessingError::Projection)?;
                let key = process_result_key(result);
                let projection = processes
                    .projection
                    .get(&key)
                    .ok_or(ProcessingError::Projection)?;
                let rule_id = result.detector().id();
                let correlation = !projection.supporting.is_empty();
                let mut tags = vec!["process_chain".to_owned(), result.category().to_owned()];
                if correlation {
                    tags.push("correlation".to_owned());
                }
                if projection.process.source_process_inferred {
                    tags.push("inferred_parent".to_owned());
                }
                if !correlation && !projection.process.secondary_rule_ids.is_empty() {
                    tags.push("deduplicated".to_owned());
                }
                tags.extend(result.tags().iter().cloned());
                let score = u64::from(result.risk_points().unwrap_or(0));
                if score == 0 && !correlation {
                    tags.push("informational".to_owned());
                }
                tags.sort();
                tags.dedup();
                let mut items = if correlation {
                    let ids = projection
                        .supporting
                        .iter()
                        .map(|key| {
                            projected_ids
                                .get(key)
                                .cloned()
                                .ok_or(ProcessingError::Projection)
                        })
                        .collect::<Result<Vec<String>, _>>()?;
                    vec![
                        evidence(
                            "correlation_sequence",
                            &projection.process.secondary_rule_ids.join(" -> "),
                            rule_id,
                            &mut budget,
                        )?,
                        evidence("correlated_event_ids", &ids.join(","), rule_id, &mut budget)?,
                    ]
                } else {
                    vec![evidence(
                        "process_chain",
                        &format!(
                            "{} -> {}",
                            projection.process.source_process_name,
                            projection.process.target_process_name
                        ),
                        rule_id,
                        &mut budget,
                    )?]
                };
                if let Some(repeat_count) = projection.repeat_count {
                    items.push(Evidence {
                        field: "repeat_count".to_owned(),
                        redacted_value: repeat_count.to_string(),
                        hash: None,
                        rule_id: Some(rule_id.to_owned()),
                    });
                }
                for variant in &projection.variants {
                    let value =
                        serde_json::to_string(variant).map_err(|_| ProcessingError::Projection)?;
                    items.push(evidence(
                        "process_context_variant",
                        &value,
                        rule_id,
                        &mut budget,
                    )?);
                }
                for step in &projection.supporting_steps {
                    items.push(evidence(
                        "correlation_process_step",
                        step,
                        rule_id,
                        &mut budget,
                    )?);
                }
                // Event3 permits timeline_anchors only on detection events. Process
                // occurrence linkage must use its existing evidence surface instead.
                let occurrence_indexes = projection
                    .occurrences
                    .iter()
                    .map(|(_, index)| index.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                items.push(evidence(
                    "canonical_occurrences",
                    &occurrence_indexes,
                    rule_id,
                    &mut budget,
                )?);
                for id in result.observation_ids() {
                    items.push(evidence(
                        "canonical_observation_id",
                        id,
                        rule_id,
                        &mut budget,
                    )?);
                }
                let risk_contributions = if score == 0 {
                    Vec::new()
                } else {
                    vec![
                        RiskContribution::new(
                            rule_id,
                            RiskContributionType::DeterministicRule,
                            score,
                            telltale_schema::event::PrivacySanitizer::try_sanitize(
                                telltale_schema::event::SanitizationContext::Evidence,
                                &projection.reason,
                                &mut |bytes| budget.charge(bytes),
                            )?,
                        )
                        .map_err(|_| ProcessingError::Projection)?,
                    ]
                };
                let mut process = projection.process.clone();
                if correlation {
                    process.dedup_key = result
                        .dedupe_key()
                        .ok_or(ProcessingError::Projection)?
                        .to_owned();
                }
                let event = process_chain_event(ProcessChainEventInput {
                    client: evaluation.client,
                    agent: agent.clone(),
                    model: model.clone(),
                    provider: provider.clone(),
                    session_id: session_id.to_owned(),
                    source_path_hash: context.source_path_hash.to_owned(),
                    tool_name: projection.tool_name.clone(),
                    rule_ids: if correlation {
                        vec![rule_id.to_owned()]
                    } else {
                        std::iter::once(rule_id.to_owned())
                            .chain(process.secondary_rule_ids.iter().cloned())
                            .collect()
                    },
                    categories: vec![result.category().to_owned()],
                    detection_classes: vec![projection.detection_class.clone()],
                    signal_types: vec![projection.signal_type.clone()],
                    analytic_intents: vec![projection.analytic_intent.clone()],
                    tags,
                    evidence: items,
                    risk_contributions,
                    event_time: projection.event_time.clone(),
                    confidence: result
                        .confidence()
                        .ok_or(ProcessingError::Projection)?
                        .as_str()
                        .to_owned(),
                    detection_reason: projection.reason.clone(),
                    mitre_attack_techniques: result
                        .techniques()
                        .iter()
                        .map(|t| t.strip_prefix("attack:").unwrap_or(t).to_owned())
                        .collect(),
                    risk_entity_type: "session".to_owned(),
                    risk_entity_value: Some(session_id.to_owned()),
                    process,
                })
                .map_err(|_| ProcessingError::Projection)?;
                let observation_ids = result.observation_ids();
                let mut seen = BTreeSet::new();
                for id in observation_ids {
                    if !seen.insert(id) {
                        continue;
                    }
                    occurrences.push(ProjectedOccurrence {
                        observation_id: id.clone(),
                        finding_index: events.len(),
                        session_id: event.session_id.clone(),
                        timeline_index: proven_occurrence_index(&projection.occurrences, id),
                        occurred_at: if observation_ids.len() == 1 {
                            projection.event_time.clone()
                        } else {
                            None
                        },
                        rule_ids: event.rule_ids.clone(),
                        categories: event.categories.clone(),
                        evidence_fields: Vec::new(),
                    });
                }
                projected_ids.insert(key, event.event_id.clone());
                let finding = result
                    .finding()
                    .map_err(|_| ProcessingError::Projection)?
                    .ok_or(ProcessingError::Projection)?;
                process_events
                    .entry(finding.finding_id().to_owned())
                    .or_default()
                    .push(events.len());
                events.push(event);
            }
        }
        for occurrence in &mut session_occurrences {
            occurrence.finding_index = events.len();
        }
        occurrences.extend(session_occurrences);
        let rule_event = ordinary_detection.as_ref().map(|_| events.len());
        let rule_event_ids = session
            .rules
            .effective_rule_ids()
            .iter()
            .map(|id| terminal_identifier("rule", id))
            .collect::<BTreeSet<_>>();
        events.extend(ordinary_detection);
        for action in &session.action_findings {
            let index = if action.detector_kind() == "process_chain" {
                match action.canonical_findings() {
                    [finding] => process_events
                        .get(finding.finding_id())
                        .and_then(|indexes| match indexes.as_slice() {
                            [index] => Some(*index),
                            _ => None,
                        }),
                    _ => None,
                }
            } else {
                // The action view can match where session selectors do not (it
                // also reads command text as URL text), so the session detection
                // is this action's event only when it carries every action rule.
                rule_event.filter(|_| {
                    action
                        .rule_ids()
                        .iter()
                        .all(|id| rule_event_ids.contains(id))
                })
            };
            action_findings.push(action.clone().with_session_event_index(index));
        }
    }
    occurrences.sort_by(|a, b| {
        a.finding_index
            .cmp(&b.finding_index)
            .then_with(|| a.timeline_index.is_none().cmp(&b.timeline_index.is_none()))
            .then_with(|| a.timeline_index.cmp(&b.timeline_index))
            .then_with(|| a.observation_id.cmp(&b.observation_id))
    });
    // Constructor success alone does not establish terminal exportability.
    for event in &events {
        let bytes = serde_json::to_vec(event).map_err(|_| ProcessingError::Projection)?;
        telltale_schema::event::Event3Record::from_json(&bytes)
            .map_err(|_| ProcessingError::Projection)?;
    }
    Ok(ProjectedSource {
        events,
        occurrences,
        action_findings,
        completion: evaluation.completion(),
    })
}

fn correlation_key(id: &CorrelationId) -> (u8, &str) {
    let origin = match id.origin() {
        CorrelationOrigin::SourceReported => 0,
        CorrelationOrigin::TelltaleOriginated => 1,
    };
    (origin, id.value())
}

fn proven_occurrence_index(associations: &[(String, usize)], id: &str) -> Option<usize> {
    let mut indexes = associations
        .iter()
        .filter(|(retained_id, _)| retained_id == id)
        .map(|(_, index)| *index);
    let index = indexes.next()?;
    indexes.all(|other| other == index).then_some(index)
}

/// Charge objects/vectors and every retained text item before copying any of
/// the anchor or occurrence material. Uses the same source-wide hard limits.
fn charge_projection_values<'a>(
    budget: &mut super::session::RetentionBudget,
    mut items: usize,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), ProcessingError> {
    let mut bytes = 0usize;
    for value in values {
        super::session::RetentionBudget::validate_text(value)?;
        items = items.checked_add(1).ok_or(ProcessingError::Bounds)?;
        bytes = bytes
            .checked_add(value.len())
            .ok_or(ProcessingError::Bounds)?;
    }
    budget.consume(items, bytes)
}

fn validate_projection_budget(
    evaluation: &CanonicalSourceEvaluation,
    context: &Event3CompatibilityContext<'_>,
    metadata_index: &BTreeMap<(u8, String), &Event3SessionMetadata<'_>>,
    budget: &mut super::session::RetentionBudget,
) -> Result<(), ProcessingError> {
    for session in &evaluation.sessions {
        // Constructors retain source IDs; terminal serialization can expand
        // them. Reserve the larger representation without weakening retention
        // accounting for long source IDs that serialize to a shorter hash.
        let source_session_id = session.session_id.as_ref().map(|id| id.value());
        let terminal_session_id =
            source_session_id.map(telltale_schema::event::terminal_session_id);
        let retained_session_id = source_session_id.map(|source| {
            terminal_session_id
                .as_deref()
                .filter(|terminal| terminal.len() > source.len())
                .unwrap_or(source)
        });
        let metadata = session.session_id.as_ref().and_then(|id| {
            metadata_index
                .get(&(correlation_key(id).0, id.value().to_owned()))
                .copied()
        });
        let shared = std::iter::once(context.source_path_hash)
            .chain(retained_session_id)
            .chain(session.event_time.as_deref())
            .chain(session.tool_name.as_deref())
            .chain(metadata.and_then(|value| value.agent))
            .chain(metadata.and_then(|value| value.model))
            .chain(metadata.and_then(|value| value.provider));
        let shared_bytes = projection_text_bytes(shared)?;
        if !session.rules.effective_rule_ids().is_empty() {
            let projection_count = session.rules.projection().count();
            let mut bytes = shared_bytes;
            bytes = add_projection_strings(bytes, session.rules.effective_rule_ids())?;
            let metadata = session.rules.compatibility_metadata();
            for values in [
                metadata.categories(),
                metadata.detection_classes(),
                metadata.signal_types(),
                metadata.analytic_intents(),
                metadata.atlas_tags(),
                metadata.tags(),
            ] {
                bytes = add_projection_strings(bytes, values)?;
            }
            for contribution in session.rules.compatibility_contributions() {
                bytes = bytes
                    .checked_add(projection_text_bytes([
                        contribution.id(),
                        contribution.rationale(),
                    ])?)
                    .ok_or(ProcessingError::Bounds)?;
            }
            for projection in session.rules.projection() {
                bytes = bytes
                    .checked_add(projection_text_bytes([
                        projection.observation_id.as_str(),
                        projection.evidence.field.as_str(),
                        projection.evidence.redacted_value.as_str(),
                        projection.evidence.hash.as_deref().unwrap_or_default(),
                        projection.evidence.rule_id.as_deref().unwrap_or_default(),
                    ])?)
                    .ok_or(ProcessingError::Bounds)?;
            }
            budget.consume(
                projection_count
                    .checked_mul(2)
                    .and_then(|count| count.checked_add(1))
                    .ok_or(ProcessingError::Bounds)?,
                bytes,
            )?;
            let mut anchors = BTreeMap::new();
            for projection in session.rules.projection() {
                anchors
                    .entry(projection.occurrence)
                    .or_insert_with(Vec::new)
                    .push(projection);
            }
            for projections in anchors.into_values() {
                let retained = projections[0];
                let rules = projections
                    .iter()
                    .filter_map(|projection| projection.evidence.rule_id.as_deref())
                    .chain(
                        session
                            .rules
                            .triggered_modifier_ids()
                            .iter()
                            .map(String::as_str),
                    )
                    .collect::<BTreeSet<_>>();
                let fields = projections
                    .iter()
                    .map(|projection| projection.evidence.field.as_str())
                    .collect::<BTreeSet<_>>();
                let anchor_values = || {
                    rules
                        .iter()
                        .copied()
                        .chain(metadata.categories().iter().map(String::as_str))
                        .chain(fields.iter().copied())
                };
                // Temporary anchor vectors retain duplicates until canonicalized.
                charge_projection_values(
                    budget,
                    4,
                    projections
                        .iter()
                        .filter_map(|projection| projection.evidence.rule_id.as_deref())
                        .chain(
                            projections
                                .iter()
                                .map(|projection| projection.evidence.field.as_str()),
                        )
                        .chain(
                            session
                                .rules
                                .triggered_modifier_ids()
                                .iter()
                                .map(String::as_str),
                        )
                        .chain(metadata.categories().iter().map(String::as_str)),
                )?;
                charge_projection_values(
                    budget,
                    4,
                    std::iter::once(retained.observation_id.as_str())
                        .chain(retained_session_id)
                        .chain(retained.occurred_at.as_deref())
                        .chain(anchor_values()),
                )?;
            }
        }
        let Some(processes) = &session.processes else {
            continue;
        };
        for result in processes.results() {
            let projection = processes
                .projection
                .get(&process_result_key(result))
                .ok_or(ProcessingError::Projection)?;
            let mut bytes = shared_bytes
                .checked_add(
                    process_context_bytes(&projection.process)
                        .map_err(|_| ProcessingError::Bounds)?,
                )
                .ok_or(ProcessingError::Bounds)?;
            bytes = bytes
                .checked_add(projection_text_bytes([
                    result.detector().id(),
                    result.category(),
                    projection.detection_class.as_str(),
                    projection.signal_type.as_str(),
                    projection.analytic_intent.as_str(),
                    projection.reason.as_str(),
                ])?)
                .ok_or(ProcessingError::Bounds)?;
            for variant in &projection.variants {
                bytes = bytes
                    .checked_add(
                        process_context_bytes(variant).map_err(|_| ProcessingError::Bounds)?,
                    )
                    .ok_or(ProcessingError::Bounds)?;
            }
            bytes = add_projection_strings(bytes, &projection.supporting_steps)?;
            bytes = add_projection_strings(bytes, result.observation_ids())?;
            let base_evidence = if projection.supporting.is_empty() {
                1
            } else {
                2
            };
            let item_count = [
                1usize,
                base_evidence,
                usize::from(projection.repeat_count.is_some()),
                projection.variants.len(),
                projection.supporting_steps.len(),
                1,
                result.observation_ids().len(),
            ]
            .into_iter()
            .try_fold(0usize, |count, next| {
                count.checked_add(next).ok_or(ProcessingError::Bounds)
            })?;
            budget.consume(item_count, bytes)?;
            let mut seen = BTreeSet::new();
            for id in result
                .observation_ids()
                .iter()
                .filter(|id| seen.insert(*id))
            {
                let secondary = if projection.supporting.is_empty() {
                    projection.process.secondary_rule_ids.as_slice()
                } else {
                    &[]
                };
                charge_projection_values(
                    budget,
                    4,
                    [
                        id.as_str(),
                        retained_session_id.ok_or(ProcessingError::Projection)?,
                        result.detector().id(),
                        result.category(),
                    ]
                    .into_iter()
                    .chain(
                        (result.observation_ids().len() == 1)
                            .then_some(projection.event_time.as_deref())
                            .flatten(),
                    )
                    .chain(secondary.iter().map(String::as_str)),
                )?;
            }
        }
    }
    Ok(())
}

fn projection_text_bytes<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<usize, ProcessingError> {
    retained_text_bytes(values).map_err(|_| ProcessingError::Bounds)
}

fn add_projection_strings(bytes: usize, values: &[String]) -> Result<usize, ProcessingError> {
    add_text_list_bytes(bytes, values).map_err(|_| ProcessingError::Bounds)
}

#[cfg(test)]
mod tests {
    use super::super::session::{
        CanonicalSourceInput, MAX_PROJECTION_ITEMS, RetentionBudget, evaluate_source,
    };
    use super::*;
    use telltale_schema::observation::*;

    #[test]
    fn unsafe_short_session_terminal_expansion_is_preflight_charged() {
        use super::super::session::MAX_COMPATIBILITY_RETAINED_BYTES;
        let plan = super::super::compile_rule_v1(
            &telltale_rules::load_rule_set_from_documents(&["version: 1\ndescription: synthetic\ndefaults: { enabled: true, case_insensitive: false }\nrules:\n  - { id: synthetic.session, category: synthetic, severity: low, score: 1, targets: [user_context], regex: needle, tags: [], explanation: synthetic }\nmodifiers: []\n"], None).unwrap().compatibility_export()
        ).unwrap();
        let instance = CorrelationId::source_reported("synthetic-instance").unwrap();
        let evaluate = |session: &str| {
            let observation = CanonicalObservationV2::builder(
                ObservationBody::Message(
                    MessageObservation::new(MessageRole::User)
                        .with_content(JsonValue::string("needle")),
                ),
                ObservationStage::MessageObserved,
                ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
                SourceProvenance::new(
                    IngestionMode::SessionStore,
                    "claude_code",
                    "claude.projects",
                    Fidelity::FullNative,
                )
                .unwrap()
                .with_native_id("synthetic-session-budget")
                .unwrap(),
            )
            .session_id(CorrelationId::source_reported(session).unwrap())
            .capability_context(
                CapabilityContext::new()
                    .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported),
            )
            .fact_metadata(
                "message.role",
                FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
            )
            .fact_metadata(
                "message.content",
                FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
            )
            .build()
            .unwrap();
            evaluate_source(
                CanonicalSourceInput {
                    client: telltale_schema::clients::ClientId::Claude,
                    source_id: "claude.projects",
                    source_instance: Some(&instance),
                    observations: &[observation],
                },
                &plan,
                None,
            )
            .unwrap()
        };
        let context = Event3CompatibilityContext {
            source_path_hash: &"a".repeat(64),
            sessions: &[],
        };
        let safe = evaluate("abc");
        let unsafe_session = evaluate("a b");
        let projected = project_event3(&unsafe_session, &context).unwrap();
        // Constructors retain source IDs; terminal serialization applies the
        // existing identity policy, which can expand a short unsafe ID.
        assert_eq!(projected.events[0].session_id, "a b");
        let terminal = telltale_schema::event::terminal_session_id("a b");
        assert!(terminal.len() > "a b".len());
        let record = telltale_schema::event::Event3Record::from_json(
            &serde_json::to_vec(&projected.events[0]).unwrap(),
        )
        .unwrap();
        assert_eq!(record.common().session_id, terminal);

        // Find the exact safe projection byte boundary without exposing budget
        // internals. The equally short unsafe source ID must not fit there.
        let fits = |evaluation: &CanonicalSourceEvaluation, capacity: usize| {
            let mut budget = RetentionBudget::new();
            budget
                .consume(0, MAX_COMPATIBILITY_RETAINED_BYTES - capacity)
                .unwrap();
            validate_projection_budget(evaluation, &context, &BTreeMap::new(), &mut budget)
        };
        let (mut low, mut high) = (0, MAX_COMPATIBILITY_RETAINED_BYTES);
        while low < high {
            let middle = low + (high - low) / 2;
            if fits(&safe, middle).is_ok() {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        assert!(fits(&safe, low).is_ok());
        assert_eq!(fits(&unsafe_session, low), Err(ProcessingError::Bounds));
    }

    #[test]
    fn process_occurrence_projection_has_its_own_preflight_charge() {
        let observation = CanonicalObservationV2::builder(
            ObservationBody::Tool(
                ToolObservation::new()
                    .with_name("shell")
                    .unwrap()
                    .with_arguments(JsonValue::string("cmd.exe /c hostname")),
            ),
            ObservationStage::ToolRequested,
            ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
            SourceProvenance::new(
                IngestionMode::SessionStore,
                "claude_code",
                "claude.projects",
                Fidelity::FullNative,
            )
            .unwrap()
            .with_native_id("synthetic-budget")
            .unwrap(),
        )
        .session_id(CorrelationId::source_reported("synthetic").unwrap())
        .occurred_at(SourceTimestamp::new("2026-09-18T00:00:00Z").unwrap())
        .fact_metadata(
            "tool.name",
            FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
        )
        .fact_metadata(
            "tool.arguments",
            FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
        )
        .build()
        .unwrap();
        let instance = CorrelationId::source_reported("synthetic-instance").unwrap();
        let rules = telltale_rules::process_chain::load_default_process_chain_rules().unwrap();
        let plan = super::super::compile_rule_v1(
            &telltale_rules::load_default_rule_set()
                .unwrap()
                .compatibility_export(),
        )
        .unwrap();
        let config = crate::process_chain::ProcessChainConfig::default();
        let evaluation = evaluate_source(
            CanonicalSourceInput {
                client: telltale_schema::clients::ClientId::Claude,
                source_id: "claude.projects",
                source_instance: Some(&instance),
                observations: &[observation],
            },
            &plan,
            Some((&rules, &config)),
        )
        .unwrap();
        let context = Event3CompatibilityContext {
            source_path_hash: &"a".repeat(64),
            sessions: &[],
        };
        let mut exact = RetentionBudget::new();
        validate_projection_budget(&evaluation, &context, &BTreeMap::new(), &mut exact).unwrap();
        assert!(
            !project_event3(&evaluation, &context)
                .unwrap()
                .occurrences
                .is_empty()
        );
        // The independently retained public occurrence (object and its three
        // vectors) must fit as well as the event/evidence material.
        let mut remaining = 0;
        while exact.consume(1, 0).is_ok() {
            remaining += 1;
        }
        let without_occurrence = MAX_PROJECTION_ITEMS - remaining - 4;
        let mut limited = RetentionBudget::new();
        limited
            .consume(MAX_PROJECTION_ITEMS - without_occurrence, 0)
            .unwrap();
        assert_eq!(
            validate_projection_budget(&evaluation, &context, &BTreeMap::new(), &mut limited),
            Err(ProcessingError::Bounds)
        );
    }

    #[test]
    fn occurrence_index_requires_exact_nonconflicting_association() {
        let associations = vec![("z".into(), 0), ("a".into(), 1), ("z".into(), 0)];
        assert_eq!(proven_occurrence_index(&associations, "a"), Some(1));
        assert_eq!(proven_occurrence_index(&associations, "z"), Some(0));
        assert_eq!(proven_occurrence_index(&associations, "missing"), None);
        assert_eq!(
            proven_occurrence_index(&[("a".into(), 0), ("a".into(), 1)], "a"),
            None
        );
    }
}
