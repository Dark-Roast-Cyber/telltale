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
    process_chain_event, redact_sensitive_text,
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
    pub completion: EvaluationCompletion,
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
    occurrences: Vec<usize>,
    supporting: Vec<ProcessResultKey>,
    variants: Vec<ProcessContext>,
    supporting_steps: Vec<String>,
    pub(crate) repeat_count: Option<u64>,
}

impl ProcessProjection {
    pub(crate) fn item_count(&self) -> usize {
        1 + self.variants.len() + self.supporting_steps.len()
    }
    pub(crate) fn atomic(
        input: &ProcessObservation,
        detection: &ProcessChainDetection,
        observation: &CanonicalObservationV2,
        occurrence: usize,
        budget: &mut super::session::RetentionBudget,
    ) -> Result<Self, DetectionError> {
        let source_process_name = input.parent.normalized_name();
        let source_process_path = input.parent.path.as_deref().map(redact_sensitive_text);
        let source_process_command_line = input
            .parent
            .command_line
            .as_deref()
            .map(redact_sensitive_text);
        let target_process_name = input.child.normalized_name();
        let target_process_path = input.child.path.as_deref().map(redact_sensitive_text);
        let target_process_command_line = input
            .child
            .command_line
            .as_deref()
            .map(redact_sensitive_text);
        let parent_process_name = input.grandparent.as_ref().map(|p| p.normalized_name());
        let parent_process_path = input
            .grandparent
            .as_ref()
            .and_then(|p| p.path.as_deref().map(redact_sensitive_text));
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
            .consume(1, bytes)
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
            occurrences: vec![occurrence],
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
        let mut supporting_steps = Vec::with_capacity(matched.len());
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
        for (key, projection) in matched {
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
                .sum::<usize>()
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
        budget
            .consume(1 + matched.len(), bytes)
            .map_err(|_| DetectionError::InvalidBounds)?;
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
                .flat_map(|(_, p)| p.occurrences.iter().copied())
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
        budget
            .consume(1, bytes)
            .map_err(|_| DetectionError::InvalidBounds)?;
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
        budget
            .consume(0, bytes)
            .map_err(|_| DetectionError::InvalidBounds)
    }
}

fn retained_text_bytes<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<usize, DetectionError> {
    let mut bytes = 0usize;
    for value in values {
        if value.len() > super::session::MAX_COMPATIBILITY_STRING_BYTES {
            return Err(DetectionError::InvalidBounds);
        }
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

fn evidence(field: &str, value: &str, rule_id: &str) -> Evidence {
    Evidence {
        field: field.to_owned(),
        redacted_value: redact_sensitive_text(value),
        hash: Some(evidence_hash(value)),
        rule_id: Some(rule_id.to_owned()),
    }
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
    let mut budget = super::session::RetentionBudget::new();
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
    for session in &evaluation.sessions {
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
                evidence: session
                    .rules
                    .projection()
                    .flat_map(|p| {
                        [
                            p.evidence.clone(),
                            evidence(
                                "canonical_observation_id",
                                &p.observation_id,
                                p.evidence.rule_id.as_deref().unwrap_or_default(),
                            ),
                        ]
                    })
                    .collect(),
                risk_contributions: session.rules.compatibility_contributions().to_vec(),
                event_time: session.event_time.clone(),
            })
            .map_err(|_| ProcessingError::Projection)?;
            let mut anchors = BTreeMap::<usize, (BTreeSet<String>, BTreeSet<String>)>::new();
            for projection in session.rules.projection() {
                let anchor = anchors.entry(projection.occurrence).or_default();
                if let Some(rule_id) = &projection.evidence.rule_id {
                    anchor.0.insert(rule_id.clone());
                }
                anchor.1.insert(projection.evidence.field.clone());
            }
            for (rule_ids, _) in anchors.values_mut() {
                rule_ids.extend(session.rules.triggered_modifier_ids().iter().cloned());
            }
            event.timeline_anchors = canonicalize_timeline_anchors(
                anchors
                    .into_iter()
                    .map(
                        |(entry_index, (rule_ids, evidence_fields))| TimelineAnchor {
                            entry_index,
                            rule_ids: rule_ids.into_iter().collect(),
                            categories: metadata.categories().to_vec(),
                            evidence_fields: evidence_fields.into_iter().collect(),
                        },
                    )
                    .collect(),
            );
            ordinary_detection = Some(event);
        }
        let Some(processes) = &session.processes else {
            events.extend(ordinary_detection);
            continue;
        };
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
                    ),
                    evidence("correlated_event_ids", &ids.join(","), rule_id),
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
                )]
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
                items.push(evidence("process_context_variant", &value, rule_id));
            }
            for step in &projection.supporting_steps {
                items.push(evidence("correlation_process_step", step, rule_id));
            }
            // Event3 permits timeline_anchors only on detection events. Process
            // occurrence linkage must use its existing evidence surface instead.
            let occurrences = projection
                .occurrences
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",");
            items.push(evidence("canonical_occurrences", &occurrences, rule_id));
            for id in result.observation_ids() {
                items.push(evidence("canonical_observation_id", id, rule_id));
            }
            let risk_contributions = if score == 0 {
                Vec::new()
            } else {
                vec![
                    RiskContribution::new(
                        rule_id,
                        RiskContributionType::DeterministicRule,
                        score,
                        redact_sensitive_text(&projection.reason),
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
            projected_ids.insert(key, event.event_id.clone());
            events.push(event);
        }
        events.extend(ordinary_detection);
    }
    // Constructor success alone does not establish terminal exportability.
    for event in &events {
        let bytes = serde_json::to_vec(event).map_err(|_| ProcessingError::Projection)?;
        telltale_schema::event::Event3Record::from_json(&bytes)
            .map_err(|_| ProcessingError::Projection)?;
    }
    Ok(ProjectedSource {
        events,
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

fn validate_projection_budget(
    evaluation: &CanonicalSourceEvaluation,
    context: &Event3CompatibilityContext<'_>,
    metadata_index: &BTreeMap<(u8, String), &Event3SessionMetadata<'_>>,
    budget: &mut super::session::RetentionBudget,
) -> Result<(), ProcessingError> {
    for session in &evaluation.sessions {
        let metadata = session.session_id.as_ref().and_then(|id| {
            metadata_index
                .get(&(correlation_key(id).0, id.value().to_owned()))
                .copied()
        });
        let shared = std::iter::once(context.source_path_hash)
            .chain(session.session_id.as_ref().map(|id| id.value()))
            .chain(session.event_time.as_deref())
            .chain(session.tool_name.as_deref())
            .chain(metadata.and_then(|value| value.agent))
            .chain(metadata.and_then(|value| value.model))
            .chain(metadata.and_then(|value| value.provider));
        let shared_bytes = projection_text_bytes(shared)?;
        if !session.rules.effective_rule_ids().is_empty() {
            let projection_count = session.rules.projection().count();
            let occurrence_count = session
                .rules
                .projection()
                .map(|projection| projection.occurrence)
                .collect::<BTreeSet<_>>()
                .len();
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
            budget.consume(1 + projection_count * 2 + occurrence_count, bytes)?;
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
            let item_count = 1
                + base_evidence
                + usize::from(projection.repeat_count.is_some())
                + projection.variants.len()
                + projection.supporting_steps.len()
                + 1
                + result.observation_ids().len();
            budget.consume(item_count, bytes)?;
        }
    }
    Ok(())
}

fn projection_text_bytes<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<usize, ProcessingError> {
    let mut bytes = 0usize;
    for value in values {
        super::session::RetentionBudget::validate_text(value)?;
        bytes = bytes
            .checked_add(value.len())
            .ok_or(ProcessingError::Bounds)?;
    }
    Ok(bytes)
}

fn add_projection_strings(bytes: usize, values: &[String]) -> Result<usize, ProcessingError> {
    bytes
        .checked_add(projection_text_bytes(values.iter().map(String::as_str))?)
        .ok_or(ProcessingError::Bounds)
}
