use super::super::compile_rule_v1;
use super::super::session::*;
use telltale_schema::clients::ClientId;
use telltale_schema::observation::*;

fn observation(
    id: &str,
    session: Option<&str>,
    time: Option<&str>,
    sequence: u64,
) -> CanonicalObservationV2 {
    let source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "claude_code",
        "claude.projects",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id(id)
    .unwrap();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User)
                .with_content(JsonValue::string("ordinary synthetic text")),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        source,
    )
    .sequence(sequence)
    .fact_metadata(
        "message.role",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    )
    .fact_metadata(
        "message.content",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    );
    if let Some(session) = session {
        builder = builder.session_id(CorrelationId::source_reported(session).unwrap());
    }
    if let Some(time) = time {
        builder = builder.occurred_at(SourceTimestamp::new(time).unwrap());
    }
    builder.build().unwrap()
}

fn metadata() -> FactMetadata {
    FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap()
}

fn message(
    id: &str,
    session: Option<&str>,
    text: &str,
    capability: CapabilityAvailability,
) -> CanonicalObservationV2 {
    message_with_correlation(
        id,
        session.map(|value| CorrelationId::source_reported(value).unwrap()),
        text,
        capability,
    )
}

fn message_with_correlation(
    id: &str,
    session: Option<CorrelationId>,
    text: &str,
    capability: CapabilityAvailability,
) -> CanonicalObservationV2 {
    let source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "claude_code",
        "claude.projects",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id(id)
    .unwrap();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string(text)),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        source,
    )
    .fact_metadata("message.role", metadata())
    .fact_metadata("message.content", metadata())
    .capability_context(
        CapabilityContext::new().with_override(CapabilityId::UserContext, capability),
    )
    .occurred_at(SourceTimestamp::new("2026-09-17T00:00:00Z").unwrap());
    if let Some(session) = session {
        builder = builder.session_id(session);
    }
    builder.build().unwrap()
}

fn plan(modifier_score: u64) -> super::super::RuleV1CompatibilityPlan {
    let document = "title: synthetic\nid: 2f33e0ea-6afb-4a33-84ae-7fa76ce268cb\nname: synthetic.atomic\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: message\ndetection:\n    selection:\n        - message.user_text|re: 'needle'\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: 'synthetic'\n    analytic_intent: alert\n    detection_class: security_detection\n    signal_type: atomic\n    tags: [synthetic]\n---\ntitle: synthetic\nid: 1ba8e050-4895-4b15-82c3-84ee5647cbc9\nname: chain.synthetic\ntaxonomy: telltale\ncorrelation:\n    type: telltale_chain\n    rules: [synthetic.atomic]\ntelltale:\n    score: 0\n    explanation: 'synthetic'\n    analytic_intent: audit\n    detection_class: security_detection\n    signal_type: chain\n";
    // Rule v2 caps a score at 100; the compiled form takes any score.
    compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[document], None)
            .unwrap()
            .compatibility_export()
            .with_modifier("chain.synthetic", |modifier| {
                modifier.score = modifier_score
            }),
    )
    .unwrap()
}

fn target_plan(targets: &str, regex: &str) -> super::super::RuleV1CompatibilityPlan {
    // `targets` lists compiled target names; each reads the Rule v2 field that
    // compiles to it.
    let selection = targets
        .split(", ")
        .enumerate()
        .map(|(index, target)| {
            let field = match target {
                "command" => "tool.command",
                "url" => "tool.url",
                "user_context" => "message.user_text",
                other => panic!("unmapped target {other}"),
            };
            if index == 0 {
                format!("        - {field}|re: &pattern '{regex}'\n")
            } else {
                format!("        - {field}|re: *pattern\n")
            }
        })
        .collect::<String>();
    let category = match (selection.contains("tool."), selection.contains("message.")) {
        (true, true) => "agent_activity",
        (false, true) => "message",
        _ => "tool_activity",
    };
    let document = format!(
        "title: synthetic\nid: 1523429f-99fb-4ca1-85ff-dfa1ea08477d\nname: synthetic.target\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: {category}\ndetection:\n    selection:\n{selection}    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: 'synthetic'\n    analytic_intent: alert\n    detection_class: security_detection\n    signal_type: atomic\n    tags: [synthetic]\n"
    );
    compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&document], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap()
}

fn evaluate(
    observations: &[CanonicalObservationV2],
    plan: &super::super::RuleV1CompatibilityPlan,
) -> Result<CanonicalSourceEvaluation, ProcessingError> {
    let instance = CorrelationId::source_reported("synthetic-source-instance").unwrap();
    evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations,
        },
        plan,
        None,
    )
}

fn context() -> super::super::event3::Event3CompatibilityContext<'static> {
    super::super::event3::Event3CompatibilityContext {
        source_path_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        sessions: &[],
    }
}

fn command(id: &str, text: &str, time: Option<&str>, sequence: u64) -> CanonicalObservationV2 {
    let source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "claude_code",
        "claude.projects",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id(id)
    .unwrap();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_arguments(JsonValue::string(text)),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        source,
    )
    .session_id(CorrelationId::source_reported("process-session").unwrap())
    .sequence(sequence)
    .fact_metadata("tool.name", metadata())
    .fact_metadata("tool.arguments", metadata())
    .capability_context(
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
    );
    if let Some(time) = time {
        builder = builder.occurred_at(SourceTimestamp::new(time).unwrap());
    }
    builder.build().unwrap()
}

#[test]
fn session_metadata_is_explicit_scoped_and_not_invented() {
    use super::super::event3::{Event3CompatibilityContext, Event3SessionMetadata, project_event3};
    let observations = [
        message(
            "one",
            Some("session-a"),
            "needle",
            CapabilityAvailability::Supported,
        ),
        message(
            "two",
            Some("session-b"),
            "needle",
            CapabilityAvailability::Supported,
        ),
    ];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    let session_id = observations[0].session_id().unwrap();
    let metadata = [Event3SessionMetadata {
        session_id,
        agent: Some("synthetic-agent"),
        model: Some("synthetic-model"),
        provider: Some("synthetic-provider"),
    }];
    let events = project_event3(
        &evaluation,
        &Event3CompatibilityContext {
            sessions: &metadata,
            ..context()
        },
    )
    .unwrap()
    .events;
    assert_eq!(events[0].model.as_deref(), Some("synthetic-model"));
    assert_eq!(events[1].model, None);
    let unknown = CorrelationId::source_reported("not-in-evaluation").unwrap();
    let invalid = [Event3SessionMetadata {
        session_id: &unknown,
        agent: None,
        model: None,
        provider: None,
    }];
    assert!(matches!(
        project_event3(
            &evaluation,
            &Event3CompatibilityContext {
                sessions: &invalid,
                ..context()
            }
        ),
        Err(ProcessingError::Projection)
    ));
}

#[test]
fn metadata_index_rejects_duplicate_and_event3_ambiguous_session_keys() {
    use super::super::event3::{Event3CompatibilityContext, Event3SessionMetadata, project_event3};
    let source_id =
        CorrelationId::new("same-visible-session", CorrelationOrigin::SourceReported).unwrap();
    let derived_id = CorrelationId::new(
        "same-visible-session",
        CorrelationOrigin::TelltaleOriginated,
    )
    .unwrap();
    let observations = [
        message_with_correlation(
            "source-origin",
            Some(source_id.clone()),
            "needle",
            CapabilityAvailability::Supported,
        ),
        message_with_correlation(
            "derived-origin",
            Some(derived_id.clone()),
            "needle",
            CapabilityAvailability::Supported,
        ),
    ];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    let duplicate = [
        Event3SessionMetadata {
            session_id: &source_id,
            agent: None,
            model: None,
            provider: None,
        },
        Event3SessionMetadata {
            session_id: &source_id,
            agent: None,
            model: None,
            provider: None,
        },
    ];
    assert!(matches!(
        project_event3(
            &evaluation,
            &Event3CompatibilityContext {
                sessions: &duplicate,
                ..context()
            }
        ),
        Err(ProcessingError::Projection)
    ));
    let ambiguous = [
        Event3SessionMetadata {
            session_id: &source_id,
            agent: None,
            model: None,
            provider: None,
        },
        Event3SessionMetadata {
            session_id: &derived_id,
            agent: None,
            model: None,
            provider: None,
        },
    ];
    assert!(matches!(
        project_event3(
            &evaluation,
            &Event3CompatibilityContext {
                sessions: &ambiguous,
                ..context()
            }
        ),
        Err(ProcessingError::Projection)
    ));
    let one_origin = [Event3SessionMetadata {
        session_id: &source_id,
        agent: Some("synthetic-agent"),
        model: None,
        provider: None,
    }];
    assert!(matches!(
        project_event3(
            &evaluation,
            &Event3CompatibilityContext {
                sessions: &one_origin,
                ..context()
            }
        ),
        Err(ProcessingError::Projection)
    ));
}

#[test]
fn reordered_inputs_have_identical_replay_stable_event3_semantics() {
    fn semantics(events: &[telltale_schema::event::Event]) -> Vec<String> {
        events
            .iter()
            .map(|event| {
                serde_json::to_string(&(
                    &event.session_id,
                    &event.rule_ids,
                    event.risk_score,
                    event
                        .evidence
                        .iter()
                        .map(|item| (&item.field, &item.hash, &item.rule_id))
                        .collect::<Vec<_>>(),
                    &event.timeline_anchors,
                    &event.event_time,
                ))
                .unwrap()
            })
            .collect()
    }
    let forward = [
        observation("later", Some("session"), Some("2026-09-17T00:01:00Z"), 2),
        message(
            "match",
            Some("session"),
            "needle",
            CapabilityAvailability::Supported,
        ),
    ];
    let reversed = [forward[1].clone(), forward[0].clone()];
    let first =
        super::super::event3::project_event3(&evaluate(&forward, &plan(0)).unwrap(), &context())
            .unwrap();
    let second =
        super::super::event3::project_event3(&evaluate(&reversed, &plan(0)).unwrap(), &context())
            .unwrap();
    assert_eq!(semantics(&first.events), semantics(&second.events));
}

#[cfg(feature = "hook-journal")]
fn stamped_observation(source_id: &str) -> CanonicalObservationV2 {
    CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User)
                .with_content(JsonValue::string("ordinary synthetic text")),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        SourceProvenance::new(
            IngestionMode::SessionStore,
            ClientId::HOOK_JOURNAL_ADAPTER_TYPE,
            source_id,
            Fidelity::FullNative,
        )
        .unwrap()
        .with_native_id("one")
        .unwrap(),
    )
    .sequence(1)
    .session_id(CorrelationId::source_reported("session").unwrap())
    .fact_metadata(
        "message.role",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    )
    .fact_metadata(
        "message.content",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    )
    .build()
    .unwrap()
}

fn evaluate_scaled(
    observations: &[CanonicalObservationV2],
    source_bytes: usize,
) -> (
    Result<CanonicalSourceEvaluation, ProcessingError>,
    EvaluationWorkBudget,
) {
    let instance = CorrelationId::source_reported("synthetic-source-instance").unwrap();
    let work = EvaluationWorkBudget::for_source(SourceScale::for_source_bytes(source_bytes));
    let result = evaluate_source_with_work_budget(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations,
        },
        &plan(0),
        None,
        &work,
    );
    (result, work)
}

fn dense_needles(count: usize, text: &str) -> Vec<CanonicalObservationV2> {
    (0..count)
        .map(|index| {
            message(
                &format!("dense{index:05}"),
                Some("session"),
                text,
                CapabilityAvailability::Supported,
            )
        })
        .collect()
}

fn omitted_markers(
    event: &telltale_schema::event::Event,
) -> Vec<&telltale_schema::event::Evidence> {
    event
        .evidence
        .iter()
        .filter(|item| item.field == telltale_schema::event::EVIDENCE_OMITTED_FIELD)
        .collect()
}

/// Rule `synthetic.no{index}`: one never-matching selection on `field`.
fn synthetic_never_match_rule(index: usize, field: &str) -> String {
    let category = if field.starts_with("message.") {
        "message"
    } else {
        "tool_activity"
    };
    format!(
        "title: Synthetic {index}\nid: 00000000-0000-4000-8000-{index:012}\nname: synthetic.no{index}\n\
         taxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: {category}\n\
         detection:\n    selection:\n        - {field}|re: NEVER-MATCH\n    condition: selection\n\
         level: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: synthetic\n\
         \x20   analytic_intent: alert\n    detection_class: security_detection\n    signal_type: atomic\n"
    )
}

mod event3_projection;
mod failure_bounds;
mod replay_order;
mod retention_limits;
mod session_metadata;
mod url_facts;
mod work_budget;
